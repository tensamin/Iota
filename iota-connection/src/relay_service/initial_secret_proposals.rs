use super::*;
use iota_storage::util::chat_secret_recovery::initial_proposals::{self as proposals, Proposal};

impl RelayService {
    pub(super) async fn accept_initial_proposal(
        &self,
        operation: PreparedRelayOperation,
        lease: Option<&iota_identity::HostedAuthorizationLease>,
        verified: &VerifiedRelayEnvelope,
    ) -> Result<RelayOutcome, RelayServiceError> {
        let prepared = crate::persisted_relay::encode_prepared_operation(&operation)
            .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
        let escrow = operation.secret_escrow.as_ref().ok_or_else(|| {
            RelayServiceError::Internal("initial secret evidence is missing".into())
        })?;
        relay_work::fault_point("before_proposal_persistence", &operation.message_id);
        let persisted = db::with_immediate_transaction(|tx| {
            operation.verify_principal_fences_on(tx)?;
            if let Some(lease) = lease {
                iota_storage::hosted_auth::verify_in_tx(tx, lease)?;
            }
            for effect in &operation.effects {
                relay_work::verify_owner_in_tx(tx, effect.owner.0, effect.principal)?;
            }
            let (first, second) = if verified.signer.principal == escrow.first {
                (&verified.signer, &verified.recipient)
            } else {
                (&verified.recipient, &verified.signer)
            };
            // `operation` was prepared from the verified original relay. Only
            // this signed evidence, never an authenticated digest assertion,
            // may supersede a competing uncommitted proposal.
            if proposals::get_on(tx, &escrow.signer, &escrow.message_id)?.is_none() {
                proposals::yield_to_verified_proposal_in_tx(tx, escrow)?;
            }
            proposals::persist_in_tx(tx, escrow, &prepared, first, second)
        });
        let proposal = match persisted {
            Ok(proposal) => proposal,
            Err(error) => return Ok(storage_outcome(&verified.frame, &error)),
        };
        relay_work::fault_point("after_proposal_persistence", &operation.message_id);
        if proposal.state == "rejected" {
            return Ok(storage_outcome(
                &verified.frame,
                &proposal_rejection(&proposal),
            ));
        }
        if proposal.state == "committed" {
            // Retention of the accepted relay inbox must not change a proposal's
            // terminal response or cause its application to execute again.
            let committed = crate::persisted_relay::decode_prepared_operation(&proposal.prepared)
                .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
            return Ok(success(
                &verified.frame,
                &committed.message_id,
                committed.accepted_at,
                "already_accepted",
                committed.recipient,
                Vec::new(),
            ));
        }
        match proposals::claim(&proposal) {
            Ok(Some(claim)) => match self.process_initial_proposal(&claim).await {
                Ok(accepted_at) => Ok(success(
                    &verified.frame,
                    &operation.message_id,
                    accepted_at,
                    "accepted",
                    operation.recipient,
                    Vec::new(),
                )),
                Err(error) => Ok(storage_outcome(&verified.frame, &error)),
            },
            Ok(None) => Ok(processing(&verified.frame, &operation.message_id)),
            Err(error) => Ok(storage_outcome(&verified.frame, &error)),
        }
    }

    async fn process_initial_proposal(&self, proposal: &Proposal) -> Result<i64, StorageError> {
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            self.commit_initial_proposal(proposal),
        )
        .await
        .unwrap_or_else(|_| Err(StorageError::Other("initial peer proof timed out".into())));
        if let Err(error) = &result {
            let rejected =
                permanent(error) || matches!(error, StorageError::HostedAuthorizationDenied);
            let code = if matches!(
                error,
                StorageError::MessageUnauthorized | StorageError::HostedAuthorizationDenied
            ) {
                "unauthorized"
            } else if matches!(error, StorageError::RelayOwnerUnavailable) {
                "owner_unavailable"
            } else if rejected {
                "conflict"
            } else {
                "peer_or_storage_unavailable"
            };
            // A superseded/erased claim cannot reschedule or reject newer work.
            match db::with_immediate_transaction(|tx| {
                proposals::finish_in_tx(
                    tx,
                    proposal,
                    if rejected {
                        "rejected"
                    } else {
                        "awaiting_peer_proof"
                    },
                    Some(code),
                )
            }) {
                Ok(()) | Err(StorageError::StaleRelayClaim) => {}
                Err(error) => iota_logger::log!(
                    "Initial secret proposal retry persistence failed: {}",
                    error
                ),
            }
            iota_logger::log!(
                "Initial secret proposal attempt: outcome={} generation={}",
                code,
                proposal.generation
            );
        }
        result
    }

    async fn commit_initial_proposal(&self, proposal: &Proposal) -> Result<i64, StorageError> {
        let operation = crate::persisted_relay::decode_prepared_operation(&proposal.prepared)?;
        let escrow = operation
            .secret_escrow
            .as_ref()
            .ok_or(StorageError::MissingRelayDependency)?;
        if escrow.signer != proposal.signer
            || escrow.message_id != proposal.message_id
            || escrow.operation_digest != proposal.digest
            || escrow.version != 1
            || escrow.original_type_map_version != proposal.type_map_version
        {
            return Err(StorageError::PendingRelayConflict);
        }
        db::with_immediate_transaction(|tx| {
            proposals::verify_identity_in_tx(tx, proposal)?;
            operation.verify_origin_authorization_in_tx(tx, true)
        })?;
        let map = TypeMap::new(
            mtp::type_map::Version::parse(&operation.type_map_version)
                .ok_or(StorageError::InvalidRelayPayload("proposal type map"))?,
        );
        // Verify original signatures independently of the accepted-replay shortcut.
        self.verify_recovery_escrow(escrow, &map)
            .await
            .map_err(|error| match error {
                RelayServiceError::Rejected(_) => StorageError::MessageUnauthorized,
                RelayServiceError::Internal(_) => {
                    StorageError::Other("proposal verification unavailable".into())
                }
            })?;
        if let crate::prepared_relay::DeliveryTarget::Remote(node) = &operation.delivery {
            // Give the destination the actual signed proposal before probing.
            // Simultaneous proposals can then select the lower verified digest.
            // Neither this receipt nor a transport failure selects a usable key;
            // the gate below still requires fresh authenticated recovery proof.
            let frame = CommunicationValue::try_from_bytes_with(&operation.frame, &map)
                .map_err(|_| StorageError::InvalidRelayPayload("proposal frame"))?
                .with_id(operation.frame_id);
            let _ = self
                .router
                .route(&RouteDestination::Iota(node.clone()), frame)
                .await;
        }
        let guard = crate::chat_secret_recovery::gate_initial_set_chat_secret(escrow)
            .await
            .map_err(|error| match error {
                crate::chat_secret_recovery::RecoveryError::Conflict => {
                    StorageError::ChatSecretConflict
                }
                crate::chat_secret_recovery::RecoveryError::Unauthorized => {
                    StorageError::MessageUnauthorized
                }
                _ => StorageError::Other("initial peer proof unavailable".into()),
            })?;
        relay_work::fault_point("after_proposal_peer_proof", &proposal.message_id);
        db::with_immediate_transaction(|tx| {
            proposals::verify_identity_in_tx(tx, proposal)?;
            guard.recheck_in_tx(tx)?;
            let relay_replay::AcquireResult::Claimed(claim) = relay_replay::acquire_in_tx(
                tx,
                operation.request(),
                now_millis_i64().saturating_add(30_000),
            )?
            else {
                return Err(StorageError::PendingRelayConflict);
            };
            tx.execute("UPDATE relay_inbox SET prepared_operation=?3 WHERE signer_principal=?1 AND message_id=?2",
                params![claim.signer.0,claim.message_id,proposal.prepared])?;
            operation.commit_in_tx(tx, &claim, true, |tx| guard.recheck_in_tx(tx))?;
            proposals::finish_in_tx(tx, proposal, "committed", None)?;
            relay_work::fault_point("before_proposal_commit", &proposal.message_id);
            Ok(())
        })?;
        relay_work::fault_point("after_proposal_commit", &proposal.message_id);
        iota_storage::util::chat_secret_recovery::notify_change();
        Ok(operation.accepted_at)
    }

    /// Startup and reconnect retry. Claims expire after crashes, and every attempt
    /// obtains new authenticated peer proof outside the SQLite transaction.
    pub async fn retry_initial_secret_proposals(&self) -> Result<(), RelayServiceError> {
        for _ in 0..32 {
            // Load one bounded payload at a time rather than retaining a page
            // of large signed frames while a slow peer consumes its timeout.
            let Some(proposal) = proposals::due(1)
                .map_err(|error| RelayServiceError::Internal(error.to_string()))?
                .pop()
            else {
                break;
            };
            if let Some(claim) = proposals::claim(&proposal)
                .map_err(|error| RelayServiceError::Internal(error.to_string()))?
            {
                let _ = self.process_initial_proposal(&claim).await;
            }
        }
        Ok(())
    }
}

fn proposal_rejection(proposal: &Proposal) -> StorageError {
    match proposal.last_error.as_deref() {
        Some("unauthorized") => StorageError::MessageUnauthorized,
        Some("owner_unavailable") => StorageError::RelayOwnerUnavailable,
        _ => StorageError::ChatSecretConflict,
    }
}
