use crate::connection_handler::{PeerRouter, RouteDestination, RouteOutcome};
use crate::message_common::now_millis_i64;
use crate::prepared_relay::{self, PreparedRelayOperation};
use async_trait::async_trait;
use iota_auth::{AuthenticatedSession, SessionCapability, SessionIdentity};
use iota_identity::{
    IdentityResolver, IotaNodeId, LocalUserStore, PrincipalHome, PrincipalStore, RelayRouterId,
};
use iota_storage::storage_error::StorageError;
use iota_storage::util::{db, downstream_relay, relay_queue, relay_replay, relay_work};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp::crypto::Keyring;
use rusqlite::{OptionalExtension, params};
use std::{sync::Arc, time::Duration};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressSource {
    Omikron { connection_id: String },
    DirectPeer { node_id: IotaNodeId },
    RelayRouter { router_id: RelayRouterId },
    HostedClient { session: AuthenticatedSession },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayServiceError {
    Rejected(String),
    Internal(String),
}

#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub selected: usize,
    pub completed: usize,
    pub superseded: usize,
    pub rescheduled: i64,
    pub blocked: i64,
    pub remaining_estimate: i64,
    pub health: relay_work::RecoveryHealth,
}

enum RecoveryFailure {
    Transient,
    MissingDependency,
    Superseded,
    InvalidPersisted,
    AccountUnavailable,
    Invariant,
    Subsystem(String),
}

enum RecoveryAttempt {
    Completed,
    Superseded,
    Rescheduled,
    Blocked,
}
impl RecoveryFailure {
    fn code(&self) -> &'static str {
        match self {
            Self::Transient => "temporary_storage_failure",
            Self::MissingDependency => "missing_dependency",
            Self::Superseded => "superseded",
            Self::InvalidPersisted => "invalid_persisted_operation",
            Self::AccountUnavailable => "account_unavailable",
            Self::Invariant => "application_invariant",
            Self::Subsystem(_) => "recovery_storage_unavailable",
        }
    }
    fn from_storage(error: &StorageError) -> Self {
        match error {
            StorageError::StaleRelayClaim => Self::Superseded,
            StorageError::MissingRelayDependency | StorageError::ChatSecretSequence => {
                Self::MissingDependency
            }
            StorageError::RelayOwnerUnavailable | StorageError::HostedAuthorizationDenied => {
                Self::AccountUnavailable
            }
            StorageError::Db(rusqlite::Error::SqliteFailure(failure, _)) => match failure.code {
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                    Self::Transient
                }
                rusqlite::ErrorCode::ConstraintViolation
                    if failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER =>
                {
                    Self::Transient
                }
                rusqlite::ErrorCode::ConstraintViolation => Self::Invariant,
                _ => Self::Subsystem(error.to_string()),
            },
            StorageError::Db(_) | StorageError::Pool(_) | StorageError::Io(_) => {
                Self::Subsystem(error.to_string())
            }
            _ => Self::Invariant,
        }
    }
}

fn recovery_delay_ms(attempts: i64) -> i64 {
    let configured = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default)
    };
    let min = configured("IOTA_RECOVERY_MIN_DELAY_MS", 2_000).clamp(1, 300_000);
    let max = configured("IOTA_RECOVERY_MAX_DELAY_MS", 300_000).clamp(min, 86_400_000);
    min.saturating_mul(1_u64 << attempts.clamp(0, 20)).min(max) as i64
}

pub type VerifiedRelayEnvelope = crate::federated_relay::VerifiedFederatedRelayV2;

/// Only an exact durable wire match can create this proof. It grants no new claim.
#[derive(Clone, Debug)]
pub(crate) struct DurableOutcome {
    state: relay_replay::RelayState,
    accepted_at: Option<i64>,
    unauthorized: bool,
}

fn durable_replay(
    frame: &CommunicationValue,
) -> Result<Option<VerifiedRelayEnvelope>, RelayServiceError> {
    use crate::federated_relay::{canonical_principal, parse_wire};
    if frame.id().is_none() {
        return Err(RelayServiceError::Rejected(
            "missing relay correlation ID".into(),
        ));
    }
    let wire = parse_wire(frame).map_err(|e| RelayServiceError::Rejected(e.to_string()))?;
    let signer_id = canonical_principal(&wire.signer)
        .map_err(|e| RelayServiceError::Rejected(e.to_string()))?;
    let recipient_id = canonical_principal(&wire.recipient)
        .map_err(|e| RelayServiceError::Rejected(e.to_string()))?;
    let store = iota_storage::identity::SqlitePrincipalStore;
    let Some(signer) = store
        .get_by_canonical_id(&signer_id)
        .map_err(|e| RelayServiceError::Internal(e.to_string()))?
    else {
        return Ok(None);
    };
    let normalized = frame
        .clone()
        .without_id()
        .to_bytes()
        .map_err(|e| RelayServiceError::Rejected(e.to_string()))?;
    let map = frame
        .type_map()
        .ok_or_else(|| RelayServiceError::Rejected("missing relay type map".into()))?
        .version
        .to_string();
    let record = db::with_db(|connection| {
        Ok(connection.query_row(
            "SELECT state, accepted_at, COALESCE(rejection_reason = 'unauthorized', 0), prepared_operation
             FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2 AND frame = ?3 AND type_map_version = ?4",
            params![signer.handle.0, wire.message_id, normalized, map],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, bool>(2)?, row.get::<_, Option<Vec<u8>>>(3)?)),
        ).optional()?)
    }).map_err(|e| RelayServiceError::Internal(e.to_string()))?;
    let Some((state, accepted_at, unauthorized, prepared)) = record else {
        return Ok(None);
    };
    let state = relay_replay::RelayState::try_from(state.as_str())
        .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
    let Some(prepared) = prepared else {
        return Ok(None);
    };
    let proof = crate::persisted_relay::decode_prepared_operation(&prepared)
        .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
    let recipient = store
        .get_by_canonical_id(&recipient_id)
        .map_err(|e| RelayServiceError::Internal(e.to_string()))?
        .ok_or_else(|| {
            RelayServiceError::Internal("persisted relay recipient is missing".into())
        })?;
    if proof.signer != signer.handle
        || proof.recipient != recipient.handle
        || proof.signer_identity != wire.signer
        || proof.recipient_identity != wire.recipient
        || proof.message_id != wire.message_id
        || proof.created_at != wire.created_at
    {
        return Err(RelayServiceError::Internal(
            "persisted relay identity conflict".into(),
        ));
    }
    let destination = IotaNodeId::new(&wire.destination)
        .map_err(|e| RelayServiceError::Rejected(e.to_string()))?;
    Ok(Some(VerifiedRelayEnvelope {
        signer,
        recipient,
        destination,
        message_id: wire.message_id,
        created_at: wire.created_at,
        content: None,
        frame: frame.clone(),
        durable_outcome: Some(DurableOutcome {
            state,
            accepted_at,
            unauthorized,
        }),
    }))
}

#[derive(Clone, Debug)]
pub struct ClientDelivery {
    pub recipient: iota_identity::PrincipalHandle,
    pub frame: CommunicationValue,
}

#[derive(Clone, Debug)]
pub enum RelayOutcome {
    Accepted {
        ingress_response: CommunicationValue,
        local_deliveries: Vec<ClientDelivery>,
    },
    Rejected {
        response: CommunicationValue,
    },
    NoRoute {
        response: CommunicationValue,
    },
    RetryLater {
        response: CommunicationValue,
    },
    Ignored,
}

impl RelayOutcome {
    pub fn into_parts(self) -> (Option<CommunicationValue>, Vec<ClientDelivery>) {
        match self {
            Self::Accepted {
                ingress_response,
                local_deliveries,
            } => (Some(ingress_response), local_deliveries),
            Self::Rejected { response }
            | Self::NoRoute { response }
            | Self::RetryLater { response } => (Some(response), Vec::new()),
            Self::Ignored => (None, Vec::new()),
        }
    }
}

#[async_trait]
pub trait RelayNodeIdentity: Send + Sync {
    async fn keyring(&self) -> Option<Arc<Keyring>>;
    fn node_id(&self) -> Option<IotaNodeId>;
}

pub struct RelayService {
    local_users: Arc<dyn LocalUserStore>,
    router: Arc<dyn PeerRouter>,
    identities: Option<Arc<dyn IdentityResolver>>,
    node_identity: Option<Arc<dyn RelayNodeIdentity>>,
    persistence_migrated: std::sync::atomic::AtomicBool,
}

impl RelayService {
    fn authorize_source(
        &self,
        source: &IngressSource,
        verified: &VerifiedRelayEnvelope,
    ) -> Result<(), RelayServiceError> {
        match source {
            IngressSource::DirectPeer { node_id } if !matches!(&verified.signer.home, PrincipalHome::Iota(home) if home == node_id) =>
            {
                return Err(RelayServiceError::Rejected(
                    "peer is not the signer home".into(),
                ));
            }
            IngressSource::Omikron { connection_id } if connection_id.is_empty() => {
                return Err(RelayServiceError::Rejected(
                    "authenticated connection is missing".into(),
                ));
            }
            _ => {}
        }
        if !matches!(source, IngressSource::HostedClient { .. })
            && self
                .node_identity
                .as_ref()
                .and_then(|node| node.node_id())
                .as_ref()
                != Some(&verified.destination)
        {
            return Err(RelayServiceError::Rejected(
                "relay destination does not match local node".into(),
            ));
        }
        Ok(())
    }
    pub fn new(local_users: Arc<dyn LocalUserStore>, router: Arc<dyn PeerRouter>) -> Self {
        Self {
            local_users,
            router,
            identities: None,
            node_identity: None,
            persistence_migrated: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn with_federation(
        mut self,
        identities: Arc<dyn IdentityResolver>,
        node_identity: Arc<dyn RelayNodeIdentity>,
    ) -> Self {
        self.identities = Some(identities);
        self.node_identity = Some(node_identity);
        self
    }

    pub async fn prepare_relay(
        &self,
        source: &IngressSource,
        frame: CommunicationValue,
    ) -> Result<VerifiedRelayEnvelope, RelayServiceError> {
        if let Some(verified) = durable_replay(&frame)? {
            self.authorize_source(source, &verified)?;
            return Ok(verified);
        }
        let identities = self.identities.as_ref().ok_or_else(|| {
            RelayServiceError::Internal("identity resolver is unavailable".into())
        })?;
        let node = self
            .node_identity
            .as_ref()
            .and_then(|node| node.node_id())
            .ok_or_else(|| {
                RelayServiceError::Internal("local node identity is unavailable".into())
            })?;
        let destination = if matches!(source, IngressSource::HostedClient { .. }) {
            None
        } else {
            Some(&node)
        };
        let keyring = self
            .node_identity
            .as_ref()
            .expect("checked node identity")
            .keyring()
            .await
            .ok_or_else(|| {
                RelayServiceError::Internal("local relay decryption key is unavailable".into())
            })?;
        tokio::time::timeout(
            Duration::from_secs(15),
            crate::federated_relay::decode_and_verify_for_ingress(
                frame,
                identities.as_ref(),
                destination,
                &keyring,
            ),
        )
        .await
        .map_err(|_| RelayServiceError::Internal("identity preparation timed out".into()))?
        .map_err(|error| match error {
            iota_identity::IdentityError::Unavailable(_)
            | iota_identity::IdentityError::Storage(_) => {
                RelayServiceError::Internal(error.to_string())
            }
            _ => RelayServiceError::Rejected(error.to_string()),
        })
    }

    pub async fn accept_relay(
        self: &Arc<Self>,
        source: IngressSource,
        frame: CommunicationValue,
    ) -> Result<RelayOutcome, RelayServiceError> {
        let verified = self.prepare_relay(&source, frame).await?;
        self.accept_verified_relay(source, verified).await
    }

    pub async fn accept_verified_relay(
        self: &Arc<Self>,
        source: IngressSource,
        verified: VerifiedRelayEnvelope,
    ) -> Result<RelayOutcome, RelayServiceError> {
        // Another ingress may have committed since this envelope was prepared.
        let verified = match durable_replay(&verified.frame)? {
            Some(replay) => replay,
            None if verified.durable_outcome.is_some() => {
                return Err(RelayServiceError::Internal(
                    "durable relay proof disappeared".into(),
                ));
            }
            None => verified,
        };
        self.authorize_source(&source, &verified)?;
        let lease =
            match source {
                IngressSource::HostedClient { session } => {
                    if !matches!(session.identity, SessionIdentity::Hosted { .. })
                        || !session.allows(&SessionCapability::RelayOrigination)
                        || session.principal() != verified.signer.handle
                    {
                        return Err(RelayServiceError::Rejected(
                            "hosted session cannot originate this relay".into(),
                        ));
                    }
                    Some(session.hosted_lease.ok_or_else(|| {
                        RelayServiceError::Rejected("hosted lease is missing".into())
                    })?)
                }
                IngressSource::DirectPeer { .. }
                | IngressSource::Omikron { .. }
                | IngressSource::RelayRouter { .. } => None,
            };
        if let Some(proof) = &verified.durable_outcome {
            // Fence outcome release against the current hosted authorization, not a session clone.
            if let Some(lease) = lease.as_ref() {
                let authorization = db::with_immediate_transaction(|tx| {
                    iota_storage::hosted_auth::verify_in_tx(tx, lease)?;
                    if verified.signer.handle != lease.identity.principal {
                        return Err(StorageError::HostedAuthorizationDenied);
                    }
                    Ok(())
                });
                if let Err(error) = authorization {
                    return Ok(storage_outcome(&verified.frame, &error));
                }
            }
            return match proof.state {
                relay_replay::RelayState::Applied
                | relay_replay::RelayState::Queued
                | relay_replay::RelayState::Delivered => {
                    let accepted_at = proof.accepted_at.ok_or_else(|| {
                        RelayServiceError::Internal(
                            "durable relay acceptance timestamp is missing".into(),
                        )
                    })?;
                    Ok(success(
                        &verified.frame,
                        &verified.message_id,
                        accepted_at,
                        "already_accepted",
                        verified.recipient.handle,
                        Vec::new(),
                    ))
                }
                relay_replay::RelayState::Received | relay_replay::RelayState::Processing => {
                    Ok(processing(&verified.frame, &verified.message_id))
                }
                relay_replay::RelayState::Rejected => Ok(response(
                    &verified.frame,
                    if proof.unauthorized {
                        CommunicationType::ErrorNotAuthenticated
                    } else {
                        CommunicationType::ErrorInvalidData
                    },
                )),
            };
        }
        let sender = self
            .local_users
            .local_user_for_principal(verified.signer.handle)
            .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
        let recipient = self
            .local_users
            .local_user_for_principal(verified.recipient.handle)
            .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
        if let Some(local_node) = self
            .node_identity
            .as_ref()
            .and_then(|identity| identity.node_id())
            && ((recipient.is_none() && verified.destination == local_node)
                || (sender.is_none()
                    && matches!(&verified.signer.home, PrincipalHome::Iota(home) if home == &local_node)))
        {
            return Ok(storage_outcome(
                &verified.frame,
                &StorageError::RelayOwnerUnavailable,
            ));
        }
        let operation = match prepared_relay::prepare_application(&verified, sender, recipient) {
            Ok(operation) => operation,
            Err(error) => return Ok(storage_outcome(&verified.frame, &error)),
        };
        relay_work::fault_point("after_preparation", &operation.message_id);
        self.accept_prepared_relay(
            operation,
            lease.as_ref(),
            verified.frame,
            recipient.map(|_| verified.recipient.handle),
        )
        .await
    }

    async fn accept_prepared_relay(
        &self,
        operation: PreparedRelayOperation,
        lease: Option<&iota_identity::HostedAuthorizationLease>,
        frame: CommunicationValue,
        recipient: Option<iota_identity::PrincipalHandle>,
    ) -> Result<RelayOutcome, RelayServiceError> {
        let serialized = crate::persisted_relay::encode_prepared_operation(&operation)
            .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
        let acquisition = db::with_immediate_transaction(|tx| {
            let deadline = now_millis_i64().saturating_add(30_000);
            let result = match lease {
                Some(lease) => relay_replay::acquire_hosted_relay_in_tx(
                    tx,
                    lease,
                    operation.request(),
                    deadline,
                ),
                None => relay_replay::acquire_in_tx(tx, operation.request(), deadline),
            }?;
            if let relay_replay::AcquireResult::Claimed(claim) = &result {
                // The parsed operation and its original verified envelope become recovery work together.
                tx.execute("UPDATE relay_inbox SET prepared_operation = COALESCE(prepared_operation, ?3) WHERE signer_principal = ?1 AND message_id = ?2", params![claim.signer.0, claim.message_id, serialized])?;
            }
            Ok(result)
        });
        let acquisition = match acquisition {
            Ok(result) => result,
            Err(error) => return Ok(storage_outcome(&frame, &error)),
        };
        match acquisition {
            relay_replay::AcquireResult::Claimed(claim) => {
                relay_work::fault_point("after_claim_acquisition", &claim.message_id);
                if let Err(error) = operation.commit(&claim) {
                    if permanent(&error) {
                        reject_claim(&claim, &error)?;
                    }
                    return Ok(storage_outcome(&frame, &error));
                }
                relay_work::fault_point("after_application_commit", &claim.message_id);
                // Delivery is supervised separately. Acceptance never depends on transport availability.
                Ok(success(
                    &frame,
                    &operation.message_id,
                    operation.accepted_at,
                    "accepted",
                    operation.recipient,
                    recipient
                        .map(|recipient| ClientDelivery {
                            recipient,
                            frame: frame.clone(),
                        })
                        .into_iter()
                        .collect(),
                ))
            }
            relay_replay::AcquireResult::Applied
            | relay_replay::AcquireResult::Queued
            | relay_replay::AcquireResult::Delivered => {
                let accepted_at = relay_work::accepted_at(operation.signer, &operation.message_id)
                    .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
                Ok(success(
                    &frame,
                    &operation.message_id,
                    accepted_at,
                    "already_accepted",
                    operation.recipient,
                    Vec::new(),
                ))
            }
            relay_replay::AcquireResult::Busy => Ok(RelayOutcome::RetryLater {
                response: CommunicationValue::new_with_type_map(
                    CommunicationType::ErrorInternal,
                    frame.type_map().expect("verified frame type map"),
                )
                .with_id(operation.frame_id)
                .add_typed_default(DataType::Status, DataValue::Str("processing".into()))
                .add_typed_default(
                    DataType::RelayMessageId,
                    DataValue::Str(operation.message_id),
                ),
            }),
            relay_replay::AcquireResult::Rejected => {
                let unauthorized = db::with_db(|conn| Ok(conn.query_row("SELECT COALESCE(rejection_reason = 'unauthorized', 0) FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2", params![operation.signer.0, operation.message_id], |r| r.get::<_, bool>(0))?)).map_err(|error| RelayServiceError::Internal(error.to_string()))?;
                Ok(response(
                    &frame,
                    if unauthorized {
                        CommunicationType::ErrorNotAuthenticated
                    } else {
                        CommunicationType::ErrorInvalidData
                    },
                ))
            }
            relay_replay::AcquireResult::Collision => {
                Ok(response(&frame, CommunicationType::ErrorInvalidData))
            }
        }
    }

    pub fn resume_relay(&self, work: &relay_work::AcceptedWork) -> Result<bool, RelayServiceError> {
        self.recover_one(work)
            .map(|outcome| matches!(outcome, RecoveryAttempt::Completed))
    }

    fn recover_one(
        &self,
        work: &relay_work::AcceptedWork,
    ) -> Result<RecoveryAttempt, RelayServiceError> {
        let mut observed = relay_work::AcceptedWork {
            signer: work.signer,
            message_id: work.message_id.clone(),
            state: work.state,
            generation: work.generation,
            owner: work.owner.clone(),
            prepared: work.prepared.clone(),
            attempts: work.attempts,
        };
        match self.resume_observed(&mut observed) {
            Ok(done) => {
                if done {
                    relay_work::resolve_outcome(&observed)
                        .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
                }
                Ok(if done {
                    RecoveryAttempt::Completed
                } else {
                    RecoveryAttempt::Superseded
                })
            }
            Err(failure) => {
                let disposition = match failure {
                    RecoveryFailure::Subsystem(detail) => {
                        return Err(RelayServiceError::Internal(detail));
                    }
                    RecoveryFailure::Superseded => return Ok(RecoveryAttempt::Superseded),
                    RecoveryFailure::InvalidPersisted
                    | RecoveryFailure::Invariant
                    | RecoveryFailure::AccountUnavailable => {
                        relay_work::RecoveryDisposition::Blocked {
                            error_code: failure.code(),
                        }
                    }
                    _ => {
                        // Zero permits indefinite bounded retries, including dependencies arriving later.
                        let maximum = std::env::var("IOTA_RECOVERY_MAX_ATTEMPTS")
                            .ok()
                            .and_then(|v| v.parse::<i64>().ok())
                            .unwrap_or(0);
                        if maximum > 0 && observed.attempts >= maximum.saturating_sub(1) {
                            relay_work::RecoveryDisposition::Blocked {
                                error_code: "retry_exhausted",
                            }
                        } else {
                            relay_work::RecoveryDisposition::Retry {
                                next_attempt_at: now_millis_i64()
                                    .saturating_add(recovery_delay_ms(observed.attempts)),
                                error_code: failure.code(),
                            }
                        }
                    }
                };
                let blocked = observed.attempts == i64::MAX
                    || matches!(disposition, relay_work::RecoveryDisposition::Blocked { .. });
                let recorded = relay_work::record_outcome(&observed, disposition)
                    .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
                iota_logger::log!(
                    "Recovery record {}: {}",
                    observed.message_id,
                    failure.code()
                );
                Ok(if !recorded {
                    RecoveryAttempt::Superseded
                } else if blocked {
                    RecoveryAttempt::Blocked
                } else {
                    RecoveryAttempt::Rescheduled
                })
            }
        }
    }

    fn resume_observed(
        &self,
        work: &mut relay_work::AcceptedWork,
    ) -> Result<bool, RecoveryFailure> {
        let operation =
            crate::persisted_relay::decode_prepared_operation(&work.prepared).map_err(|error| {
                iota_logger::log!(
                    "Persisted relay decode failed for {}: {error}",
                    work.message_id
                );
                RecoveryFailure::InvalidPersisted
            })?;
        if operation.signer != work.signer || operation.message_id != work.message_id {
            return Err(RecoveryFailure::Invariant);
        }
        if work.state == relay_replay::RelayState::Applied {
            operation
                .resume_applied(work)
                .map_err(|error| RecoveryFailure::from_storage(&error))?;
            return Ok(true);
        }
        let Some(claim) = relay_work::take_over_abandoned_processing(
            work,
            now_millis_i64().saturating_add(30_000),
        )
        .map_err(|e| RecoveryFailure::from_storage(&e))?
        else {
            return Ok(false);
        };
        work.state = relay_replay::RelayState::Processing;
        work.generation = claim.generation;
        work.owner = Some(claim.owner.clone());
        match operation.commit(&claim) {
            Ok(()) => Ok(true),
            Err(error @ StorageError::RelayOwnerUnavailable) => {
                reject_claim(&claim, &error).map_err(|_| RecoveryFailure::Invariant)?;
                Ok(false)
            }
            Err(error) => {
                iota_logger::log!(
                    "Recovery application failed for {}: {error}",
                    work.message_id
                );
                Err(RecoveryFailure::from_storage(&error))
            }
        }
    }

    pub fn recover_incomplete(&self, limit: i64) -> Result<RecoveryReport, RelayServiceError> {
        if !self
            .persistence_migrated
            .load(std::sync::atomic::Ordering::Acquire)
        {
            db::with_db(crate::persisted_relay::migrate_on)
                .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
            self.persistence_migrated
                .store(true, std::sync::atomic::Ordering::Release);
        }
        let mut report = RecoveryReport::default();
        for work in
            relay_work::incomplete(limit).map_err(|e| RelayServiceError::Internal(e.to_string()))?
        {
            report.selected += 1;
            match self.recover_one(&work)? {
                RecoveryAttempt::Completed => report.completed += 1,
                RecoveryAttempt::Superseded => report.superseded += 1,
                RecoveryAttempt::Rescheduled => report.rescheduled += 1,
                RecoveryAttempt::Blocked => report.blocked += 1,
            }
        }
        report.health =
            relay_work::health().map_err(|e| RelayServiceError::Internal(e.to_string()))?;
        report.remaining_estimate = report.health.remaining;
        Ok(report)
    }

    pub fn dispatcher(&self) -> PendingRelayDispatcher {
        PendingRelayDispatcher::new(self.router.clone())
    }
}

fn permanent(error: &StorageError) -> bool {
    matches!(
        error,
        StorageError::InvalidRelayPayload(_)
            | StorageError::UnsupportedRelayOperation
            | StorageError::MessageUnauthorized
            | StorageError::RelayOwnerUnavailable
            | StorageError::ReactionLimitReached
            | StorageError::ChatSecretConflict
            | StorageError::ChatSecretSequence
            | StorageError::PendingRelayConflict
    )
}

fn reject_claim(
    claim: &relay_replay::ProcessingClaim,
    error: &StorageError,
) -> Result<(), RelayServiceError> {
    db::with_immediate_transaction(|tx| {
        relay_replay::reject_unapplied_in_tx(tx, claim)?;
        tx.execute("UPDATE relay_inbox SET rejection_reason = ?3 WHERE signer_principal = ?1 AND message_id = ?2",
            params![claim.signer.0, claim.message_id, if matches!(error, StorageError::MessageUnauthorized) { "unauthorized" } else { "invalid_operation" }])?;
        Ok(())
    }).map_err(|error| RelayServiceError::Internal(error.to_string()))
}

fn storage_outcome(frame: &CommunicationValue, error: &StorageError) -> RelayOutcome {
    iota_logger::log!("Relay application result: {error}");
    let kind = if matches!(
        error,
        StorageError::HostedAuthorizationDenied | StorageError::MessageUnauthorized
    ) {
        CommunicationType::ErrorNotAuthenticated
    } else if permanent(error) {
        CommunicationType::ErrorInvalidData
    } else {
        CommunicationType::ErrorInternal
    };
    response(frame, kind)
}

fn response(frame: &CommunicationValue, kind: CommunicationType) -> RelayOutcome {
    let (Some(_), Some(_)) = (frame.id(), frame.type_map()) else {
        return RelayOutcome::Ignored;
    };
    let response = error_response(frame, kind);
    if kind == CommunicationType::ErrorInternal {
        RelayOutcome::RetryLater { response }
    } else {
        RelayOutcome::Rejected { response }
    }
}

/// Preserve correlation without exposing resolver, storage or cryptographic error details.
pub fn relay_error_response(
    request: &CommunicationValue,
    error: &RelayServiceError,
) -> CommunicationValue {
    iota_logger::log!("Relay ingress error: {error:?}");
    error_response(
        request,
        match error {
            RelayServiceError::Rejected(_) => CommunicationType::ErrorInvalidData,
            RelayServiceError::Internal(_) => CommunicationType::ErrorInternal,
        },
    )
}

fn error_response(frame: &CommunicationValue, kind: CommunicationType) -> CommunicationValue {
    let mut response = match frame.type_map() {
        Some(map) => CommunicationValue::new_with_type_map(kind, map),
        None => CommunicationValue::new(kind),
    };
    if let Some(id) = frame.id() {
        response = response.with_id(id);
    }
    response = response.add_typed_default(
        DataType::Status,
        DataValue::Str(
            if kind == CommunicationType::ErrorInternal {
                "recoverable_failure"
            } else {
                "rejected"
            }
            .into(),
        ),
    );
    // An echoed wire ID is correlation only. It never establishes a signer or a claim.
    if let Ok(wire) = crate::federated_relay::parse_wire(frame) {
        response =
            response.add_typed_default(DataType::RelayMessageId, DataValue::Str(wire.message_id));
    }
    crate::connection_handler::bind_relay_response_identity(frame, response.clone())
        .unwrap_or(response)
}

fn success(
    frame: &CommunicationValue,
    message_id: &str,
    accepted_at: i64,
    status: &str,
    recipient: iota_identity::PrincipalHandle,
    local_deliveries: Vec<ClientDelivery>,
) -> RelayOutcome {
    let response = CommunicationValue::new_with_type_map(
        CommunicationType::Success,
        frame.type_map().expect("verified frame type map"),
    )
    .with_id(frame.id().expect("verified frame correlation ID"))
    .add_typed_default(DataType::RelayMessageId, DataValue::Str(message_id.into()))
    .add_typed_default(
        DataType::ChatPartnerId,
        DataValue::SignedNumber(recipient.0.into()),
    )
    .add_typed_default(
        DataType::RelayAcceptedAt,
        DataValue::SignedNumber(accepted_at.into()),
    )
    .add_typed_default(DataType::Status, DataValue::Str(status.into()));
    let response = crate::connection_handler::bind_relay_response_identity(frame, response)
        .unwrap_or_else(|_| error_response(frame, CommunicationType::ErrorInternal));
    RelayOutcome::Accepted {
        ingress_response: response,
        local_deliveries,
    }
}

fn processing(frame: &CommunicationValue, message_id: &str) -> RelayOutcome {
    RelayOutcome::RetryLater {
        response: CommunicationValue::new_with_type_map(
            CommunicationType::ErrorInternal,
            frame.type_map().expect("verified frame type map"),
        )
        .with_id(frame.id().expect("verified frame correlation ID"))
        .add_typed_default(DataType::Status, DataValue::Str("processing".into()))
        .add_typed_default(DataType::RelayMessageId, DataValue::Str(message_id.into())),
    }
}

pub struct PendingRelayDispatcher {
    router: Arc<dyn PeerRouter>,
}
impl PendingRelayDispatcher {
    pub fn new(router: Arc<dyn PeerRouter>) -> Self {
        Self { router }
    }
    pub async fn dispatch_ready(&self, limit: i64) -> Result<usize, RelayServiceError> {
        let mut delivered = 0;
        let timeout_ms = std::env::var("IOTA_DISPATCH_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30_000)
            .clamp(1, 300_000);
        for _ in 0..limit.clamp(1, 500) {
            let Some(claimed) =
                relay_queue::claim_ready(1, (timeout_ms as i64).saturating_add(5_000))
                    .map_err(|e| RelayServiceError::Internal(e.to_string()))?
                    .pop()
            else {
                break;
            };
            let pending = &claimed.pending;
            let node = match &pending.target {
                relay_queue::RelayTarget::Iota(node) => node,
                relay_queue::RelayTarget::User(_) => continue,
            };
            let frame =
                mtp::type_map::Version::parse(&pending.type_map_version).and_then(|version| {
                    CommunicationValue::from_bytes_with(&pending.frame, &TypeMap::new(version)).ok()
                });
            let Some(frame) = frame else {
                relay_queue::quarantine_claimed(&claimed, "invalid_persisted_frame")
                    .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
                continue;
            };
            let frame = frame.with_id(pending.frame_id);
            let matching = match crate::federated_relay::parse_wire(&frame) {
                Ok(wire)
                    if wire.destination == node.as_str()
                        && pending.relay_message_id.as_deref() == Some(&wire.message_id) =>
                {
                    let store = iota_storage::identity::SqlitePrincipalStore;
                    let mut matching = true;
                    for (identity, expected) in [
                        (&wire.signer, pending.signer_principal),
                        (&wire.recipient, pending.destination_principal),
                    ] {
                        let Ok(canonical) = crate::federated_relay::canonical_principal(identity)
                        else {
                            matching = false;
                            break;
                        };
                        let principal = store
                            .get_by_canonical_id(&canonical)
                            .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
                        matching &= expected.is_some()
                            && principal.map(|principal| principal.handle) == expected;
                    }
                    matching
                }
                _ => false,
            };
            if !matching {
                relay_queue::quarantine_claimed(&claimed, "pending_canonical_identity_mismatch")
                    .map_err(|e| RelayServiceError::Internal(e.to_string()))?;
                continue;
            }
            if !relay_queue::verify_current_claim(&claimed)
                .map_err(|e| RelayServiceError::Internal(e.to_string()))?
            {
                continue;
            }
            let delivery = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                self.router
                    .route(&RouteDestination::Iota(node.clone()), frame),
            )
            .await;
            relay_work::fault_point(
                "after_outbound_send",
                pending.relay_message_id.as_deref().unwrap_or_default(),
            );
            let result = match delivery {
                Ok(Ok(RouteOutcome::Accepted {
                    relay_message_id,
                    destination_accepted_at,
                })) => {
                    if pending.relay_message_id.as_deref() == Some(&relay_message_id) {
                        downstream_relay::acknowledge_claimed_pending_delivery(
                            &claimed,
                            &relay_message_id,
                            destination_accepted_at,
                        )
                        .map(|result| delivered += usize::from(result))
                    } else {
                        relay_queue::quarantine_claimed(
                            &claimed,
                            "destination returned an unrelated relay identity",
                        )
                        .map(|_| ())
                    }
                }
                Ok(Ok(RouteOutcome::Rejected { .. })) => {
                    downstream_relay::reject_claimed_pending_delivery(
                        &claimed,
                        "destination_rejected",
                    )
                    .map(|_| ())
                }
                Ok(Ok(RouteOutcome::Retryable { reason })) => {
                    relay_queue::record_retry_claimed(&claimed, now_millis_i64(), &reason)
                        .map(|_| ())
                }
                Ok(Err(error)) => relay_queue::record_retry_claimed(
                    &claimed,
                    now_millis_i64(),
                    &error.to_string(),
                )
                .map(|_| ()),
                Err(_) => relay_queue::record_retry_claimed(
                    &claimed,
                    now_millis_i64(),
                    "destination timeout",
                )
                .map(|_| ()),
            };
            result.map_err(|e| RelayServiceError::Internal(e.to_string()))?;
        }
        Ok(delivered)
    }
}
