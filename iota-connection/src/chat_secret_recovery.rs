//! Direct authenticated peer recovery. Router-only recovery is unsupported and
//! returns a retryable error, never authoritative absence.
use async_trait::async_trait;
use iota_identity::{
    IdentityResolver, LocalUserId, LocalUserStore, NodeIdentityResolver, PrincipalHome,
    PrincipalId, PrincipalStore,
};
use iota_identity::{IotaNodeId, PublicKeyBundle};
use iota_storage::util::{chat_secret_recovery as storage, db, sync};
use mtp::codec::CommunicationValue;
use std::sync::Arc;
pub use tau::chat_secret_recovery::*;

#[async_trait]
pub trait RecoveryProofVerifier: Send + Sync {
    async fn verify(
        &self,
        escrow: &storage::Escrow,
        owner: LocalUserId,
    ) -> Result<(), RecoveryError>;
}

/// Independent verification must not use RelayService's durable replay shortcut.
/// A ciphertext addressed only to another node cannot be imported with this
/// verifier. It remains unavailable rather than accepting peer assertions.
pub struct OriginalOperationVerifier {
    pub relay: Arc<crate::relay_service::RelayService>,
}

#[async_trait]
impl RecoveryProofVerifier for OriginalOperationVerifier {
    async fn verify(
        &self,
        escrow: &storage::Escrow,
        _owner: LocalUserId,
    ) -> Result<(), RecoveryError> {
        let version = mtp::type_map::Version::parse(&escrow.original_type_map_version)
            .ok_or(RecoveryError::RetryablePeerUnavailable)?;
        let map = mtp::type_map::TypeMap::new(version);
        if map
            .comm_id_enum(mtp::codec::CommunicationType::SetChatSecret)
            .is_none()
        {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        self.relay
            .verify_recovery_escrow(escrow, &map)
            .await
            .map_err(|error| match error {
                crate::relay_service::RelayServiceError::Internal(_) => {
                    RecoveryError::RetryablePeerUnavailable
                }
                _ => RecoveryError::Conflict,
            })
    }
}

pub struct RecoveryCoordinator {
    identities: Arc<dyn IdentityResolver>,
    nodes: Arc<dyn NodeIdentityResolver>,
    principals: Arc<dyn PrincipalStore>,
    local_users: Arc<dyn LocalUserStore>,
    local_node: IotaNodeId,
    transport: Arc<dyn RecoveryTransport>,
    verifier: Arc<dyn RecoveryProofVerifier>,
    pairs: tokio::sync::Mutex<
        std::collections::HashMap<ConversationPair, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
    limits: std::sync::Mutex<std::collections::HashMap<ConversationPair, (i64, u32)>>,
}

/// Holds the canonical pair lock through the caller's relay commit. The caller
/// must invoke recheck_in_tx inside that same write transaction.
pub struct InitialSetGuard {
    _pair: tokio::sync::OwnedMutexGuard<()>,
    escrow: storage::Escrow,
    owner: LocalUserId,
    homes: (
        iota_identity::ResolvedPrincipal,
        iota_identity::ResolvedPrincipal,
    ),
}

impl InitialSetGuard {
    pub fn recheck_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<(), iota_storage::storage_error::StorageError> {
        let now = sync::now_millis();
        if !self.homes.0.is_valid_at(now)
            || !self.homes.1.is_valid_at(now)
            || now.saturating_sub(self.homes.0.resolved_at) > 30_000
            || now.saturating_sub(self.homes.1.resolved_at) > 30_000
        {
            return Err(iota_storage::storage_error::StorageError::RelayOwnerUnavailable);
        }
        recheck_homes_in_tx(tx, self.owner, &self.homes.0, &self.homes.1)?;
        let state = storage::initialization_state_on(
            tx,
            &self.escrow.first,
            &self.escrow.second,
            Some(&self.escrow.operation_digest),
        )?;
        match state {
            storage::InitializationState::Empty
            | storage::InitializationState::ExactPendingProposal => Ok(()),
            storage::InitializationState::Accepted => {
                let accepted = storage::escrow_for_recovery_on(
                    tx,
                    &self.escrow.first,
                    &self.escrow.second,
                    &self.homes.0.principal,
                    Some(1),
                )?;
                if accepted.as_ref() == Some(&self.escrow) {
                    Ok(())
                } else {
                    Err(iota_storage::storage_error::StorageError::ChatSecretConflict)
                }
            }
            storage::InitializationState::Conflict => {
                Err(iota_storage::storage_error::StorageError::ChatSecretConflict)
            }
        }
    }
}

impl RecoveryCoordinator {
    async fn accepted_evidence(
        &self,
        first: &PrincipalId,
        second: &PrincipalId,
        owner: &PrincipalId,
        epoch: Option<i64>,
        local: LocalUserId,
    ) -> Result<Option<storage::Escrow>, RecoveryError> {
        let epoch = db::with_db(|connection| committed_epoch_on(connection, first, second, epoch))
            .map_err(storage_error)?;
        if let Some(escrow) =
            storage::escrow_for_recovery(first, second, owner, epoch).map_err(storage_error)?
        {
            return Ok(Some(escrow));
        }
        let candidates = db::with_db(|connection| {
            crate::persisted_relay::accepted_escrow_candidates_on(
                connection, first, second, epoch, 500,
            )
        })
        .map_err(storage_error)?;
        let Some(candidate) = candidates.first() else {
            return Ok(None);
        };
        if candidates
            .iter()
            .any(|other| other.version == candidate.version && other != candidate)
        {
            return Err(RecoveryError::Conflict);
        }
        self.verifier.verify(candidate, local).await?;
        let local_principal = storage::canonical_owner(local).map_err(storage_error)?;
        let handle = self
            .principals
            .get_by_canonical_id(&local_principal)
            .map_err(|_| RecoveryError::RetryablePeerUnavailable)?
            .ok_or(RecoveryError::Unauthorized)?
            .handle;
        db::with_immediate_transaction(|tx| {
            iota_storage::util::relay_work::verify_owner_in_tx(tx, local.0, handle)?;
            if storage::canonical_owner_on(tx, local)? != local_principal {
                return Err(iota_storage::storage_error::StorageError::RelayOwnerUnavailable);
            }
            // Inbox cleanup or erasure racing verification cannot turn a stale
            // candidate into accepted evidence. No network runs in this closure.
            let current = crate::persisted_relay::accepted_escrow_candidates_on(
                tx,
                first,
                second,
                Some(candidate.version),
                500,
            )?;
            if !current.contains(candidate) || current.iter().any(|other| other != candidate) {
                return Err(iota_storage::storage_error::StorageError::ChatSecretConflict);
            }
            storage::commit_escrow_in_tx(tx, candidate)
        })
        .map_err(storage_error)?;
        Ok(Some(candidate.clone()))
    }

    pub async fn gate_initial_set_chat_secret(
        &self,
        escrow: &storage::Escrow,
    ) -> Result<InitialSetGuard, RecoveryError> {
        escrow.validate().map_err(storage_error)?;
        if escrow.version != 1 {
            return Err(RecoveryError::Conflict);
        }
        let pair = ConversationPair::new(
            protocol_principal(&escrow.first),
            protocol_principal(&escrow.second),
        )?;
        let lock = self.pair_lock(&pair).await?;
        let pair_guard = lock.lock_owned().await;
        let (owner, partner, local) = match self.owner(&escrow.first) {
            Ok(local) => (&escrow.first, &escrow.second, local),
            Err(_) => (&escrow.second, &escrow.first, self.owner(&escrow.second)?),
        };
        let homes = self.homes(owner, partner).await?;
        if homes.0.home != PrincipalHome::Iota(self.local_node.clone()) {
            return Err(RecoveryError::Unauthorized);
        }
        let state = db::with_db(|connection| {
            storage::initialization_state_on(
                connection,
                &escrow.first,
                &escrow.second,
                Some(&escrow.operation_digest),
            )
        })
        .map_err(storage_error)?;
        match state {
            storage::InitializationState::Accepted => {
                let accepted =
                    storage::escrow_for_recovery(&escrow.first, &escrow.second, owner, Some(1))
                        .map_err(storage_error)?;
                if accepted.as_ref() != Some(escrow) {
                    let _ = self.enqueue(owner, partner, None);
                    return Err(RecoveryError::Conflict);
                }
            }
            storage::InitializationState::Conflict => {
                let _ = self.enqueue(owner, partner, None);
                return Err(RecoveryError::Conflict);
            }
            storage::InitializationState::ExactPendingProposal
            | storage::InitializationState::Empty => {
                let PrincipalHome::Iota(peer) = &homes.1.home else {
                    return Err(RecoveryError::RetryablePeerUnavailable);
                };
                if peer != &self.local_node {
                    let request = RecoveryRequest {
                        version: RECOVERY_VERSION,
                        pair,
                        owner: protocol_principal(owner),
                        epoch: Some(1),
                        nonce: new_nonce(),
                        proposal_digest: Some(
                            escrow
                                .operation_digest
                                .clone()
                                .try_into()
                                .map_err(|_| RecoveryError::Conflict)?,
                        ),
                    };
                    let response = self.transport.request(peer, &request).await?;
                    if &response.node != peer || response.reply.request != request {
                        return Err(RecoveryError::Unauthorized);
                    }
                    self.check_key(peer, &response.key).await?;
                    match response.reply.result {
                        Err(RecoveryError::NoSuchConversation) => {}
                        Ok(_) => {
                            let _ = self.enqueue(owner, partner, None);
                            return Err(RecoveryError::Conflict);
                        }
                        Err(error) => return Err(error),
                    }
                    let current = self.homes(owner, partner).await?;
                    if current.0.home != homes.0.home
                        || current.1.home != homes.1.home
                        || current.0.descriptor_revision != homes.0.descriptor_revision
                        || current.1.descriptor_revision != homes.1.descriptor_revision
                    {
                        return Err(RecoveryError::Unauthorized);
                    }
                } else if self.owner(partner).is_err() {
                    return Err(RecoveryError::Unauthorized);
                }
            }
        }
        Ok(InitialSetGuard {
            _pair: pair_guard,
            escrow: escrow.clone(),
            owner: local,
            homes,
        })
    }
    pub fn new(
        identities: Arc<dyn IdentityResolver>,
        nodes: Arc<dyn NodeIdentityResolver>,
        principals: Arc<dyn PrincipalStore>,
        local_users: Arc<dyn LocalUserStore>,
        local_node: IotaNodeId,
        transport: Arc<dyn RecoveryTransport>,
        verifier: Arc<dyn RecoveryProofVerifier>,
    ) -> Self {
        Self {
            identities,
            nodes,
            principals,
            local_users,
            local_node,
            transport,
            verifier,
            pairs: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            limits: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn owner(&self, owner: &PrincipalId) -> Result<LocalUserId, RecoveryError> {
        let principal = self
            .principals
            .get_by_canonical_id(owner)
            .map_err(|_| RecoveryError::RetryablePeerUnavailable)?
            .ok_or(RecoveryError::Unauthorized)?;
        self.local_users
            .local_user_for_principal(principal.handle)
            .map_err(|_| RecoveryError::RetryablePeerUnavailable)?
            .ok_or(RecoveryError::Unauthorized)
    }

    async fn fresh(
        &self,
        principal: &PrincipalId,
    ) -> Result<iota_identity::ResolvedPrincipal, RecoveryError> {
        let resolved = self
            .identities
            .resolve_current_principal(principal)
            .await
            .map_err(|_| RecoveryError::RetryablePeerUnavailable)?;
        // Current resolution must be authoritative, not a cached fallback.
        if &resolved.principal != principal
            || !resolved.is_valid_at(sync::now_millis())
            || sync::now_millis().saturating_sub(resolved.resolved_at) > 30_000
        {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        Ok(resolved)
    }

    async fn homes(
        &self,
        owner: &PrincipalId,
        partner: &PrincipalId,
    ) -> Result<
        (
            iota_identity::ResolvedPrincipal,
            iota_identity::ResolvedPrincipal,
        ),
        RecoveryError,
    > {
        let owner = self.fresh(owner).await?;
        let partner = self.fresh(partner).await?;
        Ok((owner, partner))
    }

    async fn check_key(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
    ) -> Result<(), RecoveryError> {
        let current = self
            .nodes
            .resolve_node(node)
            .await
            .map_err(|_| RecoveryError::RetryablePeerUnavailable)?;
        if &current.node != node
            || current
                .valid_until
                .is_some_and(|until| until <= sync::now_millis())
        {
            return Err(RecoveryError::Unauthorized);
        }
        let bytes = key
            .try_as_bytes()
            .map_err(|_| RecoveryError::Unauthorized)?;
        if !current
            .public_keys
            .iter()
            .any(|key| key.try_as_bytes().is_ok_and(|candidate| candidate == bytes))
        {
            return Err(RecoveryError::Unauthorized);
        }
        Ok(())
    }

    fn rate_limit(&self, pair: &ConversationPair) -> Result<(), RecoveryError> {
        let now = sync::now_millis();
        let mut limits = self
            .limits
            .lock()
            .map_err(|_| RecoveryError::RetryablePeerUnavailable)?;
        limits.retain(|_, (start, _)| now.saturating_sub(*start) < 60_000);
        if limits.len() >= 1024 && !limits.contains_key(pair) {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        let (_, count) = limits.entry(pair.clone()).or_insert((now, 0));
        if *count >= 120 {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        *count += 1;
        Ok(())
    }

    async fn pair_lock(
        &self,
        pair: &ConversationPair,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, RecoveryError> {
        let mut locks = self.pairs.lock().await;
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks.get(pair).and_then(std::sync::Weak::upgrade) {
            return Ok(lock);
        }
        if locks.len() >= 256 {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(pair.clone(), Arc::downgrade(&lock));
        Ok(lock)
    }

    /// A durable dedup job is recorded before networking. Enqueue this for missing
    /// AddConversation hints or conflicts instead of replaying divergent secrets.
    pub fn enqueue(
        &self,
        owner: &PrincipalId,
        partner: &PrincipalId,
        epoch: Option<i64>,
    ) -> Result<i64, RecoveryError> {
        let local = self.owner(owner)?;
        let nonce = new_nonce();
        db::with_immediate_transaction(|tx| {
            storage::enqueue_recovery_in_tx(
                tx,
                local,
                owner,
                partner,
                epoch,
                &nonce,
                sync::now_millis(),
            )
        })
        .map_err(storage_error)
    }

    pub async fn retry_pending(&self) {
        let Ok(jobs) = storage::recovery_jobs(32) else {
            return;
        };
        for job in jobs {
            let Ok(owner) = storage::canonical_owner(job.owner) else {
                continue;
            };
            let partner = if owner == job.first {
                &job.second
            } else {
                &job.first
            };
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                self.recover_job(&owner, partner, job.version, Some(&job)),
            )
            .await
            .unwrap_or(Err(RecoveryError::RetryablePeerUnavailable));
        }
    }

    async fn recover_job(
        &self,
        owner: &PrincipalId,
        partner: &PrincipalId,
        epoch: Option<i64>,
        job: Option<&storage::RecoveryJob>,
    ) -> Result<(), RecoveryError> {
        let pair = ConversationPair::new(protocol_principal(owner), protocol_principal(partner))?;
        let lock = self.pair_lock(&pair).await?;
        let _guard = lock.lock().await;
        let local = self.owner(owner)?;
        if let Some(job) = job {
            let current = storage::recovery_job_by_id(job.id)
                .map_err(storage_error)?
                .ok_or(RecoveryError::RetryablePeerUnavailable)?;
            validate_recovery_job(&current, local, owner, partner, epoch)?;
            if current.nonce != job.nonce
                || current.attempts != job.attempts
                || current.next_at > sync::now_millis()
            {
                return Err(RecoveryError::RetryablePeerUnavailable);
            }
        }
        let claimed = match job {
            Some(job) => Some(
                storage::begin_recovery_attempt(job)
                    .map_err(storage_error)?
                    .ok_or(RecoveryError::RetryablePeerUnavailable)?,
            ),
            None => None,
        };
        let result = self
            .recover_pair(owner, partner, epoch, claimed.as_ref(), local, pair)
            .await;
        if let (Err(error), Some(job)) = (&result, claimed.as_ref()) {
            let delay = 1_000i64.saturating_mul(1i64 << job.attempts.clamp(0, 6));
            storage::retry_recovery_job(
                job,
                sync::now_millis().saturating_add(delay),
                &error.to_string(),
            )
            .map_err(storage_error)?;
        }
        result
    }

    async fn recover_pair(
        &self,
        owner: &PrincipalId,
        partner: &PrincipalId,
        epoch: Option<i64>,
        job: Option<&storage::RecoveryJob>,
        local: LocalUserId,
        pair: ConversationPair,
    ) -> Result<(), RecoveryError> {
        // Local committed evidence is authoritative and needs no network. Fences
        // and exact immutable comparison run again inside the write transaction.
        if let Some(escrow) = self
            .accepted_evidence(owner, partner, owner, epoch, local)
            .await?
        {
            if escrow.version > 4096 {
                return Err(RecoveryError::RetryablePeerUnavailable);
            }
            let mut history = Vec::new();
            for version in 1..=escrow.version {
                let Some(previous) = self
                    .accepted_evidence(owner, partner, owner, Some(version), local)
                    .await?
                else {
                    break;
                };
                history.push(previous);
            }
            if history.len() == escrow.version as usize {
                for previous in &history {
                    self.restore_local(local, previous, None)?;
                }
                if let Some(job) = job {
                    db::with_immediate_transaction(|tx| {
                        storage::complete_recovery_job_in_tx(tx, job)
                    })
                    .map_err(storage_error)?;
                }
                return Ok(());
            }
        }
        let (owner_home, partner_home) = self.homes(owner, partner).await?;
        if owner_home.home != PrincipalHome::Iota(self.local_node.clone()) {
            return Err(RecoveryError::Unauthorized);
        }
        let PrincipalHome::Iota(peer) = &partner_home.home else {
            return Err(RecoveryError::RetryablePeerUnavailable);
        };
        if peer == &self.local_node {
            self.owner(partner)?;
            let absent = db::with_immediate_transaction(|tx| {
                recheck_homes_in_tx(tx, local, &owner_home, &partner_home)?;
                let absent = storage::initialization_state_on(tx, owner, partner, None)?
                    == storage::InitializationState::Empty;
                if absent && let Some(job) = job {
                    storage::complete_recovery_job_in_tx(tx, job)?;
                }
                Ok(absent)
            })
            .map_err(storage_error)?;
            return Err(if absent {
                RecoveryError::NoSuchConversation
            } else {
                RecoveryError::AcceptedButEnvelopeUnavailable
            });
        }
        let nonce = match job {
            Some(job) => job
                .nonce
                .clone()
                .try_into()
                .map_err(|_| RecoveryError::Conflict)?,
            None => new_nonce(),
        };
        let request = RecoveryRequest {
            version: RECOVERY_VERSION,
            pair: pair.clone(),
            owner: protocol_principal(owner),
            epoch,
            nonce,
            proposal_digest: None,
        };
        let authenticated = self.transport.request(peer, &request).await?;
        if &authenticated.node != peer || authenticated.reply.request != request {
            return Err(RecoveryError::Unauthorized);
        }
        self.check_key(peer, &authenticated.key).await?;
        let envelope = match authenticated.reply.result {
            Ok(envelope) => envelope,
            Err(RecoveryError::NoSuchConversation) => {
                let current = self.homes(owner, partner).await?;
                if current.0.home != owner_home.home
                    || current.1.home != partner_home.home
                    || current.0.descriptor_revision != owner_home.descriptor_revision
                    || current.1.descriptor_revision != partner_home.descriptor_revision
                {
                    return Err(RecoveryError::Unauthorized);
                }
                let absent = db::with_immediate_transaction(|tx| {
                    recheck_homes_in_tx(tx, local, &current.0, &current.1)?;
                    let absent = storage::initialization_state_on(tx, owner, partner, None)?
                        == storage::InitializationState::Empty;
                    if absent && let Some(job) = job {
                        storage::complete_recovery_job_in_tx(tx, job)?;
                    }
                    Ok(absent)
                })
                .map_err(storage_error)?;
                return Err(if absent {
                    RecoveryError::NoSuchConversation
                } else {
                    RecoveryError::AcceptedButEnvelopeUnavailable
                });
            }
            Err(error) => return Err(error),
        };
        let latest = decode_evidence(&request, &envelope)?;
        let target = epoch.unwrap_or(latest.version);
        // Restore sequentially, oldest first. Each original signed operation is
        // verified outside the write transaction; no relay is replayed.
        if target > 4096 {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        for version in 1..=target {
            if let Some(local_escrow) = self
                .accepted_evidence(owner, partner, owner, Some(version), local)
                .await?
            {
                self.restore_local(local, &local_escrow, None)?;
                continue;
            }
            let escrow = if version == latest.version {
                latest.clone()
            } else {
                let request = RecoveryRequest {
                    epoch: Some(version),
                    nonce: epoch_nonce(&request.nonce, version),
                    ..request.clone()
                };
                let response = self.transport.request(peer, &request).await?;
                if response.node != *peer || response.reply.request != request {
                    return Err(RecoveryError::Unauthorized);
                }
                self.check_key(peer, &response.key).await?;
                decode_evidence(&request, &response.reply.result?)?
            };
            self.verifier.verify(&escrow, local).await?;
            let fresh = self.homes(owner, partner).await?;
            if fresh.0.home != owner_home.home
                || fresh.1.home != partner_home.home
                || fresh.0.descriptor_revision != owner_home.descriptor_revision
                || fresh.1.descriptor_revision != partner_home.descriptor_revision
            {
                return Err(RecoveryError::Unauthorized);
            }
            db::with_immediate_transaction(|tx| {
                recheck_homes_in_tx(tx, local, &fresh.0, &fresh.1)?;
                storage::commit_escrow_in_tx(tx, &escrow)?;
                storage::recover_owner_envelope_in_tx(tx, local, &escrow)?;
                Ok(())
            })
            .map_err(storage_error)?;
            storage::notify_change();
        }
        if let Some(job) = job {
            db::with_immediate_transaction(|tx| storage::complete_recovery_job_in_tx(tx, job))
                .map_err(storage_error)?;
        }
        Ok(())
    }

    fn restore_local(
        &self,
        owner: LocalUserId,
        escrow: &storage::Escrow,
        job: Option<&storage::RecoveryJob>,
    ) -> Result<(), RecoveryError> {
        db::with_immediate_transaction(|tx| {
            storage::recover_owner_envelope_in_tx(tx, owner, escrow)?;
            if let Some(job) = job {
                storage::complete_recovery_job_in_tx(tx, job)?;
            }
            Ok(())
        })
        .map_err(storage_error)?;
        storage::notify_change();
        Ok(())
    }
}

#[async_trait]
impl PeerRecoveryHandler for RecoveryCoordinator {
    async fn handle_peer_request(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
        request: &RecoveryRequest,
    ) -> Result<RecoveredEnvelope, RecoveryError> {
        request.validate()?;
        self.rate_limit(&request.pair)?;
        let owner = identity_principal(&request.owner)?;
        let partner = identity_principal(request.pair.partner(&request.owner)?)?;
        let (owner_home, partner_home) = self.homes(&owner, &partner).await?;
        if owner_home.home != PrincipalHome::Iota(node.clone())
            || partner_home.home != PrincipalHome::Iota(self.local_node.clone())
        {
            return Err(RecoveryError::Unauthorized);
        }
        self.check_key(node, key).await?;
        let local = self.owner(&partner)?;
        self.accepted_evidence(&owner, &partner, &owner, request.epoch, local)
            .await?;
        let (escrow, state) = db::with_immediate_transaction(|tx| {
            recheck_homes_in_tx(tx, local, &partner_home, &owner_home)?;
            let epoch = committed_epoch_on(tx, &owner, &partner, request.epoch)?;
            let escrow = storage::escrow_for_recovery_on(tx, &owner, &partner, &owner, epoch)?;
            let state = if escrow.is_none() {
                Some(storage::initialization_state_on(
                    tx,
                    &owner,
                    &partner,
                    request
                        .proposal_digest
                        .as_ref()
                        .map(|digest| digest.as_slice()),
                )?)
            } else {
                None
            };
            Ok((escrow, state))
        })
        .map_err(storage_error)?;
        let Some(escrow) = escrow else {
            return Err(match state {
                Some(storage::InitializationState::Empty) => RecoveryError::NoSuchConversation,
                Some(storage::InitializationState::ExactPendingProposal)
                    if request.proposal_digest.is_some() =>
                {
                    RecoveryError::NoSuchConversation
                }
                Some(storage::InitializationState::Conflict) => RecoveryError::Conflict,
                _ => RecoveryError::AcceptedButEnvelopeUnavailable,
            });
        };
        // Audit metadata only, never envelopes, requests, or operation bytes.
        iota_logger::log!(
            "Chat secret recovery served: epoch={} format={:?}",
            escrow.version,
            escrow.format
        );
        encode_evidence(&owner, &escrow)
    }
}

#[async_trait]
impl ChatSecretRecovery for RecoveryCoordinator {
    async fn gate_initial_set_chat_secret(
        &self,
        escrow: &storage::Escrow,
    ) -> Result<InitialSetGuard, RecoveryError> {
        RecoveryCoordinator::gate_initial_set_chat_secret(self, escrow).await
    }
    fn enqueue(
        &self,
        owner: &PrincipalId,
        partner: &PrincipalId,
        epoch: Option<i64>,
    ) -> Result<i64, RecoveryError> {
        RecoveryCoordinator::enqueue(self, owner, partner, epoch)
    }
    async fn recover(
        &self,
        owner: &PrincipalId,
        partner: &PrincipalId,
        epoch: Option<i64>,
    ) -> Result<(), RecoveryError> {
        let id = self.enqueue(owner, partner, epoch)?;
        // Request-triggered work uses the persisted nonce too, so a cancelled
        // client read leaves resumable work for the startup/reconnect worker.
        let job = storage::recovery_job_by_id(id)
            .map_err(storage_error)?
            .ok_or(RecoveryError::RetryablePeerUnavailable)?;
        validate_recovery_job(&job, self.owner(owner)?, owner, partner, epoch)?;
        // Explicit reads honor persistent worker backoff. Polling never changes
        // the original nonce or moves a scheduled retry earlier.
        if job.next_at > sync::now_millis() {
            EXPLICIT_DEFERRED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        EXPLICIT_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.recover_job(owner, partner, epoch, Some(&job)).await
    }
}

fn validate_recovery_job(
    job: &storage::RecoveryJob,
    local: LocalUserId,
    owner: &PrincipalId,
    partner: &PrincipalId,
    epoch: Option<i64>,
) -> Result<(), RecoveryError> {
    let same_pair = (job.first == *owner && job.second == *partner)
        || (job.first == *partner && job.second == *owner);
    if job.owner != local || job.version != epoch || !same_pair {
        Err(RecoveryError::Unauthorized)
    } else {
        Ok(())
    }
}

fn committed_epoch_on(
    connection: &rusqlite::Connection,
    first: &PrincipalId,
    second: &PrincipalId,
    epoch: Option<i64>,
) -> Result<Option<i64>, iota_storage::storage_error::StorageError> {
    match epoch {
        Some(epoch) => Ok(Some(epoch)),
        None => {
            let accepted =
                storage::pair_acceptance_on(connection, first, second)?.latest_committed_version;
            let pair = storage::sorted_pair(first, second)?;
            // A lost epoch-marker row must not hide a newer committed escrow.
            // This is positive version evidence only; import still requires the
            // normal committed read or independent original-operation proof.
            let escrow: Option<i64> = connection.query_row(
                "SELECT MAX(version) FROM chat_secret_escrows WHERE first_principal=?1 AND second_principal=?2 AND state='committed'",
                rusqlite::params![storage::principal_key(&pair[0])?,storage::principal_key(&pair[1])?], |row| row.get(0))?;
            Ok(accepted.max(escrow))
        }
    }
}

fn recheck_homes_in_tx(
    tx: &rusqlite::Transaction<'_>,
    owner: LocalUserId,
    first: &iota_identity::ResolvedPrincipal,
    second: &iota_identity::ResolvedPrincipal,
) -> Result<(), iota_storage::storage_error::StorageError> {
    iota_storage::util::relay_work::verify_owner_in_tx(tx, owner.0, first.handle)?;
    if storage::canonical_owner_on(tx, owner)? != first.principal {
        return Err(iota_storage::storage_error::StorageError::RelayOwnerUnavailable);
    }
    for principal in [first, second] {
        let PrincipalHome::Iota(_) = &principal.home else {
            return Err(iota_storage::storage_error::StorageError::MessageUnauthorized);
        };
        iota_storage::identity::PrincipalCommitFence::capture(principal)
            .map_err(|_| iota_storage::storage_error::StorageError::RelayOwnerUnavailable)?
            .verify_on(tx)?;
    }
    Ok(())
}

fn protocol_principal(principal: &PrincipalId) -> Principal {
    Principal {
        authority: principal.authority.as_str().to_owned(),
        user_id: principal.user_id,
    }
}

fn identity_principal(principal: &Principal) -> Result<PrincipalId, RecoveryError> {
    PrincipalId::try_from(principal.clone()).map_err(|_| RecoveryError::Unauthorized)
}

fn new_nonce() -> [u8; 32] {
    let mut nonce = [0; 32];
    nonce[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    nonce[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    nonce
}

fn epoch_nonce(seed: &[u8; 32], epoch: i64) -> [u8; 32] {
    // Retain a random job prefix and a stable epoch suffix across restarts.
    let mut nonce = *seed;
    nonce[24..].copy_from_slice(&epoch.to_be_bytes());
    nonce
}

fn storage_error(error: iota_storage::storage_error::StorageError) -> RecoveryError {
    use iota_storage::storage_error::StorageError;
    match error {
        StorageError::ChatSecretConflict | StorageError::InvalidRelayPayload(_) => {
            RecoveryError::Conflict
        }
        StorageError::MessageUnauthorized | StorageError::RelayOwnerUnavailable => {
            RecoveryError::Unauthorized
        }
        _ => RecoveryError::RetryablePeerUnavailable,
    }
}

/// Encode proof already selected from committed acceptance. This function does
/// not authorize disclosure or promote pending evidence.
pub fn encode_evidence(
    owner: &PrincipalId,
    escrow: &storage::Escrow,
) -> Result<RecoveredEnvelope, RecoveryError> {
    escrow.validate().map_err(storage_error)?;
    let envelope = escrow
        .envelopes
        .iter()
        .find(|envelope| &envelope.owner == owner)
        .ok_or(RecoveryError::Unauthorized)?;
    let envelope = RecoveredEnvelope {
        epoch: escrow.version,
        original_chat_id: escrow.namespace.chat_id.clone(),
        original_secret_id: escrow.namespace.secret_id.clone(),
        namespace: serde_json::to_string(&escrow.namespace).map_err(|_| RecoveryError::Conflict)?,
        operation_format: match escrow.format {
            storage::RelayFormat::NativeMtpSealedV1 => OperationFormat::NativeMtpSealedRelayV1,
            storage::RelayFormat::TauSignedRelayV1 => OperationFormat::TauSignedRelayV1,
        },
        operation_digest: escrow
            .operation_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        original_operation: escrow.original_frame.clone(),
        original_type_map_version: escrow.original_type_map_version.clone(),
        original_type_map_fingerprint: escrow.original_type_map_fingerprint.clone(),
        recipient_envelope: serde_json::to_vec(envelope).map_err(|_| RecoveryError::Conflict)?,
        provenance: serde_json::to_vec(escrow).map_err(|_| RecoveryError::Conflict)?,
    };
    envelope.validate()?;
    Ok(envelope)
}

fn decode_evidence(
    request: &RecoveryRequest,
    envelope: &RecoveredEnvelope,
) -> Result<storage::Escrow, RecoveryError> {
    envelope.validate()?;
    let escrow: storage::Escrow =
        serde_json::from_slice(&envelope.provenance).map_err(|_| RecoveryError::Conflict)?;
    escrow.validate().map_err(storage_error)?;
    let owner = identity_principal(&request.owner)?;
    if protocol_principal(&escrow.first) != request.pair.first
        || protocol_principal(&escrow.second) != request.pair.second
        || request
            .epoch
            .is_some_and(|version| version != escrow.version)
        || encode_evidence(&owner, &escrow)? != *envelope
    {
        return Err(RecoveryError::Conflict);
    }
    Ok(escrow)
}

pub struct AuthenticatedRecoveryReply {
    pub node: IotaNodeId,
    pub key: PublicKeyBundle,
    pub reply: RecoveryReply,
}

#[async_trait]
pub trait RecoveryTransport: Send + Sync {
    async fn request(
        &self,
        node: &IotaNodeId,
        request: &RecoveryRequest,
    ) -> Result<AuthenticatedRecoveryReply, RecoveryError>;
}

#[async_trait]
pub trait PeerRecoveryHandler: Send + Sync {
    /// Node and key must come from the established transport, never frame fields.
    async fn handle_peer_request(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
        request: &RecoveryRequest,
    ) -> Result<RecoveredEnvelope, RecoveryError>;
}

#[async_trait]
pub trait ChatSecretRecovery: PeerRecoveryHandler {
    async fn gate_initial_set_chat_secret(
        &self,
        escrow: &storage::Escrow,
    ) -> Result<InitialSetGuard, RecoveryError>;
    fn enqueue(
        &self,
        owner: &PrincipalId,
        partner: &PrincipalId,
        epoch: Option<i64>,
    ) -> Result<i64, RecoveryError>;
    async fn recover(
        &self,
        owner: &iota_identity::PrincipalId,
        partner: &iota_identity::PrincipalId,
        epoch: Option<i64>,
    ) -> Result<(), RecoveryError>;
}

static RECOVERY: std::sync::RwLock<Option<std::sync::Arc<dyn ChatSecretRecovery>>> =
    std::sync::RwLock::new(None);

static EXPLICIT_ATTEMPTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXPLICIT_DEFERRED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn explicit_recovery_counts() -> (u64, u64) {
    use std::sync::atomic::Ordering;
    (
        EXPLICIT_ATTEMPTS.load(Ordering::Relaxed),
        EXPLICIT_DEFERRED.load(Ordering::Relaxed),
    )
}

pub fn install_recovery(service: std::sync::Arc<dyn ChatSecretRecovery>) {
    *RECOVERY.write().expect("recovery service lock poisoned") = Some(service);
}

pub async fn gate_initial_set_chat_secret(
    escrow: &storage::Escrow,
) -> Result<InitialSetGuard, RecoveryError> {
    let service = RECOVERY
        .read()
        .ok()
        .and_then(|service| service.clone())
        .ok_or(RecoveryError::RetryablePeerUnavailable)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        service.gate_initial_set_chat_secret(escrow),
    )
    .await
    .unwrap_or(Err(RecoveryError::RetryablePeerUnavailable))
}

pub fn enqueue_recovery(
    owner: &PrincipalId,
    partner: &PrincipalId,
    epoch: Option<i64>,
) -> Result<i64, RecoveryError> {
    let service = RECOVERY
        .read()
        .ok()
        .and_then(|service| service.clone())
        .ok_or(RecoveryError::RetryablePeerUnavailable)?;
    service.enqueue(owner, partner, epoch)
}

pub async fn handle_get_chat_secret(cv: &CommunicationValue) -> CommunicationValue {
    let response = crate::message_handlers::handle_get_chat_secret(cv);
    if !response.is_type(mtp::codec::CommunicationType::ErrorInternal) {
        return response;
    }
    let (owner, partner, epoch) =
        match crate::message_handlers::validated_chat_secret_read_target(cv) {
            Ok(target) => target,
            Err(error) => return error,
        };
    let service = RECOVERY.read().ok().and_then(|service| service.clone());
    let Some(service) = service else {
        return response;
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        service.recover(&owner, &partner, epoch),
    )
    .await
    {
        Ok(Ok(())) => crate::message_handlers::handle_get_chat_secret(cv),
        Ok(Err(RecoveryError::NoSuchConversation)) => {
            use tau::CommunicationResponseExt;
            let Some(map) = cv.type_map() else {
                return response;
            };
            CommunicationValue::new_with_type_map(mtp::codec::CommunicationType::ErrorNotSet, map)
                .with_request_id(cv)
        }
        _ => response,
    }
}

#[cfg(test)]
#[path = "chat_secret_recovery_tests.rs"]
mod tests;
