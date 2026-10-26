use super::*;
use iota_identity::{
    IdentityError, PrincipalHandle, ResolutionContext, ResolvedPrincipal, UserAddress,
};

struct Directory {
    values: Vec<ResolvedPrincipal>,
    node: iota_identity::LocalNodeIdentity,
    offline: bool,
}

#[async_trait]
impl IdentityResolver for Directory {
    async fn resolve_current_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        self.resolve_principal(principal).await
    }
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }
    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        if self.offline {
            return Err(IdentityError::Unavailable("offline".into()));
        }
        self.values
            .iter()
            .find(|entry| &entry.principal == principal)
            .cloned()
            .ok_or(IdentityError::NotFound)
    }
    async fn signing_keys(
        &self,
        _: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        Err(IdentityError::NotFound)
    }
}

#[async_trait]
impl NodeIdentityResolver for Directory {
    async fn resolve_node(
        &self,
        node: &IotaNodeId,
    ) -> Result<iota_identity::ResolvedNodeIdentity, IdentityError> {
        Ok(iota_identity::ResolvedNodeIdentity {
            node: node.clone(),
            public_keys: vec![self.node.public_keys()],
            descriptor_revision: 1,
            valid_until: None,
            direct_endpoints: vec![],
            relay_hints: vec![],
            last_successful_endpoint: None,
            resolved_at: sync::now_millis(),
        })
    }
}

impl PrincipalStore for Directory {
    fn get_principal(
        &self,
        _: PrincipalHandle,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(None)
    }
    fn get_by_canonical_id(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(self
            .values
            .iter()
            .find(|entry| &entry.principal == principal)
            .cloned())
    }
    fn get_by_username(
        &self,
        _: &iota_identity::AuthorityId,
        _: &str,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(None)
    }
    fn upsert_remote_descriptor(
        &self,
        _: &iota_identity::VerifiedPrincipalDescriptor,
    ) -> Result<PrincipalHandle, IdentityError> {
        Err(IdentityError::NotFound)
    }
    fn signing_keys(&self, _: &PrincipalId) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        Ok(vec![])
    }
}

impl LocalUserStore for Directory {
    fn get_local_user(
        &self,
        _: LocalUserId,
    ) -> Result<Option<iota_identity::LocalUserDescriptor>, IdentityError> {
        Ok(None)
    }
    fn get_local_user_by_username(
        &self,
        _: &str,
    ) -> Result<Option<iota_identity::LocalUserDescriptor>, IdentityError> {
        Ok(None)
    }
    fn is_hosted_here(&self, _: LocalUserId) -> Result<bool, IdentityError> {
        Ok(false)
    }
    fn local_user_for_principal(
        &self,
        _: PrincipalHandle,
    ) -> Result<Option<LocalUserId>, IdentityError> {
        Ok(None)
    }
    fn principal_for_local_user(
        &self,
        _: LocalUserId,
    ) -> Result<Option<PrincipalHandle>, IdentityError> {
        Ok(None)
    }
}

struct Offline;
#[async_trait]
impl crate::connection_handler::PeerRouter for Offline {
    async fn route(
        &self,
        _: &crate::connection_handler::RouteDestination,
        _: CommunicationValue,
    ) -> Result<crate::connection_handler::RouteOutcome, crate::connection_handler::RouteError>
    {
        Err(crate::connection_handler::RouteError::Delivery(
            "offline".into(),
        ))
    }
}
#[async_trait]
impl RecoveryTransport for Offline {
    async fn request(
        &self,
        _: &IotaNodeId,
        _: &RecoveryRequest,
    ) -> Result<AuthenticatedRecoveryReply, RecoveryError> {
        Err(RecoveryError::RetryablePeerUnavailable)
    }
}

fn setup(
    stale: bool,
    offline: bool,
) -> (
    RecoveryCoordinator,
    RecoveryRequest,
    iota_identity::LocalNodeIdentity,
) {
    let local =
        iota_identity::LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let peer =
        iota_identity::LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let first = PrincipalId {
        authority: iota_identity::AuthorityId::new("authority-a").unwrap(),
        user_id: 1,
    };
    let second = PrincipalId {
        authority: iota_identity::AuthorityId::new("authority-b").unwrap(),
        user_id: 1,
    };
    let resolved = |principal: PrincipalId, home: IotaNodeId| ResolvedPrincipal {
        principal,
        handle: PrincipalHandle(1),
        username: None,
        public_keys: vec![peer.public_keys()],
        home: PrincipalHome::Iota(home),
        descriptor_revision: 1,
        valid_until: None,
        resolved_at: sync::now_millis() - if stale { 60_000 } else { 0 },
    };
    let directory = Arc::new(Directory {
        values: vec![
            resolved(first.clone(), peer.node_id().clone()),
            resolved(second.clone(), local.node_id().clone()),
        ],
        node: peer.clone(),
        offline,
    });
    let verifier = Arc::new(OriginalOperationVerifier {
        relay: Arc::new(crate::relay_service::RelayService::new(
            directory.clone(),
            Arc::new(Offline),
        )),
    });
    let service = RecoveryCoordinator::new(
        directory.clone(),
        directory.clone(),
        directory.clone(),
        directory,
        local.node_id().clone(),
        Arc::new(Offline),
        verifier,
    );
    let request = RecoveryRequest {
        version: RECOVERY_VERSION,
        pair: ConversationPair::new(protocol_principal(&first), protocol_principal(&second))
            .unwrap(),
        owner: protocol_principal(&first),
        epoch: Some(1),
        nonce: [1; 32],
        proposal_digest: None,
    };
    (service, request, peer)
}

#[tokio::test]
async fn caller_node_claim_cannot_replace_established_key_or_current_homes() {
    let (service, request, peer) = setup(false, false);
    let stranger =
        iota_identity::LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    assert_eq!(
        service
            .handle_peer_request(stranger.node_id(), &stranger.public_keys(), &request)
            .await,
        Err(RecoveryError::Unauthorized)
    );
    assert_eq!(
        service
            .handle_peer_request(peer.node_id(), &stranger.public_keys(), &request)
            .await,
        Err(RecoveryError::Unauthorized)
    );
    let mut other_owner = request.clone();
    other_owner.owner = request.pair.second.clone();
    assert_eq!(
        service
            .handle_peer_request(peer.node_id(), &peer.public_keys(), &other_owner)
            .await,
        Err(RecoveryError::Unauthorized)
    );
}

#[tokio::test]
async fn stale_or_offline_directory_is_retryable_not_authoritative_absence() {
    for (stale, offline) in [(true, false), (false, true)] {
        let (service, request, peer) = setup(stale, offline);
        assert_eq!(
            service
                .handle_peer_request(peer.node_id(), &peer.public_keys(), &request)
                .await,
            Err(RecoveryError::RetryablePeerUnavailable)
        );
    }
}

#[tokio::test]
async fn recovery_pair_limits_are_bounded_and_pair_serialization_is_shared() {
    let (service, request, _) = setup(false, false);
    for _ in 0..120 {
        service.rate_limit(&request.pair).unwrap();
    }
    assert_eq!(
        service.rate_limit(&request.pair),
        Err(RecoveryError::RetryablePeerUnavailable)
    );
    let first = service.pair_lock(&request.pair).await.unwrap();
    let second = service.pair_lock(&request.pair).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    let guard = first.lock().await;
    assert!(second.try_lock().is_err());
    drop(guard);
    assert!(second.try_lock().is_ok());
}

fn escrow() -> storage::Escrow {
    let first = PrincipalId {
        authority: iota_identity::AuthorityId::new("authority-a").unwrap(),
        user_id: 11,
    };
    let second = PrincipalId {
        authority: iota_identity::AuthorityId::new("authority-b").unwrap(),
        user_id: 22,
    };
    let frame = vec![1, 2, 3];
    storage::Escrow {
        first: first.clone(),
        second: second.clone(),
        version: 1,
        namespace: storage::WrappingNamespace {
            chat_id: "11:22".into(),
            secret_id: "chat:11:22:main".into(),
        },
        wrapping_scheme: "scheme".into(),
        signer: first.clone(),
        message_id: "original-id".into(),
        operation_digest: storage::operation_digest(
            storage::RelayFormat::NativeMtpSealedV1,
            &frame,
        ),
        original_frame: frame,
        original_type_map_version: "1.0".into(),
        format: storage::RelayFormat::NativeMtpSealedV1,
        envelopes: [
            storage::RecipientEnvelope {
                owner: first,
                recipient_id: storage::OriginalRecipientId::Numeric(11),
                encrypted_secret: vec![11],
                kem_ciphertext: vec![1],
            },
            storage::RecipientEnvelope {
                owner: second,
                recipient_id: storage::OriginalRecipientId::Numeric(22),
                encrypted_secret: vec![22],
                kem_ciphertext: vec![2],
            },
        ],
        created_at: 1,
    }
}

#[test]
fn evidence_binds_exact_owner_bytes_namespace_format_digest_and_original_operation() {
    let escrow = escrow();
    let request = RecoveryRequest {
        version: RECOVERY_VERSION,
        pair: ConversationPair::new(
            protocol_principal(&escrow.first),
            protocol_principal(&escrow.second),
        )
        .unwrap(),
        owner: protocol_principal(&escrow.first),
        epoch: Some(1),
        nonce: [1; 32],
        proposal_digest: None,
    };
    let envelope = encode_evidence(&escrow.first, &escrow).unwrap();
    assert_eq!(decode_evidence(&request, &envelope).unwrap(), escrow);
    assert_ne!(
        envelope.recipient_envelope,
        encode_evidence(&escrow.second, &escrow)
            .unwrap()
            .recipient_envelope
    );
    let mut changes = vec![envelope.clone(); 5];
    changes[0].original_chat_id = "22:11".into();
    changes[1].original_secret_id = "replacement".into();
    changes[2].operation_format = OperationFormat::TauSignedRelayV1;
    changes[3].recipient_envelope.push(1);
    changes[4].original_operation.push(1);
    for change in changes {
        assert_eq!(
            decode_evidence(&request, &change),
            Err(RecoveryError::Conflict)
        );
    }
}

#[test]
fn latest_epoch_never_falls_back_when_one_accepted_evidence_row_is_lost() {
    let mut connection = rusqlite::Connection::open_in_memory().unwrap();
    connection.execute_batch("CREATE TABLE principals(remote_user_id INTEGER); INSERT INTO principals VALUES(11),(22)").unwrap();
    connection.execute_batch(storage::SCHEMA).unwrap();
    let first = escrow();
    let mut second = first.clone();
    second.version = 2;
    second.message_id = "second-epoch".into();
    let tx = connection.transaction().unwrap();
    storage::commit_escrow_in_tx(&tx, &first).unwrap();
    storage::commit_escrow_in_tx(&tx, &second).unwrap();
    tx.commit().unwrap();
    connection.execute_batch("DROP TRIGGER chat_secret_epochs_accepted_delete; DELETE FROM chat_secret_epochs WHERE version=2").unwrap();
    assert_eq!(
        committed_epoch_on(&connection, &first.first, &first.second, None).unwrap(),
        Some(2)
    );
    let tx = connection.transaction().unwrap();
    storage::commit_escrow_in_tx(&tx, &second).unwrap();
    tx.commit().unwrap();
    connection.execute_batch("DROP TRIGGER chat_secret_escrows_accepted_delete; DELETE FROM chat_secret_escrows WHERE version=2").unwrap();
    assert_eq!(
        committed_epoch_on(&connection, &first.first, &first.second, None).unwrap(),
        Some(2)
    );
    assert_eq!(
        committed_epoch_on(&connection, &first.first, &first.second, Some(1)).unwrap(),
        Some(1)
    );
}

#[tokio::test]
async fn digest_and_peer_assertion_alone_are_not_cryptographic_proof() {
    let (service, _, _) = setup(false, false);
    assert_eq!(
        service.verifier.verify(&escrow(), LocalUserId(1)).await,
        Err(RecoveryError::Conflict)
    );
}
