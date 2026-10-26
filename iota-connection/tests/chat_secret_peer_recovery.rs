#[allow(dead_code)]
mod relay_support;

use async_trait::async_trait;
use iota_connection::chat_secret_recovery::*;
use iota_identity::{IdentityError, LocalNodeIdentity, NodeIdentityResolver, ResolvedNodeIdentity};
use iota_storage::{
    identity::{SqliteLocalUserStore, SqlitePrincipalStore},
    util::{chat_secret_recovery as storage, db, e2ee_storage},
};
use relay_support::{Fixture, Resolver, accepted, execute, initialize, secret};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Models the already-authenticated transport boundary. The real MTP handshake
/// and request correlation in both directions have a separate other-iota test.
struct Peer {
    node: LocalNodeIdentity,
    evidence: storage::Escrow,
    offline: AtomicBool,
    tamper: AtomicBool,
}

#[async_trait]
impl RecoveryTransport for Peer {
    async fn request(
        &self,
        node: &iota_identity::IotaNodeId,
        request: &RecoveryRequest,
    ) -> Result<AuthenticatedRecoveryReply, RecoveryError> {
        assert_eq!(node, self.node.node_id());
        if self.offline.load(Ordering::SeqCst) {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        let owner = iota_identity::PrincipalId {
            authority: iota_identity::AuthorityId::new(&request.owner.authority).unwrap(),
            user_id: request.owner.user_id,
        };
        let mut evidence = self.evidence.clone();
        if self.tamper.load(Ordering::SeqCst) {
            // A malicious peer can update all hashes and metadata, but cannot
            // produce a valid original author signature for an alternate copy.
            evidence.envelopes[0].encrypted_secret.push(99);
        }
        Ok(AuthenticatedRecoveryReply {
            node: node.clone(),
            key: self.node.public_keys(),
            reply: RecoveryReply {
                request: request.clone(),
                result: Ok(encode_evidence(&owner, &evidence).unwrap()),
            },
        })
    }
}

#[async_trait]
impl NodeIdentityResolver for Peer {
    async fn resolve_node(
        &self,
        node: &iota_identity::IotaNodeId,
    ) -> Result<ResolvedNodeIdentity, IdentityError> {
        assert_eq!(node, self.node.node_id());
        Ok(ResolvedNodeIdentity {
            node: node.clone(),
            public_keys: vec![self.node.public_keys()],
            descriptor_revision: 1,
            valid_until: None,
            direct_endpoints: vec![],
            relay_hints: vec![],
            last_successful_endpoint: None,
            resolved_at: iota_storage::util::sync::now_millis(),
        })
    }
}

#[tokio::test]
async fn missing_local_escrow_uses_exact_independently_verified_peer_operation_after_offline_retry()
{
    let directory = std::path::Path::new("/tmp/opencode")
        .join(format!("tensamin-peer-recovery-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    initialize(&directory);
    let fixture = Fixture::new(false);
    accepted(
        fixture
            .accept(0, "original-peer-accepted", secret(&fixture))
            .await,
    );
    // The fixture router only queues. Model the separate exact downstream
    // authenticated acceptance boundary before making peer evidence available.
    let evidence: storage::Escrow = db::with_db(|connection| {
        let bytes: Vec<u8> =
            connection.query_row("SELECT evidence FROM chat_secret_escrows", [], |row| {
                row.get(0)
            })?;
        Ok(serde_json::from_slice(&bytes).unwrap())
    })
    .unwrap();
    let chat_id = storage::canonical_chat_id(&fixture.ids[0], &fixture.ids[1]).unwrap();
    let query = || e2ee_storage::ChatSecretQuery {
        user_id: "1".into(),
        chat_id: chat_id.clone(),
        secret_id: Some(e2ee_storage::principal_secret_id(&chat_id)),
        version: Some(1),
    };
    let peer = Arc::new(Peer {
        node: fixture.destination.clone(),
        evidence: evidence.clone(),
        offline: AtomicBool::new(true),
        tamper: AtomicBool::new(false),
    });
    let service = RecoveryCoordinator::new(
        Arc::new(Resolver),
        peer.clone(),
        Arc::new(SqlitePrincipalStore),
        Arc::new(SqliteLocalUserStore),
        fixture.node.node_id().clone(),
        peer.clone(),
        Arc::new(OriginalOperationVerifier {
            relay: fixture.service.clone(),
        }),
    );
    assert!(
        matches!(
            service.gate_initial_set_chat_secret(&evidence).await,
            Err(RecoveryError::RetryablePeerUnavailable)
        ),
        "an exact pending proposal cannot replace fresh peer authorization"
    );
    db::with_immediate_transaction(|tx| {
        storage::commit_escrow_in_tx(tx, &evidence)?;
        storage::recover_owner_envelope_in_tx(tx, iota_identity::LocalUserId(1), &evidence)?;
        Ok(())
    })
    .unwrap();
    let original = e2ee_storage::get_chat_secret(query()).unwrap().unwrap();
    // Simulate external loss rather than an application-authorized erasure.
    execute(
        "DROP TRIGGER chat_secret_escrows_accepted_delete; DELETE FROM chat_secrets WHERE user_id='1'; DELETE FROM chat_secret_escrows;",
    );
    assert_eq!(
        service
            .recover(&fixture.ids[0], &fixture.ids[1], Some(1))
            .await,
        Err(RecoveryError::RetryablePeerUnavailable)
    );
    let jobs = storage::recovery_jobs(10).unwrap();
    assert_eq!(jobs.len(), 1);
    let nonce = jobs[0].nonce.clone();
    assert!(e2ee_storage::get_chat_secret(query()).unwrap().is_none());
    peer.offline.store(false, Ordering::SeqCst);
    peer.tamper.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .recover(&fixture.ids[0], &fixture.ids[1], Some(1))
            .await,
        Err(RecoveryError::Conflict)
    );
    assert!(e2ee_storage::get_chat_secret(query()).unwrap().is_none());
    assert!(
        storage::escrow_for_recovery(&fixture.ids[0], &fixture.ids[1], &fixture.ids[0], Some(1))
            .unwrap()
            .is_none()
    );
    assert_eq!(storage::recovery_jobs(10).unwrap()[0].nonce, nonce);
    peer.tamper.store(false, Ordering::SeqCst);
    service.retry_pending().await;
    let restored = e2ee_storage::get_chat_secret(query()).unwrap().unwrap();
    assert_eq!(restored.encrypted_secret, original.encrypted_secret);
    assert_eq!(restored.kem_ciphertext, original.kem_ciphertext);
    assert_eq!(
        storage::escrow_for_recovery(&fixture.ids[0], &fixture.ids[1], &fixture.ids[0], Some(1))
            .unwrap()
            .unwrap(),
        evidence
    );
    assert!(storage::recovery_jobs(10).unwrap().is_empty());
    db::with_db(|connection| {
        let count: i64 = connection.query_row(
            "SELECT count(*) FROM chat_secrets WHERE user_id!='1'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            count, 0,
            "recovery must not insert the peer owner's copy locally"
        );
        Ok(())
    })
    .unwrap();
}
