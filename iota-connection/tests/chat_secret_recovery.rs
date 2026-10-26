#[allow(dead_code)]
mod relay_support;

use async_trait::async_trait;
use iota_connection::chat_secret_recovery::*;
use iota_identity::{IdentityError, LocalUserId, NodeIdentityResolver, ResolvedNodeIdentity};
use iota_storage::{
    identity::{SqliteLocalUserStore, SqlitePrincipalStore},
    util::{chat_secret_recovery as storage, db, e2ee_storage},
};
use relay_support::{Fixture, Resolver, accepted, execute, initialize, secret};
use std::sync::Arc;

struct Offline;
#[async_trait]
impl RecoveryTransport for Offline {
    async fn request(
        &self,
        _: &iota_identity::IotaNodeId,
        _: &RecoveryRequest,
    ) -> Result<AuthenticatedRecoveryReply, RecoveryError> {
        panic!("committed local evidence must not need a peer");
    }
}
#[async_trait]
impl NodeIdentityResolver for Offline {
    async fn resolve_node(
        &self,
        _: &iota_identity::IotaNodeId,
    ) -> Result<ResolvedNodeIdentity, IdentityError> {
        panic!("committed local evidence must not need node resolution");
    }
}

#[tokio::test]
async fn deleted_owner_row_restores_original_copy_without_network_or_peer_copy_equality() {
    let directory = std::path::Path::new("/tmp/opencode").join(format!(
        "tensamin-secret-coordinator-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    initialize(&directory);
    let fixture = Fixture::new(true);
    accepted(
        fixture
            .accept(0, "accepted-before-deletion", secret(&fixture))
            .await,
    );
    let escrow =
        storage::escrow_for_recovery(&fixture.ids[0], &fixture.ids[1], &fixture.ids[0], Some(1))
            .unwrap()
            .unwrap();
    let chat_id = storage::canonical_chat_id(&fixture.ids[0], &fixture.ids[1]).unwrap();
    let query = |owner: usize| e2ee_storage::ChatSecretQuery {
        user_id: (owner + 1).to_string(),
        chat_id: chat_id.clone(),
        secret_id: Some(e2ee_storage::principal_secret_id(&chat_id)),
        version: Some(1),
    };
    let first = e2ee_storage::get_chat_secret(query(0)).unwrap().unwrap();
    let other = e2ee_storage::get_chat_secret(query(1)).unwrap().unwrap();
    assert_ne!(first.encrypted_secret, other.encrypted_secret);
    let service = RecoveryCoordinator::new(
        Arc::new(Resolver),
        Arc::new(Offline),
        Arc::new(SqlitePrincipalStore),
        Arc::new(SqliteLocalUserStore),
        fixture.node.node_id().clone(),
        Arc::new(Offline),
        Arc::new(OriginalOperationVerifier {
            relay: fixture.service.clone(),
        }),
    );
    for _ in 0..2 {
        execute("DELETE FROM chat_secrets WHERE user_id='1'");
        assert!(e2ee_storage::get_chat_secret(query(0)).unwrap().is_none());
        service
            .recover(&fixture.ids[0], &fixture.ids[1], Some(1))
            .await
            .unwrap();
        let restored = e2ee_storage::get_chat_secret(query(0)).unwrap().unwrap();
        assert_eq!(restored.encrypted_secret, first.encrypted_secret);
        assert_eq!(restored.kem_ciphertext, first.kem_ciphertext);
        assert_eq!(restored.version, first.version);
        assert_eq!(
            storage::escrow_for_recovery(
                &fixture.ids[0],
                &fixture.ids[1],
                &fixture.ids[0],
                Some(1)
            )
            .unwrap()
            .unwrap(),
            escrow
        );
        assert_eq!(
            e2ee_storage::get_chat_secret(query(1))
                .unwrap()
                .unwrap()
                .encrypted_secret,
            other.encrypted_secret
        );
    }
    // A single lost escrow row can also be rebuilt from the accepted inbox's
    // original signed DTO. The verifier runs before the recovery write starts.
    execute("DROP TRIGGER chat_secret_escrows_accepted_delete; DELETE FROM chat_secret_escrows");
    service.recover(&fixture.ids[0], &fixture.ids[1], Some(1)).await.unwrap();
    assert_eq!(storage::escrow_for_recovery(&fixture.ids[0], &fixture.ids[1], &fixture.ids[0], Some(1)).unwrap().unwrap(), escrow);
    // Simulate a crash after durable enqueue but before processing. The startup
    // worker resumes the same nonce and fills only the deleted owner's row.
    execute("DELETE FROM chat_secrets WHERE user_id='1'");
    service
        .enqueue(&fixture.ids[0], &fixture.ids[1], Some(1))
        .unwrap();
    let pending = storage::recovery_jobs(10).unwrap();
    assert_eq!(pending.len(), 1);
    let nonce = pending[0].nonce.clone();
    service
        .enqueue(&fixture.ids[0], &fixture.ids[1], Some(1))
        .unwrap();
    assert_eq!(storage::recovery_jobs(10).unwrap()[0].nonce, nonce);
    service.retry_pending().await;
    assert!(storage::recovery_jobs(10).unwrap().is_empty());
    assert_eq!(
        e2ee_storage::get_chat_secret(query(0))
            .unwrap()
            .unwrap()
            .encrypted_secret,
        first.encrypted_secret
    );
    let gate = service.gate_initial_set_chat_secret(&escrow).await.unwrap();
    db::with_db(|connection| {
        let tx = connection.unchecked_transaction()?;
        gate.recheck_in_tx(&tx)?;
        tx.execute("UPDATE principals SET descriptor_revision=descriptor_revision+1 WHERE authority_id=?1 AND remote_user_id=?2",
            rusqlite::params![fixture.ids[1].authority.as_str(),fixture.ids[1].user_id as i64])?;
        assert!(gate.recheck_in_tx(&tx).is_err(), "a reassignment after the probe must invalidate commit");
        tx.rollback()?;
        Ok(())
    }).unwrap();
    drop(gate);
    let mut alternate = escrow.clone();
    alternate.envelopes[0].encrypted_secret.push(99);
    assert!(matches!(
        service.gate_initial_set_chat_secret(&alternate).await,
        Err(RecoveryError::Conflict)
    ));
    // Erasure/reassignment fences reject stale escrow and jobs atomically.
    db::with_immediate_transaction(|tx| storage::purge_owner_in_tx(tx, LocalUserId(1))).unwrap();
    assert_eq!(
        service
            .recover(&fixture.ids[0], &fixture.ids[1], Some(1))
            .await,
        Err(RecoveryError::Unauthorized)
    );
}
