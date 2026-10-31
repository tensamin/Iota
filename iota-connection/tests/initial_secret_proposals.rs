#[allow(dead_code)]
mod relay_support;

use async_trait::async_trait;
use iota_connection::{
    chat_secret_recovery::*,
    relay_service::{IngressSource, RelayOutcome},
};
use iota_identity::*;
use iota_storage::{
    identity::{SqliteLocalUserStore, SqlitePrincipalStore},
    util::{chat_secret_recovery as storage, db},
};
use relay_support::*;
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

struct Peer {
    node: LocalNodeIdentity,
    mode: AtomicU8,
    requests: AtomicUsize,
}
#[async_trait]
impl NodeIdentityResolver for Peer {
    async fn resolve_node(&self, node: &IotaNodeId) -> Result<ResolvedNodeIdentity, IdentityError> {
        if self.mode.load(Ordering::SeqCst) == 5 {
            return Err(IdentityError::Unavailable("peer died after proof".into()));
        }
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
#[async_trait]
impl RecoveryTransport for Peer {
    async fn request(
        &self,
        node: &IotaNodeId,
        request: &RecoveryRequest,
    ) -> Result<AuthenticatedRecoveryReply, RecoveryError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 0 {
            return Err(RecoveryError::RetryablePeerUnavailable);
        }
        if mode == 2 {
            execute("UPDATE principals SET descriptor_revision=descriptor_revision+1");
        }
        if mode == 3 {
            db::with_immediate_transaction(|tx| storage::purge_owner_in_tx(tx, LocalUserId(1)))
                .unwrap();
        }
        let result = if mode == 7 {
            Err(RecoveryError::Conflict)
        } else if mode == 4 {
            let evidence: storage::Escrow = db::with_db(|connection| {
                let bytes: Vec<u8> = connection.query_row(
                    "SELECT verified_prepared_operation FROM initial_secret_proposals",
                    [],
                    |row| row.get(0),
                )?;
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                Ok(serde_json::from_value(value["operation"]["secret_escrow"].clone()).unwrap())
            })
            .unwrap();
            Ok(encode_evidence(&evidence.first, &evidence).unwrap())
        } else {
            Err(RecoveryError::NoSuchConversation)
        };
        Ok(AuthenticatedRecoveryReply {
            node: node.clone(),
            key: self.node.public_keys(),
            reply: RecoveryReply {
                request: request.clone(),
                result,
            },
        })
    }
}

#[tokio::test]
async fn proposals_remain_unaccepted_until_fresh_fenced_proof() {
    let Ok(scenario) = std::env::var("INITIAL_SECRET_SCENARIO") else {
        for scenario in [
            "outage",
            "identity",
            "erasure",
            "accepted_proposal",
            "proof_then_outage",
            "concurrent",
            "reverse",
            "race",
            "revocation",
            "persistence_failure",
            "dishonest_digest",
            "unproven_conflict",
        ] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "proposals_remain_unaccepted_until_fresh_fenced_proof",
                    "--nocapture",
                ])
                .env("INITIAL_SECRET_SCENARIO", scenario)
                .status()
                .unwrap();
            assert!(status.success(), "{scenario}");
        }
        return;
    };
    let directory = std::path::Path::new("/tmp/opencode")
        .join(format!("initial-proposals-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    initialize(&directory);
    let fixture = Fixture::new(false);
    let peer = Arc::new(Peer {
        node: fixture.destination.clone(),
        mode: AtomicU8::new(0),
        requests: AtomicUsize::new(0),
    });
    let recovery = Arc::new(RecoveryCoordinator::new(
        Arc::new(Resolver),
        peer.clone(),
        Arc::new(SqlitePrincipalStore),
        Arc::new(SqliteLocalUserStore),
        fixture.node.node_id().clone(),
        peer.clone(),
        Arc::new(OriginalOperationVerifier {
            relay: fixture.service.clone(),
        }),
    ));
    install_recovery(recovery.clone());
    let mut signer = usize::from(scenario == "reverse");
    let mut frame = fixture.frame(signer, "proposal", secret(&fixture));
    let mut race_incoming = None;
    if scenario == "race" {
        let other = fixture.frame(1, "proposal", secret(&fixture));
        let digest = |frame: &mtp::codec::CommunicationValue| {
            storage::operation_digest(
                storage::RelayFormat::TauSignedRelayV1,
                &frame.clone().without_id().to_bytes().unwrap(),
            )
        };
        if digest(&frame) < digest(&other) {
            race_incoming = Some(frame);
            frame = other;
            signer = 1;
        } else {
            race_incoming = Some(other);
        }
    }
    let source = if signer == 0 {
        fixture.sources[0].clone()
    } else {
        IngressSource::DirectPeer {
            node_id: fixture.destination.node_id().clone(),
        }
    };
    let accept = || fixture.service.accept_relay(source.clone(), frame.clone());
    if scenario == "persistence_failure" {
        execute(
            "CREATE TRIGGER fail_proposal BEFORE INSERT ON initial_secret_proposals BEGIN SELECT RAISE(ABORT,'storage unavailable'); END;",
        );
        assert!(matches!(
            accept().await.unwrap(),
            RelayOutcome::RetryLater { .. }
        ));
        assert_eq!(peer.requests.load(Ordering::SeqCst), 0);
        assert_eq!(count("SELECT count(*) FROM initial_secret_proposals"), 0);
        assert_eq!(count("SELECT count(*) FROM relay_inbox"), 0);
        return;
    }
    if scenario == "concurrent" {
        let reverse = fixture.frame(1, "competing-proposal", secret(&fixture));
        let lowest = [&frame, &reverse]
            .map(|frame| {
                storage::operation_digest(
                    storage::RelayFormat::TauSignedRelayV1,
                    &frame.clone().without_id().to_bytes().unwrap(),
                )
            })
            .into_iter()
            .min()
            .unwrap();
        let (first, second) = tokio::join!(
            accept(),
            fixture.service.accept_relay(
                IngressSource::DirectPeer {
                    node_id: fixture.destination.node_id().clone()
                },
                reverse
            )
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert!(
            outcomes
                .iter()
                .all(|outcome| !matches!(outcome, RelayOutcome::Accepted { .. }))
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM initial_secret_proposals WHERE state IN ('awaiting_peer_proof','verifying')"
            ),
            1
        );
        let winner: Vec<u8> = db::with_db(|connection| Ok(connection.query_row(
            "SELECT operation_digest FROM initial_secret_proposals WHERE state IN ('awaiting_peer_proof','verifying')", [], |row| row.get(0),
        )?)).unwrap();
        assert_eq!(winner, lowest);
        assert_eq!(count("SELECT count(*) FROM relay_inbox"), 0);
        return;
    }
    assert!(matches!(
        accept().await.unwrap(),
        RelayOutcome::RetryLater { .. }
    ));
    assert_eq!(count("SELECT count(*) FROM relay_inbox"), 0);
    assert_eq!(count("SELECT count(*) FROM chat_secret_escrows"), 0);
    assert_eq!(count("SELECT count(*) FROM chat_secrets"), 0);
    let observed = db::with_db(|connection| {
        storage::initial_proposals::get_on(connection, &fixture.ids[signer], "proposal")
    })
    .unwrap()
    .unwrap();
    assert_eq!(observed.generation, 1);
    if scenario == "dishonest_digest" {
        let request = RecoveryRequest {
            version: RECOVERY_VERSION,
            pair: ConversationPair::new(
                tau::relay_protocol::Principal::new(
                    fixture.ids[0].authority.as_str().into(),
                    fixture.ids[0].user_id,
                )
                .unwrap(),
                tau::relay_protocol::Principal::new(
                    fixture.ids[1].authority.as_str().into(),
                    fixture.ids[1].user_id,
                )
                .unwrap(),
            )
            .unwrap(),
            owner: tau::relay_protocol::Principal::new(
                fixture.ids[1].authority.as_str().into(),
                fixture.ids[1].user_id,
            )
            .unwrap(),
            epoch: Some(1),
            nonce: [1; 32],
            proposal_digest: Some([0; 32]),
        };
        for nonce in [1, 2, 3] {
            let request = RecoveryRequest {
                nonce: [nonce; 32],
                ..request.clone()
            };
            let _ = recovery
                .handle_peer_request(
                    fixture.destination.node_id(),
                    &fixture.destination.public_keys(),
                    &request,
                )
                .await;
            let current = db::with_db(|connection| {
                storage::initial_proposals::get_on(
                    connection,
                    &observed.signer,
                    &observed.message_id,
                )
            })
            .unwrap()
            .unwrap();
            assert_eq!(
                current.state, observed.state,
                "an authenticated peer's invented digest rejected a real proposal"
            );
            assert_eq!(current.generation, observed.generation);
        }
        assert_eq!(count("SELECT count(*) FROM chat_secret_escrows"), 0);
        assert_eq!(count("SELECT count(*) FROM chat_secrets"), 0);
        return;
    }
    execute("UPDATE initial_secret_proposals SET next_at=9223372036854775807");
    for _ in 0..10 {
        assert!(matches!(
            accept().await.unwrap(),
            RelayOutcome::RetryLater { .. }
        ));
    }
    let same = db::with_db(|connection| {
        storage::initial_proposals::get_on(connection, &fixture.ids[signer], "proposal")
    })
    .unwrap()
    .unwrap();
    assert_eq!(observed.prepared, same.prepared);
    assert_eq!(observed.digest, same.digest);
    assert_eq!(observed.generation, same.generation);
    assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
    if scenario == "race" {
        use iota_connection::federated_relay::{protocol, protocol_principal};
        let incoming = race_incoming.unwrap();
        let digest = storage::operation_digest(
            storage::RelayFormat::TauSignedRelayV1,
            &incoming.clone().without_id().to_bytes().unwrap(),
        );
        assert!(digest < observed.digest);
        let request = RecoveryRequest {
            version: RECOVERY_VERSION,
            pair: protocol::ConversationPair::new(
                protocol_principal(&fixture.ids[0]),
                protocol_principal(&fixture.ids[1]),
            )
            .unwrap(),
            owner: protocol_principal(&fixture.ids[1]),
            epoch: Some(1),
            nonce: [7; 32],
            proposal_digest: Some(digest.try_into().unwrap()),
        };
        assert!(matches!(
            recovery
                .handle_peer_request(
                    fixture.destination.node_id(),
                    &fixture.destination.public_keys(),
                    &request
                )
                .await,
            Err(RecoveryError::Conflict)
        ));
        assert_eq!(
            count("SELECT count(*) FROM initial_secret_proposals WHERE state='rejected'"),
            0
        );
        assert_eq!(count("SELECT count(*) FROM chat_secrets"), 0);
        peer.mode.store(1, Ordering::SeqCst);
        let incoming_source = if signer == 0 {
            IngressSource::DirectPeer {
                node_id: fixture.destination.node_id().clone(),
            }
        } else {
            fixture.sources[0].clone()
        };
        accepted(
            fixture
                .service
                .accept_relay(incoming_source, incoming)
                .await
                .unwrap(),
        );
        assert_eq!(
            count("SELECT count(*) FROM initial_secret_proposals WHERE state='committed'"),
            1
        );
        assert!(matches!(
            accept().await.unwrap(),
            RelayOutcome::Rejected { .. }
        ));
        return;
    }
    assert!(
        matches!(
            fixture
                .service
                .accept_relay(
                    source.clone(),
                    fixture.frame(signer, "proposal", secret(&fixture))
                )
                .await
                .unwrap(),
            RelayOutcome::Rejected { .. }
        ),
        "same canonical signer and message ID cannot replace signed bytes"
    );
    if scenario == "outage" {
        execute("UPDATE initial_secret_proposals SET next_at=0");
        let old = storage::initial_proposals::claim(&same).unwrap().unwrap();
        assert!(storage::initial_proposals::claim(&old).unwrap().is_none());
        execute("UPDATE initial_secret_proposals SET claim_deadline=0");
        let current = storage::initial_proposals::claim(&old).unwrap().unwrap();
        assert!(
            db::with_immediate_transaction(|tx| storage::initial_proposals::finish_in_tx(
                tx,
                &old,
                "committed",
                None
            ))
            .is_err()
        );
        db::with_immediate_transaction(|tx| {
            storage::initial_proposals::finish_in_tx(
                tx,
                &current,
                "awaiting_peer_proof",
                Some("test_retry"),
            )
        })
        .unwrap();
    }
    if scenario == "revocation" {
        iota_storage::hosted_auth::revoke(LocalUserId(1)).unwrap();
    }
    peer.mode.store(
        match scenario.as_str() {
            "identity" => 2,
            "erasure" => 3,
            "accepted_proposal" => 4,
            "proof_then_outage" => 5,
            "unproven_conflict" => 7,
            _ => 1,
        },
        Ordering::SeqCst,
    );
    execute("UPDATE initial_secret_proposals SET next_at=0");
    fixture
        .service
        .retry_initial_secret_proposals()
        .await
        .unwrap();
    if scenario == "reverse" {
        assert_eq!(
            count("SELECT count(*) FROM initial_secret_proposals WHERE state='committed'"),
            1
        );
        assert_eq!(count("SELECT count(*) FROM chat_secrets"), 1);
        accepted(accept().await.unwrap());
    } else if scenario == "outage" || scenario == "accepted_proposal" {
        assert_eq!(
            count("SELECT count(*) FROM initial_secret_proposals WHERE state='committed'"),
            1
        );
        assert_eq!(
            count("SELECT count(*) FROM relay_inbox WHERE state='queued'"),
            1
        );
        assert_eq!(count("SELECT count(*) FROM pending_relays"), 1);
        assert_eq!(
            count("SELECT count(*) FROM chat_secrets"),
            0,
            "origin copy still requires downstream acceptance"
        );
        accepted(accept().await.unwrap());
        execute("DELETE FROM relay_inbox WHERE message_id='proposal'");
        accepted(accept().await.unwrap());
        assert_eq!(
            count("SELECT count(*) FROM relay_inbox"),
            0,
            "terminal proposal replay must not reapply after inbox retention"
        );
        assert_eq!(count("SELECT count(*) FROM pending_relays"), 1);
    } else {
        assert_eq!(count("SELECT count(*) FROM relay_inbox"), 0);
        assert_eq!(count("SELECT count(*) FROM chat_secrets"), 0);
        assert_eq!(count("SELECT count(*) FROM chat_secret_escrows"), 0);
        match scenario.as_str() {
            "erasure" => assert_eq!(count("SELECT count(*) FROM initial_secret_proposals"), 0),
            "proof_then_outage" | "unproven_conflict" => assert_eq!(
                count(
                    "SELECT count(*) FROM initial_secret_proposals WHERE state='awaiting_peer_proof'"
                ),
                1
            ),
            _ => {
                assert_eq!(
                    count("SELECT count(*) FROM initial_secret_proposals WHERE state='rejected'"),
                    1
                );
                assert!(matches!(
                    accept().await.unwrap(),
                    RelayOutcome::Rejected { .. }
                ));
            }
        }
    }
}
