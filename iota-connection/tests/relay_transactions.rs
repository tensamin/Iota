mod relay_support;
use iota_connection::relay_service::{IngressSource, PendingRelayDispatcher, RelayOutcome};
use iota_storage::util::{db, relay_work};
use mtp::codec::{CommunicationType as C, CommunicationValue as V, DataType as D, DataValue as W};
use relay_support::*;
use std::sync::Arc;

#[tokio::test]
async fn signed_live_transactions() {
    if let Ok(scenario) = std::env::var("RELAY_TRANSACTION_SCENARIO") {
        initialize(std::path::Path::new(
            &std::env::var("RELAY_TEST_STORAGE").unwrap(),
        ));
        match scenario.as_str() {
            "local" => local_operations().await,
            "rollback" => rollback().await,
            "remote_accept" => remote(true).await,
            "remote_reject" => remote(false).await,
            "peer" => peer().await,
            _ => panic!("unknown scenario"),
        }
        return;
    }
    for scenario in [
        "local",
        "rollback",
        "remote_accept",
        "remote_reject",
        "peer",
    ] {
        let path = std::env::temp_dir().join(format!(
            "relay-transactions-{}-{scenario}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "signed_live_transactions", "--nocapture"])
            .env("RELAY_TRANSACTION_SCENARIO", scenario)
            .env("RELAY_TEST_STORAGE", &path)
            .status()
            .unwrap();
        std::fs::remove_dir_all(path).unwrap();
        assert!(status.success(), "scenario {scenario} failed");
    }
}

async fn peer() {
    let f = Fixture::new(false);
    execute("DELETE FROM hosted_principals; DELETE FROM users;");
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO users(user_id, username, public_key, created_at) VALUES(2, 'recipient', 'test', 1)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id, principal_handle) VALUES(2, ?1)", [f.handles[1].0])?;
        Ok(())
    }).unwrap();
    let service = f.destination_service();
    let source = IngressSource::DirectPeer {
        node_id: f.node.node_id().clone(),
    };
    accepted(
        service
            .accept_relay(source.clone(), f.frame(0, "peer-secret", secret(&f)))
            .await
            .unwrap(),
    );
    assert_eq!(
        count("SELECT count(*) FROM chat_secrets WHERE user_id = '2' AND encrypted_secret = X'02'"),
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM chat_secrets WHERE user_id = '1'"),
        0
    );
    let frame = f.frame(0, "peer-message", send(10));
    accepted(
        service
            .accept_relay(source.clone(), frame.clone())
            .await
            .unwrap(),
    );
    accepted(service.accept_relay(source, frame).await.unwrap());
    assert_eq!(
        count(
            "SELECT count(*) FROM messages WHERE storage_owner = 2 AND sent_by_self = 0 AND relay_message_id = 'peer-message'"
        ),
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'peer-message'"),
        1
    );
    assert!(
        service
            .accept_relay(
                IngressSource::DirectPeer {
                    node_id: f.destination.node_id().clone()
                },
                f.frame(0, "wrong-peer", send(11))
            )
            .await
            .is_err()
    );
    assert_eq!(
        count("SELECT count(*) FROM relay_inbox WHERE message_id = 'wrong-peer'"),
        0
    );
}

async fn local_operations() {
    let f = Fixture::new(true);
    accepted(f.accept(0, "secret", secret(&f)).await);
    assert_eq!(count("SELECT count(*) FROM chat_secrets"), 2);
    assert_eq!(
        count(
            "SELECT count(*) FROM chat_secrets WHERE (user_id = '1' AND encrypted_secret = X'01') OR (user_id = '2' AND encrypted_secret = X'02')"
        ),
        2
    );
    let frame = f.frame(0, "send", send(10));
    // Independently verified concurrent ingress competes on the actual SQLite reservation.
    let verified_a = f
        .service
        .prepare_relay(&f.sources[0], frame.clone())
        .await
        .unwrap();
    let verified_b = f
        .service
        .prepare_relay(&f.sources[0], frame.clone())
        .await
        .unwrap();
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let threads = [verified_a, verified_b]
            .into_iter()
            .map(|verified| {
                let f = &f;
                let barrier = &barrier;
                scope.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    barrier.wait();
                    runtime
                        .block_on(
                            f.service
                                .accept_verified_relay(f.sources[0].clone(), verified),
                        )
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(
        results
            .iter()
            .any(|result| matches!(result, RelayOutcome::Accepted { .. }))
    );
    assert!(results.iter().all(|result| matches!(
        result,
        RelayOutcome::Accepted { .. } | RelayOutcome::RetryLater { .. }
    )));
    let accepted_at = count("SELECT accepted_at FROM relay_inbox WHERE message_id = 'send'");
    for result in &results {
        if let RelayOutcome::Accepted {
            ingress_response, ..
        } = result
        {
            assert_eq!(
                ingress_response
                    .get_data(D::RelayAcceptedAt)
                    .unwrap()
                    .as_number()
                    .unwrap(),
                accepted_at as i128
            );
        }
    }
    assert_eq!(
        count("SELECT count(*) FROM messages WHERE relay_message_id = 'send'"),
        2
    );
    accepted(
        f.service
            .accept_relay(
                IngressSource::DirectPeer {
                    node_id: f.node.node_id().clone(),
                },
                frame,
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'send'"),
        1
    );
    let collision = f.accept(0, "send", send(11)).await;
    assert!(matches!(collision, RelayOutcome::Rejected { .. }));
    let edit = V::new(C::MessageEdit)
        .add_typed_default(D::SendTime, W::SignedNumber(10))
        .add_typed_default(D::VersionNumber, W::SignedNumber(1))
        .add_typed_default(D::Content, W::Str("edited".into()));
    accepted(f.accept(0, "edit", edit).await);
    assert_eq!(
        count("SELECT count(*) FROM messages WHERE content = 'edited' AND edited_count = 1"),
        2
    );
    for (id, kind, expected) in [
        ("react", C::MessageReactionAdd, 2),
        ("unreact", C::MessageReactionRemove, 0),
    ] {
        accepted(
            f.accept(
                1,
                id,
                V::new(kind)
                    .add_typed_default(D::SendTime, W::SignedNumber(10))
                    .add_typed_default(D::Reaction, W::Str("ok".into())),
            )
            .await,
        );
        assert_eq!(count("SELECT count(*) FROM reactions"), expected);
    }
    iota_storage::util::receipt_policy::set(2, true, true).unwrap();
    for state in ["received", "read"] {
        accepted(
            f.accept(
                1,
                state,
                V::new(C::MessageState)
                    .add_typed_default(D::ChatPartnerId, W::SignedNumber(1))
                    .add_typed_default(D::RelayMessageId, W::Str("send".into()))
                    .add_typed_default(D::MessageState, W::Str(state.into()))
                    .add_typed_default(
                        D::EventAt,
                        W::SignedNumber(iota_storage::util::sync::now_millis().into()),
                    ),
            )
            .await,
        );
        assert_eq!(
            count(&format!(
                "SELECT count(*) FROM messages WHERE message_state = '{state}'"
            )),
            2
        );
    }
    accepted(
        f.accept(
            0,
            "conversation",
            V::new(C::AddConversation)
                .add_typed_default(D::ChatPartnerId, W::SignedNumber(2))
                .add_typed_default(D::ChatPartnerName, W::Str("friend".into())),
        )
        .await,
    );
    assert_eq!(count("SELECT count(*) FROM contacts"), 2);
    for (id, kind, time) in [
        ("delete", C::MessageDelete, 10),
        ("delete-live", C::MessageDeleteLive, 20),
    ] {
        if time == 20 {
            accepted(f.accept(0, "second", send(20)).await);
        }
        accepted(
            f.accept(
                0,
                id,
                V::new(kind).add_typed_default(D::SendTime, W::SignedNumber(time.into())),
            )
            .await,
        );
        assert_eq!(
            count(&format!(
                "SELECT count(*) FROM messages WHERE message_time = {time} AND storage_owner = 1 AND history_deleted = 0"
            )),
            0
        );
        assert_eq!(
            count(&format!(
                "SELECT count(*) FROM messages WHERE message_time = {time} AND storage_owner = 2 AND deleted_by_external = 1"
            )),
            1
        );
    }
    assert!(matches!(
        f.accept(0, "malformed", V::new(C::MessageSend)).await,
        RelayOutcome::Rejected { .. }
    ));
    assert_eq!(
        count("SELECT count(*) FROM relay_inbox WHERE message_id = 'malformed'"),
        0
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM relay_inbox WHERE state <> 'queued' OR prepared_operation IS NULL"
        ),
        0
    );
}

async fn rollback() {
    let f = Fixture::new(true);
    accepted(f.accept(0, "secret", secret(&f)).await);
    execute(
        "CREATE TRIGGER fail_second_copy BEFORE INSERT ON messages WHEN NEW.storage_owner = 2 BEGIN SELECT RAISE(ABORT, 'injected second-copy failure'); END;",
    );
    assert!(matches!(
        f.accept(0, "rollback", send(10)).await,
        RelayOutcome::RetryLater { .. }
    ));
    assert_eq!(count("SELECT count(*) FROM messages"), 0);
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'rollback'"),
        0
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM relay_inbox WHERE message_id = 'rollback' AND state = 'processing' AND prepared_operation IS NOT NULL AND applied_at IS NULL"
        ),
        1
    );
    execute(
        "DROP TRIGGER fail_second_copy; UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'rollback';",
    );
    let old = relay_work::incomplete(10).unwrap().remove(0);
    execute(
        "UPDATE relay_inbox SET processing_deadline = 9223372036854775807 WHERE message_id = 'rollback';",
    );
    assert!(!f.service.resume_relay(&old).unwrap());
    assert_eq!(count("SELECT count(*) FROM messages"), 0);
    execute("UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'rollback';");
    let claim = relay_work::take_over_abandoned_processing(&old, i64::MAX)
        .unwrap()
        .unwrap();
    assert!(!f.service.resume_relay(&old).unwrap());
    assert!(
        db::with_immediate_transaction(|tx| iota_storage::util::relay_replay::verify_claim_in_tx(
            tx, &claim
        ))
        .is_ok()
    );
    execute("UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'rollback';");
    assert_eq!(f.service.recover_incomplete(10).unwrap().completed, 1);
    assert!(
        db::with_immediate_transaction(|tx| iota_storage::util::relay_replay::verify_claim_in_tx(
            tx, &claim
        ))
        .is_err()
    );
    assert_eq!(count("SELECT count(*) FROM messages"), 2);
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'rollback'"),
        1
    );
}

async fn remote(accept: bool) {
    let f = Fixture::new(false);
    accepted(f.accept(0, "remote-secret", secret(&f)).await);
    assert_eq!(count("SELECT count(*) FROM chat_secrets"), 0);
    assert_eq!(
        count("SELECT count(*) FROM relay_deferred_secrets WHERE completed_at IS NULL"),
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE delivery_state = 'ready'"),
        1
    );
    let dispatcher = PendingRelayDispatcher::new(Arc::new(Router(accept)));
    assert_eq!(
        dispatcher.dispatch_ready(10).await.unwrap(),
        usize::from(accept)
    );
    assert_eq!(
        count("SELECT count(*) FROM chat_secrets"),
        i64::from(accept)
    );
    if accept {
        assert_eq!(
            count("SELECT count(*) FROM relay_inbox WHERE state = 'delivered'"),
            1
        );
        assert_eq!(count("SELECT count(*) FROM pending_relays"), 0);
        assert_eq!(
            count("SELECT count(*) FROM chat_secrets WHERE encrypted_secret = X'01'"),
            1
        );
    } else {
        assert_eq!(
            count("SELECT count(*) FROM pending_relays WHERE delivery_state = 'quarantined'"),
            1
        );
        assert_eq!(
            count("SELECT count(*) FROM relay_deferred_secrets WHERE completed_at IS NULL"),
            1
        );
    }
    assert_eq!(dispatcher.dispatch_ready(10).await.unwrap(), 0);
    if !accept {
        let chat_id =
            iota_storage::util::e2ee_storage::principal_chat_id(f.handles[0], f.handles[1])
                .unwrap();
        iota_storage::util::e2ee_storage::put_chat_secret(
            iota_storage::util::e2ee_storage::StoredChatSecret {
                user_id: "1".into(),
                secret_id: iota_storage::util::e2ee_storage::principal_secret_id(&chat_id),
                chat_id,
                version: 1,
                encrypted_secret: vec![1],
                kem_ciphertext: vec![11],
                wrapping_scheme: "test".into(),
                created_at: 1,
                updated_at: 1,
            },
        )
        .unwrap();
    }
    accepted(f.accept(0, "remote-message", send(30)).await);
    assert_eq!(
        count(
            "SELECT count(*) FROM messages WHERE relay_message_id = 'remote-message' AND message_state = 'sending' AND destination_iota_received_at IS NULL"
        ),
        1
    );
    assert_eq!(
        dispatcher.dispatch_ready(10).await.unwrap(),
        usize::from(accept)
    );
    if accept {
        assert_eq!(
            count(
                "SELECT count(*) FROM messages WHERE relay_message_id = 'remote-message' AND message_state = 'sent' AND destination_iota_received_at = 1234"
            ),
            1
        );
    } else {
        assert_eq!(
            count(
                "SELECT count(*) FROM messages WHERE relay_message_id = 'remote-message' AND delivery_failure = 'destination_rejected' AND destination_iota_received_at IS NULL"
            ),
            1
        );
    }
}
