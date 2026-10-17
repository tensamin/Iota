#[allow(
    dead_code,
    reason = "shared fixtures support other relay test binaries"
)]
mod relay_support;

use iota_connection::relay_service::{
    IngressSource, RelayOutcome, RelayService, RelayServiceError,
};
use iota_identity::{
    PrincipalDescriptor, PrincipalHome, PrincipalStore, SignedPrincipalDescriptor,
};
use iota_storage::{
    identity::{SqliteLocalUserStore, SqlitePrincipalStore},
    util::{db, relay_replay, relay_work},
};
use mtp::{
    codec::{DataType, DataValue},
    crypto::Keyring,
};
use relay_support::*;
use std::sync::{Arc, Barrier};

// Each child owns the global storage configuration and SQLite pool. Reusing the
// directory across phases tests persistence without reusing process-local state.
fn isolated(test: &str, phases: &[&str]) -> Option<String> {
    if let Ok(phase) = std::env::var("RECOVERY_SCHEDULING_PHASE") {
        initialize(std::path::Path::new(
            &std::env::var("RELAY_TEST_STORAGE").unwrap(),
        ));
        assert!(count("PRAGMA user_version") >= 59);
        return Some(phase);
    }
    let path =
        std::env::temp_dir().join(format!("relay-scheduling-{test}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).unwrap();
    let mut failed = Vec::new();
    for phase in phases {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("RECOVERY_SCHEDULING_PHASE", phase)
            .env("RELAY_TEST_STORAGE", &path)
            .env("IOTA_RECOVERY_MIN_DELAY_MS", "60000")
            .env("IOTA_RECOVERY_MAX_DELAY_MS", "240000")
            .status()
            .unwrap();
        if !status.success() {
            failed.push(*phase);
            break;
        }
    }
    std::fs::remove_dir_all(path).unwrap();
    assert!(failed.is_empty(), "failed phases: {failed:?}");
    None
}

fn recovery_service() -> RelayService {
    RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true)))
}

async fn interrupted_messages(ids: &[&str]) -> Fixture {
    let fixture = Fixture::new(true);
    accepted(fixture.accept(0, "secret", secret(&fixture)).await);
    execute(
        "CREATE TRIGGER interrupt_message BEFORE INSERT ON messages WHEN NEW.storage_owner = 2 BEGIN SELECT RAISE(ABORT, 'recovery scheduling interruption'); END;",
    );
    for (index, id) in ids.iter().enumerate() {
        assert!(matches!(
            fixture.accept(0, id, send(10 + index as i64)).await,
            RelayOutcome::RetryLater { .. }
        ));
    }
    assert_eq!(count("SELECT count(*) FROM messages"), 0);
    assert_eq!(
        count(
            "SELECT count(*) FROM relay_inbox WHERE state = 'processing' AND prepared_operation IS NOT NULL"
        ),
        ids.len() as i64
    );
    execute("UPDATE relay_inbox SET processing_deadline = 0 WHERE state = 'processing';");
    fixture
}

#[tokio::test]
async fn selected_applied_work_cannot_resume_after_erasure_and_rehosting() {
    let Some(_) = isolated(
        "selected_applied_work_cannot_resume_after_erasure_and_rehosting",
        &["run"],
    ) else {
        return;
    };
    let fixture = Fixture::new(true);
    accepted(fixture.accept(0, "secret", secret(&fixture)).await);
    accepted(fixture.accept(0, "selected-before-erasure", send(10)).await);
    execute("DELETE FROM pending_relays WHERE relay_message_id = 'selected-before-erasure';
        UPDATE relay_inbox SET state = 'applied', queued_at = NULL WHERE message_id = 'selected-before-erasure';");
    execute(
        "CREATE TRIGGER selected_unapplied BEFORE INSERT ON messages WHEN NEW.relay_message_id = 'selected-unapplied' BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
    );
    assert!(matches!(
        fixture.accept(0, "selected-unapplied", send(20)).await,
        RelayOutcome::RetryLater { .. }
    ));
    execute(
        "DROP TRIGGER selected_unapplied; UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'selected-unapplied';",
    );
    let selected = relay_work::incomplete(10).unwrap();
    assert_eq!(selected.len(), 2);
    iota_storage::users::user_manager::erase_user_locally(2).unwrap();
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(2,'restored','test',1)", [])?;
        tx.execute("INSERT OR REPLACE INTO hosted_principals(local_user_id,principal_handle) VALUES(2,?1)", [fixture.handles[1].0])?;
        tx.execute("INSERT INTO user_residency(user_id,username,lifecycle_state,data_state,credential_origin,updated_at) VALUES(2,'restored','managed','present','external',1) ON CONFLICT(user_id) DO UPDATE SET lifecycle_state='managed',data_state='present'", [])?;
        relay_work::verify_owner_in_tx(tx, 2, fixture.handles[1])?;
        Ok(())
    }).unwrap();
    for work in selected {
        assert!(!fixture.service.resume_relay(&work).unwrap());
    }
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM pending_relays WHERE relay_message_id = 'selected-before-erasure'"
        ),
        0
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM messages WHERE storage_owner = 2"),
        0
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM relay_inbox WHERE message_id = 'selected-before-erasure' AND state = 'applied' AND recovery_status = 'blocked' AND recovery_error_code = 'recipient_erased'"
        ),
        1
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM relay_inbox WHERE message_id = 'selected-unapplied' AND state = 'rejected' AND recovery_status = 'blocked' AND recovery_error_code = 'recipient_erased'"
        ),
        1
    );
}

#[tokio::test]
async fn malformed_metadata_is_isolated_across_restart() {
    let Some(phase) = isolated(
        "malformed_metadata_is_isolated_across_restart",
        &["seed", "recover", "verify"],
    ) else {
        return;
    };
    match phase.as_str() {
        "seed" => {
            interrupted_messages(&[
                "bad-frame-id",
                "bad-generation",
                "bad-attempts",
                "healthy-metadata",
            ])
            .await;
            execute("DROP TRIGGER interrupt_message;
                UPDATE relay_inbox SET frame_id = -1 WHERE message_id = 'bad-frame-id';
                UPDATE relay_inbox SET processing_generation = 'corrupt' WHERE message_id = 'bad-generation';
                UPDATE relay_inbox SET recovery_attempts = 'corrupt' WHERE message_id = 'bad-attempts';");
        }
        "recover" => {
            let report = recovery_service().recover_incomplete(10).unwrap();
            assert_eq!((report.completed, report.health.blocked), (1, 3));
            assert_eq!(
                count(
                    "SELECT count(*) FROM relay_inbox WHERE message_id LIKE 'bad-%' AND recovery_status = 'blocked' AND recovery_error_code = 'invalid_persisted_metadata' AND prepared_operation IS NOT NULL"
                ),
                3
            );
            assert_eq!(
                count("SELECT frame_id FROM relay_inbox WHERE message_id = 'bad-frame-id'"),
                -1
            );
            assert_eq!(
                count(
                    "SELECT count(*) FROM relay_inbox WHERE message_id = 'bad-generation' AND processing_generation = 'corrupt'"
                ),
                1
            );
            assert_eq!(
                count(
                    "SELECT count(*) FROM relay_inbox WHERE message_id = 'bad-attempts' AND recovery_attempts = 'corrupt'"
                ),
                1
            );
        }
        "verify" => {
            let report = recovery_service().recover_incomplete(10).unwrap();
            assert_eq!((report.selected, report.health.blocked), (0, 3));
            assert_eq!(
                count("SELECT count(*) FROM messages WHERE relay_message_id = 'healthy-metadata'"),
                2
            );
        }
        _ => panic!("unknown phase"),
    }
}

#[tokio::test]
async fn missing_application_schema_is_fatal_without_consuming_retry_budget() {
    let Some(_) = isolated(
        "missing_application_schema_is_fatal_without_consuming_retry_budget",
        &["run"],
    ) else {
        return;
    };
    let fixture = interrupted_messages(&["missing-messages-table"]).await;
    execute("DROP TABLE messages;");
    let error = fixture.service.recover_incomplete(10).unwrap_err();
    assert!(
        matches!(error, RelayServiceError::Internal(ref detail) if detail.contains("messages"))
    );
    assert_eq!(
        count(
            "SELECT recovery_attempts FROM relay_inbox WHERE message_id = 'missing-messages-table'"
        ),
        0
    );
    assert_eq!(relay_work::health().unwrap().retrying, 0);
}

#[tokio::test]
async fn erased_applied_owner_blocks_publication_without_reconstruction() {
    let Some(_) = isolated(
        "erased_applied_owner_blocks_publication_without_reconstruction",
        &["run"],
    ) else {
        return;
    };
    let fixture = Fixture::new(true);
    accepted(fixture.accept(0, "secret", secret(&fixture)).await);
    accepted(fixture.accept(0, "applied-before-erasure", send(10)).await);
    execute("DELETE FROM pending_relays WHERE relay_message_id = 'applied-before-erasure';
        UPDATE relay_inbox SET state = 'applied', queued_at = NULL WHERE message_id = 'applied-before-erasure';
        DELETE FROM hosted_principals WHERE local_user_id = 2;
        DELETE FROM users WHERE user_id = 2;
        DELETE FROM messages WHERE storage_owner = 2;");
    let report = fixture.service.recover_incomplete(10).unwrap();
    assert_eq!(
        (report.selected, report.completed, report.blocked),
        (1, 0, 1)
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM relay_inbox WHERE message_id = 'applied-before-erasure' AND state = 'applied' AND recovery_status = 'blocked' AND recovery_error_code = 'account_unavailable'"
        ),
        1
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM pending_relays WHERE relay_message_id = 'applied-before-erasure'"
        ),
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM messages WHERE storage_owner = 2"),
        0
    );
}

#[tokio::test]
async fn unavailable_work_enumeration_is_a_subsystem_error() {
    let Some(_) = isolated(
        "unavailable_work_enumeration_is_a_subsystem_error",
        &["run"],
    ) else {
        return;
    };
    execute("DROP TABLE relay_inbox;");
    assert!(matches!(
        recovery_service().recover_incomplete(10),
        Err(RelayServiceError::Internal(_))
    ));
    assert!(relay_work::health().is_err());
}

#[tokio::test]
async fn exhausted_attempts_block_only_the_failing_record() {
    let Some(_) = isolated("exhausted_attempts_block_only_the_failing_record", &["run"]) else {
        return;
    };
    let fixture = interrupted_messages(&["exhausted", "healthy-after-exhaustion"]).await;
    execute("DROP TRIGGER interrupt_message;
        CREATE TRIGGER fail_exhausted BEFORE INSERT ON messages WHEN NEW.relay_message_id = 'exhausted'
        BEGIN SELECT RAISE(ABORT, 'temporary failure'); END;
        UPDATE relay_inbox SET recovery_attempts = 9223372036854775807 WHERE message_id = 'exhausted';");
    let report = fixture.service.recover_incomplete(10).unwrap();
    assert_eq!(
        (
            report.selected,
            report.completed,
            report.blocked,
            report.rescheduled
        ),
        (2, 1, 1, 0)
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM relay_inbox WHERE message_id = 'exhausted' AND recovery_attempts = 9223372036854775807 AND recovery_status = 'blocked' AND recovery_error_code = 'recovery_attempts_exhausted'"
        ),
        1
    );
    assert!(relay_work::incomplete(10).unwrap().is_empty());
    let next = fixture.service.recover_incomplete(10).unwrap();
    assert_eq!(
        (next.selected, next.blocked, next.health.blocked),
        (0, 0, 1)
    );
}

#[tokio::test]
async fn malformed_early_work_cannot_starve_later_batches() {
    let Some(_) = isolated("malformed_early_work_cannot_starve_later_batches", &["run"]) else {
        return;
    };
    let fixture = interrupted_messages(&["bad-1", "bad-2", "bad-3", "healthy"]).await;
    execute("DROP TRIGGER interrupt_message;
        UPDATE relay_inbox SET prepared_operation = X'FF', recovery_next_at = 0 WHERE message_id LIKE 'bad-%';
        UPDATE relay_inbox SET recovery_next_at = 1 WHERE message_id = 'healthy';");
    let mut completed = 0;
    // More corrupt records than the batch size must not pin the first page forever.
    for _ in 0..4 {
        let report = fixture.service.recover_incomplete(2).unwrap();
        assert!(report.selected <= 2);
        completed += report.completed;
        if completed == 1 {
            break;
        }
    }
    assert_eq!(
        completed, 1,
        "healthy work behind the corrupt prefix starved"
    );
    assert_eq!(
        count("SELECT count(*) FROM messages WHERE relay_message_id = 'healthy'"),
        2
    );
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'healthy'"),
        1
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM relay_inbox WHERE message_id LIKE 'bad-%' AND prepared_operation = X'FF' AND recovery_status = 'blocked' AND applied_at IS NULL"
        ),
        3
    );
    assert!(relay_work::incomplete(2).unwrap().is_empty());
    let report = fixture.service.recover_incomplete(2).unwrap();
    assert_eq!(
        (report.selected, report.completed, report.superseded),
        (0, 0, 0)
    );
    assert_eq!(
        (
            report.blocked,
            report.health.blocked,
            report.health.eligible
        ),
        (0, 3, 0)
    );
}

#[tokio::test]
async fn blocked_only_backlog_remains_visible_after_restart() {
    let Some(phase) = isolated(
        "blocked_only_backlog_remains_visible_after_restart",
        &["seed", "verify"],
    ) else {
        return;
    };
    if phase == "seed" {
        interrupted_messages(&["blocked"]).await;
        execute("DROP TRIGGER interrupt_message;");
        let work = relay_work::incomplete(1).unwrap().remove(0);
        assert!(
            relay_work::record_outcome(
                &work,
                relay_work::RecoveryDisposition::Blocked {
                    error_code: "operator_review_required",
                }
            )
            .unwrap()
        );
    } else {
        assert!(relay_work::incomplete(10).unwrap().is_empty());
        let report = recovery_service().recover_incomplete(10).unwrap();
        assert_eq!(
            (report.selected, report.completed, report.rescheduled),
            (0, 0, 0)
        );
        assert_eq!(
            (
                report.blocked,
                report.health.blocked,
                report.health.eligible
            ),
            (0, 1, 0)
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM relay_inbox WHERE message_id = 'blocked' AND recovery_attempts = 1 AND recovery_error_code = 'operator_review_required' AND recovery_last_attempt_at IS NOT NULL"
            ),
            1
        );
        assert_eq!(count("SELECT count(*) FROM messages"), 0);
    }
}

#[tokio::test]
async fn retry_backoff_survives_restart_and_eventually_completes() {
    let Some(phase) = isolated(
        "retry_backoff_survives_restart_and_eventually_completes",
        &["seed", "retry_again", "complete", "verify"],
    ) else {
        return;
    };
    let service = recovery_service();
    match phase.as_str() {
        "seed" => {
            interrupted_messages(&["retry"]).await;
            let report = service.recover_incomplete(1).unwrap();
            assert_eq!(
                (
                    report.selected,
                    report.completed,
                    report.rescheduled,
                    report.blocked
                ),
                (1, 0, 1, 0)
            );
            assert_eq!(
                count("SELECT recovery_attempts FROM relay_inbox WHERE message_id = 'retry'"),
                1
            );
            assert!(
                count(
                    "SELECT recovery_next_at - recovery_last_attempt_at FROM relay_inbox WHERE message_id = 'retry'"
                ) >= 59_000
            );
        }
        "retry_again" => {
            execute("UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'retry';");
            assert_eq!(
                count("SELECT recovery_attempts FROM relay_inbox WHERE message_id = 'retry'"),
                1
            );
            assert!(
                count("SELECT recovery_next_at FROM relay_inbox WHERE message_id = 'retry'")
                    > iota_storage::util::sync::now_millis()
            );
            assert!(relay_work::incomplete(1).unwrap().is_empty());
            let report = service.recover_incomplete(1).unwrap();
            assert_eq!(
                (
                    report.selected,
                    report.health.retrying,
                    report.health.eligible
                ),
                (0, 1, 0)
            );
            // Advance the persisted due time and lease instead of sleeping in the test.
            execute(
                "UPDATE relay_inbox SET recovery_next_at = 0, processing_deadline = 0 WHERE message_id = 'retry';",
            );
            assert_eq!(relay_work::incomplete(1).unwrap()[0].attempts, 1);
            let report = service.recover_incomplete(1).unwrap();
            assert_eq!(
                (report.selected, report.completed, report.rescheduled),
                (1, 0, 1)
            );
            assert_eq!(
                count("SELECT recovery_attempts FROM relay_inbox WHERE message_id = 'retry'"),
                2
            );
            assert!(
                count(
                    "SELECT recovery_next_at - recovery_last_attempt_at FROM relay_inbox WHERE message_id = 'retry'"
                ) >= 119_000
            );
            assert_eq!(count("SELECT count(*) FROM messages"), 0);
        }
        "complete" => {
            execute("UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'retry';");
            assert_eq!(
                count("SELECT recovery_attempts FROM relay_inbox WHERE message_id = 'retry'"),
                2
            );
            assert_eq!(service.recover_incomplete(1).unwrap().selected, 0);
            execute(
                "DROP TRIGGER interrupt_message; UPDATE relay_inbox SET recovery_next_at = 0, processing_deadline = 0 WHERE message_id = 'retry';",
            );
            let report = service.recover_incomplete(1).unwrap();
            assert_eq!(
                (
                    report.selected,
                    report.completed,
                    report.blocked,
                    report.health.retrying
                ),
                (1, 1, 0, 0)
            );
        }
        "verify" => {
            assert_eq!(service.recover_incomplete(1).unwrap().selected, 0);
            assert_eq!(
                count("SELECT count(*) FROM messages WHERE relay_message_id = 'retry'"),
                2
            );
            assert_eq!(
                count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'retry'"),
                1
            );
            assert_eq!(
                count(
                    "SELECT count(*) FROM relay_inbox WHERE message_id = 'retry' AND state = 'queued' AND recovery_status = 'ready' AND recovery_next_at = 0 AND recovery_error_code IS NULL"
                ),
                1
            );
        }
        _ => panic!("unknown phase"),
    }
}

#[tokio::test]
async fn stale_workers_cannot_schedule_a_newer_claim_or_attempt() {
    let Some(_) = isolated(
        "stale_workers_cannot_schedule_a_newer_claim_or_attempt",
        &["run"],
    ) else {
        return;
    };
    interrupted_messages(&["fenced"]).await;
    let stale = relay_work::incomplete(1).unwrap().remove(0);
    let claim = relay_work::take_over_abandoned_processing(&stale, i64::MAX)
        .unwrap()
        .unwrap();
    assert!(!recovery_service().resume_relay(&stale).unwrap());
    for disposition in [
        relay_work::RecoveryDisposition::Retry {
            next_attempt_at: i64::MAX,
            error_code: "stale_retry",
        },
        relay_work::RecoveryDisposition::Blocked {
            error_code: "stale_block",
        },
    ] {
        assert!(!relay_work::record_outcome(&stale, disposition).unwrap());
    }
    db::with_immediate_transaction(|tx| relay_replay::verify_claim_in_tx(tx, &claim)).unwrap();
    assert_eq!(
        count("SELECT recovery_attempts FROM relay_inbox WHERE message_id = 'fenced'"),
        0
    );
    execute("UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'fenced';");
    let current = relay_work::incomplete(1).unwrap().remove(0);
    assert_eq!(current.generation, claim.generation);
    let barrier = Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let workers = (0..2)
            .map(|_| {
                let current = &current;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    relay_work::record_outcome(
                        current,
                        relay_work::RecoveryDisposition::Retry {
                            next_attempt_at: i64::MAX,
                            error_code: "temporary_storage_failure",
                        },
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.into_iter().filter(|won| *won).count(), 1);
    // The generation and owner still match, but this observation predates the winner's attempt.
    assert!(
        !relay_work::record_outcome(
            &current,
            relay_work::RecoveryDisposition::Blocked {
                error_code: "late_block",
            }
        )
        .unwrap()
    );
    assert_eq!(
        count(
            "SELECT count(*) FROM relay_inbox WHERE message_id = 'fenced' AND recovery_status = 'retry' AND recovery_next_at = 9223372036854775807 AND recovery_attempts = 1 AND recovery_error_code = 'temporary_storage_failure'"
        ),
        1
    );
}

#[tokio::test]
async fn concurrent_recovery_workers_apply_once() {
    let Some(_) = isolated("concurrent_recovery_workers_apply_once", &["run"]) else {
        return;
    };
    interrupted_messages(&["contended"]).await;
    execute("DROP TRIGGER interrupt_message;");
    let barrier = Barrier::new(2);
    let reports = std::thread::scope(|scope| {
        let workers = (0..2)
            .map(|_| {
                let barrier = &barrier;
                scope.spawn(move || {
                    let service = recovery_service();
                    barrier.wait();
                    service.recover_incomplete(1).unwrap()
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(reports.iter().map(|r| r.completed).sum::<usize>(), 1);
    assert!(reports.iter().all(|r| r.blocked == 0 && r.rescheduled == 0));
    assert_eq!(
        count("SELECT count(*) FROM messages WHERE relay_message_id = 'contended'"),
        2
    );
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'contended'"),
        1
    );
    assert_eq!(
        recovery_service().recover_incomplete(1).unwrap().selected,
        0
    );
}

#[tokio::test]
async fn accepted_replay_checks_direct_peer_after_signing_key_rotation() {
    let Some(_) = isolated(
        "accepted_replay_checks_direct_peer_after_signing_key_rotation",
        &["run"],
    ) else {
        return;
    };
    let fixture = Fixture::new(false);
    // Model this database as the destination, with only the recipient hosted here.
    execute("DELETE FROM hosted_principals; DELETE FROM users;");
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO users(user_id, username, public_key, created_at) VALUES(2, 'recipient', 'test', 1)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id, principal_handle) VALUES(2, ?1)", [fixture.handles[1].0])?;
        Ok(())
    }).unwrap();
    let service = fixture.destination_service();
    let legitimate = IngressSource::DirectPeer {
        node_id: fixture.node.node_id().clone(),
    };
    let unrelated = IngressSource::DirectPeer {
        node_id: fixture.destination.node_id().clone(),
    };
    accepted(
        service
            .accept_relay(
                legitimate.clone(),
                fixture.frame(0, "peer-secret", secret(&fixture)),
            )
            .await
            .unwrap(),
    );
    let frame = fixture.frame(0, "peer-replay", send(10));
    accepted(
        service
            .accept_relay(legitimate.clone(), frame.clone())
            .await
            .unwrap(),
    );
    let accepted_at = count("SELECT accepted_at FROM relay_inbox WHERE message_id = 'peer-replay'");
    let rotated = Keyring::generate();
    let now = iota_storage::util::sync::now_millis();
    let descriptor = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: fixture.ids[0].clone(),
            authority_kind: iota_identity::AuthorityKind::Iota,
            username: Some("user0".into()),
            display_name: None,
            public_keys: vec![rotated.public_key_bundle()],
            home: PrincipalHome::Iota(fixture.node.node_id().clone()),
            revision: 2,
            valid_until: Some(now + 600_000),
            issued_at: now,
        },
        &fixture.node.keyring(),
    )
    .unwrap()
    .verify(
        fixture.node.authority_id(),
        &fixture.node.public_keys(),
        None,
        now,
    )
    .unwrap();
    SqlitePrincipalStore
        .upsert_remote_descriptor(&descriptor)
        .unwrap();
    assert_eq!(
        SqlitePrincipalStore
            .signing_keys(&fixture.ids[0])
            .unwrap()
            .iter()
            .map(|keys| keys.try_to_base64().unwrap())
            .collect::<Vec<_>>(),
        vec![rotated.public_key_bundle().try_to_base64().unwrap()]
    );
    assert!(matches!(
        service.accept_relay(unrelated.clone(), frame.clone()).await,
        Err(RelayServiceError::Rejected(_))
    ));
    let proof = service
        .prepare_relay(&legitimate, frame.clone())
        .await
        .unwrap();
    assert!(matches!(
        service.accept_verified_relay(unrelated, proof).await,
        Err(RelayServiceError::Rejected(_))
    ));
    let RelayOutcome::Accepted {
        ingress_response,
        local_deliveries,
    } = service
        .accept_relay(legitimate, frame.with_id(88))
        .await
        .unwrap()
    else {
        panic!("legitimate exact replay must survive signing key rotation");
    };
    assert_eq!(ingress_response.id(), Some(88));
    assert_eq!(
        ingress_response
            .get_data(DataType::Status)
            .and_then(DataValue::as_str),
        Some("already_accepted")
    );
    assert_eq!(
        ingress_response
            .get_data(DataType::RelayAcceptedAt)
            .and_then(DataValue::as_number),
        Some(accepted_at as i128)
    );
    assert!(local_deliveries.is_empty());
    assert_eq!(
        count("SELECT count(*) FROM messages WHERE relay_message_id = 'peer-replay'"),
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'peer-replay'"),
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM relay_inbox WHERE message_id = 'peer-replay'"),
        1
    );
}
