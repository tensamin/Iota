#[allow(
    dead_code,
    reason = "shared fixtures also support the transaction test binary"
)]
mod relay_support;
use iota_connection::relay_service::{RelayOutcome, RelayService};
use iota_storage::{identity::SqliteLocalUserStore, util::relay_work};
use relay_support::*;
use std::sync::Arc;

#[tokio::test]
async fn accepted_work_survives_process_restart() {
    if let Ok(phase) = std::env::var("RELAY_RECOVERY_PHASE") {
        initialize(std::path::Path::new(
            &std::env::var("RELAY_TEST_STORAGE").unwrap(),
        ));
        match phase.as_str() {
            "seed_applied" => {
                let f = Fixture::new(true);
                accepted(f.accept(0, "secret", secret(&f)).await);
                accepted(f.accept(0, "restart", send(10)).await);
                // Model a historical commit with application complete but queue publication missing.
                execute(
                    "DELETE FROM pending_relays WHERE relay_message_id = 'restart'; UPDATE relay_inbox SET state = 'applied', queued_at = NULL WHERE message_id = 'restart'; UPDATE messages SET content = 'must not be replayed' WHERE relay_message_id = 'restart';",
                );
            }
            "recover_applied" => {
                let service =
                    RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true)));
                assert_eq!(service.recover_incomplete(10).unwrap().completed, 1);
                assert_eq!(
                    count(
                        "SELECT count(*) FROM messages WHERE relay_message_id = 'restart' AND content = 'must not be replayed'"
                    ),
                    2
                );
                assert_eq!(
                    count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'restart'"),
                    1
                );
                assert_eq!(
                    count(
                        "SELECT count(*) FROM relay_inbox WHERE message_id = 'restart' AND state = 'queued'"
                    ),
                    1
                );
                assert_eq!(service.recover_incomplete(10).unwrap().completed, 0);
            }
            "received" => {
                execute(
                    "UPDATE relay_inbox SET state = 'received', processing_owner = NULL, processing_deadline = NULL WHERE message_id = 'restart';",
                );
            }
            "seed" => {
                let f = Fixture::new(true);
                accepted(f.accept(0, "secret", secret(&f)).await);
                // Abort after the first local copy has been written in the same transaction.
                execute(
                    "CREATE TRIGGER crash_before_commit BEFORE INSERT ON messages WHEN NEW.storage_owner = 2 BEGIN SELECT RAISE(ABORT, 'restart injection'); END;",
                );
                assert!(matches!(
                    f.accept(0, "restart", send(10)).await,
                    RelayOutcome::RetryLater { .. }
                ));
                assert_eq!(count("SELECT count(*) FROM messages"), 0);
                assert_eq!(
                    count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'restart'"),
                    0
                );
                assert_eq!(
                    count(
                        "SELECT count(*) FROM relay_inbox WHERE message_id = 'restart' AND state = 'processing' AND prepared_operation IS NOT NULL AND applied_at IS NULL"
                    ),
                    1
                );
                execute(
                    "DROP TRIGGER crash_before_commit; UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'restart';",
                );
            }
            "erase" => {
                // Remove the actual account and ownership binding before a fresh process recovers.
                execute(
                    "DELETE FROM hosted_principals WHERE local_user_id = 2; DELETE FROM users WHERE user_id = 2;",
                );
            }
            "recover" | "recover_erased" => {
                let service =
                    RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true)));
                let work = relay_work::incomplete(10).unwrap();
                assert_eq!(work.len(), 1);
                let generation = work[0].generation;
                let erased = phase == "recover_erased";
                assert_eq!(
                    service.recover_incomplete(10).unwrap().completed,
                    usize::from(!erased)
                );
                assert!(!service.resume_relay(&work[0]).unwrap());
                assert_eq!(service.recover_incomplete(10).unwrap().completed, 0);
                assert_eq!(
                    count("SELECT count(*) FROM messages"),
                    if erased { 0 } else { 2 }
                );
                assert_eq!(
                    count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'restart'"),
                    i64::from(!erased)
                );
                let state = if erased { "rejected" } else { "queued" };
                assert_eq!(
                    count(&format!(
                        "SELECT count(*) FROM relay_inbox WHERE message_id = 'restart' AND state = '{state}' AND processing_generation = {} AND processing_owner IS NULL",
                        generation + 1
                    )),
                    1
                );
                if erased {
                    assert_eq!(
                        count("SELECT count(*) FROM messages WHERE storage_owner = 2"),
                        0
                    );
                }
            }
            "verify" => {
                let service =
                    RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true)));
                assert_eq!(service.recover_incomplete(10).unwrap().completed, 0);
                assert_eq!(
                    count("SELECT count(*) FROM messages WHERE relay_message_id = 'restart'"),
                    2
                );
                assert_eq!(
                    count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'restart'"),
                    1
                );
            }
            _ => panic!("unknown phase"),
        }
        return;
    }
    for scenario in ["processing", "received", "erased", "applied"] {
        let path =
            std::env::temp_dir().join(format!("relay-recovery-{}-{scenario}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let phases = match scenario {
            "erased" => vec!["seed", "erase", "recover_erased"],
            "received" => vec!["seed", "received", "recover", "verify"],
            "applied" => vec!["seed_applied", "recover_applied", "verify"],
            _ => vec!["seed", "recover", "verify"],
        };
        for phase in phases {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "accepted_work_survives_process_restart",
                    "--nocapture",
                ])
                .env("RELAY_RECOVERY_PHASE", phase)
                .env("RELAY_TEST_STORAGE", &path)
                .status()
                .unwrap();
            assert!(status.success(), "{phase} failed");
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
