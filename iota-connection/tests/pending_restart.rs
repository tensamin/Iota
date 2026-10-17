use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::relay_service::PendingRelayDispatcher;
use iota_storage::util::relay_queue;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::path::Path;
use std::process::Command;

#[allow(dead_code, reason = "fixtures are shared with other relay tests")]
mod relay_support;

struct AcceptingRouter;

struct StalledRouter;

#[async_trait]
impl PeerRouter for StalledRouter {
    async fn route(
        &self,
        _: &RouteDestination,
        _: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        std::future::pending().await
    }
}

#[async_trait]
impl PeerRouter for AcceptingRouter {
    async fn route(
        &self,
        destination: &RouteDestination,
        _: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        assert!(matches!(destination, RouteDestination::Iota(_)));
        Ok(RouteOutcome::Accepted {
            relay_message_id: "restart-relay".into(),
            destination_accepted_at: 10,
        })
    }
}

fn initialize(storage: &Path) {
    iota_util::file_util::configure_storage_directory(storage.to_owned());
    iota_storage::util::db::initialize_database().unwrap();
}

async fn seed(storage: &Path) {
    initialize(storage);
    let fixture = relay_support::Fixture::new(false);
    relay_support::accepted(
        fixture
            .accept(
                0,
                "restart-relay",
                CommunicationValue::new(CommunicationType::AddConversation)
                    .add_typed_default(DataType::ChatPartnerId, DataValue::SignedNumber(2)),
            )
            .await,
    );
    assert_eq!(relay_queue::list_active(10).unwrap().len(), 1);
    let abandoned = relay_queue::claim_ready(1, 30_000).unwrap().pop().unwrap();
    assert_eq!(abandoned.claim.generation, 1);
    iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "UPDATE pending_relays SET dispatch_deadline = 0 WHERE id = ?1",
            [abandoned.pending.id],
        )?;
        Ok(())
    })
    .unwrap();
}

async fn deliver(storage: &Path) {
    initialize(storage);
    let dispatcher = PendingRelayDispatcher::new(std::sync::Arc::new(AcceptingRouter));
    assert_eq!(dispatcher.dispatch_ready(10).await.unwrap(), 1);
    assert_eq!(dispatcher.dispatch_ready(10).await.unwrap(), 0);
    assert!(relay_queue::list(10).unwrap().is_empty());
    let state = iota_storage::util::db::with_db(|connection| {
        Ok(connection.query_row(
            "SELECT state FROM relay_inbox WHERE message_id = 'restart-relay'",
            [],
            |row| row.get::<_, String>(0),
        )?)
    })
    .unwrap();
    assert_eq!(state, "delivered");
}

#[tokio::test]
async fn pending_relay_survives_process_restart_and_delivers_once() {
    let storage =
        std::env::var_os("TENSAMIN_PENDING_RESTART_STORAGE").map(std::path::PathBuf::from);
    match std::env::var("TENSAMIN_PENDING_RESTART_PHASE").as_deref() {
        Ok("seed") => {
            seed(storage.as_deref().unwrap()).await;
            return;
        }
        Ok("deliver") => {
            deliver(storage.as_deref().unwrap()).await;
            return;
        }
        Ok("timeout") => {
            initialize(storage.as_deref().unwrap());
            let dispatcher = PendingRelayDispatcher::new(std::sync::Arc::new(StalledRouter));
            assert_eq!(dispatcher.dispatch_ready(10).await.unwrap(), 0);
            iota_storage::util::db::with_db(|connection| {
                let retry: (i64, Option<String>, i64) = connection.query_row(
                    "SELECT attempt_count,dispatch_owner,next_attempt_at FROM pending_relays",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                assert_eq!(retry.0, 1);
                assert!(retry.1.is_none());
                assert!(retry.2 > iota_storage::util::sync::now_millis());
                connection.execute("UPDATE pending_relays SET next_attempt_at = 0", [])?;
                Ok(())
            })
            .unwrap();
            return;
        }
        _ => {}
    }

    let storage = std::env::temp_dir().join(format!(
        "tensamin-pending-restart-{}-{}",
        std::process::id(),
        iota_storage::util::sync::now_millis()
    ));
    std::fs::create_dir(&storage).unwrap();
    let executable = std::env::current_exe().unwrap();
    for phase in ["seed", "timeout", "deliver"] {
        let status = Command::new(&executable)
            .args([
                "--exact",
                "pending_relay_survives_process_restart_and_delivers_once",
                "--nocapture",
            ])
            .env("TENSAMIN_PENDING_RESTART_PHASE", phase)
            .env("TENSAMIN_PENDING_RESTART_STORAGE", &storage)
            .env("IOTA_DISPATCH_TIMEOUT_MS", "10")
            .status()
            .unwrap();
        assert!(status.success(), "{phase} child process failed");
    }
    std::fs::remove_dir_all(&storage).unwrap();
}
