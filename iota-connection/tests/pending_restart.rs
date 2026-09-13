use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::relay_service::PendingRelayDispatcher;
use iota_identity::{IotaNodeId, PrincipalHandle};
use iota_storage::util::relay_queue::{self, RelayIdentity, RelayTarget};
use mtp::codec::{CommunicationType, CommunicationValue};
use mtp::crypto::Keyring;
use std::path::Path;
use std::process::Command;

struct AcceptingRouter;

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

fn seed(storage: &Path) {
    initialize(storage);
    let (signer, recipient) = iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('iota', 'iota:first', 1, 1, 1)",
            [],
        )?;
        let signer = connection.last_insert_rowid();
        connection.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('iota', 'iota:second', 1, 1, 1)",
            [],
        )?;
        Ok((signer, connection.last_insert_rowid()))
    })
    .unwrap();
    let frame = CommunicationValue::new(CommunicationType::Relay).with_id(7);
    let version = frame.type_map().unwrap().version.to_string();
    let bytes = frame.to_bytes().unwrap();
    relay_queue::enqueue(
        RelayTarget::Iota(
            IotaNodeId::from_public_keys(&Keyring::generate().public_key_bundle()).unwrap(),
        ),
        &RelayIdentity {
            signer: PrincipalHandle(signer),
            recipient: PrincipalHandle(recipient),
            message_id: "restart-relay".into(),
            legacy_signer_id: None,
            legacy_recipient_id: None,
        },
        &bytes,
        0,
        7,
        &version,
    )
    .unwrap();
    assert_eq!(relay_queue::list_active(10).unwrap().len(), 1);
}

async fn deliver(storage: &Path) {
    initialize(storage);
    let dispatcher = PendingRelayDispatcher::new(std::sync::Arc::new(AcceptingRouter));
    assert_eq!(dispatcher.dispatch_ready(10).await.unwrap(), 1);
    assert_eq!(dispatcher.dispatch_ready(10).await.unwrap(), 0);
    assert!(relay_queue::list(10).unwrap().is_empty());
}

#[tokio::test]
async fn pending_relay_survives_process_restart_and_delivers_once() {
    let storage =
        std::env::var_os("TENSAMIN_PENDING_RESTART_STORAGE").map(std::path::PathBuf::from);
    match std::env::var("TENSAMIN_PENDING_RESTART_PHASE").as_deref() {
        Ok("seed") => {
            seed(storage.as_deref().unwrap());
            return;
        }
        Ok("deliver") => {
            deliver(storage.as_deref().unwrap()).await;
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
    for phase in ["seed", "deliver"] {
        let status = Command::new(&executable)
            .args([
                "--exact",
                "pending_relay_survives_process_restart_and_delivers_once",
                "--nocapture",
            ])
            .env("TENSAMIN_PENDING_RESTART_PHASE", phase)
            .env("TENSAMIN_PENDING_RESTART_STORAGE", &storage)
            .status()
            .unwrap();
        assert!(status.success(), "{phase} child process failed");
    }
    std::fs::remove_dir_all(&storage).unwrap();
}
