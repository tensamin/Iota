#![cfg(feature = "relay-fault-injection")]

#[allow(
    dead_code,
    reason = "fixtures shared with other relay integration binaries"
)]
mod relay_support;

use iota_connection::relay_service::{PendingRelayDispatcher, RelayService};
use iota_storage::{
    identity::SqliteLocalUserStore,
    storage_error::StorageError,
    util::{
        client_relay_delivery::{self, ClientRelayDeliveryResult},
        downstream_relay, relay_queue, relay_work,
    },
};
use relay_support::*;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

fn storage(scenario: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("relay-crash-{scenario}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).unwrap();
    path
}

fn child(test: &str, phase: &str, path: &Path, boundary: &str, crash: bool) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .env("RELAY_CRASH_PHASE", phase)
        .env("RELAY_TEST_STORAGE", path)
        .env("RELAY_CRASH_BOUNDARY", boundary)
        .env_remove("IOTA_RELAY_FAULT_POINT")
        .env_remove("IOTA_RELAY_FAULT_MESSAGE_ID");
    if crash {
        command
            .env("IOTA_RELAY_FAULT_POINT", boundary)
            .env("IOTA_RELAY_FAULT_MESSAGE_ID", "fault");
    }
    let status = command.status().unwrap();
    assert_eq!(
        status.code(),
        Some(if crash { 86 } else { 0 }),
        "{boundary}/{phase}: {status}"
    );
}

fn phase() -> Option<String> {
    let phase = std::env::var("RELAY_CRASH_PHASE").ok()?;
    initialize(Path::new(&std::env::var("RELAY_TEST_STORAGE").unwrap()));
    Some(phase)
}

fn service() -> RelayService {
    RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true)))
}

fn target_counts(messages: i64, queue: i64, state: &str) {
    assert_eq!(
        count("SELECT count(*) FROM messages WHERE relay_message_id = 'fault'"),
        messages
    );
    assert_eq!(
        count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'fault'"),
        queue
    );
    assert_eq!(
        count(&format!(
            "SELECT count(*) FROM relay_inbox WHERE message_id = 'fault' AND state = '{state}'"
        )),
        1
    );
}

#[tokio::test]
async fn ingress_crash_boundaries() {
    if let Some(phase) = phase() {
        let boundary = std::env::var("RELAY_CRASH_BOUNDARY").unwrap();
        match phase.as_str() {
            "apply" => {
                let fixture = Fixture::new(true);
                accepted(fixture.accept(0, "setup-secret", secret(&fixture)).await);
                accepted(fixture.accept(0, "fault", send(10)).await);
                panic!("fault hook did not terminate process");
            }
            "recover" => {
                let service = service();
                match boundary.as_str() {
                    "after_preparation" | "after_inbox_reservation" => {
                        assert_eq!(
                            count("SELECT count(*) FROM relay_inbox WHERE message_id = 'fault'"),
                            0
                        );
                        assert_eq!(
                            count("SELECT count(*) FROM messages WHERE relay_message_id = 'fault'"),
                            0
                        );
                        assert_eq!(
                            count(
                                "SELECT count(*) FROM pending_relays WHERE relay_message_id = 'fault'"
                            ),
                            0
                        );
                        assert_eq!(service.recover_incomplete(10).unwrap().completed, 0);
                    }
                    "after_application_commit" => {
                        target_counts(2, 1, "queued");
                        assert_eq!(service.recover_incomplete(10).unwrap().completed, 0);
                    }
                    _ => {
                        target_counts(0, 0, "processing");
                        assert_eq!(
                            count(
                                "SELECT count(*) FROM relay_inbox WHERE message_id = 'fault' AND prepared_operation IS NOT NULL AND applied_at IS NULL"
                            ),
                            1
                        );
                        execute(
                            "UPDATE relay_inbox SET processing_deadline = 0 WHERE message_id = 'fault';",
                        );
                        let old = relay_work::incomplete(10).unwrap().remove(0);
                        assert_eq!(service.recover_incomplete(10).unwrap().completed, 1);
                        assert!(!service.resume_relay(&old).unwrap());
                        assert_eq!(
                            count(&format!(
                                "SELECT count(*) FROM relay_inbox WHERE message_id = 'fault' AND processing_generation = {} AND processing_owner IS NULL",
                                old.generation + 1
                            )),
                            1
                        );
                        target_counts(2, 1, "queued");
                        assert_eq!(service.recover_incomplete(10).unwrap().completed, 0);
                    }
                }
            }
            "verify" => {
                assert_eq!(service().recover_incomplete(10).unwrap().completed, 0);
                if !matches!(
                    boundary.as_str(),
                    "after_preparation" | "after_inbox_reservation"
                ) {
                    target_counts(2, 1, "queued");
                    assert_eq!(
                        count(
                            "SELECT count(DISTINCT storage_owner) FROM messages WHERE relay_message_id = 'fault'"
                        ),
                        2
                    );
                }
            }
            _ => panic!("unknown phase"),
        }
        return;
    }
    for boundary in [
        "after_preparation",
        "after_inbox_reservation",
        "after_claim_acquisition",
        "after_local_mutation",
        "after_queue_publication",
        "after_application_completion",
        "after_application_commit",
    ] {
        let path = storage(boundary);
        child("ingress_crash_boundaries", "apply", &path, boundary, true);
        child(
            "ingress_crash_boundaries",
            "recover",
            &path,
            boundary,
            false,
        );
        child("ingress_crash_boundaries", "verify", &path, boundary, false);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn deferred_acknowledgement_crash_boundaries() {
    if let Some(phase) = phase() {
        match phase.as_str() {
            "seed" => {
                let fixture = Fixture::new(false);
                accepted(fixture.accept(0, "fault", secret(&fixture)).await);
                target_counts(0, 1, "queued");
                assert_eq!(count("SELECT count(*) FROM chat_secrets"), 0);
            }
            "dispatch" => {
                PendingRelayDispatcher::new(Arc::new(Router(true)))
                    .dispatch_ready(10)
                    .await
                    .unwrap();
                panic!("fault hook did not terminate process");
            }
            "recover" => {
                target_counts(0, 1, "queued");
                assert_eq!(count("SELECT count(*) FROM chat_secrets"), 0);
                assert_eq!(
                    count(
                        "SELECT count(*) FROM relay_deferred_secrets WHERE message_id = 'fault' AND completed_at IS NULL"
                    ),
                    1
                );
                let pending = relay_queue::list(10).unwrap().remove(0);
                assert_eq!(
                    PendingRelayDispatcher::new(Arc::new(Router(true)))
                        .dispatch_ready(10)
                        .await
                        .unwrap(),
                    0
                );
                // A restart does not bypass another process's still-current dispatch lease.
                execute(
                    "UPDATE pending_relays SET dispatch_deadline = 0 WHERE relay_message_id = 'fault';",
                );
                assert_eq!(
                    PendingRelayDispatcher::new(Arc::new(Router(true)))
                        .dispatch_ready(10)
                        .await
                        .unwrap(),
                    1
                );
                target_counts(0, 0, "delivered");
                assert!(
                    !downstream_relay::acknowledge_pending_delivery(&pending, "fault", 1234)
                        .unwrap()
                );
                assert_eq!(
                    count(
                        "SELECT count(*) FROM chat_secrets WHERE user_id = '1' AND encrypted_secret = X'01'"
                    ),
                    1
                );
                assert_eq!(
                    count("SELECT count(*) FROM chat_secrets WHERE version = 1"),
                    1
                );
                assert_eq!(
                    count(
                        "SELECT count(*) FROM relay_deferred_secrets WHERE message_id = 'fault' AND completed_at IS NOT NULL"
                    ),
                    1
                );
            }
            "verify" => {
                target_counts(0, 0, "delivered");
                assert_eq!(count("SELECT count(*) FROM chat_secrets"), 1);
                assert_eq!(
                    count("SELECT count(*) FROM chat_secrets WHERE version = 1"),
                    1
                );
                assert_eq!(
                    PendingRelayDispatcher::new(Arc::new(Router(true)))
                        .dispatch_ready(10)
                        .await
                        .unwrap(),
                    0
                );
            }
            _ => panic!("unknown phase"),
        }
        return;
    }
    for boundary in [
        "after_outbound_send",
        "before_destination_acknowledgement",
        "after_deferred_secret_application",
        "after_terminal_completion",
    ] {
        let path = storage(boundary);
        child(
            "deferred_acknowledgement_crash_boundaries",
            "seed",
            &path,
            boundary,
            false,
        );
        child(
            "deferred_acknowledgement_crash_boundaries",
            "dispatch",
            &path,
            boundary,
            true,
        );
        child(
            "deferred_acknowledgement_crash_boundaries",
            "recover",
            &path,
            boundary,
            false,
        );
        child(
            "deferred_acknowledgement_crash_boundaries",
            "verify",
            &path,
            boundary,
            false,
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn exact_local_pending_acknowledgement() {
    if phase().is_some() {
        let fixture = Fixture::new(true);
        accepted(fixture.accept(0, "setup-secret", secret(&fixture)).await);
        accepted(fixture.accept(0, "collision", send(10)).await);
        accepted(fixture.accept(1, "collision", send(20)).await);
        let pending: Vec<_> = relay_queue::list(10)
            .unwrap()
            .into_iter()
            .filter(|p| p.relay_message_id.as_deref() == Some("collision"))
            .collect();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].frame_id, pending[1].frame_id);
        assert_ne!(pending[0].signer_principal, pending[1].signer_principal);
        assert_ne!(
            pending[0].destination_principal,
            pending[1].destination_principal
        );
        for altered in 0..5 {
            let mut mismatch = pending[0].clone();
            match altered {
                0 => mismatch.signer_principal = pending[1].signer_principal,
                1 => mismatch.destination_principal = pending[1].destination_principal,
                2 => mismatch.frame.push(0),
                3 => mismatch.target = pending[1].target.clone(),
                _ => mismatch.relay_message_id = Some("other".into()),
            }
            assert!(matches!(
                client_relay_delivery::acknowledge_pending_client_delivery(&mismatch),
                Err(StorageError::PendingRelayConflict)
            ));
        }
        assert_eq!(
            count(
                "SELECT count(*) FROM relay_inbox WHERE message_id = 'collision' AND state = 'queued'"
            ),
            2
        );
        assert_eq!(
            client_relay_delivery::acknowledge_pending_client_delivery(&pending[0]).unwrap(),
            ClientRelayDeliveryResult::Acknowledged
        );
        assert_eq!(
            client_relay_delivery::acknowledge_pending_client_delivery(&pending[0]).unwrap(),
            ClientRelayDeliveryResult::NotFound
        );
        assert_eq!(
            count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'collision'"),
            1
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM relay_inbox WHERE message_id = 'collision' AND state = 'delivered'"
            ),
            1
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM relay_inbox WHERE message_id = 'collision' AND state = 'queued'"
            ),
            1
        );
        assert_eq!(
            client_relay_delivery::acknowledge_pending_client_delivery(&pending[1]).unwrap(),
            ClientRelayDeliveryResult::Acknowledged
        );
        assert_eq!(
            client_relay_delivery::acknowledge_pending_client_delivery(&pending[0]).unwrap(),
            ClientRelayDeliveryResult::NotFound
        );
        assert_eq!(
            client_relay_delivery::acknowledge_pending_client_delivery(&pending[1]).unwrap(),
            ClientRelayDeliveryResult::NotFound
        );
        assert_eq!(
            count("SELECT count(*) FROM pending_relays WHERE relay_message_id = 'collision'"),
            0
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM relay_inbox WHERE message_id = 'collision' AND state = 'delivered'"
            ),
            2
        );
        return;
    }
    let path = storage("exact-ack");
    child(
        "exact_local_pending_acknowledgement",
        "run",
        &path,
        "",
        false,
    );
    std::fs::remove_dir_all(path).unwrap();
}
