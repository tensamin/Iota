use iota_identity::{IotaNodeId, PrincipalHandle};
use iota_storage::util::relay_queue::{
    self, PendingRelayDeliveryState, RelayIdentity, RelayTarget,
};
use mtp::crypto::Keyring;

#[test]
fn pending_iota_relay_uses_bounded_backoff_and_quarantine() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    iota_storage::util::db::initialize_database().unwrap();
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
    let node = IotaNodeId::from_public_keys(&Keyring::generate().public_key_bundle()).unwrap();
    relay_queue::enqueue(
        RelayTarget::Iota(node),
        &RelayIdentity {
            signer: PrincipalHandle(signer),
            recipient: PrincipalHandle(recipient),
            message_id: "retry".into(),
            legacy_signer_id: Some(1),
            legacy_recipient_id: Some(1),
        },
        &[1, 2, 3],
        1,
        7,
        "1.0",
    )
    .unwrap();
    let id = relay_queue::list(1).unwrap()[0].id;
    let now = iota_storage::util::sync::now_millis();

    for attempt in 0..8 {
        relay_queue::record_retry(id, now, "offline").unwrap();
        let relay = relay_queue::list(1).unwrap().remove(0);
        let exponent = attempt.min(6);
        let expected_delay = (5_000_i64 * (1_i64 << exponent)).min(300_000);
        assert_eq!(relay.attempt_count, attempt + 1);
        assert_eq!(relay.last_attempt_at, Some(now));
        assert_eq!(relay.next_attempt_at, now + expected_delay);
        assert_eq!(relay.last_error.as_deref(), Some("offline"));
    }
    assert!(relay_queue::list_active(1).unwrap().is_empty());

    relay_queue::quarantine_for_frame(7, "wrong acknowledgement").unwrap();
    let relay = relay_queue::list(1).unwrap().remove(0);
    assert_eq!(relay.delivery_state, PendingRelayDeliveryState::Quarantined);
    assert_eq!(relay.last_error.as_deref(), Some("wrong acknowledgement"));
}
