use iota_identity::PrincipalHandle;
use iota_storage::util::chat_files::{self, MessageState, NewMessage};

#[test]
fn message_offset_counts_visible_newer_messages_in_one_chat() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    iota_storage::util::db::initialize_database().unwrap();

    iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('iota', 'iota:peer', 2, 1, 1)",
            [],
        )?;
        let principal = connection.last_insert_rowid();
        connection.execute(
            "INSERT INTO contacts (storage_owner, user_id, principal_handle, created_at) VALUES (1, 2, ?1, 1)",
            [principal],
        )?;
        connection.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('iota', 'iota:other', 3, 1, 1)",
            [],
        )?;
        let other_principal = connection.last_insert_rowid();
        connection.execute(
            "INSERT INTO contacts (storage_owner, user_id, principal_handle, created_at) VALUES (1, 3, ?1, 1)",
            [other_principal],
        )?;
        Ok(())
    })
    .unwrap();

    for (send_time, relay_message_id, external_user, external_principal) in [
        (10, "first", 2, 1),
        (20, "second", 2, 1),
        (30, "hidden", 2, 1),
        (40, "other-chat", 3, 2),
    ] {
        chat_files::add_message(NewMessage {
            relay_signer_id: external_user,
            relay_signer_principal: PrincipalHandle(external_principal),
            relay_message_id,
            authored_at: send_time,
            send_time,
            storage_owner: 1,
            external_user,
            external_principal: PrincipalHandle(external_principal),
            sent_by_self: false,
            content: relay_message_id,
            height: 0,
            key_version: 1,
            reply_to: None,
            origin_iota_received_at: None,
            destination_iota_received_at: Some(send_time),
            initial_state: MessageState::Sent,
        })
        .unwrap();
    }

    iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "UPDATE messages SET history_deleted = 1 WHERE relay_message_id = 'hidden'",
            [],
        )?;
        Ok(())
    })
    .unwrap();

    let newest = chat_files::get_message_with_offset(1, 2, 20)
        .unwrap()
        .unwrap();
    assert_eq!(newest.1, 0);

    let first = chat_files::get_message_with_offset(1, 2, 10)
        .unwrap()
        .unwrap();
    assert_eq!(first.1, 1);

    assert!(
        chat_files::get_message_with_offset(1, 3, 10)
            .unwrap()
            .is_none()
    );
}
