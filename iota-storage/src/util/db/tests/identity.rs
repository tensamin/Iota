use super::*;

#[test]
fn client_acknowledgement_uses_canonical_identity_and_rejects_ambiguity() -> Result<(), StorageError>
{
    use crate::util::{chat_files, client_relay_delivery, relay_queue, relay_replay};
    use iota_identity::PrincipalHandle;
    use rusqlite::params;

    let mut conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute_batch(
            "INSERT INTO principals (principal_pk, authority_kind, authority_id, remote_user_id, last_resolved_at)
                VALUES (70, 'omega', 'omega:test', 7, 0), (71, 'omega', 'omega:test', 8, 0), (72, 'omega', 'omega:test', 9, 0);",
        )?;
    conn.execute("INSERT INTO user_message_storage_policy (user_id, history_mode, retention_mode, revision, updated_at) VALUES (8, 'delete_after_client_delivery', 'forever', 1, 20)", [])?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for (signer, signer_id, message_id) in [(70, 7, "first"), (72, 9, "second")] {
        let frame = message_id.as_bytes();
        let relay_replay::AcquireResult::Claimed(claim) = relay_replay::acquire_in_tx(
            &tx,
            relay_replay::RelayReservationRequest {
                signer_principal: PrincipalHandle(signer),
                signer_id,
                message_id,
                created_at: 10,
                accepted_at: 20,
                destination_id: 8,
                frame,
                frame_id: 42,
                type_map_version: "1.0",
            },
            100,
        )?
        else {
            panic!("missing claim")
        };
        relay_replay::complete_application_in_tx(&tx, &claim)?;
        relay_replay::mark_queued_in_tx(&tx, claim.signer, message_id)?;
        chat_files::add_message_in_tx(
            &tx,
            chat_files::NewMessage {
                relay_signer_id: signer_id as i64,
                relay_signer_principal: claim.signer,
                relay_message_id: message_id,
                authored_at: 10,
                send_time: 10,
                storage_owner: 8,
                external_user: signer_id as i64,
                external_principal: claim.signer,
                sent_by_self: false,
                content: "ciphertext",
                height: 0,
                key_version: 1,
                reply_to: None,
                origin_iota_received_at: None,
                destination_iota_received_at: Some(20),
                initial_state: chat_files::MessageState::Sent,
            },
        )?;
    }
    let identity = relay_queue::RelayIdentity {
        signer: PrincipalHandle(70),
        recipient: PrincipalHandle(71),
        message_id: "first".into(),
        legacy_signer_id: Some(7),
        legacy_recipient_id: Some(8),
    };
    relay_queue::enqueue_in_tx(
        &tx,
        relay_queue::RelayTarget::User(8),
        &identity,
        b"first",
        20,
        42,
        "1.0",
    )?;
    assert_eq!(
        client_relay_delivery::acknowledge_client_delivery_in_tx(&tx, 8, 42)?,
        client_relay_delivery::ClientRelayDeliveryResult::Acknowledged
    );
    let states: Vec<(String, String)> = tx
        .prepare("SELECT message_id, state FROM relay_inbox ORDER BY message_id")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(
        states,
        vec![
            ("first".into(), "delivered".into()),
            ("second".into(), "queued".into())
        ]
    );
    let history: Vec<(String, i64)> = tx
        .prepare(
            "SELECT relay_message_id, history_deleted FROM messages ORDER BY relay_message_id",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(history, vec![("first".into(), 1), ("second".into(), 0)]);
    assert_eq!(
        tx.query_row("SELECT count(*) FROM pending_relays", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        client_relay_delivery::acknowledge_client_delivery_in_tx(&tx, 8, 42)?,
        client_relay_delivery::ClientRelayDeliveryResult::NotFound
    );
    tx.commit()?;

    let tx = conn.transaction()?;
    for (frame, message_id) in [(b"a".as_slice(), "a"), (b"b".as_slice(), "b")] {
        let identity = relay_queue::RelayIdentity {
            message_id: message_id.into(),
            ..identity.clone()
        };
        relay_queue::enqueue_in_tx(
            &tx,
            relay_queue::RelayTarget::User(8),
            &identity,
            frame,
            20,
            42,
            "1.0",
        )?;
    }
    assert!(matches!(
        client_relay_delivery::acknowledge_client_delivery_in_tx(&tx, 8, 42),
        Err(StorageError::AmbiguousRelayDelivery)
    ));
    assert_eq!(
        tx.query_row("SELECT count(*) FROM pending_relays", [], |row| row
            .get::<_, i64>(0))?,
        2
    );
    tx.rollback()?;

    let tx = conn.transaction()?;
    let identity = relay_queue::RelayIdentity {
        message_id: "missing".into(),
        ..identity
    };
    relay_queue::enqueue_in_tx(
        &tx,
        relay_queue::RelayTarget::User(8),
        &identity,
        b"missing",
        20,
        42,
        "1.0",
    )?;
    assert!(matches!(
        client_relay_delivery::acknowledge_client_delivery_in_tx(&tx, 8, 42),
        Err(StorageError::InvalidRelayTransition)
    ));
    assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM pending_relays WHERE relay_message_id = ?1",
            params!["missing"],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    Ok(())
}

#[test]
fn replay_schema_scopes_equal_numeric_signers_by_principal() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('omega', 'omega:first', 7, 0, 0)",
            [],
        )?;
    let first = conn.last_insert_rowid();
    conn.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('omega', 'omega:second', 7, 0, 0)",
            [],
        )?;
    let second = conn.last_insert_rowid();

    let first_insert = conn.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_principal, signer_id, message_id, created_at) VALUES (?1, 7, 'same-message', 1)",
            [first],
        )?;
    let second_insert = conn.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_principal, signer_id, message_id, created_at) VALUES (?1, 7, 'same-message', 1)",
            [second],
        )?;

    assert_eq!((first_insert, second_insert), (1, 1));
    Ok(())
}

#[test]
fn principal_identity_is_scoped_by_authority() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, last_resolved_at) VALUES ('omega', 'omega:first', 7, 1)",
            [],
        )?;
    conn.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, last_resolved_at) VALUES ('omega', 'omega:second', 7, 1)",
            [],
        )?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM principals WHERE remote_user_id = 7",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    Ok(())
}

#[test]
fn local_identity_allocator_starts_at_one() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    let next: i64 = conn.query_row(
        "SELECT next_user_id FROM local_identity_allocator WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(next, 1);
    Ok(())
}

#[test]
fn equal_numeric_users_remain_separate_in_application_storage() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('iota', 'iota:first', 7, 0, 0)",
            [],
        )?;
    let first = conn.last_insert_rowid();
    conn.execute(
            "INSERT INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('iota', 'iota:second', 7, 0, 0)",
            [],
        )?;
    let second = conn.last_insert_rowid();

    conn.execute(
            "INSERT INTO contacts (storage_owner, user_id, principal_handle, created_at, notifications) VALUES (1, 7, ?1, 1, 2)",
            [first],
        )?;
    conn.execute(
            "INSERT INTO contacts (storage_owner, user_id, principal_handle, created_at, notifications) VALUES (1, 7, ?1, 1, 3)",
            [second],
        )?;
    conn.execute(
        "UPDATE contacts SET notifications = 0 WHERE storage_owner = 1 AND principal_handle = ?1",
        [first],
    )?;
    let notifications: Vec<i64> = conn
        .prepare(
            "SELECT notifications FROM contacts WHERE storage_owner = 1 ORDER BY principal_handle",
        )?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(notifications, vec![0, 3]);

    conn.execute(
            "INSERT INTO blocked_users (user_id, blocked_user_id, blocked_principal, revision, created_at) VALUES (1, 7, ?1, 0, 1)",
            [first],
        )?;
    conn.execute(
            "INSERT INTO blocked_users (user_id, blocked_user_id, blocked_principal, revision, created_at) VALUES (1, 7, ?1, 0, 1)",
            [second],
        )?;

    conn.execute(
            "INSERT INTO messages (storage_owner, external_user, external_principal, relay_signer_id, relay_signer_principal, relay_message_id, message_time, content, sent_by_self, message_state) VALUES (1, 7, ?1, 7, ?1, 'first-message', 1, 'one', 0, 'sent')",
            [first],
        )?;
    let message = conn.last_insert_rowid();
    conn.execute(
            "INSERT INTO reactions (message_id, user_id, user_principal, reaction, created_at) VALUES (?1, 7, ?2, 'same', 1)",
            rusqlite::params![message, first],
        )?;
    conn.execute(
            "INSERT INTO reactions (message_id, user_id, user_principal, reaction, created_at) VALUES (?1, 7, ?2, 'same', 1)",
            rusqlite::params![message, second],
        )?;

    for (principal, target_message) in [(first, "first-message"), (second, "second-message")] {
        conn.execute(
                "INSERT INTO message_receipts (storage_owner, target_signer_id, target_signer_principal, target_message_id, receipt_signer_id, receipt_signer_principal, receipt_message_id, receipt_type, event_at, recorded_at) VALUES (1, 1, 1, ?1, 7, ?2, 'same-receipt', 'read', 1, 1)",
                rusqlite::params![target_message, principal],
            )?;
    }

    let counts = (
        conn.query_row("SELECT COUNT(*) FROM contacts", [], |row| {
            row.get::<_, i64>(0)
        })?,
        conn.query_row("SELECT COUNT(*) FROM blocked_users", [], |row| {
            row.get::<_, i64>(0)
        })?,
        conn.query_row("SELECT COUNT(*) FROM reactions", [], |row| {
            row.get::<_, i64>(0)
        })?,
        conn.query_row("SELECT COUNT(*) FROM message_receipts", [], |row| {
            row.get::<_, i64>(0)
        })?,
    );
    assert_eq!(counts, (2, 2, 2, 2));
    Ok(())
}

#[test]
fn observed_remote_references_receive_authority_scoped_principals() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute(
            "INSERT INTO identity_configuration (singleton, omega_authority_id) VALUES (1, 'omega:omega-a.example')",
            [],
        )?;
    conn.execute(
        "INSERT INTO contacts (storage_owner, user_id, created_at) VALUES (1, 7, 1)",
        [],
    )?;
    conn.execute(
            "INSERT INTO messages (storage_owner, external_user, message_time, content, sent_by_self, message_state) VALUES (1, 7, 1, 'message', 0, 'received')",
            [],
        )?;
    let (contact_principal, message_principal, authority): (i64, i64, String) =
            conn.query_row(
                "SELECT c.principal_handle, m.external_principal, p.authority_id FROM contacts c JOIN messages m ON m.external_user = c.user_id JOIN principals p ON p.principal_pk = c.principal_handle",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
    assert_eq!(contact_principal, message_principal);
    assert_eq!(authority, "omega:omega-a.example");
    Ok(())
}
