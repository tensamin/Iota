use super::*;

#[test]
fn message_mutations_and_sync_events_use_the_callers_transaction() -> Result<(), StorageError> {
    use crate::util::{chat_files, chats_util};
    use iota_identity::PrincipalHandle;
    let mut conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute_batch(
            "INSERT INTO principals (principal_pk, authority_kind, authority_id, remote_user_id, last_resolved_at)
             VALUES (70, 'omega', 'omega:test', 7, 0), (71, 'omega', 'omega:test', 8, 0);",
        )?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for (owner, external, principal, sent_by_self) in [(7, 8, 71, true), (8, 7, 70, false)] {
        chat_files::add_message_in_tx(
            &tx,
            chat_files::NewMessage {
                relay_signer_id: 7,
                relay_signer_principal: PrincipalHandle(70),
                relay_message_id: "send",
                authored_at: 10,
                send_time: 10,
                storage_owner: owner,
                external_user: external,
                external_principal: PrincipalHandle(principal),
                sent_by_self,
                content: "original",
                height: 0,
                key_version: 1,
                reply_to: None,
                origin_iota_received_at: Some(20),
                destination_iota_received_at: Some(20),
                initial_state: chat_files::MessageState::Sent,
            },
        )?;
    }
    tx.commit()?;
    let baseline_events: i64 =
        conn.query_row("SELECT count(*) FROM sync_events", [], |row| row.get(0))?;
    conn.execute_batch(
        "CREATE TRIGGER interrupt_destination BEFORE UPDATE ON messages
             WHEN OLD.storage_owner = 8
             BEGIN SELECT RAISE(ABORT, 'injected destination failure'); END;",
    )?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    chat_files::edit_message_for_principal_in_tx(&tx, 7, 8, PrincipalHandle(71), 10, 7, "edited")?;
    assert!(
        chat_files::apply_remote_edit_for_principal_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            7,
            "edited"
        )
        .is_err()
    );
    tx.rollback()?;
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM messages WHERE content = 'original' AND edited_count = 0",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        2
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM message_edits", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM sync_events", [], |row| row
            .get::<_, i64>(0))?,
        baseline_events
    );
    conn.execute_batch("DROP TRIGGER interrupt_destination;")?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    chat_files::edit_message_for_principal_in_tx(&tx, 7, 8, PrincipalHandle(71), 10, 7, "edited")?;
    chat_files::apply_remote_edit_for_principal_in_tx(
        &tx,
        8,
        7,
        PrincipalHandle(70),
        10,
        7,
        "edited",
    )?;
    chat_files::add_reaction_for_principal_in_tx(
        &tx,
        7,
        8,
        PrincipalHandle(71),
        10,
        7,
        PrincipalHandle(70),
        "a",
    )?;
    chat_files::remove_reaction_for_principal_in_tx(
        &tx,
        7,
        8,
        PrincipalHandle(71),
        10,
        7,
        PrincipalHandle(70),
        "a",
    )?;
    chat_files::delete_edit_history_in_tx(&tx, 7, 8, 10)?;
    chats_util::add_conversation_in_tx(&tx, 7, 8, PrincipalHandle(71), Some("new name"))?;
    chat_files::apply_remote_delete_for_principal_in_tx(&tx, 8, 7, PrincipalHandle(70), 10, 7)?;
    chat_files::delete_message_for_principal_in_tx(&tx, 7, 8, PrincipalHandle(71), 10)?;
    assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM messages WHERE deleted_by_external = 0",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    tx.rollback()?;
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM messages WHERE content = 'original' AND deleted_by_external = 0",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        2
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM message_edits", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM reactions", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM contacts WHERE user_name IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM sync_events", [], |row| row
            .get::<_, i64>(0))?,
        baseline_events
    );

    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    assert!(matches!(
        chat_files::edit_message_for_principal_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            8,
            "invalid"
        ),
        Err(StorageError::MessageUnauthorized)
    ));
    assert!(matches!(
        chat_files::apply_remote_edit_for_principal_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            8,
            "invalid"
        ),
        Err(StorageError::MessageUnauthorized)
    ));
    assert!(matches!(
        chat_files::delete_message_for_principal_in_tx(&tx, 8, 7, PrincipalHandle(70), 10),
        Err(StorageError::MessageUnauthorized)
    ));
    assert!(matches!(
        chat_files::apply_remote_delete_for_principal_in_tx(&tx, 7, 8, PrincipalHandle(71), 10, 8),
        Err(StorageError::MessageUnauthorized)
    ));
    for index in 0..chat_files::MAX_UNIQUE_REACTIONS_PER_MESSAGE {
        chat_files::add_reaction_for_principal_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            PrincipalHandle(70),
            &index.to_string(),
        )?;
    }
    chat_files::add_reaction_for_principal_in_tx(
        &tx,
        7,
        8,
        PrincipalHandle(71),
        10,
        7,
        PrincipalHandle(70),
        "0",
    )?;
    assert!(matches!(
        chat_files::add_reaction_for_principal_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            PrincipalHandle(70),
            "overflow"
        ),
        Err(StorageError::ReactionLimitReached)
    ));
    chats_util::add_conversation_in_tx(&tx, 7, 8, PrincipalHandle(71), Some("Alice"))?;
    chats_util::add_conversation_in_tx(&tx, 7, 8, PrincipalHandle(71), None)?;
    assert_eq!(
        tx.query_row(
            "SELECT user_name FROM contacts WHERE storage_owner = 7",
            [],
            |row| row.get::<_, String>(0)
        )?,
        "Alice"
    );
    tx.commit()?;
    assert_eq!(
        conn.query_row("SELECT count(*) FROM reactions", [], |row| row
            .get::<_, i64>(0))?,
        chat_files::MAX_UNIQUE_REACTIONS_PER_MESSAGE as i64
    );
    Ok(())
}

#[test]
fn queue_conflicts_and_exact_downstream_completion_preserve_relay_states()
-> Result<(), StorageError> {
    use crate::util::{downstream_relay, relay_queue, relay_replay};
    use iota_identity::{IotaNodeId, PrincipalHandle};
    let mut conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute_batch(
            "INSERT INTO principals (principal_pk, authority_kind, authority_id, remote_user_id, last_resolved_at)
             VALUES (70, 'omega', 'omega:test', 7, 0), (71, 'omega', 'omega:test', 8, 0);",
        )?;
    let target = relay_queue::RelayTarget::Iota(
        IotaNodeId::new(format!("iota:v1:{}", "01".repeat(32))).unwrap(),
    );
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut records = Vec::new();
    for message_id in ["first", "second"] {
        let identity = relay_queue::RelayIdentity {
            signer: PrincipalHandle(70),
            recipient: PrincipalHandle(71),
            message_id: message_id.into(),
            legacy_signer_id: Some(7),
            legacy_recipient_id: Some(8),
        };
        let frame = message_id.as_bytes();
        let relay_replay::AcquireResult::Claimed(claim) = relay_replay::acquire_in_tx(
            &tx,
            relay_replay::RelayReservationRequest {
                signer_principal: identity.signer,
                signer_id: 7,
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
        let id = relay_queue::enqueue_in_tx(&tx, target.clone(), &identity, frame, 20, 42, "1.0")?;
        assert_eq!(
            relay_queue::enqueue_in_tx(&tx, target.clone(), &identity, frame, 30, 99, "1.0")?,
            id
        );
        assert!(matches!(
            relay_queue::enqueue_in_tx(&tx, target.clone(), &identity, b"changed", 20, 42, "1.0"),
            Err(StorageError::PendingRelayConflict)
        ));
        let record = tx.query_row(
                "SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at FROM pending_relays WHERE id = ?1",
                [id], relay_queue::pending_relay_from_row,
            )?;
        records.push(record);
    }
    tx.commit()?;
    conn.execute_batch(
        "CREATE TRIGGER interrupt_ack BEFORE DELETE ON pending_relays
             BEGIN SELECT RAISE(ABORT, 'injected acknowledgement interruption'); END;",
    )?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    assert!(
        downstream_relay::acknowledge_pending_delivery_in_tx(&tx, &records[0], "first", 30)
            .is_err()
    );
    tx.rollback()?;
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM relay_inbox WHERE state = 'queued'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        2
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM pending_relays", [], |row| row
            .get::<_, i64>(0))?,
        2
    );
    conn.execute_batch("DROP TRIGGER interrupt_ack;")?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut wrong_target = records[0].clone();
    wrong_target.target = relay_queue::RelayTarget::Iota(
        IotaNodeId::new(format!("iota:v1:{}", "02".repeat(32))).unwrap(),
    );
    assert!(matches!(
        downstream_relay::acknowledge_pending_delivery_in_tx(&tx, &wrong_target, "first", 30),
        Err(StorageError::PendingRelayConflict)
    ));
    assert!(matches!(
        downstream_relay::acknowledge_pending_delivery_in_tx(&tx, &records[0], "second", 30),
        Err(StorageError::PendingRelayConflict)
    ));
    assert!(downstream_relay::acknowledge_pending_delivery_in_tx(
        &tx,
        &records[0],
        "first",
        30
    )?);
    assert!(!downstream_relay::acknowledge_pending_delivery_in_tx(
        &tx,
        &records[0],
        "first",
        30
    )?);
    assert!(downstream_relay::reject_pending_delivery_in_tx(
        &tx,
        &records[1],
        "destination_rejected"
    )?);
    assert!(matches!(
        downstream_relay::acknowledge_pending_delivery_in_tx(&tx, &records[1], "second", 30),
        Err(StorageError::InvalidRelayTransition)
    ));
    let states = tx
        .prepare("SELECT message_id, state FROM relay_inbox ORDER BY message_id")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        states,
        vec![
            ("first".into(), "delivered".into()),
            ("second".into(), "queued".into())
        ]
    );
    assert_eq!(
        tx.query_row(
            "SELECT last_error FROM pending_relays WHERE id = ?1",
            [records[1].id],
            |row| row.get::<_, String>(0)
        )?,
        "destination_rejected"
    );
    tx.commit()?;
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM relay_inbox WHERE state = 'delivered'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM pending_relays", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn secret_import_is_atomic_and_does_not_resurrect_deleted_records() -> Result<(), StorageError> {
    use crate::util::e2ee_storage;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("e2ee.sqlite3");
    let legacy = Connection::open(&path)?;
    legacy.execute_batch(
            "CREATE TABLE chat_secrets (
                user_id TEXT, chat_id TEXT, secret_id TEXT, version INTEGER,
                encrypted_secret BLOB, kem_ciphertext BLOB, wrapping_scheme TEXT,
                created_at INTEGER, updated_at INTEGER
             );
             INSERT INTO chat_secrets VALUES ('7', '7:8', 'chat:7:8:main', 5, x'01', x'02', 'scheme', 10, 20);",
        )?;
    let connection = Connection::open_in_memory()?;
    run_migrations_on_connection(&connection)?;
    // Interrupt the destination commit after copying its secret rows.
    connection.execute_batch(
        "CREATE TRIGGER interrupt_import BEFORE INSERT ON storage_imports
             BEGIN SELECT RAISE(ABORT, 'injected import interruption'); END;",
    )?;
    assert!(e2ee_storage::import_legacy_database(&connection, &path).is_err());
    assert_eq!(
        connection.query_row("SELECT count(*) FROM chat_secrets", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        connection.query_row("SELECT count(*) FROM storage_imports", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    connection.execute_batch("DROP TRIGGER interrupt_import;")?;
    e2ee_storage::import_legacy_database(&connection, &path)?;
    let query = e2ee_storage::ChatSecretQuery {
        user_id: "7".into(),
        chat_id: "7:8".into(),
        secret_id: Some("chat:7:8:main".into()),
        version: Some(5),
    };
    let imported =
        e2ee_storage::get_chat_secret_on(&connection, &query)?.expect("missing imported secret");
    assert_eq!(imported.encrypted_secret, vec![1]);
    assert_eq!((imported.created_at, imported.updated_at), (10, 20));
    connection.execute("DELETE FROM chat_secrets", [])?;
    e2ee_storage::import_legacy_database(&connection, &path)?;
    assert!(e2ee_storage::get_chat_secret_on(&connection, &query)?.is_none());
    assert_eq!(
        legacy.query_row("SELECT count(*) FROM chat_secrets", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn secret_and_relay_completion_share_one_rollback_boundary() -> Result<(), StorageError> {
    use crate::util::{e2ee_storage, relay_replay};
    let mut connection = Connection::open_in_memory()?;
    run_migrations_on_connection(&connection)?;
    connection.execute("INSERT INTO principals (principal_pk, authority_kind, authority_id, remote_user_id, last_resolved_at) VALUES (70, 'omega', 'omega:test', 7, 0)", [])?;
    let secret = e2ee_storage::StoredChatSecret {
        user_id: "7".into(),
        chat_id: "principal:70:71".into(),
        secret_id: "chat:principal:70:71:main".into(),
        version: 1,
        encrypted_secret: vec![1],
        kem_ciphertext: vec![2],
        wrapping_scheme: "scheme".into(),
        created_at: 10,
        updated_at: 20,
    };
    let tx = connection.transaction()?;
    let relay_replay::AcquireResult::Claimed(claim) = relay_replay::acquire_in_tx(
        &tx,
        relay_replay::RelayReservationRequest {
            signer_principal: iota_identity::PrincipalHandle(70),
            signer_id: 7,
            message_id: "secret",
            created_at: 10,
            accepted_at: 20,
            destination_id: 8,
            frame: b"secret",
            frame_id: 42,
            type_map_version: "1.0",
        },
        100,
    )?
    else {
        panic!("missing claim")
    };
    tx.commit()?;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    relay_replay::verify_claim_in_tx(&tx, &claim)?;
    e2ee_storage::put_chat_secret_in_tx(&tx, &secret)?;
    relay_replay::complete_application_in_tx(&tx, &claim)?;
    tx.rollback()?;
    let query = e2ee_storage::ChatSecretQuery {
        user_id: secret.user_id.clone(),
        chat_id: secret.chat_id.clone(),
        secret_id: Some(secret.secret_id.clone()),
        version: Some(1),
    };
    assert!(e2ee_storage::get_chat_secret_on(&connection, &query)?.is_none());
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    relay_replay::verify_claim_in_tx(&tx, &claim)?;
    e2ee_storage::put_chat_secret_in_tx(&tx, &secret)?;
    e2ee_storage::put_chat_secret_in_tx(&tx, &secret)?;
    let conflicting = e2ee_storage::StoredChatSecret {
        encrypted_secret: vec![3],
        ..secret
    };
    assert!(matches!(
        e2ee_storage::put_chat_secret_in_tx(&tx, &conflicting),
        Err(StorageError::ChatSecretConflict)
    ));
    relay_replay::complete_application_in_tx(&tx, &claim)?;
    tx.commit()?;
    assert_eq!(
        connection.query_row("SELECT count(*) FROM chat_secrets", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}
