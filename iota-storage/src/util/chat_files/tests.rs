use super::*;
use iota_identity::PrincipalHandle;
use rusqlite::Connection;

fn edit_fixture(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, storage_owner INTEGER,
                external_user INTEGER, external_principal INTEGER, message_time INTEGER,
                content TEXT, sent_by_self INTEGER, history_deleted INTEGER DEFAULT 0,
                edited_count INTEGER DEFAULT 0, key_version INTEGER);
             CREATE TABLE message_edits (message_id INTEGER, content_before TEXT,
                 content_after TEXT, edited_at INTEGER, edited_by INTEGER,
                 content_before_key_version INTEGER, content_after_key_version INTEGER);
             CREATE TABLE sync_heads (user_id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
             CREATE TABLE sync_events (user_id INTEGER, version INTEGER, entity_type TEXT,
                entity_id INTEGER, operation TEXT, created_at INTEGER);
             CREATE TABLE chat_secrets (user_id TEXT, chat_id TEXT, secret_id TEXT,
                version INTEGER, encrypted_secret BLOB, kem_ciphertext BLOB,
                wrapping_scheme TEXT, created_at INTEGER, updated_at INTEGER);
             INSERT INTO messages (id, storage_owner, external_user, external_principal,
                message_time, content, sent_by_self, key_version)
             VALUES (1, 7, 8, 71, 10, 'original', 1, 2),
                    (2, 8, 7, 70, 10, 'original', 0, 2);
             INSERT INTO chat_secrets VALUES
                ('7', 'principal:70:71', 'chat:principal:70:71:main', 1, X'01', X'02', 'test', 0, 0),
                ('7', 'principal:70:71', 'chat:principal:70:71:main', 2, X'03', X'04', 'test', 0, 0);",
        )?;
    Ok(())
}

fn edit_state(conn: &Connection) -> Result<(String, i64, i64, i64, i64), StorageError> {
    Ok(conn.query_row(
        "SELECT content, key_version, edited_count,
                (SELECT count(*) FROM message_edits), (SELECT count(*) FROM sync_events)
             FROM messages WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?)
}

#[test]
fn edit_epochs_update_ciphertext_metadata_history_and_sync_together() -> Result<(), StorageError> {
    let mut conn = Connection::open_in_memory()?;
    edit_fixture(&conn)?;
    let tx = conn.transaction()?;
    // An older epoch remains usable after rotation, even when it differs
    // from the key of the original ciphertext.
    require_edit_key_in_tx(&tx, 7, "principal:70:71", 1)?;
    edit_message_for_principal_versioned_in_tx(
        &tx,
        7,
        8,
        PrincipalHandle(71),
        10,
        7,
        "old-key edit",
        1,
    )?;
    require_edit_key_in_tx(&tx, 7, "principal:70:71", 2)?;
    edit_message_for_principal_versioned_in_tx(
        &tx,
        7,
        8,
        PrincipalHandle(71),
        10,
        7,
        "new-key edit",
        2,
    )?;
    apply_remote_edit_for_principal_versioned_in_tx(
        &tx,
        8,
        7,
        PrincipalHandle(70),
        10,
        7,
        "old-key edit",
        1,
    )?;
    // Legacy callers do not declare a new epoch and preserve the current one.
    edit_message_for_principal_in_tx(&tx, 7, 8, PrincipalHandle(71), 10, 7, "compatible edit")?;
    tx.commit()?;
    assert_eq!(edit_state(&conn)?, ("compatible edit".into(), 2, 3, 4, 4));
    assert_eq!(
        conn.query_row(
            "SELECT content, key_version, edited_count FROM messages WHERE id = 2",
            [],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?
            )),
        )?,
        ("old-key edit".into(), 1, 1)
    );
    let history: Vec<(String, String, i64)> = conn.prepare(
            "SELECT content_before, content_after, edited_by FROM message_edits WHERE message_id = 1 ORDER BY rowid",
        )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;
    assert_eq!(
        history,
        vec![
            ("original".into(), "old-key edit".into(), 7),
            ("old-key edit".into(), "new-key edit".into(), 7),
            ("new-key edit".into(), "compatible edit".into(), 7),
        ]
    );
    let epochs: Vec<(i64, i64)> = conn.prepare("SELECT content_before_key_version, content_after_key_version FROM message_edits WHERE message_id = 1 ORDER BY rowid")?
            .query_map([], |row| Ok((row.get(0)?,row.get(1)?)))?.collect::<Result<_,_>>()?;
    assert_eq!(epochs, vec![(2, 1), (1, 2), (2, 2)]);
    Ok(())
}

#[test]
fn edit_sync_failure_rolls_back_both_copies_and_can_retry() -> Result<(), StorageError> {
    let mut conn = Connection::open_in_memory()?;
    edit_fixture(&conn)?;
    let before = edit_state(&conn)?;
    conn.execute_batch(
        "CREATE TRIGGER fail_recipient_sync BEFORE INSERT ON sync_events
             WHEN NEW.user_id = 8
             BEGIN SELECT RAISE(ABORT, 'injected sync failure'); END;",
    )?;
    let tx = conn.transaction()?;
    edit_message_for_principal_versioned_in_tx(&tx, 7, 8, PrincipalHandle(71), 10, 7, "edited", 1)?;
    assert!(matches!(
        apply_remote_edit_for_principal_versioned_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            7,
            "edited",
            1,
        ),
        Err(StorageError::Db(_))
    ));
    tx.rollback()?;
    assert_eq!(edit_state(&conn)?, before);
    assert_eq!(conn.query_row(
            "SELECT count(*) FROM messages WHERE content = 'original' AND key_version = 2 AND edited_count = 0",
            [], |row| row.get::<_, i64>(0),
        )?, 2);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM sync_heads", [], |row| row
            .get::<_, i64>(0))?,
        0
    );

    conn.execute_batch("DROP TRIGGER fail_recipient_sync;")?;
    let tx = conn.transaction()?;
    edit_message_for_principal_versioned_in_tx(&tx, 7, 8, PrincipalHandle(71), 10, 7, "edited", 1)?;
    apply_remote_edit_for_principal_versioned_in_tx(
        &tx,
        8,
        7,
        PrincipalHandle(70),
        10,
        7,
        "edited",
        1,
    )?;
    tx.commit()?;
    assert_eq!(edit_state(&conn)?, ("edited".into(), 1, 1, 2, 2));
    assert_eq!(conn.query_row(
            "SELECT count(*) FROM messages WHERE content = 'edited' AND key_version = 1 AND edited_count = 1",
            [], |row| row.get::<_, i64>(0),
        )?, 2);
    Ok(())
}

#[test]
fn invalid_or_unauthorized_edits_do_not_change_history_or_sync() -> Result<(), StorageError> {
    let mut conn = Connection::open_in_memory()?;
    edit_fixture(&conn)?;
    let before = edit_state(&conn)?;
    let tx = conn.transaction()?;
    for version in [0, -1] {
        assert!(matches!(
            require_edit_key_in_tx(&tx, 7, "principal:70:71", version),
            Err(StorageError::InvalidRelayPayload(_))
        ));
        assert!(matches!(
            edit_message_for_principal_versioned_in_tx(
                &tx,
                7,
                8,
                PrincipalHandle(71),
                10,
                7,
                "invalid",
                version,
            ),
            Err(StorageError::InvalidRelayPayload(_))
        ));
    }
    assert!(matches!(
        apply_remote_edit_for_principal_versioned_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            9,
            "forged",
            1,
        ),
        Err(StorageError::MessageUnauthorized)
    ));
    assert!(matches!(
        apply_remote_edit_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            8,
            "wrong direction",
            1,
        ),
        Err(StorageError::MessageUnauthorized)
    ));
    assert!(matches!(
        edit_message_for_principal_versioned_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            8,
            "wrong direction",
            1,
        ),
        Err(StorageError::MessageUnauthorized)
    ));
    assert!(matches!(
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(999),
            10,
            7,
            "wrong authority",
            1,
        ),
        Err(StorageError::MissingRelayDependency)
    ));
    assert!(matches!(
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            11,
            7,
            "missing target",
            1,
        ),
        Err(StorageError::MissingRelayDependency)
    ));
    tx.commit()?;
    assert_eq!(edit_state(&conn)?, before);
    Ok(())
}

#[test]
fn missing_edit_epoch_can_recover_after_reopen_without_partial_mutation() -> Result<(), StorageError>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("edit.sqlite3");
    {
        let mut conn = Connection::open(&path)?;
        edit_fixture(&conn)?;
        let before = edit_state(&conn)?;
        let tx = conn.transaction()?;
        // The other owner's key and another authority's namespace do not satisfy this edit.
        for (owner, chat, version) in [
            (8, "principal:70:71", 1),
            (7, "principal:70:99", 1),
            (7, "principal:70:71", 3),
        ] {
            assert!(matches!(
                require_edit_key_in_tx(&tx, owner, chat, version),
                Err(StorageError::MissingRelayDependency)
            ));
        }
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "uncommitted",
            1,
        )?;
        // A failed second local effect must roll back key metadata and history too.
        assert!(matches!(
            require_edit_key_in_tx(&tx, 8, "principal:70:71", 1),
            Err(StorageError::MissingRelayDependency)
        ));
        tx.rollback()?;
        assert_eq!(edit_state(&conn)?, before);
    }
    let mut conn = Connection::open(&path)?;
    let tx = conn.transaction()?;
    tx.execute("INSERT INTO chat_secrets SELECT user_id, chat_id, secret_id, 3, encrypted_secret, kem_ciphertext, wrapping_scheme, created_at, updated_at FROM chat_secrets WHERE version = 2", [])?;
    require_edit_key_in_tx(&tx, 7, "principal:70:71", 3)?;
    edit_message_for_principal_versioned_in_tx(
        &tx,
        7,
        8,
        PrincipalHandle(71),
        10,
        7,
        "recovered",
        3,
    )?;
    tx.commit()?;
    assert_eq!(edit_state(&conn)?, ("recovered".into(), 3, 1, 1, 1));
    Ok(())
}

#[test]
fn versioned_edit_does_not_restore_removed_history() -> Result<(), StorageError> {
    let mut conn = Connection::open_in_memory()?;
    edit_fixture(&conn)?;
    conn.execute("UPDATE messages SET content = '', history_deleted = 1", [])?;
    let before = edit_state(&conn)?;
    let tx = conn.transaction()?;
    edit_message_for_principal_versioned_in_tx(
        &tx,
        7,
        8,
        PrincipalHandle(71),
        10,
        7,
        "restore",
        1,
    )?;
    apply_remote_edit_for_principal_versioned_in_tx(
        &tx,
        8,
        7,
        PrincipalHandle(70),
        10,
        7,
        "restore",
        1,
    )?;
    tx.commit()?;
    assert_eq!(edit_state(&conn)?, before);
    Ok(())
}

#[test]
fn upgrade_prefers_highest_state() {
    assert_eq!(
        MessageState::Sending.upgrade(MessageState::Sent),
        MessageState::Sent
    );
    assert_eq!(
        MessageState::Sent.upgrade(MessageState::Received),
        MessageState::Received
    );
    assert_eq!(
        MessageState::Received.upgrade(MessageState::Read),
        MessageState::Read
    );
    assert_eq!(
        MessageState::Read.upgrade(MessageState::Received),
        MessageState::Read
    );
}

#[test]
fn from_str_is_case_insensitive() {
    assert_eq!(MessageState::from_str("READ"), MessageState::Read);
    assert_eq!(MessageState::from_str("received"), MessageState::Received);
    assert_eq!(MessageState::from_str("Sent"), MessageState::Sent);
    assert_eq!(MessageState::from_str("unknown"), MessageState::Sending);
}
