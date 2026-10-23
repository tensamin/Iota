use super::*;

#[test]
fn receipt_upgrade_isolates_malformed_source_column_types() -> Result<(), StorageError> {
    use rusqlite::types::Value;
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute_batch("DROP TABLE relay_acceptance_receipts; DROP TABLE relay_receipt_backfill_blocks;
            ALTER TABLE message_edits DROP COLUMN content_before_key_version;
            ALTER TABLE message_edits DROP COLUMN content_after_key_version;
            INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,last_resolved_at) VALUES(70,'omega','omega:test',7,0);
            INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'owner','test',1);
            INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,70);
            PRAGMA user_version = 58;")?;
    let prepared = br#"{"effects":[{"owner":7,"principal":70}],"operation":{"MessageSend":{"content":"ciphertext","send_time":100,"height":0,"version":1,"reply_to":null}}}"#.to_vec();
    for (message, accepted, operation) in [
        (
            Value::Text("bad-time".into()),
            Value::Text("corrupt".into()),
            Value::Blob(prepared.clone()),
        ),
        (
            Value::Blob(b"bad-message".to_vec()),
            Value::Integer(1),
            Value::Blob(prepared.clone()),
        ),
        (
            Value::Text("text-operation".into()),
            Value::Integer(1),
            Value::Text(String::from_utf8(prepared.clone()).unwrap()),
        ),
        (
            Value::Text("healthy".into()),
            Value::Integer(1),
            Value::Blob(prepared),
        ),
    ] {
        conn.execute("INSERT INTO relay_inbox(signer_principal,signer_id,message_id,created_at,accepted_at,destination_id,frame,type_map_version,frame_id,state,prepared_operation) VALUES(70,7,?1,1,?2,8,X'01','1.0',1,'queued',?3)", rusqlite::params![message,accepted,operation])?;
    }
    run_migrations_on_connection(&conn)?;
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM relay_acceptance_receipts WHERE message_id = 'healthy'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert!(
        conn.query_row(
            "SELECT COUNT(*) FROM relay_receipt_backfill_blocks WHERE storage_owner = 0",
            [],
            |r| r.get::<_, i64>(0)
        )? > 0
    );
    assert!(crate::util::relay_acceptance_receipts::upper_on(&conn, 7).is_err());
    assert_eq!(
        conn.query_row(
            "SELECT accepted_at FROM relay_inbox WHERE message_id = 'bad-time'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "corrupt"
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM relay_inbox WHERE typeof(message_id) = 'blob'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert_eq!(conn.query_row("SELECT typeof(prepared_operation) FROM relay_inbox WHERE message_id = 'text-operation'", [], |r| r.get::<_,String>(0))?,"text");
    Ok(())
}

#[test]
fn edit_epoch_migration_preserves_unknown_historical_versions() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute_batch("ALTER TABLE message_edits DROP COLUMN content_before_key_version;
            ALTER TABLE message_edits DROP COLUMN content_after_key_version;
            INSERT INTO message_edits(message_id,content_before,content_after,edited_at,edited_by) VALUES(1,'old ciphertext','new ciphertext',1,1);
            PRAGMA user_version = 59;")?;
    run_migrations_on_connection(&conn)?;
    let historical: (String, String, Option<i64>, Option<i64>) = conn.query_row("SELECT content_before,content_after,content_before_key_version,content_after_key_version FROM message_edits", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    assert_eq!(
        historical,
        ("old ciphertext".into(), "new ciphertext".into(), None, None)
    );
    Ok(())
}

#[test]
fn legacy_target_migration_preserves_canonical_pending_work() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    run_migrations_on_connection(&conn)?;
    conn.execute_batch("INSERT INTO pending_relays(destination_id,target_kind,frame,created_at,frame_id,type_map_version,delivery_state) VALUES (1,1,X'01',0,1,'1.0','ready'), (2,2,X'02',0,2,'1.0','ready');
            DELETE FROM relay_migration_history WHERE name = 'legacy_relay_targets_quarantined';
            DROP TABLE relay_acceptance_receipts;
            DROP TABLE relay_receipt_backfill_blocks;
            ALTER TABLE message_edits DROP COLUMN content_before_key_version;
            ALTER TABLE message_edits DROP COLUMN content_after_key_version;
            PRAGMA user_version = 57;")?;
    run_migrations_on_connection(&conn)?;
    let rows: Vec<(i64, String, Option<String>)> = conn
        .prepare(
            "SELECT target_kind,delivery_state,last_error FROM pending_relays ORDER BY target_kind",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(
        rows,
        vec![
            (
                1,
                "quarantined".into(),
                Some("legacy_target_requires_operator_review".into())
            ),
            (2, "ready".into(), None)
        ]
    );
    Ok(())
}

#[test]
fn pool_creation_failure_is_returned() -> Result<(), StorageError> {
    let not_a_directory =
        std::env::temp_dir().join(format!("iota-storage-pool-test-{}", std::process::id()));
    std::fs::File::create(&not_a_directory)?;
    let database_path = not_a_directory.join("messages.sqlite3");

    assert!(create_pool_with_timeout(database_path, Duration::from_millis(1)).is_err());
    std::fs::remove_file(not_a_directory)?;
    Ok(())
}

#[test]
fn resumes_migration_when_height_exists_before_its_version() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        r#"
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_owner INTEGER NOT NULL,
                external_user INTEGER NOT NULL,
                message_time INTEGER NOT NULL,
                content TEXT NOT NULL,
                sent_by_self INTEGER NOT NULL,
                message_state TEXT NOT NULL
            );
            ALTER TABLE messages ADD COLUMN height INTEGER NOT NULL DEFAULT 0;
            PRAGMA user_version = 1;
            "#,
    )?;

    run_migrations_on_connection(&conn)?;

    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 64);
    for column in ["height", "reply_to", "edited_count", "deleted_by_external"] {
        let mut statement =
            conn.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = ?1")?;
        assert!(statement.exists([column])?);
    }

    Ok(())
}

#[test]
fn migrates_version_five_once_and_is_idempotent() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, storage_owner INTEGER NOT NULL, external_user INTEGER NOT NULL, message_time INTEGER NOT NULL, content TEXT NOT NULL, sent_by_self INTEGER NOT NULL, message_state TEXT NOT NULL, height INTEGER NOT NULL DEFAULT 0, reply_to INTEGER, edited_count INTEGER NOT NULL DEFAULT 0, deleted_by_external INTEGER NOT NULL DEFAULT 0); PRAGMA user_version = 5;",
        )?;
    run_migrations_on_connection(&conn)?;
    run_migrations_on_connection(&conn)?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 64);
    for table in [
        "sync_heads",
        "sync_events",
        "client_sync_state",
        "client_device_sync_state",
        "user_residency",
        "relay_replay",
        "pending_relays",
        "relay_inbox",
        "synced_settings",
        "pending_user_operations",
        "user_blobs",
        "blocked_users",
        "user_receipt_policy",
        "user_message_storage_policy",
        "user_invitations",
        "principals",
        "principal_keys",
        "identity_configuration",
        "user_password_credentials",
        "protected_command_replay",
    ] {
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        assert_eq!(exists, 1);
    }
    for column in [
        "frame_id",
        "target_kind",
        "type_map_version",
        "delivery_state",
        "last_error",
        "attempt_count",
        "last_attempt_at",
        "next_attempt_at",
    ] {
        let mut statement =
            conn.prepare("SELECT 1 FROM pragma_table_info('pending_relays') WHERE name = ?1")?;
        assert!(statement.exists([column])?);
    }
    let password_columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('user_password_credentials')")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for required in [
        "user_id",
        "opaque_profile",
        "opaque_record",
        "encrypted_tu_credential",
        "account_public_key_sha256",
        "created_at",
        "updated_at",
    ] {
        assert!(
            password_columns.iter().any(|column| column == required),
            "missing password column {required}"
        );
    }
    Ok(())
}

#[test]
fn removes_password_version_columns_without_losing_credentials() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
            r#"
            CREATE TABLE user_password_credentials (
                user_id INTEGER PRIMARY KEY,
                protocol_version INTEGER NOT NULL,
                credential_format_version INTEGER NOT NULL,
                opaque_record BLOB NOT NULL,
                encrypted_tu_credential BLOB NOT NULL,
                account_public_key_sha256 BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            INSERT INTO user_password_credentials VALUES (7, 1, 1, x'0102', x'0304', x'0506', 10, 20);
            PRAGMA user_version = 47;
            "#,
        )?;

    run_migrations_on_connection(&conn)?;
    run_migrations_on_connection(&conn)?;

    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 64);
    let credential: (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = conn.query_row(
            "SELECT opaque_profile, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at FROM user_password_credentials WHERE user_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )?;
    assert_eq!(credential, (1, vec![1, 2], vec![3, 4], vec![5, 6], 10, 20));
    let old_columns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('user_password_credentials') WHERE name IN ('protocol_version', 'credential_format_version')",
            [],
            |row| row.get(0),
        )?;
    assert_eq!(old_columns, 0);
    Ok(())
}

#[test]
fn migration_adds_opaque_profile_to_existing_credentials() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        r#"
            CREATE TABLE user_password_credentials (
                user_id INTEGER PRIMARY KEY,
                opaque_record BLOB NOT NULL,
                encrypted_tu_credential BLOB NOT NULL,
                account_public_key_sha256 BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            INSERT INTO user_password_credentials VALUES (7, x'0102', x'0304', x'0506', 10, 20);
            PRAGMA user_version = 48;
            "#,
    )?;
    run_migrations_on_connection(&conn)?;
    run_migrations_on_connection(&conn)?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 64);
    let credential: (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = conn.query_row(
            "SELECT opaque_profile, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at FROM user_password_credentials WHERE user_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )?;
    assert_eq!(credential, (1, vec![1, 2], vec![3, 4], vec![5, 6], 10, 20));
    Ok(())
}

#[test]
fn adds_synced_settings_to_a_version_eleven_schema() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch("PRAGMA user_version = 11;")?;

    run_migrations_on_connection(&conn)?;

    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 64);
    for column in [
        "id",
        "user_id",
        "scope_type",
        "scope_key",
        "name",
        "payload",
        "revision",
        "deleted",
    ] {
        let mut statement =
            conn.prepare("SELECT 1 FROM pragma_table_info('synced_settings') WHERE name = ?1")?;
        assert!(statement.exists([column])?);
    }

    Ok(())
}

#[test]
fn credential_origin_migration_allows_external_profiles() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        r#"
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                private_key_hash TEXT NOT NULL,
                reset_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                display_name TEXT
            );
            CREATE TABLE user_residency (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                data_state TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            PRAGMA user_version = 20;
            "#,
    )?;
    run_migrations_on_connection(&conn)?;
    conn.execute(
            "INSERT INTO users (user_id, username, public_key, private_key_hash, reset_token, created_at) VALUES (1, 'alice', 'key', NULL, NULL, 1)",
            [],
        )?;
    let origin_exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('user_residency') WHERE name = 'credential_origin'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(origin_exists, 1);
    Ok(())
}

#[test]
fn pending_purge_migration_preserves_lifecycle_operations() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
            r#"
            CREATE TABLE pending_user_operations (
                user_id INTEGER PRIMARY KEY,
                operation TEXT NOT NULL
                    CHECK (operation IN ('create', 'attach', 'release')),
                username TEXT NOT NULL,
                public_key TEXT,
                private_key_hash TEXT,
                reset_token TEXT,
                registration_token TEXT,
                phase TEXT NOT NULL DEFAULT 'prepared'
                    CHECK (phase IN ('prepared', 'credential_written', 'remote_committed', 'local_committed')),
                created_at INTEGER NOT NULL
            );
            INSERT INTO pending_user_operations (
                user_id, operation, username, phase, created_at
            ) VALUES (1, 'release', 'alice', 'remote_committed', 1);
            PRAGMA user_version = 21;
            "#,
        )?;

    run_migrations_on_connection(&conn)?;
    conn.execute(
            "INSERT INTO pending_user_operations (user_id, operation, username, phase, created_at) VALUES (2, 'purge', 'bob', 'filesystem_purged', 2)",
            [],
        )?;

    let preserved: String = conn.query_row(
        "SELECT phase FROM pending_user_operations WHERE user_id = 1",
        [],
        |row| row.get(0),
    )?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(preserved, "remote_committed");
    assert_eq!(version, 64);
    Ok(())
}

#[test]
fn invitation_authority_migration_discards_unmappable_omega_mirrors() -> Result<(), StorageError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        r#"
            CREATE TABLE user_invitations (
                invitation_id TEXT PRIMARY KEY,
                token_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                state TEXT NOT NULL,
                redeemed_user_id INTEGER,
                redeemed_at INTEGER,
                revoked_at INTEGER
            );
            INSERT INTO user_invitations (
                invitation_id, token_hash, created_at, expires_at, state
            ) VALUES
                ('42', X'0102', 10, 20, 'pending'),
                ('4f40e654-1234-1234-1234-123456789abc', X'0102', 10, 20, 'pending'),
                ('af40e654-1234-1234-1234-123456789abc', X'0102', 10, 20, 'pending'),
                ('malformed', X'0102', 10, 20, 'pending');
            PRAGMA user_version = 26;
            "#,
    )?;

    run_migrations_on_connection(&conn)?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM user_invitations", [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 0);
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 64);
    Ok(())
}
