use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version < 1 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_owner INTEGER NOT NULL,
                external_user INTEGER NOT NULL,
                message_time INTEGER NOT NULL,
                content TEXT NOT NULL,
                sent_by_self INTEGER NOT NULL,
                message_state TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_lookup
                ON messages (storage_owner, external_user, message_time DESC);

            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_owner INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                user_name TEXT,
                created_at INTEGER NOT NULL,
                last_message_at INTEGER,
                notifications INTEGER NOT NULL DEFAULT 0,
                notifications_read_at INTEGER NOT NULL DEFAULT 0,
                UNIQUE(storage_owner, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_contacts_owner
                ON contacts (storage_owner, last_message_at DESC, user_id ASC);

            CREATE TABLE IF NOT EXISTS communities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_owner INTEGER NOT NULL,
                address TEXT NOT NULL,
                title TEXT NOT NULL,
                position TEXT NOT NULL,
                UNIQUE(storage_owner, address)
            );
            CREATE INDEX IF NOT EXISTS idx_communities_owner
                ON communities (storage_owner);

            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                private_key_hash TEXT NOT NULL,
                reset_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                display_name TEXT
            );

            CREATE TABLE IF NOT EXISTS trusted_apps (
                user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                app_secret TEXT NOT NULL,
                PRIMARY KEY (user_id, app_id)
            );

            PRAGMA user_version = 1;
            "#,
        )?;
    }

    if current_version < 2 {
        add_column_if_missing(conn, "height", "height INTEGER NOT NULL DEFAULT 0")?;
        conn.execute_batch("PRAGMA user_version = 2;")?;
    }

    if current_version < 3 {
        add_column_if_missing(conn, "reply_to", "reply_to INTEGER")?;
        conn.execute_batch("PRAGMA user_version = 3;")?;
    }

    if current_version < 4 {
        add_column_if_missing(
            conn,
            "edited_count",
            "edited_count INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(
            conn,
            "deleted_by_external",
            "deleted_by_external INTEGER NOT NULL DEFAULT 0",
        )?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS message_edits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL REFERENCES messages(id),
                content_before TEXT NOT NULL,
                content_after TEXT NOT NULL,
                edited_at INTEGER NOT NULL,
                edited_by INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_message_edits_msg
                ON message_edits (message_id, edited_at DESC);

            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL REFERENCES messages(id),
                user_id INTEGER NOT NULL,
                reaction TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(message_id, user_id, reaction)
            );
            CREATE INDEX IF NOT EXISTS idx_reactions_msg
                ON reactions (message_id, reaction);

            PRAGMA user_version = 4;
            "#,
        )?;
    }

    let messages_exist: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
        [],
        |row| row.get(0),
    )?;
    if messages_exist {
        add_column_if_missing(
            conn,
            "key_version",
            "key_version INTEGER NOT NULL DEFAULT 1",
        )?;
    }

    if current_version < 5 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS settings (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (user_id, session_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_settings_lookup
                ON settings (user_id, session_id, name);

            PRAGMA user_version = 5;
            "#,
        )?;
    }

    if current_version < 6 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sync_heads (
                user_id INTEGER PRIMARY KEY,
                version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sync_events (
                user_id INTEGER NOT NULL,
                version INTEGER NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                operation TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_sync_events_user_version
                ON sync_events (user_id, version);
            CREATE TABLE IF NOT EXISTS client_sync_state (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                acknowledged_version INTEGER NOT NULL,
                cache_schema_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, session_id)
            );
            PRAGMA user_version = 6;
            "#,
        )?;
    }

    if current_version < 7 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS user_residency (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('managed', 'released')),
                data_state TEXT NOT NULL CHECK (data_state IN ('present', 'empty')),
                updated_at INTEGER NOT NULL
            );
            PRAGMA user_version = 7;
            "#,
        )?;
    }

    if current_version < 8 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS relay_replay (
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (signer_id, message_id)
            );
            CREATE INDEX IF NOT EXISTS idx_relay_replay_created_at
                ON relay_replay (created_at);
            CREATE TABLE IF NOT EXISTS pending_relays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination_id INTEGER NOT NULL,
                target_kind INTEGER NOT NULL DEFAULT 0,
                frame BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                frame_id INTEGER NOT NULL DEFAULT 0,
                UNIQUE(destination_id, frame)
            );
            CREATE INDEX IF NOT EXISTS idx_pending_relays_destination
                ON pending_relays (destination_id, id);
            PRAGMA user_version = 8;
            "#,
        )?;
    }

    if current_version < 9 {
        add_table_column_if_missing(
            conn,
            "pending_relays",
            "target_kind",
            "target_kind INTEGER NOT NULL DEFAULT 0",
        )?;
        add_table_column_if_missing(
            conn,
            "pending_relays",
            "type_map_version",
            "type_map_version TEXT NOT NULL DEFAULT '1.0'",
        )?;
        add_table_column_if_missing(
            conn,
            "pending_relays",
            "frame_id",
            "frame_id INTEGER NOT NULL DEFAULT 0",
        )?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS relay_inbox (
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                destination_id INTEGER NOT NULL,
                frame BLOB NOT NULL,
                type_map_version TEXT NOT NULL,
                frame_id INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('received', 'applied', 'queued', 'delivered', 'rejected')),
                PRIMARY KEY (signer_id, message_id)
            );
            CREATE INDEX IF NOT EXISTS idx_relay_inbox_state
                ON relay_inbox (state, created_at);
            PRAGMA user_version = 9;
            "#,
        )?;
    }

    if current_version < 10 {
        conn.execute_batch(
            r#"
            CREATE INDEX IF NOT EXISTS idx_messages_history
                ON messages (
                    storage_owner,
                    external_user,
                    deleted_by_external,
                    message_time DESC,
                    id DESC
                );
            PRAGMA user_version = 10;
            "#,
        )?;
    }

    if current_version < 11 {
        for (column, definition) in [
            ("relay_signer_id", "relay_signer_id INTEGER"),
            ("relay_message_id", "relay_message_id TEXT"),
            ("authored_at", "authored_at INTEGER"),
            ("origin_iota_received_at", "origin_iota_received_at INTEGER"),
            (
                "destination_iota_received_at",
                "destination_iota_received_at INTEGER",
            ),
            ("client_received_at", "client_received_at INTEGER"),
            (
                "client_received_recorded_at",
                "client_received_recorded_at INTEGER",
            ),
            ("read_at", "read_at INTEGER"),
            ("read_recorded_at", "read_recorded_at INTEGER"),
        ] {
            add_column_if_missing(conn, column, definition)?;
        }
        for (column, definition) in [
            ("accepted_at", "accepted_at INTEGER"),
            ("applied_at", "applied_at INTEGER"),
            ("queued_at", "queued_at INTEGER"),
            ("downstream_acked_at", "downstream_acked_at INTEGER"),
            ("rejected_at", "rejected_at INTEGER"),
        ] {
            add_table_column_if_missing(conn, "relay_inbox", column, definition)?;
        }
        conn.execute_batch(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_relay_identity
                ON messages (storage_owner, relay_signer_id, relay_message_id)
                WHERE relay_message_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS message_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_owner INTEGER NOT NULL,
                target_signer_id INTEGER NOT NULL,
                target_message_id TEXT NOT NULL,
                receipt_signer_id INTEGER NOT NULL,
                receipt_message_id TEXT NOT NULL,
                receipt_type TEXT NOT NULL CHECK (receipt_type IN ('received', 'read')),
                event_at INTEGER NOT NULL,
                recorded_at INTEGER NOT NULL,
                UNIQUE(receipt_signer_id, receipt_message_id),
                UNIQUE(storage_owner, target_signer_id, target_message_id,
                       receipt_signer_id, receipt_type)
            );
            CREATE INDEX IF NOT EXISTS idx_message_receipts_target
                ON message_receipts (storage_owner, target_signer_id, target_message_id);
            PRAGMA user_version = 11;
            "#,
        )?;
    }

    if current_version < 12 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS synced_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scope_type TEXT NOT NULL
                    CHECK (scope_type IN ('user', 'contact', 'community')),
                scope_key TEXT NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                revision INTEGER NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0
                    CHECK (deleted IN (0, 1)),
                UNIQUE(user_id, scope_type, scope_key, name)
            );
            CREATE INDEX IF NOT EXISTS idx_synced_settings_owner
                ON synced_settings (user_id, deleted);
            CREATE INDEX IF NOT EXISTS idx_synced_settings_scope
                ON synced_settings (user_id, scope_type, scope_key, deleted);
            PRAGMA user_version = 12;
            "#,
        )?;
    }

    if current_version < 13 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS pending_user_operations (
                user_id INTEGER PRIMARY KEY,
                operation TEXT NOT NULL
                    CHECK (operation IN ('create', 'attach', 'release')),
                username TEXT NOT NULL,
                public_key TEXT,
                private_key_hash TEXT,
                reset_token TEXT,
                registration_token TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_user_operations_operation
                ON pending_user_operations (operation, created_at);
            PRAGMA user_version = 13;
            "#,
        )?;
    }

    if current_version < 14 {
        conn.execute_batch(
            r#"
            ALTER TABLE pending_user_operations
                ADD COLUMN phase TEXT NOT NULL DEFAULT 'prepared'
                CHECK (phase IN ('prepared', 'credential_written', 'remote_committed', 'local_committed'));
            PRAGMA user_version = 14;
            "#,
        )?;
    }

    if current_version < 15 {
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            conn.execute_batch(
                r#"
                DROP INDEX IF EXISTS idx_messages_history;
                CREATE INDEX IF NOT EXISTS idx_messages_history_accepted
                    ON messages (
                        storage_owner,
                        external_user,
                        deleted_by_external,
                        destination_iota_received_at DESC,
                        origin_iota_received_at DESC,
                        authored_at DESC,
                        id DESC
                    );
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 15)?;
    }

    if current_version < 16 {
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            add_column_if_missing(conn, "delivery_failed_at", "delivery_failed_at INTEGER")?;
            add_column_if_missing(conn, "delivery_failure", "delivery_failure TEXT")?;
        }
        let contacts_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'contacts')",
            [],
            |row| row.get(0),
        )?;
        if contacts_exist {
            add_table_column_if_missing(conn, "contacts", "created_at", "created_at INTEGER")?;
            conn.execute(
                "UPDATE contacts SET created_at = COALESCE(created_at, last_message_at, 0)",
                [],
            )?;
        }
        conn.pragma_update(None, "user_version", 16)?;
    }

    if current_version < 17 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS user_blobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                blob_id TEXT NOT NULL,
                blob BLOB NOT NULL,
                revision INTEGER NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
                updated_at INTEGER NOT NULL,
                UNIQUE(user_id, blob_id)
            );
            CREATE INDEX IF NOT EXISTS idx_user_blobs_owner
                ON user_blobs (user_id, deleted);
            CREATE TABLE IF NOT EXISTS blocked_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                blocked_user_id INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(user_id, blocked_user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_users_owner ON blocked_users (user_id);
            CREATE TABLE IF NOT EXISTS user_receipt_policy (
                user_id INTEGER PRIMARY KEY,
                send_read_receipts INTEGER NOT NULL CHECK (send_read_receipts IN (0, 1)),
                send_received_receipts INTEGER NOT NULL CHECK (send_received_receipts IN (0, 1)),
                revision INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_message_storage_policy (
                user_id INTEGER PRIMARY KEY,
                history_mode TEXT NOT NULL CHECK (history_mode IN ('retain', 'delete_after_client_delivery')),
                retention_mode TEXT NOT NULL CHECK (retention_mode IN ('forever', 'duration')),
                retention_duration_ms INTEGER,
                revision INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            PRAGMA user_version = 17;
            "#,
        )?;
    }

    if current_version < 18 {
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            add_column_if_missing(conn, "stored_at", "stored_at INTEGER")?;
            add_column_if_missing(conn, "expires_at", "expires_at INTEGER")?;
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages (storage_owner, expires_at) WHERE expires_at IS NOT NULL;",
            )?;
        }
        conn.pragma_update(None, "user_version", 18)?;
    }

    if current_version < 19 {
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            conn.execute(
                "UPDATE messages SET stored_at = COALESCE(destination_iota_received_at, origin_iota_received_at) WHERE stored_at IS NULL",
                [],
            )?;
        }
        conn.pragma_update(None, "user_version", 19)?;
    }

    if current_version < 20 {
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            add_column_if_missing(
                conn,
                "history_deleted",
                "history_deleted INTEGER NOT NULL DEFAULT 0 CHECK (history_deleted IN (0, 1))",
            )?;
            add_column_if_missing(conn, "history_deleted_at", "history_deleted_at INTEGER")?;
        }
        let pending_relays_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_relays')",
            [],
            |row| row.get(0),
        )?;
        if pending_relays_exist {
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "relay_signer_id",
                "relay_signer_id INTEGER",
            )?;
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "relay_destination_user_id",
                "relay_destination_user_id INTEGER",
            )?;
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "relay_message_id",
                "relay_message_id TEXT",
            )?;
        }
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS client_message_deliveries (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                sync_version INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, session_id, sync_version, message_id)
            );
            CREATE INDEX IF NOT EXISTS idx_client_message_deliveries_session
                ON client_message_deliveries (user_id, session_id, sync_version);
            PRAGMA user_version = 20;
            "#,
        )?;
    }

    Ok(())
}
