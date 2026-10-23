use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version < 41 {
        let pending_relays_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_relays')",
            [],
            |row| row.get(0),
        )?;
        if pending_relays_exist {
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "attempt_count",
                "attempt_count INTEGER NOT NULL DEFAULT 0",
            )?;
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "last_attempt_at",
                "last_attempt_at INTEGER",
            )?;
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "next_attempt_at",
                "next_attempt_at INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        conn.pragma_update(None, "user_version", 41)?;
    }

    if current_version < 42 {
        let principals_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'principals')",
            [],
            |row| row.get(0),
        )?;
        if principals_exist {
            add_table_column_if_missing(
                conn,
                "principals",
                "descriptor_issued_at",
                "descriptor_issued_at INTEGER",
            )?;
            conn.execute(
                "UPDATE principals SET descriptor_issued_at = last_resolved_at WHERE descriptor_issued_at IS NULL AND principal_pk IN (SELECT principal_handle FROM hosted_principals)",
                [],
            )?;
        }
        conn.pragma_update(None, "user_version", 42)?;
    }

    if current_version < 43 {
        let endpoint_pins_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'node_endpoint_pins')",
            [],
            |row| row.get(0),
        )?;
        if endpoint_pins_exist {
            add_table_column_if_missing(
                conn,
                "node_endpoint_pins",
                "tls_certificate",
                "tls_certificate BLOB",
            )?;
        }
        conn.pragma_update(None, "user_version", 43)?;
    }

    if current_version < 44 {
        conn.execute_batch(
            r#"
            DROP TABLE IF EXISTS trusted_apps;
            CREATE TABLE tauth_owner_apps (
                app_id TEXT PRIMARY KEY,
                owner_user_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                public_key TEXT NOT NULL,
                owner_certificate TEXT NOT NULL,
                connection_mode TEXT NOT NULL CHECK (connection_mode IN ('hosted', 'forced_omikron')),
                endpoint_url TEXT NOT NULL,
                omikron_public_key TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE tauth_grants (
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                app_name TEXT NOT NULL,
                domain TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scopes TEXT NOT NULL,
                app_public_key TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                security_state TEXT NOT NULL CHECK (security_state IN ('secure', 'insecure')),
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (local_user_id, app_id)
            );
            CREATE TABLE tauth_codes (
                code_hash BLOB PRIMARY KEY,
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scopes TEXT NOT NULL,
                pkce_challenge TEXT NOT NULL,
                authorization_request TEXT NOT NULL,
                locator TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX tauth_codes_expiry ON tauth_codes (expires_at);
            CREATE TABLE tauth_sessions (
                token_hash BLOB PRIMARY KEY,
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                locator TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX tauth_sessions_grant ON tauth_sessions (local_user_id, app_id);
            CREATE TABLE tauth_metadata (
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (local_user_id, app_id)
            );
            PRAGMA user_version = 44;
            "#,
        )?;
    }

    if current_version < 45 {
        conn.execute_batch(
            r#"
            CREATE TABLE user_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                asset_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 BLOB NOT NULL,
                mime_type TEXT NOT NULL,
                revision INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                published_upload_id TEXT NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0,
                UNIQUE(user_id, asset_id)
            );
            CREATE INDEX user_assets_owner ON user_assets (user_id, deleted);
            CREATE TABLE user_asset_uploads (
                upload_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                asset_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 BLOB NOT NULL,
                mime_type TEXT NOT NULL,
                received INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL CHECK (state IN ('uploading', 'committed')),
                revision INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                committed_at INTEGER
            );
            CREATE INDEX user_asset_uploads_owner ON user_asset_uploads (user_id, state, updated_at);
            PRAGMA user_version = 45;
            "#,
        )?;
    }

    if current_version < 46 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS call_envelopes (
                recipient_id INTEGER NOT NULL,
                call_id TEXT NOT NULL,
                owner_omikron_id INTEGER NOT NULL,
                inviter_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                secret_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                encrypted_secret BLOB NOT NULL,
                kem_ciphertext BLOB NOT NULL,
                wrapping_scheme TEXT NOT NULL,
                PRIMARY KEY (recipient_id, call_id)
            );
            CREATE INDEX IF NOT EXISTS call_envelopes_expiry ON call_envelopes (expires_at);
            PRAGMA user_version = 46;
            "#,
        )?;
    }

    if current_version < 47 {
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
            CREATE TABLE protected_command_replay (
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (signer_id, message_id)
            );
            CREATE INDEX protected_command_replay_created_at
                ON protected_command_replay (created_at);
            PRAGMA user_version = 47;
            "#,
        )?;
    }

    if current_version < 48 {
        let has_version_columns: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('user_password_credentials') WHERE name = 'protocol_version')",
            [],
            |row| row.get(0),
        )?;
        if has_version_columns {
            conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE user_password_credentials_unversioned (
                    user_id INTEGER PRIMARY KEY,
                    opaque_record BLOB NOT NULL,
                    encrypted_tu_credential BLOB NOT NULL,
                    account_public_key_sha256 BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                INSERT INTO user_password_credentials_unversioned
                    (user_id, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at)
                    SELECT user_id, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at
                    FROM user_password_credentials;
                DROP TABLE user_password_credentials;
                ALTER TABLE user_password_credentials_unversioned RENAME TO user_password_credentials;
                PRAGMA user_version = 48;
                COMMIT;
                "#,
            )?;
        } else {
            conn.pragma_update(None, "user_version", 48)?;
        }
    }

    if current_version < 49 {
        conn.execute_batch(
            r#"
            ALTER TABLE user_password_credentials
                ADD COLUMN opaque_profile INTEGER NOT NULL DEFAULT 1;
            PRAGMA user_version = 49;
            "#,
        )?;
    }

    if current_version < 50 {
        let directory_exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'node_directory')",
            [], |row| row.get(0),
        )?;
        if directory_exists {
            add_table_column_if_missing(
                conn,
                "node_directory",
                "authentication_hint",
                "authentication_hint INTEGER",
            )?;
            let nodes = {
                let mut statement = conn.prepare("SELECT node_id FROM node_directory")?;
                statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for node in nodes {
                let identity = iota_identity::IotaNodeId::new(&node)
                    .map_err(|error| StorageError::Other(error.to_string()))?;
                conn.execute(
                    "UPDATE node_directory SET authentication_hint = ?2 WHERE node_id = ?1",
                    rusqlite::params![node, identity.mtp_authentication_hint() as i64],
                )?;
            }
            conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_node_authentication_hint ON node_directory(authentication_hint);")?;
        }
        conn.pragma_update(None, "user_version", 50)?;
    }

    if current_version < 51 {
        crate::hosted_auth::migrate(conn)?;
    }

    if current_version < 52 {
        crate::util::relay_replay::migrate(conn)?;
    }

    if current_version < 53 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            "CREATE TABLE chat_secrets (
                user_id TEXT NOT NULL, chat_id TEXT NOT NULL, secret_id TEXT NOT NULL,
                version INTEGER NOT NULL, encrypted_secret BLOB NOT NULL,
                kem_ciphertext BLOB NOT NULL, wrapping_scheme TEXT NOT NULL,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, chat_id, secret_id, version)
             );
             CREATE INDEX idx_chat_secrets_owner ON chat_secrets (user_id, chat_id, secret_id);
             CREATE TABLE storage_imports (name TEXT PRIMARY KEY, completed_at INTEGER NOT NULL);",
        )?;
        tx.pragma_update(None, "user_version", 53)?;
        tx.commit()?;
    }

    if current_version < 54 {
        let tx = conn.unchecked_transaction()?;
        let inbox_exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'relay_inbox')", [], |r| r.get(0))?;
        let queue_exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_relays')", [], |r| r.get(0))?;
        if inbox_exists {
            tx.execute_batch("ALTER TABLE relay_inbox ADD COLUMN prepared_operation BLOB;
                ALTER TABLE relay_inbox ADD COLUMN rejection_reason TEXT CHECK(rejection_reason IN ('unauthorized', 'invalid_operation'));
                UPDATE relay_inbox SET state = 'rejected', rejected_at = COALESCE(rejected_at, accepted_at, created_at),
                processing_owner = NULL, processing_deadline = NULL WHERE state IN ('received', 'processing');")?;
        }
        if queue_exists {
            tx.execute_batch("UPDATE pending_relays SET delivery_state = 'quarantined', last_error = 'pre_fenced_pipeline_requires_operator_review';")?;
        }
        tx.execute_batch(
            "CREATE TABLE relay_deferred_secrets (
                 signer_principal INTEGER NOT NULL, message_id TEXT NOT NULL,
                 storage_owner INTEGER NOT NULL, owner_principal INTEGER NOT NULL,
                 legacy_chat_id TEXT, chat_id TEXT NOT NULL, secret_id TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK(version > 0), encrypted_secret BLOB NOT NULL,
                 kem_ciphertext BLOB NOT NULL, wrapping_scheme TEXT NOT NULL,
                 created_at INTEGER NOT NULL, completed_at INTEGER,
                 PRIMARY KEY(signer_principal, message_id, storage_owner)
             );
             CREATE TABLE relay_migration_history(name TEXT PRIMARY KEY, completed_at INTEGER NOT NULL);
             INSERT INTO relay_migration_history(name, completed_at)
                 VALUES ('pre_fenced_relay_quarantine', CAST(strftime('%s', 'now') AS INTEGER) * 1000);",
        )?;
        tx.pragma_update(None, "user_version", 54)?;
        tx.commit()?;
    }
    if current_version < 55 {
        crate::hosted_auth::migrate_server_instances(conn)?;
        conn.pragma_update(None, "user_version", 55)?;
    }
    if current_version < 56 {
        let tx = conn.unchecked_transaction()?;
        let inbox_exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'relay_inbox' AND type = 'table')", [], |r| r.get(0))?;
        let queue_exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'pending_relays' AND type = 'table')", [], |r| r.get(0))?;
        if inbox_exists {
            tx.execute_batch("ALTER TABLE relay_inbox ADD COLUMN recovery_attempts INTEGER NOT NULL DEFAULT 0 CHECK(recovery_attempts >= 0);
            ALTER TABLE relay_inbox ADD COLUMN recovery_next_at INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE relay_inbox ADD COLUMN recovery_status TEXT NOT NULL DEFAULT 'ready' CHECK(recovery_status IN ('ready', 'retry', 'blocked'));
            ALTER TABLE relay_inbox ADD COLUMN recovery_error_code TEXT;
            ALTER TABLE relay_inbox ADD COLUMN recovery_last_attempt_at INTEGER;
            CREATE INDEX idx_relay_inbox_recovery ON relay_inbox(recovery_status, recovery_next_at, accepted_at) WHERE prepared_operation IS NOT NULL;")?;
        }
        if queue_exists {
            tx.execute_batch("ALTER TABLE pending_relays ADD COLUMN dispatch_generation INTEGER NOT NULL DEFAULT 0 CHECK(dispatch_generation >= 0);
            ALTER TABLE pending_relays ADD COLUMN dispatch_owner TEXT;
            ALTER TABLE pending_relays ADD COLUMN dispatch_deadline INTEGER;
            CREATE INDEX idx_pending_relays_dispatch ON pending_relays(delivery_state, next_attempt_at, dispatch_deadline, id);")?;
        }
        tx.pragma_update(None, "user_version", 56)?;
        tx.commit()?;
    }
    if current_version < 57 {
        let tx = conn.unchecked_transaction()?;
        // Conversion belongs to the application codec and is resumable after schema initialization.
        tx.execute_batch("INSERT INTO relay_migration_history(name, completed_at) VALUES ('prepared_dto_schema_ready', CAST(strftime('%s', 'now') AS INTEGER) * 1000);")?;
        tx.pragma_update(None, "user_version", 57)?;
        tx.commit()?;
    }
    if current_version < 58 {
        let tx = conn.unchecked_transaction()?;
        let queue_exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'pending_relays' AND type = 'table')", [], |r| r.get(0))?;
        if queue_exists {
            tx.execute_batch("UPDATE pending_relays SET delivery_state = 'quarantined', last_error = 'legacy_target_requires_operator_review', dispatch_owner = NULL, dispatch_deadline = NULL WHERE target_kind = 1;")?;
        }
        tx.execute_batch("INSERT INTO relay_migration_history(name, completed_at) VALUES ('legacy_relay_targets_quarantined', CAST(strftime('%s', 'now') AS INTEGER) * 1000);")?;
        tx.pragma_update(None, "user_version", 58)?;
        tx.commit()?;
    }
    if current_version < 59 {
        let tx = conn.unchecked_transaction()?;
        let source_exists: bool = tx.query_row("SELECT COUNT(*) = 3 FROM sqlite_master WHERE type = 'table' AND name IN ('relay_inbox','users','hosted_principals')", [], |r| r.get(0))?;
        if source_exists {
            crate::util::relay_acceptance_receipts::migrate_on(&tx)?;
        } else {
            // Historical migration fixtures can contain only a subset of the old schema.
            tx.execute_batch(crate::util::relay_acceptance_receipts::SCHEMA)?;
        }
        tx.pragma_update(None, "user_version", 59)?;
        tx.commit()?;
    }
    if current_version < 60 {
        let tx = conn.unchecked_transaction()?;
        let edits_exist: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'message_edits' AND type = 'table')", [], |r| r.get(0))?;
        if edits_exist {
            // Historical ciphertext epochs cannot be inferred after key rotation.
            tx.execute_batch("ALTER TABLE message_edits ADD COLUMN content_before_key_version INTEGER CHECK(content_before_key_version > 0);
                ALTER TABLE message_edits ADD COLUMN content_after_key_version INTEGER CHECK(content_after_key_version > 0);")?;
        }
        tx.pragma_update(None, "user_version", 60)?;
        tx.commit()?;
    }
    if current_version < 61 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(crate::authority_directory::SCHEMA)?;
        tx.pragma_update(None, "user_version", 61)?;
        tx.commit()?;
    }
    if current_version < 62 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(crate::peer_admission::SCHEMA)?;
        tx.pragma_update(None, "user_version", 62)?;
        tx.commit()?;
    }
    if current_version < 63 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(crate::relay_mailbox::SCHEMA)?;
        tx.pragma_update(None, "user_version", 63)?;
        tx.commit()?;
    }
    if current_version < 64 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(crate::node_transition::SCHEMA)?;
        tx.pragma_update(None, "user_version", 64)?;
        tx.commit()?;
    }
    Ok(())
}
