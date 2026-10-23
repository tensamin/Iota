use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version < 21 {
        let users_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users')",
            [],
            |row| row.get(0),
        )?;
        if users_exist {
            conn.execute_batch(
                r#"
                ALTER TABLE users RENAME TO users_before_credential_origin;
                CREATE TABLE users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    public_key TEXT NOT NULL,
                    private_key_hash TEXT,
                    reset_token TEXT,
                    created_at INTEGER NOT NULL,
                    display_name TEXT
                );
                INSERT INTO users (user_id, username, public_key, private_key_hash, reset_token, created_at, display_name)
                    SELECT user_id, username, public_key, private_key_hash, reset_token, created_at, display_name
                    FROM users_before_credential_origin;
                DROP TABLE users_before_credential_origin;
                "#,
            )?;
        }
        let residency_exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_residency')",
            [],
            |row| row.get(0),
        )?;
        if residency_exists {
            add_table_column_if_missing(
                conn,
                "user_residency",
                "credential_origin",
                "credential_origin TEXT NOT NULL DEFAULT 'local' CHECK (credential_origin IN ('local', 'external'))",
            )?;
        }
        conn.pragma_update(None, "user_version", 21)?;
    }

    if current_version < 22 {
        let pending_exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_user_operations')",
            [],
            |row| row.get(0),
        )?;
        if pending_exists {
            conn.execute_batch(
                r#"
                ALTER TABLE pending_user_operations RENAME TO pending_user_operations_before_purge;
                CREATE TABLE pending_user_operations (
                    user_id INTEGER PRIMARY KEY,
                    operation TEXT NOT NULL
                        CHECK (operation IN ('create', 'attach', 'release', 'purge')),
                    username TEXT NOT NULL,
                    public_key TEXT,
                    private_key_hash TEXT,
                    reset_token TEXT,
                    registration_token TEXT,
                    phase TEXT NOT NULL DEFAULT 'prepared'
                        CHECK (phase IN (
                            'prepared', 'credential_written', 'remote_committed', 'local_committed',
                            'database_purged', 'e2ee_purged', 'filesystem_purged'
                        )),
                    created_at INTEGER NOT NULL
                );
                INSERT INTO pending_user_operations (
                    user_id, operation, username, public_key, private_key_hash,
                    reset_token, registration_token, phase, created_at
                )
                SELECT user_id, operation, username, public_key, private_key_hash,
                       reset_token, registration_token, phase, created_at
                FROM pending_user_operations_before_purge;
                DROP TABLE pending_user_operations_before_purge;
                CREATE INDEX idx_pending_user_operations_operation
                    ON pending_user_operations (operation, created_at);
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 22)?;
    }

    if current_version < 23 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS user_invitations (
                invitation_id TEXT PRIMARY KEY,
                token_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                state TEXT NOT NULL CHECK (state IN ('pending', 'redeemed', 'revoked', 'expired')),
                redeemed_user_id INTEGER,
                redeemed_at INTEGER,
                revoked_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_user_invitations_state_created
                ON user_invitations (state, created_at);
            PRAGMA user_version = 23;
            "#,
        )?;
    }

    if current_version < 24 {
        let pending_relays_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_relays')",
            [],
            |row| row.get(0),
        )?;
        if pending_relays_exist {
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "delivery_state",
                "delivery_state TEXT NOT NULL DEFAULT 'ready' CHECK (delivery_state IN ('ready', 'waiting_client', 'quarantined'))",
            )?;
            add_table_column_if_missing(conn, "pending_relays", "last_error", "last_error TEXT")?;
            conn.execute_batch(
                r#"
                UPDATE pending_relays
                SET delivery_state = 'quarantined', last_error = 'target_recipient_mismatch'
                WHERE target_kind = 0
                  AND relay_destination_user_id IS NOT NULL
                  AND destination_id <> relay_destination_user_id;
                CREATE INDEX IF NOT EXISTS idx_pending_relays_active
                    ON pending_relays (delivery_state, target_kind, destination_id, id);
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 24)?;
    }

    if current_version < 25 {
        let contacts_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'contacts')",
            [],
            |row| row.get(0),
        )?;
        if contacts_exist {
            add_table_column_if_missing(
                conn,
                "contacts",
                "notifications",
                "notifications INTEGER NOT NULL DEFAULT 0",
            )?;
            add_table_column_if_missing(
                conn,
                "contacts",
                "notifications_read_at",
                "notifications_read_at INTEGER NOT NULL DEFAULT 0",
            )?;
            conn.execute(
                "UPDATE contacts SET notifications_read_at = COALESCE(last_message_at, 0) WHERE notifications_read_at = 0 AND notifications = 0",
                [],
            )?;
        }
        conn.pragma_update(None, "user_version", 25)?;
    }

    if current_version < 27 {
        let invitation_exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_invitations')",
            [],
            |row| row.get(0),
        )?;
        if invitation_exists {
            conn.execute_batch(
                r#"
                ALTER TABLE user_invitations RENAME TO user_invitations_before_authority;
                CREATE TABLE user_invitations (
                    invitation_id INTEGER PRIMARY KEY,
                    authority TEXT NOT NULL CHECK (authority IN ('omega', 'iota')),
                    token_hash BLOB NOT NULL,
                    label TEXT,
                    password_protected INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    state TEXT NOT NULL CHECK (state IN ('pending', 'provisioning', 'redeemed', 'revoked', 'expired')),
                    redeemed_user_id INTEGER,
                    redeemed_at INTEGER,
                    revoked_at INTEGER,
                    local_revocation_pending INTEGER NOT NULL DEFAULT 0
                );
                /* Omega owns these mirror records. Historical string identifiers
                   cannot be mapped safely into Omega's numeric namespace, so a
                   fresh authoritative snapshot rebuilds them after reconnect. */
                DROP TABLE user_invitations_before_authority;
                CREATE INDEX idx_user_invitations_state_created
                    ON user_invitations (state, created_at);
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 27)?;
    }

    if current_version < 26 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS client_device_sync_state (
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                acknowledged_version INTEGER NOT NULL,
                cache_schema_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, device_id)
            );
            "#,
        )?;
        conn.pragma_update(None, "user_version", 27)?;
    }

    if current_version < 28 {
        let invitation_exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_invitations')",
            [],
            |row| row.get(0),
        )?;
        if invitation_exists {
            conn.execute_batch(
                r#"
                ALTER TABLE user_invitations RENAME TO user_invitations_before_revision;
                CREATE TABLE user_invitations (
                    invitation_id INTEGER PRIMARY KEY,
                    authority TEXT NOT NULL CHECK (authority IN ('omega', 'iota')),
                    token_hash BLOB,
                    label TEXT,
                    password_protected INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    state TEXT NOT NULL CHECK (state IN ('pending', 'provisioning', 'redeemed', 'revoked', 'expired')),
                    redeemed_user_id INTEGER,
                    redeemed_at INTEGER,
                    revoked_at INTEGER,
                    pending_action TEXT CHECK (pending_action IS NULL OR pending_action = 'revoke'),
                    pending_action_at INTEGER,
                    remote_revision INTEGER NOT NULL DEFAULT 0,
                    last_synced_at INTEGER
                );
                INSERT INTO user_invitations (
                    invitation_id, authority, token_hash, label, password_protected,
                    created_at, expires_at, state, redeemed_user_id, redeemed_at,
                    revoked_at, pending_action, pending_action_at
                )
                SELECT invitation_id, authority,
                       CASE WHEN authority = 'iota' THEN token_hash ELSE NULL END,
                       label, password_protected, created_at, expires_at, state,
                       redeemed_user_id, redeemed_at, revoked_at,
                       CASE WHEN local_revocation_pending = 1 THEN 'revoke' ELSE NULL END,
                       CASE WHEN local_revocation_pending = 1 THEN revoked_at ELSE NULL END
                FROM user_invitations_before_revision;
                DROP TABLE user_invitations_before_revision;
                CREATE INDEX idx_user_invitations_state_created
                    ON user_invitations (state, created_at);
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 28)?;
    }

    if current_version < 29 {
        conn.execute_batch(
            "ALTER TABLE user_invitations ADD COLUMN local_provisioned_user_id INTEGER; \
             ALTER TABLE user_invitations ADD COLUMN local_provisioned_at INTEGER;",
        )?;
        conn.pragma_update(None, "user_version", 29)?;
    }

    if current_version < 30 {
        conn.execute_batch(
            r#"
            ALTER TABLE user_invitations RENAME TO user_invitations_before_composite_key;
            CREATE TABLE user_invitations (
                invitation_id INTEGER NOT NULL,
                authority TEXT NOT NULL CHECK (authority IN ('omega', 'iota')),
                token_hash BLOB,
                label TEXT,
                password_protected INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                state TEXT NOT NULL CHECK (state IN ('pending', 'provisioning', 'redeemed', 'revoked', 'expired')),
                redeemed_user_id INTEGER,
                redeemed_at INTEGER,
                revoked_at INTEGER,
                pending_action TEXT CHECK (pending_action IS NULL OR pending_action = 'revoke'),
                pending_action_at INTEGER,
                remote_revision INTEGER NOT NULL DEFAULT 0,
                last_synced_at INTEGER,
                local_provisioned_user_id INTEGER,
                local_provisioned_at INTEGER,
                PRIMARY KEY (authority, invitation_id)
            );
            INSERT INTO user_invitations
            SELECT * FROM user_invitations_before_composite_key;
            DROP TABLE user_invitations_before_composite_key;
            CREATE INDEX idx_user_invitations_state_created
                ON user_invitations (authority, state, created_at);
            PRAGMA user_version = 30;
            "#,
        )?;
    }

    Ok(())
}
