use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version < 31 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS principals (
                principal_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                authority_kind TEXT NOT NULL CHECK (authority_kind IN ('iota', 'omega')),
                authority_id TEXT NOT NULL,
                remote_user_id INTEGER NOT NULL,
                username TEXT,
                display_name TEXT,
                home TEXT,
                descriptor_revision INTEGER NOT NULL DEFAULT 0,
                descriptor_valid_until INTEGER,
                last_resolved_at INTEGER NOT NULL,
                UNIQUE(authority_id, remote_user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_principals_username
                ON principals (authority_id, username);
            CREATE TABLE IF NOT EXISTS principal_keys (
                principal_pk INTEGER NOT NULL REFERENCES principals(principal_pk) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                valid_from INTEGER NOT NULL,
                valid_until INTEGER,
                source_revision INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (principal_pk, public_key)
            );
            CREATE INDEX IF NOT EXISTS idx_principal_keys_validity
                ON principal_keys (principal_pk, valid_until);

            "#,
        )?;
        let users_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users')",
            [],
            |row| row.get(0),
        )?;
        if users_exist {
            conn.execute_batch(
                r#"
                INSERT OR IGNORE INTO principals (
                    authority_kind, authority_id, remote_user_id, username, display_name,
                    descriptor_revision, last_resolved_at
                )
                SELECT 'omega', 'omega:central', user_id, username, display_name, 0, created_at
                FROM users;
                INSERT OR IGNORE INTO principal_keys (
                    principal_pk, public_key, valid_from, source_revision
                )
                SELECT p.principal_pk, u.public_key, u.created_at, 0
                FROM users u
                JOIN principals p
                  ON p.authority_id = 'omega:central' AND p.remote_user_id = u.user_id;
                "#,
            )?;
        }
        for (table, column, definition) in [
            (
                "contacts",
                "principal_handle",
                "principal_handle INTEGER REFERENCES principals(principal_pk)",
            ),
            (
                "messages",
                "external_principal",
                "external_principal INTEGER REFERENCES principals(principal_pk)",
            ),
            (
                "relay_replay",
                "signer_principal",
                "signer_principal INTEGER REFERENCES principals(principal_pk)",
            ),
            (
                "relay_inbox",
                "signer_principal",
                "signer_principal INTEGER REFERENCES principals(principal_pk)",
            ),
            (
                "pending_relays",
                "destination_principal",
                "destination_principal INTEGER REFERENCES principals(principal_pk)",
            ),
            (
                "blocked_users",
                "blocked_principal",
                "blocked_principal INTEGER REFERENCES principals(principal_pk)",
            ),
        ] {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )?;
            if exists {
                add_table_column_if_missing(conn, table, column, definition)?;
            }
        }
        let contacts_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'contacts')",
            [],
            |row| row.get(0),
        )?;
        if contacts_exist {
            conn.execute(
                r#"UPDATE contacts SET principal_handle = (
                       SELECT principal_pk FROM principals
                       WHERE authority_id = 'omega:central' AND remote_user_id = contacts.user_id
                   ) WHERE principal_handle IS NULL"#,
                [],
            )?;
        }
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            conn.execute(
                r#"UPDATE messages SET external_principal = (
                       SELECT principal_pk FROM principals
                       WHERE authority_id = 'omega:central' AND remote_user_id = messages.external_user
                   ) WHERE external_principal IS NULL"#,
                [],
            )?;
        }
        conn.pragma_update(None, "user_version", 31)?;
    }

    if current_version < 32 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS identity_configuration (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                omega_authority_id TEXT NOT NULL
            );
            "#,
        )?;
        for (table, trigger) in [
            (
                "contacts",
                "CREATE TRIGGER IF NOT EXISTS contacts_assign_principal_after_insert AFTER INSERT ON contacts WHEN NEW.principal_handle IS NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.user_id, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.user_id > 0; UPDATE contacts SET principal_handle = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.user_id) WHERE rowid = NEW.rowid; END;",
            ),
            (
                "messages",
                "CREATE TRIGGER IF NOT EXISTS messages_assign_principal_after_insert AFTER INSERT ON messages WHEN NEW.external_principal IS NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.external_user, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.external_user > 0; UPDATE messages SET external_principal = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.external_user) WHERE rowid = NEW.rowid; END;",
            ),
            (
                "relay_replay",
                "CREATE TRIGGER IF NOT EXISTS relay_replay_assign_principal_after_insert AFTER INSERT ON relay_replay WHEN NEW.signer_principal IS NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.signer_id, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.signer_id > 0; UPDATE relay_replay SET signer_principal = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.signer_id) WHERE rowid = NEW.rowid; END;",
            ),
            (
                "relay_inbox",
                "CREATE TRIGGER IF NOT EXISTS relay_inbox_assign_principal_after_insert AFTER INSERT ON relay_inbox WHEN NEW.signer_principal IS NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.signer_id, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.signer_id > 0; UPDATE relay_inbox SET signer_principal = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.signer_id) WHERE rowid = NEW.rowid; END;",
            ),
            (
                "pending_relays",
                "CREATE TRIGGER IF NOT EXISTS pending_relays_assign_principal_after_insert AFTER INSERT ON pending_relays WHEN NEW.destination_principal IS NULL AND NEW.relay_destination_user_id IS NOT NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.relay_destination_user_id, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.relay_destination_user_id > 0; UPDATE pending_relays SET destination_principal = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.relay_destination_user_id) WHERE rowid = NEW.rowid; END; CREATE TRIGGER IF NOT EXISTS pending_relays_assign_principal_after_update AFTER UPDATE OF relay_destination_user_id ON pending_relays WHEN NEW.destination_principal IS NULL AND NEW.relay_destination_user_id IS NOT NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.relay_destination_user_id, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.relay_destination_user_id > 0; UPDATE pending_relays SET destination_principal = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.relay_destination_user_id) WHERE rowid = NEW.rowid; END;",
            ),
            (
                "blocked_users",
                "CREATE TRIGGER IF NOT EXISTS blocked_users_assign_principal_after_insert AFTER INSERT ON blocked_users WHEN NEW.blocked_principal IS NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.blocked_user_id, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.blocked_user_id > 0; UPDATE blocked_users SET blocked_principal = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.blocked_user_id) WHERE rowid = NEW.rowid; END;",
            ),
        ] {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )?;
            if exists {
                conn.execute_batch(trigger)?;
            }
        }
        conn.pragma_update(None, "user_version", 32)?;
    }

    if current_version < 33 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS relay_replay (
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                signer_principal INTEGER REFERENCES principals(principal_pk),
                PRIMARY KEY (signer_id, message_id)
            );
            CREATE TABLE IF NOT EXISTS relay_inbox (
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                destination_id INTEGER NOT NULL,
                frame BLOB NOT NULL,
                type_map_version TEXT NOT NULL,
                frame_id INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('received', 'applied', 'queued', 'delivered', 'rejected')),
                accepted_at INTEGER,
                applied_at INTEGER,
                queued_at INTEGER,
                downstream_acked_at INTEGER,
                rejected_at INTEGER,
                signer_principal INTEGER REFERENCES principals(principal_pk),
                PRIMARY KEY (signer_id, message_id)
            );
            DROP TRIGGER IF EXISTS relay_replay_assign_principal_after_insert;
            DROP TRIGGER IF EXISTS relay_inbox_assign_principal_after_insert;

            INSERT OR IGNORE INTO principals (
                authority_kind, authority_id, remote_user_id,
                descriptor_revision, last_resolved_at
            )
            SELECT 'omega', 'omega:central', signer_id, 0, 0
            FROM relay_replay
            WHERE signer_principal IS NULL AND signer_id > 0;
            INSERT OR IGNORE INTO principals (
                authority_kind, authority_id, remote_user_id,
                descriptor_revision, last_resolved_at
            )
            SELECT 'omega', 'omega:central', signer_id, 0, 0
            FROM relay_inbox
            WHERE signer_principal IS NULL AND signer_id > 0;
            UPDATE relay_replay
            SET signer_principal = (
                SELECT principal_pk FROM principals
                WHERE authority_id = 'omega:central'
                  AND remote_user_id = relay_replay.signer_id
            )
            WHERE signer_principal IS NULL;
            UPDATE relay_inbox
            SET signer_principal = (
                SELECT principal_pk FROM principals
                WHERE authority_id = 'omega:central'
                  AND remote_user_id = relay_inbox.signer_id
            )
            WHERE signer_principal IS NULL;

            CREATE TABLE relay_replay_v33 (
                signer_principal INTEGER NOT NULL REFERENCES principals(principal_pk),
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (signer_principal, message_id)
            );
            INSERT INTO relay_replay_v33
                (signer_principal, signer_id, message_id, created_at)
            SELECT signer_principal, signer_id, message_id, created_at
            FROM relay_replay;
            DROP TABLE relay_replay;
            ALTER TABLE relay_replay_v33 RENAME TO relay_replay;
            CREATE INDEX idx_relay_replay_created_at ON relay_replay (created_at);

            CREATE TABLE relay_inbox_v33 (
                signer_principal INTEGER NOT NULL REFERENCES principals(principal_pk),
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                destination_id INTEGER NOT NULL,
                frame BLOB NOT NULL,
                type_map_version TEXT NOT NULL,
                frame_id INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('received', 'applied', 'queued', 'delivered', 'rejected')),
                accepted_at INTEGER,
                applied_at INTEGER,
                queued_at INTEGER,
                downstream_acked_at INTEGER,
                rejected_at INTEGER,
                PRIMARY KEY (signer_principal, message_id)
            );
            INSERT INTO relay_inbox_v33 (
                signer_principal, signer_id, message_id, created_at,
                destination_id, frame, type_map_version, frame_id, state,
                accepted_at, applied_at, queued_at, downstream_acked_at, rejected_at
            )
            SELECT signer_principal, signer_id, message_id, created_at,
                   destination_id, frame, type_map_version, frame_id, state,
                   accepted_at, applied_at, queued_at, downstream_acked_at, rejected_at
            FROM relay_inbox;
            DROP TABLE relay_inbox;
            ALTER TABLE relay_inbox_v33 RENAME TO relay_inbox;
            CREATE INDEX idx_relay_inbox_state ON relay_inbox (state, created_at);
            "#,
        )?;
        conn.pragma_update(None, "user_version", 33)?;
    }

    if current_version < 34 {
        let pending_relays_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_relays')",
            [],
            |row| row.get(0),
        )?;
        if pending_relays_exist {
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "signer_principal",
                "signer_principal INTEGER REFERENCES principals(principal_pk)",
            )?;
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "destination_node_id",
                "destination_node_id TEXT",
            )?;
            add_table_column_if_missing(
                conn,
                "pending_relays",
                "destination_authority_id",
                "destination_authority_id TEXT",
            )?;
            conn.execute_batch(
                r#"
                DROP TRIGGER IF EXISTS pending_relays_assign_principal_after_insert;
                DROP TRIGGER IF EXISTS pending_relays_assign_principal_after_update;
                UPDATE pending_relays
                SET signer_principal = (
                    SELECT p.principal_pk
                    FROM principals p
                    JOIN identity_configuration c
                      ON c.singleton = 1 AND p.authority_id = c.omega_authority_id
                    WHERE p.remote_user_id = pending_relays.relay_signer_id
                )
                WHERE signer_principal IS NULL AND relay_signer_id IS NOT NULL;
                UPDATE pending_relays
                SET destination_authority_id = (
                    SELECT omega_authority_id FROM identity_configuration WHERE singleton = 1
                )
                WHERE target_kind = 1 AND destination_authority_id IS NULL;
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 34)?;
    }

    if current_version < 35 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS hosted_principals (
                local_user_id INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                principal_handle INTEGER NOT NULL UNIQUE REFERENCES principals(principal_pk)
            );
            "#,
        )?;
        let users_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users')",
            [],
            |row| row.get(0),
        )?;
        if users_exist {
            conn.execute_batch(
                r#"
                INSERT OR IGNORE INTO hosted_principals (local_user_id, principal_handle)
                SELECT u.user_id, p.principal_pk
                FROM users u
                JOIN principals p ON p.remote_user_id = u.user_id
                JOIN identity_configuration c
                  ON c.singleton = 1 AND p.authority_id = c.omega_authority_id;
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 35)?;
    }

    if current_version < 36 {
        let contacts_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'contacts')",
            [],
            |row| row.get(0),
        )?;
        if contacts_exist {
            conn.execute_batch(
                r#"
                INSERT OR IGNORE INTO principals (
                    authority_kind, authority_id, remote_user_id,
                    descriptor_revision, last_resolved_at
                )
                SELECT 'omega',
                       COALESCE(
                           (SELECT omega_authority_id FROM identity_configuration WHERE singleton = 1),
                           'omega:central'
                       ),
                       user_id, 0, 0
                FROM contacts
                WHERE principal_handle IS NULL;
                UPDATE contacts
                SET principal_handle = (
                    SELECT principal_pk
                    FROM principals
                    WHERE authority_id = COALESCE(
                              (SELECT omega_authority_id FROM identity_configuration WHERE singleton = 1),
                              'omega:central'
                          )
                      AND remote_user_id = contacts.user_id
                )
                WHERE principal_handle IS NULL;
                DROP TRIGGER IF EXISTS contacts_assign_principal_after_insert;
                CREATE TABLE contacts_v36 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    storage_owner INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    principal_handle INTEGER REFERENCES principals(principal_pk),
                    user_name TEXT,
                    created_at INTEGER NOT NULL,
                    last_message_at INTEGER,
                    notifications INTEGER NOT NULL DEFAULT 0,
                    notifications_read_at INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(storage_owner, principal_handle)
                );
                INSERT INTO contacts_v36 (
                    id, storage_owner, user_id, principal_handle, user_name, created_at,
                    last_message_at, notifications, notifications_read_at
                )
                SELECT id, storage_owner, user_id, principal_handle, user_name, created_at,
                       last_message_at, notifications, notifications_read_at
                FROM contacts;
                DROP TABLE contacts;
                ALTER TABLE contacts_v36 RENAME TO contacts;
                CREATE INDEX idx_contacts_owner
                    ON contacts (storage_owner, last_message_at DESC, user_id ASC);
                CREATE TRIGGER contacts_assign_principal_after_insert
                AFTER INSERT ON contacts
                WHEN NEW.principal_handle IS NULL
                BEGIN
                    INSERT OR IGNORE INTO principals (
                        authority_kind, authority_id, remote_user_id,
                        descriptor_revision, last_resolved_at
                    )
                    SELECT 'omega', omega_authority_id, NEW.user_id, 0, 0
                    FROM identity_configuration
                    WHERE singleton = 1 AND NEW.user_id > 0;
                    UPDATE contacts
                    SET principal_handle = (
                        SELECT p.principal_pk
                        FROM principals p
                        JOIN identity_configuration c
                          ON c.singleton = 1 AND p.authority_id = c.omega_authority_id
                        WHERE p.remote_user_id = NEW.user_id
                    )
                    WHERE rowid = NEW.rowid;
                END;
                "#,
            )?;
        }
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_principal_lookup ON messages (storage_owner, external_principal, message_time DESC)",
                [],
            )?;
        }
        conn.pragma_update(None, "user_version", 36)?;
    }

    if current_version < 37 {
        let blocked_users_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'blocked_users')",
            [],
            |row| row.get(0),
        )?;
        if blocked_users_exist {
            conn.execute_batch(
                r#"
                INSERT OR IGNORE INTO principals (
                    authority_kind, authority_id, remote_user_id,
                    descriptor_revision, last_resolved_at
                )
                SELECT 'omega',
                       COALESCE(
                           (SELECT omega_authority_id FROM identity_configuration WHERE singleton = 1),
                           'omega:central'
                       ),
                       blocked_user_id, 0, 0
                FROM blocked_users
                WHERE blocked_principal IS NULL;
                UPDATE blocked_users
                SET blocked_principal = (
                    SELECT principal_pk
                    FROM principals
                    WHERE authority_id = COALESCE(
                              (SELECT omega_authority_id FROM identity_configuration WHERE singleton = 1),
                              'omega:central'
                          )
                      AND remote_user_id = blocked_users.blocked_user_id
                )
                WHERE blocked_principal IS NULL;
                DROP TRIGGER IF EXISTS blocked_users_assign_principal_after_insert;
                CREATE TABLE blocked_users_v37 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    blocked_user_id INTEGER NOT NULL,
                    blocked_principal INTEGER NOT NULL REFERENCES principals(principal_pk),
                    revision INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(user_id, blocked_principal)
                );
                INSERT INTO blocked_users_v37 (
                    id, user_id, blocked_user_id, blocked_principal, revision, created_at
                )
                SELECT id, user_id, blocked_user_id, blocked_principal, revision, created_at
                FROM blocked_users;
                DROP TABLE blocked_users;
                ALTER TABLE blocked_users_v37 RENAME TO blocked_users;
                CREATE INDEX idx_blocked_users_owner ON blocked_users (user_id);
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 37)?;
    }

    if current_version < 38 {
        let messages_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |row| row.get(0),
        )?;
        if messages_exist {
            add_table_column_if_missing(
                conn,
                "messages",
                "relay_signer_principal",
                "relay_signer_principal INTEGER REFERENCES principals(principal_pk)",
            )?;
            conn.execute_batch(
                r#"
                UPDATE messages
                SET relay_signer_principal = CASE
                    WHEN sent_by_self = 1 THEN (
                        SELECT principal_handle FROM hosted_principals
                        WHERE local_user_id = messages.storage_owner
                    )
                    ELSE external_principal
                END
                WHERE relay_signer_principal IS NULL;
                DROP INDEX IF EXISTS idx_messages_relay_identity;
                CREATE UNIQUE INDEX idx_messages_relay_principal_identity
                    ON messages (storage_owner, relay_signer_principal, relay_message_id)
                    WHERE relay_signer_principal IS NOT NULL AND relay_message_id IS NOT NULL;
                CREATE UNIQUE INDEX idx_messages_legacy_relay_identity
                    ON messages (storage_owner, relay_signer_id, relay_message_id)
                    WHERE relay_signer_principal IS NULL AND relay_message_id IS NOT NULL;
                "#,
            )?;
        }

        let reactions_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'reactions')",
            [],
            |row| row.get(0),
        )?;
        if reactions_exist {
            add_table_column_if_missing(
                conn,
                "reactions",
                "user_principal",
                "user_principal INTEGER REFERENCES principals(principal_pk)",
            )?;
            conn.execute_batch(
                r#"
                UPDATE reactions
                SET user_principal = CASE
                    WHEN user_id = (SELECT storage_owner FROM messages WHERE id = reactions.message_id)
                        THEN (SELECT hp.principal_handle FROM hosted_principals hp
                              JOIN messages m ON m.storage_owner = hp.local_user_id
                              WHERE m.id = reactions.message_id)
                    WHEN user_id = (SELECT external_user FROM messages WHERE id = reactions.message_id)
                        THEN (SELECT external_principal FROM messages WHERE id = reactions.message_id)
                END
                WHERE user_principal IS NULL;
                DROP INDEX IF EXISTS idx_reactions_msg;
                DROP INDEX IF EXISTS idx_reactions_principal_identity;
                ALTER TABLE reactions RENAME TO reactions_v37;
                CREATE TABLE reactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id INTEGER NOT NULL REFERENCES messages(id),
                    user_id INTEGER NOT NULL,
                    user_principal INTEGER REFERENCES principals(principal_pk),
                    reaction TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                INSERT INTO reactions (
                    id, message_id, user_id, user_principal, reaction, created_at
                )
                SELECT id, message_id, user_id, user_principal, reaction, created_at
                FROM reactions_v37;
                DROP TABLE reactions_v37;
                CREATE INDEX idx_reactions_msg
                    ON reactions (message_id, reaction);
                CREATE UNIQUE INDEX idx_reactions_principal_identity
                    ON reactions (message_id, user_principal, reaction)
                    WHERE user_principal IS NOT NULL;
                CREATE UNIQUE INDEX idx_reactions_legacy_identity
                    ON reactions (message_id, user_id, reaction)
                    WHERE user_principal IS NULL;
                "#,
            )?;
        }

        let receipts_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'message_receipts')",
            [],
            |row| row.get(0),
        )?;
        if receipts_exist {
            add_table_column_if_missing(
                conn,
                "message_receipts",
                "target_signer_principal",
                "target_signer_principal INTEGER REFERENCES principals(principal_pk)",
            )?;
            add_table_column_if_missing(
                conn,
                "message_receipts",
                "receipt_signer_principal",
                "receipt_signer_principal INTEGER REFERENCES principals(principal_pk)",
            )?;
            conn.execute_batch(
                r#"
                UPDATE message_receipts
                SET target_signer_principal = (
                        SELECT relay_signer_principal FROM messages
                        WHERE storage_owner = message_receipts.storage_owner
                          AND relay_signer_id = message_receipts.target_signer_id
                          AND relay_message_id = message_receipts.target_message_id
                    ),
                    receipt_signer_principal = (
                        SELECT external_principal FROM messages
                        WHERE storage_owner = message_receipts.storage_owner
                          AND relay_signer_id = message_receipts.target_signer_id
                          AND relay_message_id = message_receipts.target_message_id
                    )
                WHERE target_signer_principal IS NULL OR receipt_signer_principal IS NULL;
                DROP INDEX IF EXISTS idx_message_receipts_target;
                DROP INDEX IF EXISTS idx_message_receipts_principal_identity;
                DROP INDEX IF EXISTS idx_message_receipts_principal_target;
                ALTER TABLE message_receipts RENAME TO message_receipts_v37;
                CREATE TABLE message_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    storage_owner INTEGER NOT NULL,
                    target_signer_id INTEGER NOT NULL,
                    target_signer_principal INTEGER REFERENCES principals(principal_pk),
                    target_message_id TEXT NOT NULL,
                    receipt_signer_id INTEGER NOT NULL,
                    receipt_signer_principal INTEGER REFERENCES principals(principal_pk),
                    receipt_message_id TEXT NOT NULL,
                    receipt_type TEXT NOT NULL CHECK (receipt_type IN ('received', 'read')),
                    event_at INTEGER NOT NULL,
                    recorded_at INTEGER NOT NULL
                );
                INSERT INTO message_receipts (
                    id, storage_owner, target_signer_id, target_signer_principal,
                    target_message_id, receipt_signer_id, receipt_signer_principal,
                    receipt_message_id, receipt_type, event_at, recorded_at
                )
                SELECT id, storage_owner, target_signer_id, target_signer_principal,
                       target_message_id, receipt_signer_id, receipt_signer_principal,
                       receipt_message_id, receipt_type, event_at, recorded_at
                FROM message_receipts_v37;
                DROP TABLE message_receipts_v37;
                CREATE UNIQUE INDEX idx_message_receipts_principal_message
                    ON message_receipts (receipt_signer_principal, receipt_message_id)
                    WHERE receipt_signer_principal IS NOT NULL;
                CREATE UNIQUE INDEX idx_message_receipts_principal_identity
                    ON message_receipts (
                        storage_owner, target_signer_principal, target_message_id,
                        receipt_signer_principal, receipt_type
                    )
                    WHERE target_signer_principal IS NOT NULL
                      AND receipt_signer_principal IS NOT NULL;
                CREATE UNIQUE INDEX idx_message_receipts_legacy_message
                    ON message_receipts (receipt_signer_id, receipt_message_id)
                    WHERE receipt_signer_principal IS NULL;
                CREATE UNIQUE INDEX idx_message_receipts_legacy_identity
                    ON message_receipts (
                        storage_owner, target_signer_id, target_message_id,
                        receipt_signer_id, receipt_type
                    )
                    WHERE target_signer_principal IS NULL
                      AND receipt_signer_principal IS NULL;
                CREATE INDEX idx_message_receipts_principal_target
                    ON message_receipts (storage_owner, target_signer_principal, target_message_id);
                "#,
            )?;
        }
        conn.pragma_update(None, "user_version", 38)?;
    }

    if current_version < 39 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS local_identity_allocator (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_user_id INTEGER NOT NULL
            );
            "#,
        )?;
        let users_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users')",
            [],
            |row| row.get(0),
        )?;
        if users_exist {
            conn.execute(
                "INSERT OR IGNORE INTO local_identity_allocator (singleton, next_user_id) SELECT 1, COALESCE(MAX(user_id), 0) + 1 FROM users",
                [],
            )?;
        } else {
            conn.execute(
                "INSERT OR IGNORE INTO local_identity_allocator (singleton, next_user_id) VALUES (1, 1)",
                [],
            )?;
        }
        let principals_exist: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'principals')",
            [],
            |row| row.get(0),
        )?;
        if principals_exist {
            add_table_column_if_missing(conn, "principals", "retired_at", "retired_at INTEGER")?;
        }
        conn.pragma_update(None, "user_version", 39)?;
    }

    if current_version < 40 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS node_directory (
                node_id TEXT PRIMARY KEY,
                descriptor_revision INTEGER NOT NULL,
                descriptor_valid_until INTEGER,
                direct_endpoints TEXT NOT NULL,
                relay_hints TEXT NOT NULL,
                last_successful_endpoint TEXT,
                last_resolved_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS node_keys (
                node_id TEXT NOT NULL REFERENCES node_directory(node_id) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                valid_from INTEGER NOT NULL,
                valid_until INTEGER,
                source_revision INTEGER NOT NULL,
                PRIMARY KEY (node_id, public_key)
            );
            CREATE TABLE IF NOT EXISTS node_endpoint_pins (
                endpoint TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                pinned_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_node_keys_validity
                ON node_keys (node_id, valid_until);
            PRAGMA user_version = 40;
            "#,
        )?;
    }

    Ok(())
}
