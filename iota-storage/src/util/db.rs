use once_cell::sync::OnceCell;
use r2d2::ManageConnection;
use rusqlite::{Connection, Transaction};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::storage_error::StorageError;

const DB_NAME: &str = "messages";

/// A simple r2d2 manager for rusqlite connections.
pub struct SqliteManager {
    database_path: PathBuf,
}

impl ManageConnection for SqliteManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Connection, rusqlite::Error> {
        let conn = Connection::open(&self.database_path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        conn.busy_timeout(Duration::from_millis(250))?;
        Ok(conn)
    }

    fn is_valid(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch("SELECT 1")
    }

    fn has_broken(&self, _conn: &mut Connection) -> bool {
        false
    }
}

static POOL: OnceCell<Arc<r2d2::Pool<SqliteManager>>> = OnceCell::new();

fn create_pool(database_path: PathBuf) -> Result<Arc<r2d2::Pool<SqliteManager>>, StorageError> {
    create_pool_with_timeout(database_path, Duration::from_secs(30))
}

fn create_pool_with_timeout(
    database_path: PathBuf,
    connection_timeout: Duration,
) -> Result<Arc<r2d2::Pool<SqliteManager>>, StorageError> {
    let manager = SqliteManager { database_path };
    let pool = r2d2::Pool::builder()
        .max_size(8)
        .connection_timeout(connection_timeout)
        .build(manager)
        .map_err(|error| StorageError::Pool(error.to_string()))?;
    run_migrations(&pool)?;
    Ok(Arc::new(pool))
}

/// Opens the SQLite pool and applies all schema migrations.
///
/// Daemon startup calls this after database verification and before storage is
/// reported healthy, so connection and migration failures become a storage
/// component failure instead of a lazy-initialization panic.
pub fn initialize_database() -> Result<(), StorageError> {
    let storage_dir = iota_util::file_util::storage_directory();
    std::fs::create_dir_all(&storage_dir)?;
    let database_path = storage_dir.join(format!("{DB_NAME}.sqlite3"));
    POOL.get_or_try_init(|| create_pool(database_path))?;
    Ok(())
}

pub fn pool() -> Result<Arc<r2d2::Pool<SqliteManager>>, StorageError> {
    POOL.get()
        .cloned()
        .ok_or_else(|| StorageError::Other("database has not been initialized".into()))
}

pub fn with_db<T, F>(f: F) -> Result<T, StorageError>
where
    F: FnOnce(&Connection) -> Result<T, StorageError>,
{
    blocking_region(|| {
        let pool = pool()?;
        let conn = pool.get().map_err(|e| StorageError::Pool(e.to_string()))?;
        f(&conn)
    })
}

pub fn with_immediate_transaction<T, F>(f: F) -> Result<T, StorageError>
where
    F: FnOnce(&Transaction<'_>) -> Result<T, StorageError>,
{
    blocking_region(|| {
        let pool = pool()?;
        let mut conn = pool.get().map_err(|e| StorageError::Pool(e.to_string()))?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    })
}

/* SQLite remains synchronous, but daemon transports run on Tokio. Entering a
 * blocking region lets Tokio replace the worker that is waiting on the bounded
 * eight-connection pool, so database latency cannot stall unrelated I/O. A
 * current-thread runtime (used by unit tests and small tools) has no worker to
 * hand off and therefore executes directly. */
fn blocking_region<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/* Verify the persistent database before the pool is initialized. A corrupt
 * database is moved aside rather than opened again, preserving material for
 * operator recovery while allowing the daemon to report the failed storage. */
pub fn verify_and_backup_database() -> Result<(), StorageError> {
    let storage_dir = iota_util::file_util::storage_directory();
    std::fs::create_dir_all(&storage_dir)?;
    let path = storage_dir.join(format!("{DB_NAME}.sqlite3"));
    if !path.exists() {
        return Ok(());
    }

    let connection = Connection::open(&path)?;
    connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
    connection.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    drop(connection);
    if integrity != "ok" {
        let recovery = storage_dir.join("recovery");
        std::fs::create_dir_all(&recovery)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for suffix in ["", "-wal", "-shm"] {
            let source = PathBuf::from(format!("{}{}", path.display(), suffix));
            if source.exists() {
                let destination = recovery.join(format!("{DB_NAME}.sqlite3.{timestamp}{suffix}"));
                std::fs::rename(source, destination)?;
            }
        }
        return Err(StorageError::Other(format!(
            "database integrity check failed ({integrity}); moved database files to {}",
            recovery.display()
        )));
    }

    let backup_dir = storage_dir.join("backups");
    std::fs::create_dir_all(&backup_dir)?;
    let backup = backup_dir.join(format!("{DB_NAME}.sqlite3"));
    let temporary = backup_dir.join(format!(".{DB_NAME}.sqlite3.tmp"));
    std::fs::copy(&path, &temporary)?;
    std::fs::File::open(&temporary)?.sync_all()?;
    std::fs::rename(temporary, backup)?;
    Ok(())
}

fn db_file_path(db_name: &str) -> PathBuf {
    let storage_dir = iota_util::file_util::storage_directory();
    // Creating storage belongs to initialization/connection setup, never to a
    // configuration read.
    std::fs::create_dir_all(&storage_dir).expect("create Iota storage directory");
    storage_dir.join(format!("{db_name}.sqlite3"))
}

fn run_migrations(pool: &r2d2::Pool<SqliteManager>) -> Result<(), StorageError> {
    let conn = pool.get().map_err(|e| StorageError::Pool(e.to_string()))?;
    run_migrations_on_connection(&conn)
}

/*
 * Older builds could apply a schema change without advancing user_version.
 * Check each added column so those databases can resume upgrading.
 */
fn add_column_if_missing(
    conn: &Connection,
    column: &str,
    definition: &str,
) -> Result<(), StorageError> {
    add_table_column_if_missing(conn, "messages", column, definition)
}

fn add_table_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), StorageError> {
    let mut statement = conn.prepare(&format!(
        "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
    ))?;
    let exists = statement.exists([column])?;

    if !exists {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {definition};"))?;
    }

    Ok(())
}

fn run_migrations_on_connection(conn: &Connection) -> Result<(), StorageError> {
    let current_version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;

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

    Ok(())
}

pub fn open_connection(db_name: &str) -> Result<Connection, rusqlite::Error> {
    let path = db_file_path(db_name);
    Connection::open(path)
}

pub fn create_shared_connection(
    db_name: &str,
    init_sql: &str,
) -> Result<Arc<std::sync::Mutex<Connection>>, String> {
    let path = db_file_path(db_name);
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(init_sql).map_err(|e| e.to_string())?;
    let _ = conn.busy_timeout(Duration::from_millis(250));
    Ok(Arc::new(std::sync::Mutex::new(conn)))
}

pub fn with_conn<T, F>(shared: &Arc<std::sync::Mutex<Connection>>, f: F) -> Result<T, String>
where
    F: FnOnce(&Connection) -> Result<T, rusqlite::Error>,
{
    blocking_region(|| {
        let guard = shared
            .lock()
            .map_err(|e| format!("DB mutex poisoned: {:?}", e))?;
        f(&*guard).map_err(|e| e.to_string())
    })
}

/// Legacy - kept for e2ee_storage which uses its own DB.
pub fn create_general_messages_db() -> Result<Arc<std::sync::Mutex<Connection>>, String> {
    create_shared_connection(DB_NAME, "")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(version, 43);
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
        assert_eq!(version, 43);
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
    fn adds_synced_settings_to_a_version_eleven_schema() -> Result<(), StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA user_version = 11;")?;

        run_migrations_on_connection(&conn)?;

        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, 43);
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
        assert_eq!(version, 43);
        Ok(())
    }

    #[test]
    fn invitation_authority_migration_discards_unmappable_omega_mirrors() -> Result<(), StorageError>
    {
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
        assert_eq!(version, 43);
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
    fn observed_remote_references_receive_authority_scoped_principals() -> Result<(), StorageError>
    {
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
}
