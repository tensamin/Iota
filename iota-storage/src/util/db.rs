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
    let legacy_path = database_path.with_file_name("e2ee.sqlite3");
    let manager = SqliteManager { database_path };
    let pool = r2d2::Pool::builder()
        .max_size(8)
        .connection_timeout(connection_timeout)
        .build(manager)
        .map_err(|error| StorageError::Pool(error.to_string()))?;
    run_migrations(&pool)?;
    let connection = pool
        .get()
        .map_err(|error| StorageError::Pool(error.to_string()))?;
    crate::util::e2ee_storage::import_legacy_database(&connection, &legacy_path)?;
    drop(connection);
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
        let before: i64 = tx.query_row(
            "SELECT sequence FROM hosted_auth_changes WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let value = f(&tx)?;
        let after: i64 = tx.query_row(
            "SELECT sequence FROM hosted_auth_changes WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        tx.commit()?;
        if before != after {
            crate::hosted_auth::notify_change();
        }
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
            super::relay_acceptance_receipts::migrate_on(&tx)?;
        } else {
            // Historical migration fixtures can contain only a subset of the old schema.
            tx.execute_batch(super::relay_acceptance_receipts::SCHEMA)?;
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
        f(&guard).map_err(|e| e.to_string())
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
        assert!(super::super::relay_acceptance_receipts::upper_on(&conn, 7).is_err());
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
        let rows: Vec<(i64, String, Option<String>)> = conn.prepare("SELECT target_kind,delivery_state,last_error FROM pending_relays ORDER BY target_kind")?.query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect::<Result<_,_>>()?;
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
        chat_files::edit_message_for_principal_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "edited",
        )?;
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
        chat_files::edit_message_for_principal_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "edited",
        )?;
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
        assert_eq!(conn.query_row("SELECT count(*) FROM messages WHERE content = 'original' AND deleted_by_external = 0", [], |row| row.get::<_, i64>(0))?, 2);
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
            chat_files::apply_remote_delete_for_principal_in_tx(
                &tx,
                7,
                8,
                PrincipalHandle(71),
                10,
                8
            ),
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
            let id =
                relay_queue::enqueue_in_tx(&tx, target.clone(), &identity, frame, 20, 42, "1.0")?;
            assert_eq!(
                relay_queue::enqueue_in_tx(&tx, target.clone(), &identity, frame, 30, 99, "1.0")?,
                id
            );
            assert!(matches!(
                relay_queue::enqueue_in_tx(
                    &tx,
                    target.clone(),
                    &identity,
                    b"changed",
                    20,
                    42,
                    "1.0"
                ),
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
    fn secret_import_is_atomic_and_does_not_resurrect_deleted_records() -> Result<(), StorageError>
    {
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
        let imported = e2ee_storage::get_chat_secret_on(&connection, &query)?
            .expect("missing imported secret");
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

    #[test]
    fn client_acknowledgement_uses_canonical_identity_and_rejects_ambiguity()
    -> Result<(), StorageError> {
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
        assert_eq!(version, 60);
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
        assert_eq!(version, 60);
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
        assert_eq!(version, 60);
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
        assert_eq!(version, 60);
        let credential: (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = conn.query_row(
            "SELECT opaque_profile, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at FROM user_password_credentials WHERE user_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )?;
        assert_eq!(credential, (1, vec![1, 2], vec![3, 4], vec![5, 6], 10, 20));
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
        assert_eq!(version, 60);
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
        assert_eq!(version, 60);
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
        assert_eq!(version, 60);
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
