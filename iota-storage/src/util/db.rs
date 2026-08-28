use once_cell::sync::Lazy;
use r2d2::ManageConnection;
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::storage_error::StorageError;

const DB_NAME: &str = "messages";

/// A simple r2d2 manager for rusqlite connections.
pub struct SqliteManager;

impl ManageConnection for SqliteManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Connection, rusqlite::Error> {
        let path = db_file_path(DB_NAME);
        let conn = Connection::open(path)?;
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

static POOL: Lazy<Arc<r2d2::Pool<SqliteManager>>> = Lazy::new(|| {
    let manager = SqliteManager;
    let pool = r2d2::Pool::builder()
        .max_size(8)
        .build(manager)
        .expect("Failed to create database connection pool");
    run_migrations(&pool).expect("Failed to run database migrations");
    Arc::new(pool)
});

pub fn pool() -> Arc<r2d2::Pool<SqliteManager>> {
    POOL.clone()
}

pub fn with_db<T, F>(f: F) -> Result<T, StorageError>
where
    F: FnOnce(&Connection) -> Result<T, StorageError>,
{
    let conn = POOL.get().map_err(|e| StorageError::Pool(e.to_string()))?;
    f(&conn)
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
    let current_version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap_or(0);

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
                last_message_at INTEGER,
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
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| {
            let guard = shared
                .lock()
                .map_err(|e| format!("DB mutex poisoned: {:?}", e))?;
            f(&*guard).map_err(|e| e.to_string())
        })
    } else {
        let guard = shared
            .lock()
            .map_err(|e| format!("DB mutex poisoned: {:?}", e))?;
        f(&*guard).map_err(|e| e.to_string())
    }
}

/// Legacy - kept for e2ee_storage which uses its own DB.
pub fn create_general_messages_db() -> Result<Arc<std::sync::Mutex<Connection>>, String> {
    create_shared_connection(DB_NAME, "")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(version, 9);
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
        conn.execute_batch("PRAGMA user_version = 5;")?;
        run_migrations_on_connection(&conn)?;
        run_migrations_on_connection(&conn)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, 9);
        for table in [
            "sync_heads",
            "sync_events",
            "client_sync_state",
            "user_residency",
            "relay_replay",
            "pending_relays",
            "relay_inbox",
        ] {
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )?;
            assert_eq!(exists, 1);
        }
        for column in ["frame_id", "target_kind", "type_map_version"] {
            let mut statement =
                conn.prepare("SELECT 1 FROM pragma_table_info('pending_relays') WHERE name = ?1")?;
            assert!(statement.exists([column])?);
        }
        Ok(())
    }
}
