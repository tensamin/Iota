use iota_util::file_util::get_directory;
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
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
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

fn db_file_path(db_name: &str) -> String {
    let mut p = PathBuf::from(get_directory());
    p.push(format!("{db_name}.sqlite3"));
    p.to_string_lossy().to_string()
}

fn run_migrations(pool: &r2d2::Pool<SqliteManager>) -> Result<(), StorageError> {
    let conn = pool.get().map_err(|e| StorageError::Pool(e.to_string()))?;
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
                message_state TEXT NOT NULL,
                height INTEGER NOT NULL DEFAULT 0
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
        conn.execute_batch(
            r#"
            ALTER TABLE messages ADD COLUMN height INTEGER NOT NULL DEFAULT 0;
            PRAGMA user_version = 2;
            "#,
        )?;
    }

    if current_version < 3 {
        conn.execute_batch(
            r#"
            ALTER TABLE messages ADD COLUMN reply_to INTEGER;
            PRAGMA user_version = 3;
            "#,
        )?;
    }

    if current_version < 4 {
        conn.execute_batch(
            r#"
            ALTER TABLE messages ADD COLUMN edited_count INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE messages ADD COLUMN deleted_by_external INTEGER NOT NULL DEFAULT 0;

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
