mod backup;
use backup::db_file_path;
pub use backup::verify_and_backup_database;
mod migrations;
use migrations::run_migrations;
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
mod tests;
