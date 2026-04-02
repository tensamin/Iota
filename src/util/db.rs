//! Database helper utilities.
//!
//! This module provides small helpers to open/init sqlite databases and to
//! create a shared (Arc<Mutex<Connection>>) connection wrapper callers can
//! reuse. The goal is to centralize the "open and initialize" logic and
//! provide small convenience helpers used by other util modules.

use crate::util::file_util::get_directory;
use rusqlite::{Connection, Error as RusqliteError};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Returns the file path for a named DB inside the application's data directory.
///
/// Arguments:
/// - `db_name` : name of the DB (without extension). Example: `"messages"`.
pub fn db_file_path(db_name: &str) -> String {
    let mut p = PathBuf::from(get_directory());
    p.push(format!("{db_name}.sqlite3"));
    p.to_string_lossy().to_string()
}

/// Open a sqlite connection to the named DB file (no initialization).
///
/// Arguments:
/// - `db_name`: name of the DB (without extension).
pub fn open_connection(db_name: &str) -> Result<Connection, RusqliteError> {
    let path = db_file_path(db_name);
    Connection::open(path)
}

/// Open a connection and immediately run `init_sql` via `execute_batch`.
///
/// Arguments:
/// - `db_name`: name of the DB (without extension).
/// - `init_sql`: SQL statements to initialize schema & PRAGMAs (can be multiple).
pub fn open_and_init(db_name: &str, init_sql: &str) -> Result<Connection, RusqliteError> {
    let conn = open_connection(db_name)?;
    conn.execute_batch(init_sql)?;
    Ok(conn)
}

/// Create a shared, Arc<Mutex<Connection>> initialized with the given SQL.
///
/// This is a convenience wrapper that returns an owned Arc<Mutex<Connection>>
/// so caller modules can store it in a `static` or pass it around.
///
/// Arguments:
/// - `db_name`: DB name (without extension).
/// - `init_sql`: init SQL (eg PRAGMA + CREATE TABLE statements).
pub fn create_shared_connection(
    db_name: &str,
    init_sql: &str,
) -> Result<Arc<Mutex<Connection>>, String> {
    match open_and_init(db_name, init_sql) {
        Ok(conn) => {
            // Configure some sensible defaults for concurrency
            // Attempt to set a busy timeout to reduce SQLITE_BUSY failures.
            let _ = conn.busy_timeout(Duration::from_millis(250));
            Ok(Arc::new(Mutex::new(conn)))
        }
        Err(e) => Err(format!("Failed to open/init DB '{}': {}", db_name, e)),
    }
}

/// Acquire the Connection from an Arc<Mutex<Connection>> and run the provided
/// closure. Converts rusqlite::Error into a String on error.
///
/// Arguments:
/// - `shared`: Arc<Mutex<Connection>>
/// - `f`: closure that receives &Connection and returns Result<T, RusqliteError>
///
/// Returns Ok(T) or Err(String).
pub fn with_conn<T, F>(shared: &Arc<Mutex<Connection>>, f: F) -> Result<T, String>
where
    F: FnOnce(&Connection) -> Result<T, RusqliteError>,
{
    // When invoked from within an async runtime (such as Tokio), taking a blocking
    // std::sync::Mutex lock on the runtime thread can cause deadlocks or permanent
    // awaits. Detect whether we're running inside a Tokio runtime and, if so,
    // execute the blocking lock + database closure using Tokio's blocking helper.
    //
    // The blocking section returns Result<T, String> so we can propagate errors
    // in the same form as before.
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

/// Initialize a general-purpose messages+contacts DB and return a shared
/// connection. This helper creates a single DB file that can contain multiple
/// tables (messages, contacts, ...). The SQL here is conservative and intended
/// to be safe if called multiple times.
///
/// Callers may prefer to call `create_shared_connection("messages", INIT_SQL)`
/// directly, but this convenience is useful for code that expects both tables.
pub fn create_general_messages_db() -> Result<Arc<Mutex<Connection>>, String> {
    // Keep PRAGMA and schema in one multi-statement string so callers only
    // need to call a single execute_batch.
    const INIT_SQL: &str = r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

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
    "#;

    match create_shared_connection("messages", INIT_SQL) {
        Ok(shared_conn) => {
            // Attempt to add the height column for backwards compatibility.
            // This will fail if the column already exists, which is expected.
            let _ = with_conn(&shared_conn, |conn| {
                let _ = conn.execute(
                    "ALTER TABLE messages ADD COLUMN height INTEGER NOT NULL DEFAULT 0",
                    [],
                );
                Ok(())
            });
            Ok(shared_conn)
        }
        Err(e) => Err(e),
    }
}

/*
Example usage:

// In some util module (at init time, e.g. lazy_static or LazyLock)
static MESSAGES_DB: LazyLock<Arc<Mutex<Connection>>> = LazyLock::new(|| {
    create_general_messages_db().expect("failed to create messages DB")
});

// Later, to run a query:
let res: Result<Vec<MyRow>, String> = with_conn(&MESSAGES_DB, |conn| {
    let mut stmt = conn.prepare("SELECT ...")?;
    let rows = stmt.query_map(...)?;
    // collect and return Ok(...)
});
*/
