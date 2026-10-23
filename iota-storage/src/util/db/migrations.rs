mod v01_to_v20;
mod v21_to_v30;
mod v31_to_v40;
mod v41_to_v64;

use super::*;

pub(super) fn run_migrations(pool: &r2d2::Pool<SqliteManager>) -> Result<(), StorageError> {
    let conn = pool.get().map_err(|e| StorageError::Pool(e.to_string()))?;
    run_migrations_on_connection(&conn)
}

/*
 * Older builds could apply a schema change without advancing user_version.
 * Check each added column so those databases can resume upgrading.
 */
pub(super) fn add_column_if_missing(
    conn: &Connection,
    column: &str,
    definition: &str,
) -> Result<(), StorageError> {
    add_table_column_if_missing(conn, "messages", column, definition)
}

pub(super) fn add_table_column_if_missing(
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

pub(super) fn run_migrations_on_connection(conn: &Connection) -> Result<(), StorageError> {
    let current_version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;

    v01_to_v20::migrate(conn, current_version)?;
    v21_to_v30::migrate(conn, current_version)?;
    v31_to_v40::migrate(conn, current_version)?;
    v41_to_v64::migrate(conn, current_version)?;
    Ok(())
}
