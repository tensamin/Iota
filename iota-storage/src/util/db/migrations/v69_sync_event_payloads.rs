use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 69 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    let journal: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_events')",
        [],
        |row| row.get(0),
    )?;
    if journal {
        add_table_column_if_missing(&tx, "sync_events", "projection", "projection BLOB")?;
        add_table_column_if_missing(
            &tx,
            "sync_events",
            "projection_principal",
            "projection_principal TEXT",
        )?;
        add_table_column_if_missing(
            &tx,
            "sync_events",
            "projection_generation",
            "projection_generation INTEGER",
        )?;
        add_table_column_if_missing(
            &tx,
            "sync_events",
            "projection_dictionary",
            "projection_dictionary TEXT",
        )?;
        tx.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS sync_event_projection_immutable BEFORE UPDATE ON sync_events
             WHEN OLD.projection IS NOT NULL OR OLD.projection_principal IS NOT NULL
               OR OLD.projection_generation IS NOT NULL OR OLD.projection_dictionary IS NOT NULL
             BEGIN SELECT RAISE(ABORT,'sync event is immutable'); END;
             INSERT INTO account_sync_floors(user_id,sequence) SELECT user_id,version FROM sync_heads WHERE true
             ON CONFLICT(user_id) DO UPDATE SET sequence=MAX(sequence,excluded.sequence);"
        )?;
    }
    // Old locator-only events are not backfilled with present-day row contents.
    tx.pragma_update(None, "user_version", 69)?;
    tx.commit()?;
    Ok(())
}
