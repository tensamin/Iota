use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 68 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS account_sync_pages (
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, scope TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('snapshot','delta')), after_sequence INTEGER NOT NULL,
            head INTEGER NOT NULL, floor INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            item_count INTEGER NOT NULL DEFAULT 0, issued_through INTEGER NOT NULL DEFAULT 0
         );
         CREATE INDEX IF NOT EXISTS account_sync_pages_expiry ON account_sync_pages(expires_at);
         CREATE TABLE IF NOT EXISTS account_sync_page_items (
            page_id TEXT NOT NULL, position INTEGER NOT NULL, payload BLOB NOT NULL,
            PRIMARY KEY(page_id,position)
         );
         CREATE TRIGGER IF NOT EXISTS account_sync_pages_delete AFTER DELETE ON account_sync_pages BEGIN
            DELETE FROM account_sync_page_items WHERE page_id=OLD.id;
         END;
         CREATE TABLE IF NOT EXISTS account_sync_checkpoints (
            user_id INTEGER NOT NULL, scope TEXT NOT NULL, sequence INTEGER NOT NULL,
            updated_at INTEGER NOT NULL, PRIMARY KEY(user_id,scope)
         );
         CREATE TABLE IF NOT EXISTS account_sync_floors(user_id INTEGER PRIMARY KEY, sequence INTEGER NOT NULL);
         CREATE TRIGGER IF NOT EXISTS account_sync_revocation AFTER UPDATE ON hosted_auth_state
         WHEN NEW.generation != OLD.generation OR NEW.enabled=0 BEGIN
            DELETE FROM account_sync_pages WHERE user_id=OLD.local_user_id;
            DELETE FROM account_sync_checkpoints WHERE user_id=OLD.local_user_id;
            DELETE FROM client_device_sync_state WHERE user_id=OLD.local_user_id;
         END;
         CREATE TRIGGER IF NOT EXISTS account_sync_erasure AFTER DELETE ON hosted_auth_state BEGIN
            DELETE FROM account_sync_pages WHERE user_id=OLD.local_user_id;
            DELETE FROM account_sync_checkpoints WHERE user_id=OLD.local_user_id;
            DELETE FROM account_sync_floors WHERE user_id=OLD.local_user_id;
            DELETE FROM client_device_sync_state WHERE user_id=OLD.local_user_id;
         END;
         -- Captured pages can contain a peer's conversation state. Invalidate
         -- them on erasure rather than release pre-erasure records afterwards.
         CREATE TRIGGER IF NOT EXISTS account_sync_peer_erasure AFTER INSERT ON chat_secret_erasure_fences BEGIN
            DELETE FROM account_sync_pages;
         END;
         CREATE TRIGGER IF NOT EXISTS chat_secret_sync_insert AFTER INSERT ON chat_secrets BEGIN
            INSERT INTO sync_heads(user_id,version) VALUES(CAST(NEW.user_id AS INTEGER),1)
            ON CONFLICT(user_id) DO UPDATE SET version=version+1;
            INSERT INTO sync_events(user_id,version,entity_type,entity_id,operation,created_at)
            SELECT user_id,version,'chat_secret',NEW.rowid,'upsert',NEW.updated_at FROM sync_heads WHERE user_id=CAST(NEW.user_id AS INTEGER);
         END;"
    )?;
    // Historical migration fixtures can contain only the subsystem under test.
    // Backfill a retention boundary only when its source journal exists.
    let journal: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_heads')",
        [],
        |row| row.get(0),
    )?;
    if journal {
        tx.execute("INSERT OR IGNORE INTO account_sync_floors(user_id,sequence) SELECT h.user_id,COALESCE(MIN(e.version)-1,h.version) FROM sync_heads h LEFT JOIN sync_events e ON e.user_id=h.user_id GROUP BY h.user_id", [])?;
    }
    tx.pragma_update(None, "user_version", 68)?;
    tx.commit()?;
    Ok(())
}
