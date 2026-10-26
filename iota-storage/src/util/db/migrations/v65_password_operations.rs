use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 65 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_password_mutations (
            user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            operation_id TEXT NOT NULL,
            request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
            account_public_key TEXT NOT NULL,
            authorization_generation INTEGER NOT NULL,
            enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
            committed_at INTEGER NOT NULL,
            PRIMARY KEY(user_id, operation_id)
         );
         CREATE TRIGGER IF NOT EXISTS user_password_mutations_immutable BEFORE UPDATE ON user_password_mutations
         BEGIN SELECT RAISE(ABORT, 'password mutation receipts are immutable'); END;",
    )?;
    // Historical migration fixtures can contain only a subset of the old schema.
    for (table, trigger) in [
        ("users", "CREATE TRIGGER IF NOT EXISTS user_password_mutations_key_change AFTER UPDATE OF public_key ON users
         WHEN OLD.public_key != NEW.public_key
         BEGIN DELETE FROM user_password_mutations WHERE user_id = NEW.user_id; END;"),
        ("user_residency", "CREATE TRIGGER IF NOT EXISTS user_password_mutations_residency AFTER UPDATE ON user_residency
         WHEN NEW.lifecycle_state != 'managed' OR NEW.data_state != 'present'
         BEGIN DELETE FROM user_password_mutations WHERE user_id = NEW.user_id; END;"),
    ] {
        if tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)", [table], |row| row.get::<_, bool>(0))? {
            tx.execute_batch(trigger)?;
        }
    }
    tx.pragma_update(None, "user_version", 65)?;
    tx.commit()?;
    Ok(())
}
