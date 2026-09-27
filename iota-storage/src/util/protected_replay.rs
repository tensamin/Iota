use rusqlite::params;

use crate::{storage_error::StorageError, util::db};

pub fn accept(signer_id: i64, message_id: &str, created_at: i64) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        Ok(conn.execute(
        "INSERT OR IGNORE INTO protected_command_replay (signer_id, message_id, created_at) VALUES (?1, ?2, ?3)",
        params![signer_id, message_id, created_at],
    )? == 1)
    })
}

pub fn prune(before: i64) -> Result<usize, StorageError> {
    db::with_db(|conn| {
        Ok(conn.execute(
            "DELETE FROM protected_command_replay WHERE created_at < ?1",
            params![before],
        )?)
    })
}
