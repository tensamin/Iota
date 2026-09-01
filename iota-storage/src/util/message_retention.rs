/* Retention cleanup removes only stored history; pending transport is retained. */
use crate::storage_error::StorageError;
use crate::util::{chat_files, db};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionResult {
    pub deleted_messages: usize,
}

pub fn purge_expired_messages(now: i64) -> Result<RetentionResult, StorageError> {
    let expired = db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT id, storage_owner FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1 ORDER BY expires_at ASC",
        )?;
        statement
            .query_map([now], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    })?;
    let mut result = RetentionResult::default();
    for (message_id, storage_owner) in expired {
        chat_files::purge_message(storage_owner, message_id)?;
        result.deleted_messages += 1;
    }
    Ok(result)
}
