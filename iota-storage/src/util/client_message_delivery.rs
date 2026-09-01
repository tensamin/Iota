/* Delivery records bind a specific state-sync response to the messages it contained. */
use crate::storage_error::StorageError;
use crate::util::{chat_files, db, message_storage_policy, sync};
use rusqlite::{OptionalExtension, params};

pub fn record_sync_delivery(
    user_id: i64,
    session_id: i64,
    version: i64,
    message_ids: impl IntoIterator<Item = i64>,
) -> Result<(), StorageError> {
    if user_id <= 0 || session_id <= 0 || version < 0 {
        return Err(StorageError::Other(
            "invalid message delivery record".into(),
        ));
    }
    db::with_immediate_transaction(|tx| {
        for message_id in message_ids {
            tx.execute("INSERT OR IGNORE INTO client_message_deliveries (user_id, session_id, sync_version, message_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)", params![user_id, session_id, version, message_id, sync::now_millis()])?;
        }
        Ok(())
    })
}

pub fn acknowledge_sync_delivery(
    user_id: i64,
    session_id: i64,
    version: i64,
) -> Result<Vec<i64>, StorageError> {
    db::with_immediate_transaction(|tx| {
        let mut statement = tx.prepare("SELECT DISTINCT message_id FROM client_message_deliveries WHERE user_id = ?1 AND session_id = ?2 AND sync_version <= ?3")?;
        let ids = statement
            .query_map(params![user_id, session_id, version], |row| row.get(0))?
            .collect::<Result<Vec<i64>, _>>()
            .map_err(StorageError::from)?;
        tx.execute("DELETE FROM client_message_deliveries WHERE user_id = ?1 AND session_id = ?2 AND sync_version <= ?3", params![user_id, session_id, version])?;
        Ok(ids)
    })
}

/* Acknowledge a state-sync response and delete only its recorded visible messages atomically. */
pub fn acknowledge_client_state(
    user_id: i64,
    session_id: i64,
    version: i64,
    cache_schema_version: i64,
) -> Result<(), StorageError> {
    if user_id <= 0 || session_id <= 0 || version < 0 {
        return Err(StorageError::Other("invalid sync acknowledgement".into()));
    }
    db::with_immediate_transaction(|tx| {
        let head = tx
            .query_row(
                "SELECT version FROM sync_heads WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or_default();
        if version > head {
            return Err(StorageError::Other(
                "acknowledgement is ahead of head".into(),
            ));
        }
        let ids = {
            let mut statement = tx.prepare("SELECT DISTINCT message_id FROM client_message_deliveries WHERE user_id = ?1 AND session_id = ?2 AND sync_version <= ?3")?;
            statement
                .query_map(params![user_id, session_id, version], |row| {
                    row.get::<_, i64>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        tx.execute("INSERT INTO client_sync_state (user_id, session_id, acknowledged_version, cache_schema_version, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(user_id, session_id) DO UPDATE SET acknowledged_version = MAX(acknowledged_version, excluded.acknowledged_version), cache_schema_version = excluded.cache_schema_version, updated_at = excluded.updated_at", params![user_id, session_id, version, cache_schema_version, sync::now_millis()])?;
        if message_storage_policy::get_in_tx(tx, user_id)?.history_mode
            == message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery
        {
            for message_id in ids {
                chat_files::remove_message_history_in_tx(tx, user_id, message_id)?;
            }
        }
        tx.execute("DELETE FROM client_message_deliveries WHERE user_id = ?1 AND session_id = ?2 AND sync_version <= ?3", params![user_id, session_id, version])?;
        Ok(())
    })
}

pub fn purge_session_deliveries(user_id: i64, session_id: i64) -> Result<usize, StorageError> {
    db::with_db(|conn| {
        Ok(conn.execute(
            "DELETE FROM client_message_deliveries WHERE user_id = ?1 AND session_id = ?2",
            params![user_id, session_id],
        )?)
    })
}
