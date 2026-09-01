/* Retention policy is normalized so invalid combinations cannot reach cleanup logic. */
use crate::storage_error::StorageError;
use crate::util::{db, sync};
use rusqlite::{OptionalExtension, Transaction};

pub const MIN_RETENTION_DURATION_MS: i64 = 60_000;
pub const MAX_RETENTION_DURATION_MS: i64 = 31_536_000_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageHistoryMode {
    Retain,
    DeleteAfterClientDelivery,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRetention {
    Forever,
    Duration { duration_ms: i64 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageStoragePolicy {
    pub user_id: i64,
    pub history_mode: MessageHistoryMode,
    pub retention: MessageRetention,
    pub revision: i64,
    pub updated_at: i64,
}
pub fn default_policy() -> MessageStoragePolicy {
    MessageStoragePolicy {
        user_id: 0,
        history_mode: MessageHistoryMode::Retain,
        retention: MessageRetention::Forever,
        revision: 0,
        updated_at: 0,
    }
}
fn validate(user_id: i64, retention: MessageRetention) -> Result<(), StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other(
            "invalid message storage policy owner".into(),
        ));
    }
    if let MessageRetention::Duration { duration_ms } = retention {
        if !(MIN_RETENTION_DURATION_MS..=MAX_RETENTION_DURATION_MS).contains(&duration_ms) {
            return Err(StorageError::Other("invalid retention duration".into()));
        }
    }
    Ok(())
}
fn history_name(value: MessageHistoryMode) -> &'static str {
    match value {
        MessageHistoryMode::Retain => "retain",
        MessageHistoryMode::DeleteAfterClientDelivery => "delete_after_client_delivery",
    }
}
fn parse_history(value: &str) -> Result<MessageHistoryMode, StorageError> {
    match value {
        "retain" => Ok(MessageHistoryMode::Retain),
        "delete_after_client_delivery" => Ok(MessageHistoryMode::DeleteAfterClientDelivery),
        _ => Err(StorageError::Other(
            "invalid stored message history mode".into(),
        )),
    }
}
pub fn get(user_id: i64) -> Result<MessageStoragePolicy, StorageError> {
    validate(user_id, MessageRetention::Forever)?;
    db::with_db(|conn| {
        let found = conn.query_row("SELECT history_mode, retention_mode, retention_duration_ms, revision, updated_at FROM user_message_storage_policy WHERE user_id = ?1", [user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?))).optional()?;
        policy_from_found(user_id, found)
    })
}

pub fn get_in_tx(tx: &Transaction<'_>, user_id: i64) -> Result<MessageStoragePolicy, StorageError> {
    validate(user_id, MessageRetention::Forever)?;
    let found = tx.query_row("SELECT history_mode, retention_mode, retention_duration_ms, revision, updated_at FROM user_message_storage_policy WHERE user_id = ?1", [user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?))).optional()?;
    policy_from_found(user_id, found)
}

fn policy_from_found(
    user_id: i64,
    found: Option<(String, String, Option<i64>, i64, i64)>,
) -> Result<MessageStoragePolicy, StorageError> {
    match found {
        None => Ok(MessageStoragePolicy {
            user_id,
            ..default_policy()
        }),
        Some((history, mode, duration, revision, updated_at)) => {
            let retention = match (mode.as_str(), duration) {
                ("forever", None) => MessageRetention::Forever,
                ("duration", Some(duration_ms)) => MessageRetention::Duration { duration_ms },
                _ => {
                    return Err(StorageError::Other(
                        "invalid stored retention policy".into(),
                    ));
                }
            };
            validate(user_id, retention)?;
            Ok(MessageStoragePolicy {
                user_id,
                history_mode: parse_history(&history)?,
                retention,
                revision,
                updated_at,
            })
        }
    }
}
pub fn set(
    user_id: i64,
    history_mode: MessageHistoryMode,
    retention: MessageRetention,
) -> Result<MessageStoragePolicy, StorageError> {
    validate(user_id, retention)?;
    db::with_immediate_transaction(|tx| {
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::MessageStoragePolicy,
            user_id,
            sync::Operation::Upsert,
        )?;
        let updated_at = sync::now_millis();
        let (retention_mode, duration): (&str, Option<i64>) = match retention {
            MessageRetention::Forever => ("forever", None),
            MessageRetention::Duration { duration_ms } => ("duration", Some(duration_ms)),
        };
        tx.execute("INSERT INTO user_message_storage_policy (user_id, history_mode, retention_mode, retention_duration_ms, revision, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(user_id) DO UPDATE SET history_mode = excluded.history_mode, retention_mode = excluded.retention_mode, retention_duration_ms = excluded.retention_duration_ms, revision = excluded.revision, updated_at = excluded.updated_at", rusqlite::params![user_id, history_name(history_mode), retention_mode, duration, revision, updated_at])?;
        match retention {
            MessageRetention::Forever => {
                tx.execute(
                    "UPDATE messages SET expires_at = NULL WHERE storage_owner = ?1",
                    [user_id],
                )?;
            }
            MessageRetention::Duration { duration_ms } => {
                tx.execute(
                    "UPDATE messages SET expires_at = stored_at + ?2 WHERE storage_owner = ?1 AND stored_at IS NOT NULL",
                    rusqlite::params![user_id, duration_ms],
                )?;
            }
        }
        Ok(MessageStoragePolicy {
            user_id,
            history_mode,
            retention,
            revision,
            updated_at,
        })
    })
}
