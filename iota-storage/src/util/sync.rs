/* Durable per-user state journal used by device cache synchronization. */
use crate::storage_error::StorageError;
use crate::util::db;
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::BTreeMap;

pub const CACHE_SCHEMA_VERSION: i64 = 5;
pub const STALE_CLIENT_SYNC_STATE_MS: i64 = 90 * 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    Message,
    Contact,
    Setting,
    UserBlob,
    BlockedUser,
    ReceiptPolicy,
    MessageStoragePolicy,
}
impl EntityType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Contact => "contact",
            Self::Setting => "setting",
            Self::UserBlob => "user_blob",
            Self::BlockedUser => "blocked_user",
            Self::ReceiptPolicy => "receipt_policy",
            Self::MessageStoragePolicy => "message_storage_policy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Upsert,
    Delete,
}
impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Delta {
    pub message_upserts: Vec<i64>,
    pub deleted_message_ids: Vec<i64>,
    pub contact_upserts: Vec<i64>,
    pub deleted_contact_ids: Vec<i64>,
    pub setting_upserts: Vec<i64>,
    pub deleted_setting_ids: Vec<i64>,
    pub blob_upserts: Vec<i64>,
    pub deleted_blob_ids: Vec<i64>,
    pub blocked_user_upserts: Vec<i64>,
    pub deleted_blocked_user_ids: Vec<i64>,
    pub receipt_policy_changed: bool,
    pub message_storage_policy_changed: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncCompactionResult {
    pub removed_stale_clients: usize,
    pub removed_events: usize,
    pub removed_blob_tombstones: usize,
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn record_event(
    tx: &Transaction<'_>,
    user_id: i64,
    entity: EntityType,
    entity_id: i64,
    operation: Operation,
) -> Result<i64, StorageError> {
    tx.execute(
        "INSERT INTO sync_heads (user_id, version) VALUES (?1, 0) ON CONFLICT(user_id) DO NOTHING",
        [user_id],
    )?;
    let previous: i64 = tx.query_row(
        "SELECT version FROM sync_heads WHERE user_id = ?1",
        [user_id],
        |r| r.get(0),
    )?;
    let version = previous
        .checked_add(1)
        .ok_or_else(|| StorageError::Other("sync version overflow".into()))?;
    tx.execute(
        "UPDATE sync_heads SET version = ?2 WHERE user_id = ?1",
        params![user_id, version],
    )?;
    tx.execute("INSERT INTO sync_events (user_id, version, entity_type, entity_id, operation, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![user_id, version, entity.as_str(), entity_id, operation.as_str(), now_millis()])?;
    Ok(version)
}

pub fn head(user_id: i64) -> Result<i64, StorageError> {
    db::with_db(|conn| {
        Ok(conn
            .query_row(
                "SELECT version FROM sync_heads WHERE user_id = ?1",
                [user_id],
                |r| r.get(0),
            )
            .unwrap_or(0))
    })
}

pub fn has_device(user_id: i64, device_id: &str) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        Ok(conn
            .query_row(
                "SELECT 1 FROM client_device_sync_state WHERE user_id = ?1 AND device_id = ?2",
                params![user_id, device_id],
                |_| Ok(()),
            )
            .is_ok())
    })
}

pub fn acknowledged_version(user_id: i64, device_id: &str) -> Result<Option<i64>, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT acknowledged_version FROM client_device_sync_state WHERE user_id = ?1 AND device_id = ?2",
            params![user_id, device_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(StorageError::from)
    })
}

/* Retain deltas until every non-stale client has acknowledged them. */
pub fn compact_user_sync_state(user_id: i64) -> Result<SyncCompactionResult, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid sync owner".into()));
    }
    let stale_before = now_millis().saturating_sub(STALE_CLIENT_SYNC_STATE_MS);
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "DELETE FROM client_message_deliveries WHERE user_id = ?1 AND created_at < ?2",
            params![user_id, stale_before],
        )?;
        let removed_stale_clients = tx.execute(
            "DELETE FROM client_device_sync_state WHERE user_id = ?1 AND updated_at < ?2",
            params![user_id, stale_before],
        )?;
        let minimum_acknowledged: Option<i64> = tx.query_row(
            "SELECT MIN(acknowledged_version) FROM client_device_sync_state WHERE user_id = ?1",
            [user_id],
            |row| row.get(0),
        )?;
        let revision = match minimum_acknowledged {
            Some(revision) => revision,
            None => tx
                .query_row(
                    "SELECT version FROM sync_heads WHERE user_id = ?1",
                    [user_id],
                    |row| row.get(0),
                )
                .unwrap_or(0),
        };
        let removed_events = tx.execute(
            "DELETE FROM sync_events WHERE user_id = ?1 AND version <= ?2",
            params![user_id, revision],
        )?;
        let removed_blob_tombstones = tx.execute(
            "DELETE FROM user_blobs WHERE user_id = ?1 AND deleted = 1 AND revision <= ?2",
            params![user_id, revision],
        )?;
        Ok(SyncCompactionResult {
            removed_stale_clients,
            removed_events,
            removed_blob_tombstones,
        })
    })
}

pub fn compact_all_sync_state() -> Result<SyncCompactionResult, StorageError> {
    let users = db::with_db(|conn| {
        let mut statement = conn.prepare("SELECT user_id FROM sync_heads")?;
        statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    })?;
    let mut total = SyncCompactionResult::default();
    for user_id in users {
        let result = compact_user_sync_state(user_id)?;
        total.removed_stale_clients += result.removed_stale_clients;
        total.removed_events += result.removed_events;
        total.removed_blob_tombstones += result.removed_blob_tombstones;
    }
    Ok(total)
}

/// Returns the final operation for each entity after `from_version`.
pub fn delta(user_id: i64, from_version: i64, captured_head: i64) -> Result<Delta, StorageError> {
    if from_version < 0 || from_version > captured_head {
        return Err(StorageError::Other("invalid sync cursor".into()));
    }
    db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT entity_type, entity_id, operation FROM sync_events WHERE user_id = ?1 AND version > ?2 AND version <= ?3 ORDER BY version ASC")?;
        let mut final_events = BTreeMap::<(String, i64), String>::new();
        for row in stmt.query_map(params![user_id, from_version, captured_head], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (kind, id, operation) = row?;
            final_events.insert((kind, id), operation);
        }
        Ok(reduce_events(final_events))
    })
}

fn reduce_events(events: BTreeMap<(String, i64), String>) -> Delta {
    let mut out = Delta::default();
    for ((kind, id), operation) in events {
        match (kind.as_str(), operation.as_str()) {
            ("message", "delete") => out.deleted_message_ids.push(id),
            ("message", _) => out.message_upserts.push(id),
            ("contact", "delete") => out.deleted_contact_ids.push(id),
            ("contact", _) => out.contact_upserts.push(id),
            ("setting", "delete") => out.deleted_setting_ids.push(id),
            ("setting", _) => out.setting_upserts.push(id),
            ("user_blob", "delete") => out.deleted_blob_ids.push(id),
            ("user_blob", _) => out.blob_upserts.push(id),
            ("blocked_user", "delete") => out.deleted_blocked_user_ids.push(id),
            ("blocked_user", _) => out.blocked_user_upserts.push(id),
            ("receipt_policy", _) => out.receipt_policy_changed = true,
            ("message_storage_policy", _) => out.message_storage_policy_changed = true,
            _ => {}
        }
    }
    out
}

#[cfg(test)]
fn reduce_event_sequence<I>(events: I) -> Delta
where
    I: IntoIterator<Item = (String, i64, String)>,
{
    let mut final_events = BTreeMap::new();
    for (kind, id, operation) in events {
        final_events.insert((kind, id), operation);
    }
    reduce_events(final_events)
}

#[cfg(test)]
mod tests {
    use super::{EntityType, Operation, reduce_event_sequence, reduce_events};
    use rusqlite::Connection;
    use std::collections::BTreeMap;

    #[test]
    fn setting_upsert_is_included_in_delta() {
        let mut events = BTreeMap::new();
        events.insert(
            (EntityType::Setting.as_str().to_string(), 7),
            Operation::Upsert.as_str().to_string(),
        );

        let delta = reduce_events(events);

        assert_eq!(delta.setting_upserts, vec![7]);
        assert!(delta.deleted_setting_ids.is_empty());
    }

    #[test]
    fn setting_delete_is_included_in_delta() {
        let mut events = BTreeMap::new();
        events.insert(
            (EntityType::Setting.as_str().to_string(), 7),
            Operation::Delete.as_str().to_string(),
        );

        let delta = reduce_events(events);

        assert_eq!(delta.deleted_setting_ids, vec![7]);
        assert!(delta.setting_upserts.is_empty());
    }

    #[test]
    fn blob_delete_is_included_in_delta() {
        let mut events = BTreeMap::new();
        events.insert(
            (EntityType::UserBlob.as_str().to_string(), 7),
            Operation::Delete.as_str().to_string(),
        );

        let delta = reduce_events(events);

        assert_eq!(delta.deleted_blob_ids, vec![7]);
        assert!(delta.blob_upserts.is_empty());
    }

    #[test]
    fn final_setting_operation_wins() {
        let mut events = BTreeMap::new();
        events.insert(
            (EntityType::Setting.as_str().to_string(), 7),
            Operation::Upsert.as_str().to_string(),
        );
        events.insert(
            (EntityType::Setting.as_str().to_string(), 8),
            Operation::Delete.as_str().to_string(),
        );

        let delta = reduce_events(events);

        assert_eq!(delta.setting_upserts, vec![7]);
        assert_eq!(delta.deleted_setting_ids, vec![8]);
    }

    #[test]
    fn setting_upsert_then_delete_resolves_to_delete() {
        let delta = reduce_event_sequence([
            (
                EntityType::Setting.as_str().to_string(),
                7,
                Operation::Upsert.as_str().to_string(),
            ),
            (
                EntityType::Setting.as_str().to_string(),
                7,
                Operation::Delete.as_str().to_string(),
            ),
        ]);

        assert_eq!(delta.deleted_setting_ids, vec![7]);
        assert!(delta.setting_upserts.is_empty());
    }

    #[test]
    fn setting_delete_then_upsert_resolves_to_upsert() {
        let delta = reduce_event_sequence([
            (
                EntityType::Setting.as_str().to_string(),
                7,
                Operation::Delete.as_str().to_string(),
            ),
            (
                EntityType::Setting.as_str().to_string(),
                7,
                Operation::Upsert.as_str().to_string(),
            ),
        ]);

        assert_eq!(delta.setting_upserts, vec![7]);
        assert!(delta.deleted_setting_ids.is_empty());
    }

    #[test]
    fn setting_events_share_the_user_sync_head() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE sync_heads (user_id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
                CREATE TABLE sync_events (
                    user_id INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    operation TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (user_id, version)
                );
                ",
            )
            .unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        let message =
            super::record_event(&transaction, 1, EntityType::Message, 10, Operation::Upsert)
                .unwrap();
        let setting =
            super::record_event(&transaction, 1, EntityType::Setting, 11, Operation::Upsert)
                .unwrap();
        let contact =
            super::record_event(&transaction, 1, EntityType::Contact, 12, Operation::Upsert)
                .unwrap();
        transaction.commit().unwrap();

        assert_eq!((message, setting, contact), (1, 2, 3));
    }
}
