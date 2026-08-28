//! Durable per-user state journal used by device cache synchronization.
use crate::storage_error::StorageError;
use crate::util::db;
use rusqlite::{Transaction, params};
use std::collections::BTreeMap;

pub const CACHE_SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    Message,
    Contact,
}
impl EntityType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Contact => "contact",
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

pub fn has_session(user_id: i64, session_id: i64) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        Ok(conn
            .query_row(
                "SELECT 1 FROM client_sync_state WHERE user_id = ?1 AND session_id = ?2",
                params![user_id, session_id],
                |_| Ok(()),
            )
            .is_ok())
    })
}

pub fn acknowledge(
    user_id: i64,
    session_id: i64,
    version: i64,
    cache_schema_version: i64,
) -> Result<(), StorageError> {
    if user_id <= 0 || session_id <= 0 || version < 0 {
        return Err(StorageError::Other("invalid sync acknowledgement".into()));
    }
    db::with_db(|conn| {
        let head = conn
            .query_row(
                "SELECT version FROM sync_heads WHERE user_id = ?1",
                [user_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if version > head {
            return Err(StorageError::Other(
                "acknowledgement is ahead of head".into(),
            ));
        }
        conn.execute("INSERT INTO client_sync_state (user_id, session_id, acknowledged_version, cache_schema_version, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(user_id, session_id) DO UPDATE SET acknowledged_version = MAX(acknowledged_version, excluded.acknowledged_version), cache_schema_version = excluded.cache_schema_version, updated_at = excluded.updated_at", params![user_id, session_id, version, cache_schema_version, now_millis()])?;
        Ok(())
    })
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
        let mut out = Delta::default();
        for ((kind, id), operation) in final_events {
            match (kind.as_str(), operation.as_str()) {
                ("message", "delete") => out.deleted_message_ids.push(id),
                ("message", _) => out.message_upserts.push(id),
                ("contact", "delete") => out.deleted_contact_ids.push(id),
                ("contact", _) => out.contact_upserts.push(id),
                _ => {}
            }
        }
        Ok(out)
    })
}
