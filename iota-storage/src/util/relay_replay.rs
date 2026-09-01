use crate::storage_error::StorageError;
use crate::util::db;
use rusqlite::{OptionalExtension, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredRelay {
    pub signer_id: i64,
    pub message_id: String,
    pub destination_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReservation {
    New,
    Existing { state: String, frame_matches: bool },
}

pub fn reserve(
    signer_id: u64,
    message_id: &str,
    created_at: u64,
    accepted_at: i64,
    destination_id: u64,
    frame: &[u8],
    frame_id: u32,
    type_map_version: &str,
) -> Result<RelayReservation, StorageError> {
    let signer_id = i64::try_from(signer_id)
        .map_err(|_| StorageError::Other("relay signer ID exceeds SQLite range".into()))?;
    let created_at = i64::try_from(created_at)
        .map_err(|_| StorageError::Other("relay creation time exceeds SQLite range".into()))?;
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;

    db::with_db(|connection| {
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO relay_inbox (signer_id, message_id, created_at, accepted_at, destination_id, frame, frame_id, type_map_version, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'received')",
            params![
                signer_id,
                message_id,
                created_at,
                accepted_at,
                destination_id,
                frame,
                i64::from(frame_id),
                type_map_version
            ],
        )?;
        if inserted == 1 {
            return Ok(RelayReservation::New);
        }

        let (state, existing_destination_id, existing_frame, existing_type_map_version):
            (String, i64, Vec<u8>, String) = connection.query_row(
            "SELECT state, destination_id, frame, type_map_version FROM relay_inbox WHERE signer_id = ?1 AND message_id = ?2",
            params![signer_id, message_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get(3)?,
                ))
            },
        )?;
        Ok(RelayReservation::Existing {
            state,
            frame_matches: existing_destination_id == destination_id
                && existing_frame == frame
                && existing_type_map_version == type_map_version,
        })
    })
}

pub fn mark_delivered_for_frame(
    destination_id: u64,
    frame_id: u32,
) -> Result<Option<DeliveredRelay>, StorageError> {
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_immediate_transaction(|tx| {
        let delivered_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let relay = tx
            .query_row(
                "SELECT signer_id, message_id, destination_id FROM relay_inbox WHERE destination_id = ?1 AND frame_id = ?2",
                params![destination_id, i64::from(frame_id)],
                |row| Ok(DeliveredRelay { signer_id: row.get(0)?, message_id: row.get(1)?, destination_id: row.get(2)? }),
            )
            .optional()?;
        if relay.is_none() {
            return Ok(None);
        }
        tx.execute(
            "UPDATE relay_inbox SET state = 'delivered', downstream_acked_at = COALESCE(downstream_acked_at, ?3) WHERE destination_id = ?1 AND frame_id = ?2",
            params![destination_id, i64::from(frame_id), delivered_at],
        )?;
        Ok(relay)
    })
}

pub fn mark_delivered_for_frame_in_tx(
    tx: &rusqlite::Transaction<'_>,
    destination_id: i64,
    frame_id: u32,
) -> Result<(), StorageError> {
    let changed = tx.execute(
        "UPDATE relay_inbox SET state = 'delivered', downstream_acked_at = COALESCE(downstream_acked_at, ?3) WHERE destination_id = ?1 AND frame_id = ?2",
        params![destination_id, i64::from(frame_id), crate::util::sync::now_millis()],
    )?;
    if changed == 0 {
        return Err(StorageError::Other(
            "pending relay has no relay inbox record".into(),
        ));
    }
    Ok(())
}

fn mark_transition(
    signer_id: u64,
    message_id: &str,
    state: &str,
    column: &str,
) -> Result<(), StorageError> {
    let signer_id = i64::try_from(signer_id)
        .map_err(|_| StorageError::Other("relay signer ID exceeds SQLite range".into()))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    db::with_db(|connection| {
        connection.execute(
            &format!("UPDATE relay_inbox SET state = ?3, {column} = COALESCE({column}, ?4) WHERE signer_id = ?1 AND message_id = ?2"),
            params![signer_id, message_id, state, timestamp],
        )?;
        Ok(())
    })
}

pub fn mark_applied(signer_id: u64, message_id: &str) -> Result<(), StorageError> {
    mark_transition(signer_id, message_id, "applied", "applied_at")
}

pub fn mark_queued(signer_id: u64, message_id: &str) -> Result<(), StorageError> {
    mark_transition(signer_id, message_id, "queued", "queued_at")
}

pub fn mark_queued_in_tx(
    tx: &rusqlite::Transaction<'_>,
    signer_id: i64,
    message_id: &str,
) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE relay_inbox SET state = 'queued', queued_at = COALESCE(queued_at, ?3) WHERE signer_id = ?1 AND message_id = ?2",
        params![signer_id, message_id, crate::util::sync::now_millis()],
    )?;
    Ok(())
}

pub fn mark_downstream_acked(signer_id: u64, message_id: &str) -> Result<(), StorageError> {
    mark_transition(signer_id, message_id, "delivered", "downstream_acked_at")
}

pub fn mark_rejected(signer_id: u64, message_id: &str) -> Result<(), StorageError> {
    mark_transition(signer_id, message_id, "rejected", "rejected_at")
}

pub fn prune_completed(before_terminal_at: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute(
            "DELETE FROM relay_inbox WHERE COALESCE(downstream_acked_at, rejected_at) < ?1 AND state IN ('delivered', 'rejected')",
            params![before_terminal_at],
        )?;
        connection.execute(
            "DELETE FROM relay_replay WHERE NOT EXISTS (SELECT 1 FROM relay_inbox WHERE relay_inbox.signer_id = relay_replay.signer_id AND relay_inbox.message_id = relay_replay.message_id)",
            [],
        )?;
        Ok(())
    })
}

pub fn accept(signer_id: u64, message_id: &str, created_at: u64) -> Result<bool, StorageError> {
    let signer_id = i64::try_from(signer_id)
        .map_err(|_| StorageError::Other("relay signer ID exceeds SQLite range".into()))?;
    let created_at = i64::try_from(created_at)
        .map_err(|_| StorageError::Other("relay creation time exceeds SQLite range".into()))?;

    db::with_db(|connection| {
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_id, message_id, created_at) VALUES (?1, ?2, ?3)",
            params![signer_id, message_id, created_at],
        )?;
        Ok(inserted == 1)
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};

    #[test]
    fn replay_identity_uses_signer_and_message_id() -> Result<(), rusqlite::Error> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE relay_replay (signer_id INTEGER NOT NULL, message_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (signer_id, message_id));",
        )?;

        let first = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_id, message_id, created_at) VALUES (?1, ?2, ?3)",
            params![7_i64, "message", 1_i64],
        )?;
        let duplicate = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_id, message_id, created_at) VALUES (?1, ?2, ?3)",
            params![7_i64, "message", 2_i64],
        )?;
        let other_signer = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_id, message_id, created_at) VALUES (?1, ?2, ?3)",
            params![8_i64, "message", 2_i64],
        )?;

        assert_eq!((first, duplicate, other_signer), (1, 0, 1));
        Ok(())
    }
}
