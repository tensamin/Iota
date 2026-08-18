use crate::storage_error::StorageError;
use crate::util::db;
use rusqlite::params;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReservation {
    New,
    Existing { state: String, frame_matches: bool },
}

pub fn reserve(
    signer_id: u64,
    message_id: &str,
    created_at: u64,
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
            "INSERT OR IGNORE INTO relay_inbox (signer_id, message_id, created_at, destination_id, frame, frame_id, type_map_version, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'received')",
            params![
                signer_id,
                message_id,
                created_at,
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

pub fn mark_delivered_for_frame(destination_id: u64, frame_id: u32) -> Result<(), StorageError> {
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_db(|connection| {
        connection.execute(
            "UPDATE relay_inbox SET state = 'delivered' WHERE destination_id = ?1 AND frame_id = ?2",
            params![destination_id, i64::from(frame_id)],
        )?;
        Ok(())
    })
}

pub fn mark_state(signer_id: u64, message_id: &str, state: &str) -> Result<(), StorageError> {
    if !matches!(
        state,
        "received" | "applied" | "queued" | "delivered" | "rejected"
    ) {
        return Err(StorageError::Other("invalid relay inbox state".into()));
    }
    let signer_id = i64::try_from(signer_id)
        .map_err(|_| StorageError::Other("relay signer ID exceeds SQLite range".into()))?;
    db::with_db(|connection| {
        connection.execute(
            "UPDATE relay_inbox SET state = ?3 WHERE signer_id = ?1 AND message_id = ?2",
            params![signer_id, message_id, state],
        )?;
        Ok(())
    })
}

pub fn prune_completed(before_created_at: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute(
            "DELETE FROM relay_inbox WHERE created_at < ?1 AND state IN ('delivered', 'rejected')",
            params![before_created_at],
        )?;
        connection.execute(
            "DELETE FROM relay_replay WHERE created_at < ?1",
            params![before_created_at],
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
