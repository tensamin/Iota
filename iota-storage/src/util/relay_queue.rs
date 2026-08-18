use crate::storage_error::StorageError;
use crate::util::db;
use iota_util::route_target::RouteTarget;
use rusqlite::params;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRelay {
    pub id: i64,
    pub target: RouteTarget,
    pub frame: Vec<u8>,
    pub created_at: i64,
    pub frame_id: u32,
    pub type_map_version: String,
}

pub fn enqueue(
    target: RouteTarget,
    frame: &[u8],
    created_at: i64,
    frame_id: u32,
    type_map_version: &str,
) -> Result<(), StorageError> {
    let destination_id = i64::try_from(target.id())
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    let target_kind = match target {
        RouteTarget::User(_) => 0_i64,
        RouteTarget::Iota(_) => 1_i64,
    };
    db::with_db(|connection| {
        connection.execute(
            "INSERT OR IGNORE INTO pending_relays (destination_id, target_kind, frame, created_at, frame_id, type_map_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                destination_id,
                target_kind,
                frame,
                created_at,
                i64::from(frame_id),
                type_map_version
            ],
        )?;
        Ok(())
    })
}

pub fn list(limit: i64) -> Result<Vec<PendingRelay>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare(
            "SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version FROM pending_relays ORDER BY id LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit.clamp(1, 500)], |row| {
            let destination_id = row.get::<_, i64>(1)?;
            let target_kind = row.get::<_, i64>(2)?;
            let destination_id = u64::try_from(destination_id).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    "negative relay destination ID".into(),
                )
            })?;
            let target = match target_kind {
                0 => RouteTarget::User(destination_id),
                1 => RouteTarget::Iota(destination_id),
                _ => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Integer,
                        "invalid relay target kind".into(),
                    ));
                }
            };
            Ok(PendingRelay {
                id: row.get(0)?,
                target,
                frame: row.get(3)?,
                created_at: row.get(4)?,
                frame_id: u32::try_from(row.get::<_, i64>(5)?).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Integer,
                        "negative relay frame ID".into(),
                    )
                })?,
                type_map_version: row.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
}

pub fn acknowledge(destination_id: u64, frame_id: u32) -> Result<bool, StorageError> {
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_db(|connection| {
        let changed = connection.execute(
            "DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = 0 AND frame_id = ?2",
            params![destination_id, i64::from(frame_id)],
        )?;
        Ok(changed == 1)
    })
}

pub fn acknowledge_iota(destination_id: u64, frame_id: u32) -> Result<bool, StorageError> {
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_db(|connection| {
        let changed = connection.execute(
            "DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = 1 AND frame_id = ?2",
            params![destination_id, i64::from(frame_id)],
        )?;
        Ok(changed == 1)
    })
}

pub fn remove_for_frame(target: RouteTarget, frame_id: u32) -> Result<bool, StorageError> {
    let destination_id = i64::try_from(target.id())
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    let target_kind = match target {
        RouteTarget::User(_) => 0_i64,
        RouteTarget::Iota(_) => 1_i64,
    };
    db::with_db(|connection| {
        let changed = connection.execute(
            "DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = ?2 AND frame_id = ?3",
            params![destination_id, target_kind, i64::from(frame_id)],
        )?;
        Ok(changed == 1)
    })
}

pub fn delete(id: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute("DELETE FROM pending_relays WHERE id = ?1", params![id])?;
        Ok(())
    })
}
