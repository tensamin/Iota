/* Opaque client-owned bytes. Confidentiality is provided by the client-side blob format. */
use crate::storage_error::StorageError;
use crate::util::{db, sync};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

pub const MAX_BLOB_ID_BYTES: usize = 256;
pub const MAX_BLOB_BYTES: usize = 1_048_576;
pub const MAX_USER_BLOB_BYTES: usize = 16_777_216;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBlob {
    pub id: i64,
    pub user_id: i64,
    pub blob_id: String,
    pub blob: Vec<u8>,
    pub revision: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBlobMetadata {
    pub blob_id: String,
    pub revision: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedUserBlob {
    pub id: i64,
    pub blob_id: String,
    pub revision: i64,
    pub changed: bool,
}

fn validate(user_id: i64, blob_id: &str, blob: Option<&[u8]>) -> Result<(), StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid blob owner".into()));
    }
    if blob_id.is_empty() || blob_id.len() > MAX_BLOB_ID_BYTES {
        return Err(StorageError::Other("invalid blob id".into()));
    }
    if let Some(blob) = blob {
        if blob.len() > MAX_BLOB_BYTES {
            return Err(StorageError::Other("blob exceeds size limit".into()));
        }
    }
    Ok(())
}

fn from_row(row: &Row<'_>) -> rusqlite::Result<UserBlob> {
    Ok(UserBlob {
        id: row.get(0)?,
        user_id: row.get(1)?,
        blob_id: row.get(2)?,
        blob: row.get(3)?,
        revision: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn metadata_from_row(row: &Row<'_>) -> rusqlite::Result<UserBlobMetadata> {
    Ok(UserBlobMetadata {
        blob_id: row.get(0)?,
        revision: row.get(1)?,
        updated_at: row.get(2)?,
    })
}

fn load(tx: &Transaction<'_>, id: i64) -> Result<UserBlob, StorageError> {
    Ok(tx.query_row("SELECT id, user_id, blob_id, blob, revision, updated_at FROM user_blobs WHERE id = ?1 AND deleted = 0", [id], from_row)?)
}

pub fn put(
    user_id: i64,
    blob_id: &str,
    blob: &[u8],
    expected_revision: Option<i64>,
) -> Result<UserBlob, StorageError> {
    validate(user_id, blob_id, Some(blob))?;
    db::with_immediate_transaction(|tx| {
        let existing = tx
            .query_row(
                "SELECT id, revision, deleted, length(blob) FROM user_blobs WHERE user_id = ?1 AND blob_id = ?2",
                params![user_id, blob_id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let existing_id = if let Some((id, revision, deleted, _)) = existing {
            if deleted {
                if !matches!(expected_revision, Some(0)) {
                    return Err(StorageError::RevisionConflict);
                }
            } else if expected_revision != Some(revision) {
                return Err(StorageError::RevisionConflict);
            }
            Some(id)
        } else {
            if !matches!(expected_revision, None | Some(0)) {
                return Err(StorageError::RevisionConflict);
            }
            None
        };
        let current_size = existing
            .filter(|(_, _, deleted, _)| !*deleted)
            .map(|(_, _, _, size)| size)
            .unwrap_or(0);
        let aggregate: i64 = tx.query_row("SELECT COALESCE(SUM(length(blob)), 0) FROM user_blobs WHERE user_id = ?1 AND deleted = 0", [user_id], |r| r.get(0))?;
        let proposed_size = aggregate
            .checked_sub(current_size)
            .and_then(|size| size.checked_add(blob.len() as i64))
            .ok_or_else(|| StorageError::Other("user blob storage quota overflow".into()))?;
        if proposed_size > MAX_USER_BLOB_BYTES as i64 {
            return Err(StorageError::Other(
                "user blob storage limit exceeded".into(),
            ));
        }
        let id = match existing_id {
            Some(id) => id,
            None => {
                tx.execute("INSERT INTO user_blobs (user_id, blob_id, blob, revision, deleted, updated_at) VALUES (?1, ?2, ?3, 0, 0, ?4)", params![user_id, blob_id, blob, sync::now_millis()])?;
                tx.last_insert_rowid()
            }
        };
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::UserBlob,
            id,
            sync::Operation::Upsert,
        )?;
        tx.execute("UPDATE user_blobs SET blob = ?2, revision = ?3, deleted = 0, updated_at = ?4 WHERE id = ?1", params![id, blob, revision, sync::now_millis()])?;
        load(tx, id)
    })
}

pub fn get(user_id: i64, blob_id: &str) -> Result<Option<UserBlob>, StorageError> {
    validate(user_id, blob_id, None)?;
    db::with_db(|conn| get_on(conn, user_id, blob_id))
}
fn get_on(
    conn: &Connection,
    user_id: i64,
    blob_id: &str,
) -> Result<Option<UserBlob>, StorageError> {
    Ok(conn.query_row("SELECT id, user_id, blob_id, blob, revision, updated_at FROM user_blobs WHERE user_id = ?1 AND blob_id = ?2 AND deleted = 0", params![user_id, blob_id], from_row).optional()?)
}
pub fn list(user_id: i64) -> Result<Vec<UserBlob>, StorageError> {
    list_by_query(
        user_id,
        "SELECT id, user_id, blob_id, blob, revision, updated_at FROM user_blobs WHERE user_id = ?1 AND deleted = 0",
        &[],
    )
}

pub fn list_metadata(user_id: i64) -> Result<Vec<UserBlobMetadata>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid blob owner".into()));
    }
    db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT blob_id, revision, updated_at FROM user_blobs WHERE user_id = ?1 AND deleted = 0",
        )?;
        let rows = statement.query_map([user_id], metadata_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    })
}
pub fn list_by_ids(user_id: i64, ids: &[i64]) -> Result<Vec<UserBlob>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid blob owner".into()));
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    db::with_db(|conn| {
        let mut out = Vec::new();
        for id in ids {
            if let Some(blob) = conn.query_row("SELECT id, user_id, blob_id, blob, revision, updated_at FROM user_blobs WHERE user_id = ?1 AND id = ?2 AND deleted = 0", params![user_id, id], from_row).optional()? { out.push(blob); }
        }
        Ok(out)
    })
}

pub fn list_deleted_by_ids(
    user_id: i64,
    ids: &[i64],
) -> Result<Vec<DeletedUserBlob>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid blob owner".into()));
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    db::with_db(|conn| {
        let mut deleted = Vec::new();
        for id in ids {
            if let Some(blob) = conn.query_row(
                "SELECT id, blob_id, revision FROM user_blobs WHERE user_id = ?1 AND id = ?2 AND deleted = 1",
                params![user_id, id],
                |row| {
                    Ok(DeletedUserBlob {
                        id: row.get(0)?,
                        blob_id: row.get(1)?,
                        revision: row.get(2)?,
                        changed: true,
                    })
                },
            ).optional()? {
                deleted.push(blob);
            }
        }
        Ok(deleted)
    })
}
fn list_by_query(user_id: i64, query: &str, _: &[i64]) -> Result<Vec<UserBlob>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid blob owner".into()));
    }
    db::with_db(|conn| {
        let mut statement = conn.prepare(query)?;
        let rows = statement.query_map([user_id], from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    })
}
pub fn delete(
    user_id: i64,
    blob_id: &str,
    expected_revision: Option<i64>,
) -> Result<Option<DeletedUserBlob>, StorageError> {
    validate(user_id, blob_id, None)?;
    db::with_immediate_transaction(|tx| {
        let existing = tx
            .query_row(
                "SELECT id, revision, deleted FROM user_blobs WHERE user_id = ?1 AND blob_id = ?2",
                params![user_id, blob_id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, current, deleted)) = existing else {
            return Ok(None);
        };
        if deleted {
            return Ok(Some(DeletedUserBlob {
                id,
                blob_id: blob_id.into(),
                revision: current,
                changed: false,
            }));
        }
        if expected_revision != Some(current) {
            return Err(StorageError::RevisionConflict);
        }
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::UserBlob,
            id,
            sync::Operation::Delete,
        )?;
        tx.execute(
            "UPDATE user_blobs SET blob = X'', deleted = 1, revision = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, revision, sync::now_millis()],
        )?;
        Ok(Some(DeletedUserBlob {
            id,
            blob_id: blob_id.into(),
            revision,
            changed: true,
        }))
    })
}
