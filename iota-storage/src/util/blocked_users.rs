/* Blocks are user policy independent of contacts or conversations. */
use crate::storage_error::StorageError;
use crate::util::{db, sync};
use rusqlite::{OptionalExtension, params};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockMutation {
    pub blocked_user_id: i64,
    pub revision: i64,
    pub deleted: bool,
}
fn validate(user_id: i64, blocked_user_id: i64) -> Result<(), StorageError> {
    if user_id <= 0 || blocked_user_id <= 0 || user_id == blocked_user_id {
        Err(StorageError::Other("invalid block relationship".into()))
    } else {
        Ok(())
    }
}
pub fn block(user_id: i64, blocked_user_id: i64) -> Result<BlockMutation, StorageError> {
    validate(user_id, blocked_user_id)?;
    db::with_immediate_transaction(|tx| {
        let prior = tx.query_row("SELECT id, revision FROM blocked_users WHERE user_id = ?1 AND blocked_user_id = ?2", params![user_id, blocked_user_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).optional()?;
        if let Some((_, revision)) = prior {
            return Ok(BlockMutation {
                blocked_user_id,
                revision,
                deleted: false,
            });
        }
        let created_at = sync::now_millis();
        tx.execute("INSERT INTO blocked_users (user_id, blocked_user_id, revision, created_at) VALUES (?1, ?2, 0, ?3)", params![user_id, blocked_user_id, created_at])?;
        let id = tx.last_insert_rowid();
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::BlockedUser,
            id,
            sync::Operation::Upsert,
        )?;
        tx.execute(
            "UPDATE blocked_users SET revision = ?2 WHERE id = ?1",
            params![id, revision],
        )?;
        Ok(BlockMutation {
            blocked_user_id,
            revision,
            deleted: false,
        })
    })
}
pub fn unblock(user_id: i64, blocked_user_id: i64) -> Result<Option<BlockMutation>, StorageError> {
    validate(user_id, blocked_user_id)?;
    db::with_immediate_transaction(|tx| {
        let id = tx
            .query_row(
                "SELECT id FROM blocked_users WHERE user_id = ?1 AND blocked_user_id = ?2",
                params![user_id, blocked_user_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            return Ok(None);
        };
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::BlockedUser,
            id,
            sync::Operation::Delete,
        )?;
        tx.execute("DELETE FROM blocked_users WHERE id = ?1", [id])?;
        Ok(Some(BlockMutation {
            blocked_user_id,
            revision,
            deleted: true,
        }))
    })
}
pub fn is_blocked(user_id: i64, candidate_sender_id: i64) -> Result<bool, StorageError> {
    validate(user_id, candidate_sender_id)?;
    db::with_db(|conn| {
        Ok(conn
            .query_row(
                "SELECT 1 FROM blocked_users WHERE user_id = ?1 AND blocked_user_id = ?2",
                params![user_id, candidate_sender_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    })
}
pub fn list(user_id: i64) -> Result<Vec<i64>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid block owner".into()));
    }
    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT blocked_user_id FROM blocked_users WHERE user_id = ?1 ORDER BY blocked_user_id",
        )?;
        stmt.query_map([user_id], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    })
}
