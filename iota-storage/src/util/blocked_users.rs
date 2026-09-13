/* Blocks are user policy independent of contacts or conversations. */
use crate::storage_error::StorageError;
use crate::util::{db, sync};
use rusqlite::{OptionalExtension, params};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockMutation {
    pub blocked_user_id: i64,
    pub blocked_principal: iota_identity::PrincipalHandle,
    pub revision: i64,
    pub deleted: bool,
}
fn validate(
    user_id: i64,
    blocked_principal: iota_identity::PrincipalHandle,
) -> Result<(), StorageError> {
    if user_id <= 0 || blocked_principal.0 <= 0 {
        Err(StorageError::Other("invalid block relationship".into()))
    } else {
        Ok(())
    }
}
pub fn block(
    user_id: i64,
    blocked_principal: iota_identity::PrincipalHandle,
) -> Result<BlockMutation, StorageError> {
    validate(user_id, blocked_principal)?;
    db::with_immediate_transaction(|tx| {
        let blocked_user_id = tx.query_row(
            "SELECT remote_user_id FROM principals WHERE principal_pk = ?1",
            [blocked_principal.0],
            |row| row.get::<_, i64>(0),
        )?;
        let prior = tx.query_row("SELECT id, revision FROM blocked_users WHERE user_id = ?1 AND blocked_principal = ?2", params![user_id, blocked_principal.0], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).optional()?;
        if let Some((_, revision)) = prior {
            return Ok(BlockMutation {
                blocked_user_id,
                blocked_principal,
                revision,
                deleted: false,
            });
        }
        let created_at = sync::now_millis();
        tx.execute("INSERT INTO blocked_users (user_id, blocked_user_id, blocked_principal, revision, created_at) VALUES (?1, ?2, ?3, 0, ?4)", params![user_id, blocked_user_id, blocked_principal.0, created_at])?;
        let id = tx.last_insert_rowid();
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::BlockedUser,
            blocked_principal.0,
            sync::Operation::Upsert,
        )?;
        tx.execute(
            "UPDATE blocked_users SET revision = ?2 WHERE id = ?1",
            params![id, revision],
        )?;
        Ok(BlockMutation {
            blocked_user_id,
            blocked_principal,
            revision,
            deleted: false,
        })
    })
}
pub fn unblock(
    user_id: i64,
    blocked_principal: iota_identity::PrincipalHandle,
) -> Result<Option<BlockMutation>, StorageError> {
    validate(user_id, blocked_principal)?;
    db::with_immediate_transaction(|tx| {
        let row = tx
            .query_row(
                "SELECT id, blocked_user_id FROM blocked_users WHERE user_id = ?1 AND blocked_principal = ?2",
                params![user_id, blocked_principal.0],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((id, blocked_user_id)) = row else {
            return Ok(None);
        };
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::BlockedUser,
            blocked_principal.0,
            sync::Operation::Delete,
        )?;
        tx.execute("DELETE FROM blocked_users WHERE id = ?1", [id])?;
        Ok(Some(BlockMutation {
            blocked_user_id,
            blocked_principal,
            revision,
            deleted: true,
        }))
    })
}
pub fn is_blocked(user_id: i64, candidate_sender_id: i64) -> Result<bool, StorageError> {
    if user_id <= 0 || candidate_sender_id <= 0 || user_id == candidate_sender_id {
        return Err(StorageError::Other("invalid block relationship".into()));
    }
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

pub fn is_principal_blocked(
    user_id: i64,
    candidate: iota_identity::PrincipalHandle,
) -> Result<bool, StorageError> {
    if user_id <= 0 || candidate.0 <= 0 {
        return Err(StorageError::Other("invalid block relationship".into()));
    }
    db::with_db(|conn| {
        Ok(conn
            .query_row(
                "SELECT 1 FROM blocked_users WHERE user_id = ?1 AND blocked_principal = ?2",
                params![user_id, candidate.0],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    })
}
pub fn list(user_id: i64) -> Result<Vec<BlockMutation>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid block owner".into()));
    }
    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT blocked_user_id, blocked_principal, revision FROM blocked_users WHERE user_id = ?1 ORDER BY blocked_principal",
        )?;
        stmt.query_map([user_id], |r| {
            Ok(BlockMutation {
                blocked_user_id: r.get(0)?,
                blocked_principal: iota_identity::PrincipalHandle(r.get(1)?),
                revision: r.get(2)?,
                deleted: false,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StorageError::from)
    })
}
