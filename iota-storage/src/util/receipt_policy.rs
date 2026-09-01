/* Receipt disclosure is typed policy because Iota enforces it when relaying states. */
use crate::storage_error::StorageError;
use crate::util::{db, sync};
use rusqlite::OptionalExtension;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptPolicy {
    pub user_id: i64,
    pub send_read_receipts: bool,
    pub send_received_receipts: bool,
    pub revision: i64,
    pub updated_at: i64,
}
pub fn default_policy() -> ReceiptPolicy {
    ReceiptPolicy {
        user_id: 0,
        send_read_receipts: true,
        send_received_receipts: false,
        revision: 0,
        updated_at: 0,
    }
}
fn validate(user_id: i64) -> Result<(), StorageError> {
    if user_id > 0 {
        Ok(())
    } else {
        Err(StorageError::Other("invalid receipt policy owner".into()))
    }
}
pub fn get(user_id: i64) -> Result<ReceiptPolicy, StorageError> {
    validate(user_id)?;
    db::with_db(|conn| {
        let found = conn.query_row("SELECT send_read_receipts, send_received_receipts, revision, updated_at FROM user_receipt_policy WHERE user_id = ?1", [user_id], |r| Ok(ReceiptPolicy { user_id, send_read_receipts: r.get(0)?, send_received_receipts: r.get(1)?, revision: r.get(2)?, updated_at: r.get(3)? })).optional()?;
        Ok(found.unwrap_or(ReceiptPolicy {
            user_id,
            ..default_policy()
        }))
    })
}
pub fn set(
    user_id: i64,
    send_read_receipts: bool,
    send_received_receipts: bool,
) -> Result<ReceiptPolicy, StorageError> {
    validate(user_id)?;
    db::with_immediate_transaction(|tx| {
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::ReceiptPolicy,
            user_id,
            sync::Operation::Upsert,
        )?;
        let updated_at = sync::now_millis();
        tx.execute("INSERT INTO user_receipt_policy (user_id, send_read_receipts, send_received_receipts, revision, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(user_id) DO UPDATE SET send_read_receipts = excluded.send_read_receipts, send_received_receipts = excluded.send_received_receipts, revision = excluded.revision, updated_at = excluded.updated_at", rusqlite::params![user_id, send_read_receipts, send_received_receipts, revision, updated_at])?;
        Ok(ReceiptPolicy {
            user_id,
            send_read_receipts,
            send_received_receipts,
            revision,
            updated_at,
        })
    })
}
