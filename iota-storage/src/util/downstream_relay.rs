/* Completes or rejects an Iota-to-Iota relay without leaving retry state behind. */
use crate::storage_error::StorageError;
use crate::util::{db, sync};
use rusqlite::{OptionalExtension, params};

pub fn acknowledge_iota_delivery(
    frame_id: u32,
    signer_principal: iota_identity::PrincipalHandle,
    _legacy_signer_id: Option<i64>,
    relay_message_id: &str,
    destination_accepted_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let pending_id = tx
            .query_row(
                "SELECT id FROM pending_relays WHERE signer_principal = ?1 AND frame_id = ?2",
                params![signer_principal.0, i64::from(frame_id)],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(pending_id) = pending_id else {
            return Ok(());
        };
        let message = tx
            .query_row(
                "SELECT id, storage_owner FROM messages WHERE relay_signer_principal = ?1 AND relay_message_id = ?2",
                params![signer_principal.0, relay_message_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        if let Some((message_id, storage_owner)) = message {
            tx.execute("UPDATE messages SET destination_iota_received_at = COALESCE(destination_iota_received_at, ?1), delivery_failed_at = NULL, delivery_failure = NULL, message_state = CASE WHEN message_state = 'sending' THEN 'sent' ELSE message_state END WHERE id = ?2", params![destination_accepted_at, message_id])?;
            sync::record_event(
                tx,
                storage_owner,
                sync::EntityType::Message,
                message_id,
                sync::Operation::Upsert,
            )?;
        }
        tx.execute("UPDATE relay_inbox SET state = 'delivered', downstream_acked_at = COALESCE(downstream_acked_at, ?3) WHERE signer_principal = ?1 AND message_id = ?2", params![signer_principal.0, relay_message_id, sync::now_millis()])?;
        tx.execute("DELETE FROM pending_relays WHERE id = ?1", [pending_id])?;
        Ok(())
    })
}

pub fn reject_iota_delivery(
    frame_id: u32,
    signer_principal: iota_identity::PrincipalHandle,
    _legacy_signer_id: Option<i64>,
    relay_message_id: &str,
    failure: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let pending_id = tx
            .query_row(
                "SELECT id FROM pending_relays WHERE signer_principal = ?1 AND frame_id = ?2",
                params![signer_principal.0, i64::from(frame_id)],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(pending_id) = pending_id else {
            return Ok(());
        };
        let message = tx
            .query_row(
                "SELECT id, storage_owner FROM messages WHERE relay_signer_principal = ?1 AND relay_message_id = ?2",
                params![signer_principal.0, relay_message_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        if let Some((message_id, storage_owner)) = message {
            tx.execute(
                "UPDATE messages SET delivery_failed_at = ?1, delivery_failure = ?2 WHERE id = ?3",
                params![sync::now_millis(), failure, message_id],
            )?;
            sync::record_event(
                tx,
                storage_owner,
                sync::EntityType::Message,
                message_id,
                sync::Operation::Upsert,
            )?;
        }
        tx.execute("UPDATE relay_inbox SET state = 'rejected', rejected_at = COALESCE(rejected_at, ?3) WHERE signer_principal = ?1 AND message_id = ?2", params![signer_principal.0, relay_message_id, sync::now_millis()])?;
        tx.execute("DELETE FROM pending_relays WHERE id = ?1", [pending_id])?;
        Ok(())
    })
}
