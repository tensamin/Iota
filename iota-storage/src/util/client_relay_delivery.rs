/* Commits client delivery, relay state, and retention cleanup as one operation. */
use crate::storage_error::StorageError;
use crate::util::{chat_files, db, message_storage_policy, relay_queue, relay_replay};
use rusqlite::OptionalExtension;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRelayDeliveryResult {
    NotFound,
    Acknowledged,
}

pub fn acknowledge_client_delivery(
    destination_id: i64,
    frame_id: u32,
) -> Result<ClientRelayDeliveryResult, StorageError> {
    db::with_immediate_transaction(|tx| {
        let Some((pending_id, relay)) =
            relay_queue::find_user_delivery_in_tx(tx, destination_id, frame_id)?
        else {
            return Ok(ClientRelayDeliveryResult::NotFound);
        };
        let policy = message_storage_policy::get_in_tx(tx, destination_id)?;
        relay_replay::mark_delivered_for_frame_in_tx(tx, destination_id, frame_id)?;
        if policy.history_mode
            == message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery
        {
            let message_id = tx.query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_id = ?2 AND relay_message_id = ?3",
                rusqlite::params![destination_id, relay.signer_id, relay.message_id],
                |row| row.get::<_, i64>(0),
            ).optional()?;
            if let Some(message_id) = message_id {
                chat_files::remove_message_history_in_tx(tx, destination_id, message_id)?;
            }
        }
        relay_queue::acknowledge_in_tx(tx, pending_id)?;
        Ok(ClientRelayDeliveryResult::Acknowledged)
    })
}
