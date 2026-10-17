/* Accepts an outgoing relay only when its retry record and retention state commit together. */
use crate::storage_error::StorageError;
use crate::util::{chat_files, db, message_storage_policy};
use rusqlite::OptionalExtension;

pub fn apply_outgoing_history_policy(
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        apply_outgoing_history_policy_in_tx(
            tx,
            storage_owner,
            relay_signer_principal,
            relay_message_id,
        )
    })
}

pub fn apply_outgoing_history_policy_in_tx(
    tx: &rusqlite::Transaction<'_>,
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
) -> Result<(), StorageError> {
    if message_storage_policy::get_in_tx(tx, storage_owner)?.history_mode
        != message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery
    {
        return Ok(());
    }
    let message_id = tx.query_row(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
            rusqlite::params![storage_owner, relay_signer_principal.0, relay_message_id],
            |row| row.get::<_, i64>(0),
        ).optional()?;
    if let Some(message_id) = message_id {
        chat_files::remove_message_history_in_tx(tx, storage_owner, message_id)?;
    }
    Ok(())
}
