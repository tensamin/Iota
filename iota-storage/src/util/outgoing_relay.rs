/* Accepts an outgoing relay only when its retry record and retention state commit together. */
use crate::storage_error::StorageError;
use crate::util::{chat_files, db, message_storage_policy, relay_queue, relay_replay};
use rusqlite::OptionalExtension;

pub struct OutgoingRelay<'a> {
    pub target: relay_queue::RelayTarget,
    pub identity: &'a relay_queue::RelayIdentity,
    pub frame: &'a [u8],
    pub created_at: i64,
    pub frame_id: u32,
    pub type_map_version: &'a str,
}

pub fn commit_outgoing_relay(relay: OutgoingRelay<'_>) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        relay_queue::enqueue_in_tx(
            tx,
            relay.target,
            relay.identity,
            relay.frame,
            relay.created_at,
            relay.frame_id,
            relay.type_map_version,
        )?;
        let signer_id = tx
            .query_row(
                "SELECT local_user_id FROM hosted_principals WHERE principal_handle = ?1",
                [relay.identity.signer.0],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Other("outgoing signer is not hosted locally".into()))?;
        if message_storage_policy::get_in_tx(tx, signer_id)?.history_mode
            == message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery
        {
            let message_id = tx.query_row("SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3", rusqlite::params![signer_id, relay.identity.signer.0, relay.identity.message_id], |row| row.get::<_, i64>(0)).optional()?;
            if let Some(message_id) = message_id {
                chat_files::remove_message_history_in_tx(tx, signer_id, message_id)?;
            }
        }
        relay_replay::mark_queued_in_tx(tx, relay.identity.signer, &relay.identity.message_id)?;
        Ok(())
    })
}

pub fn apply_outgoing_history_policy(
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
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
    })
}
