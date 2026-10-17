/* Commits client delivery, relay state, and retention cleanup as one operation. */
use crate::storage_error::StorageError;
use crate::util::{chat_files, db, message_storage_policy, relay_queue, relay_replay};
use rusqlite::OptionalExtension;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRelayDeliveryResult {
    NotFound,
    Acknowledged,
}

pub fn acknowledge_pending_client_delivery(
    pending: &relay_queue::PendingRelay,
) -> Result<ClientRelayDeliveryResult, StorageError> {
    db::with_immediate_transaction(|tx| acknowledge_pending_client_delivery_in_tx(tx, pending))
}

pub fn acknowledge_claimed_client_delivery(
    claimed: &relay_queue::ClaimedPendingRelay,
) -> Result<ClientRelayDeliveryResult, StorageError> {
    db::with_immediate_transaction(|tx| acknowledge_claimed_client_delivery_in_tx(tx, claimed))
}

pub fn acknowledge_claimed_client_delivery_in_tx(
    tx: &rusqlite::Transaction<'_>,
    claimed: &relay_queue::ClaimedPendingRelay,
) -> Result<ClientRelayDeliveryResult, StorageError> {
    if !relay_queue::verify_claim_in_tx(tx, claimed, relay_queue::now_millis())? {
        return Ok(ClientRelayDeliveryResult::NotFound);
    }
    let pending = &claimed.pending;
    let relay_queue::RelayTarget::User(destination) = pending.target else {
        return Err(StorageError::PendingRelayConflict);
    };
    let destination = i64::try_from(destination).map_err(|_| StorageError::PendingRelayConflict)?;
    let relay = relay_queue::RelayIdentity {
        signer: pending
            .signer_principal
            .ok_or(StorageError::PendingRelayOwnershipUnknown)?,
        recipient: pending
            .destination_principal
            .ok_or(StorageError::PendingRelayOwnershipUnknown)?,
        message_id: pending
            .relay_message_id
            .clone()
            .ok_or(StorageError::PendingRelayOwnershipUnknown)?,
        legacy_signer_id: pending.relay_signer_id,
        legacy_recipient_id: pending.relay_destination_user_id,
    };
    if relay.legacy_recipient_id != Some(destination) {
        return Err(StorageError::PendingRelayConflict);
    }
    complete_effects_in_tx(tx, destination, &relay)?;
    tx.execute("DELETE FROM pending_relays WHERE id = ?1 AND dispatch_generation = ?2 AND dispatch_owner = ?3", rusqlite::params![pending.id, claimed.claim.generation, claimed.claim.owner])?;
    Ok(ClientRelayDeliveryResult::Acknowledged)
}

pub fn acknowledge_pending_client_delivery_in_tx(
    tx: &rusqlite::Transaction<'_>,
    pending: &relay_queue::PendingRelay,
) -> Result<ClientRelayDeliveryResult, StorageError> {
    let relay_queue::RelayTarget::User(destination) = pending.target else {
        return Err(StorageError::PendingRelayConflict);
    };
    let destination = i64::try_from(destination).map_err(|_| StorageError::PendingRelayConflict)?;
    let Some(current) = relay_queue::load_in_tx(tx, pending.id)? else {
        return Ok(ClientRelayDeliveryResult::NotFound);
    };
    if !current.matches_immutable(pending) {
        return Err(StorageError::PendingRelayConflict);
    }
    if current.delivery_state != relay_queue::PendingRelayDeliveryState::Ready {
        return Err(StorageError::InvalidRelayTransition);
    }
    let relay = relay_queue::RelayIdentity {
        signer: current
            .signer_principal
            .ok_or(StorageError::PendingRelayOwnershipUnknown)?,
        recipient: current
            .destination_principal
            .ok_or(StorageError::PendingRelayOwnershipUnknown)?,
        message_id: current
            .relay_message_id
            .ok_or(StorageError::PendingRelayOwnershipUnknown)?,
        legacy_signer_id: current.relay_signer_id,
        legacy_recipient_id: current.relay_destination_user_id,
    };
    if relay.legacy_recipient_id != Some(destination) {
        return Err(StorageError::PendingRelayConflict);
    }
    complete_in_tx(tx, destination, pending.id, &relay)
}

#[cfg(test)]
pub(crate) fn acknowledge_client_delivery_in_tx(
    tx: &rusqlite::Transaction<'_>,
    destination_id: i64,
    frame_id: u32,
) -> Result<ClientRelayDeliveryResult, StorageError> {
    let Some((pending_id, relay)) =
        relay_queue::find_user_delivery_in_tx(tx, destination_id, frame_id)?
    else {
        return Ok(ClientRelayDeliveryResult::NotFound);
    };
    complete_in_tx(tx, destination_id, pending_id, &relay)
}

fn complete_in_tx(
    tx: &rusqlite::Transaction<'_>,
    destination_id: i64,
    pending_id: i64,
    relay: &relay_queue::RelayIdentity,
) -> Result<ClientRelayDeliveryResult, StorageError> {
    let unclaimed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pending_relays WHERE id = ?1 AND dispatch_generation = 0)",
        [pending_id],
        |r| r.get(0),
    )?;
    if !unclaimed {
        return Ok(ClientRelayDeliveryResult::NotFound);
    }
    complete_effects_in_tx(tx, destination_id, relay)?;
    relay_queue::acknowledge_in_tx(tx, pending_id)?;
    Ok(ClientRelayDeliveryResult::Acknowledged)
}

fn complete_effects_in_tx(
    tx: &rusqlite::Transaction<'_>,
    destination_id: i64,
    relay: &relay_queue::RelayIdentity,
) -> Result<(), StorageError> {
    let policy = message_storage_policy::get_in_tx(tx, destination_id)?;
    relay_replay::mark_delivered_in_tx(tx, relay.signer, &relay.message_id)?;
    if policy.history_mode == message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery
    {
        let message_id = tx.query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                rusqlite::params![destination_id, relay.signer.0, relay.message_id],
                |row| row.get::<_, i64>(0),
            ).optional()?;
        if let Some(message_id) = message_id {
            chat_files::remove_message_history_in_tx(tx, destination_id, message_id)?;
        }
    }
    Ok(())
}
