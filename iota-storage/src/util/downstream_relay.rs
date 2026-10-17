use crate::storage_error::StorageError;
use crate::util::{chat_files, db, relay_queue, relay_replay};
use relay_queue::{ClaimedPendingRelay, PendingRelay, PendingRelayDeliveryState, RelayTarget};
use rusqlite::{OptionalExtension, Transaction, params};

/// The response belongs to the immutable work selected for this transport send.
pub fn acknowledge_pending_delivery(
    pending: &PendingRelay,
    relay_message_id: &str,
    destination_accepted_at: i64,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        acknowledge_pending_delivery_in_tx(tx, pending, relay_message_id, destination_accepted_at)
    })
}

pub fn acknowledge_pending_delivery_in_tx(
    tx: &Transaction<'_>,
    pending: &PendingRelay,
    relay_message_id: &str,
    destination_accepted_at: i64,
) -> Result<bool, StorageError> {
    acknowledge_exact_in_tx(tx, pending, None, relay_message_id, destination_accepted_at)
}

/// Completes only the exact pending delivery under a live dispatch claim.
/// Stale, expired, released and removed work returns `false` without side effects.
pub fn acknowledge_claimed_pending_delivery(
    claimed: &ClaimedPendingRelay,
    relay_message_id: &str,
    destination_accepted_at: i64,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        acknowledge_claimed_pending_delivery_in_tx(
            tx,
            claimed,
            relay_message_id,
            destination_accepted_at,
        )
    })
}

pub fn acknowledge_claimed_pending_delivery_in_tx(
    tx: &Transaction<'_>,
    claimed: &ClaimedPendingRelay,
    relay_message_id: &str,
    destination_accepted_at: i64,
) -> Result<bool, StorageError> {
    acknowledge_exact_in_tx(
        tx,
        &claimed.pending,
        Some(claimed),
        relay_message_id,
        destination_accepted_at,
    )
}

fn acknowledge_exact_in_tx(
    tx: &Transaction<'_>,
    pending: &PendingRelay,
    claimed: Option<&ClaimedPendingRelay>,
    relay_message_id: &str,
    destination_accepted_at: i64,
) -> Result<bool, StorageError> {
    if destination_accepted_at < 0 {
        return Err(StorageError::PendingRelayConflict);
    }
    let Some(signer) = verify_pending_in_tx(tx, pending, claimed, relay_message_id)? else {
        return Ok(false);
    };
    super::relay_work::fault_point("before_destination_acknowledgement", relay_message_id);
    super::relay_work::complete_deferred_in_tx(tx, signer, relay_message_id)?;
    // This transition fences late responses before any message metadata changes.
    relay_replay::mark_delivered_in_tx(tx, signer, relay_message_id)?;
    super::relay_work::fault_point("after_terminal_completion", relay_message_id);
    let message = origin_message_in_tx(tx, signer, relay_message_id)?;
    if let Some((_, storage_owner)) = message {
        chat_files::record_destination_iota_received_in_tx(
            tx,
            storage_owner,
            signer,
            relay_message_id,
            destination_accepted_at,
        )?;
    }
    tx.execute("DELETE FROM pending_relays WHERE id = ?1", [pending.id])?;
    Ok(true)
}

pub fn reject_pending_delivery(
    pending: &PendingRelay,
    failure: &str,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| reject_pending_delivery_in_tx(tx, pending, failure))
}

pub fn reject_pending_delivery_in_tx(
    tx: &Transaction<'_>,
    pending: &PendingRelay,
    failure: &str,
) -> Result<bool, StorageError> {
    reject_exact_in_tx(tx, pending, None, failure)
}

/// Records failure only under a live dispatch claim, preserving application state.
pub fn reject_claimed_pending_delivery(
    claimed: &ClaimedPendingRelay,
    failure: &str,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| reject_claimed_pending_delivery_in_tx(tx, claimed, failure))
}

pub fn reject_claimed_pending_delivery_in_tx(
    tx: &Transaction<'_>,
    claimed: &ClaimedPendingRelay,
    failure: &str,
) -> Result<bool, StorageError> {
    reject_exact_in_tx(tx, &claimed.pending, Some(claimed), failure)
}

fn reject_exact_in_tx(
    tx: &Transaction<'_>,
    pending: &PendingRelay,
    claimed: Option<&ClaimedPendingRelay>,
    failure: &str,
) -> Result<bool, StorageError> {
    let message_id = pending
        .relay_message_id
        .as_deref()
        .ok_or(StorageError::PendingRelayOwnershipUnknown)?;
    let Some(signer) = verify_pending_in_tx(tx, pending, claimed, message_id)? else {
        return Ok(false);
    };
    let state: String = tx.query_row(
        "SELECT state FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2",
        params![signer.0, message_id],
        |row| row.get(0),
    )?;
    if !matches!(
        relay_replay::RelayState::try_from(state.as_str())?,
        relay_replay::RelayState::Applied | relay_replay::RelayState::Queued
    ) {
        return Err(StorageError::InvalidRelayTransition);
    }
    if let Some((_, storage_owner)) = origin_message_in_tx(tx, signer, message_id)? {
        chat_files::record_delivery_failure_in_tx(
            tx,
            storage_owner,
            signer,
            message_id,
            failure,
            crate::util::sync::now_millis(),
        )?;
    }
    // Application completion remains intact. The exact delivery records the failure.
    tx.execute(
        "UPDATE pending_relays SET delivery_state = 'quarantined', last_error = ?2, dispatch_owner = NULL, dispatch_deadline = NULL WHERE id = ?1 AND delivery_state = 'ready'",
        params![pending.id, failure],
    )?;
    Ok(true)
}

fn origin_message_in_tx(
    tx: &Transaction<'_>,
    signer: iota_identity::PrincipalHandle,
    message_id: &str,
) -> Result<Option<(i64, i64)>, StorageError> {
    Ok(tx.query_row(
        "SELECT id, storage_owner FROM messages WHERE relay_signer_principal = ?1 AND relay_message_id = ?2 AND sent_by_self = 1 AND storage_owner IN (SELECT local_user_id FROM hosted_principals WHERE principal_handle = ?1)",
        params![signer.0, message_id], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?)
}

fn verify_pending_in_tx(
    tx: &Transaction<'_>,
    expected: &PendingRelay,
    claimed: Option<&ClaimedPendingRelay>,
    message_id: &str,
) -> Result<Option<iota_identity::PrincipalHandle>, StorageError> {
    if expected.relay_message_id.as_deref() != Some(message_id)
        || matches!(expected.target, RelayTarget::User(_))
        || expected.destination_principal.is_none()
    {
        return Err(StorageError::PendingRelayConflict);
    }
    let Some(current) = relay_queue::load_in_tx(tx, expected.id)? else {
        return Ok(None);
    };
    if !current.matches_immutable(expected) {
        return Err(StorageError::PendingRelayConflict);
    }
    if let Some(claimed) = claimed {
        if !relay_queue::verify_claim_in_tx(tx, claimed, relay_queue::now_millis())? {
            return Ok(None);
        }
    } else {
        // Compatibility operations must never complete work dispatched under a lease.
        let generation: i64 = tx.query_row(
            "SELECT dispatch_generation FROM pending_relays WHERE id = ?1",
            [expected.id],
            |row| row.get(0),
        )?;
        if generation != 0 {
            return Ok(None);
        }
    }
    if current.delivery_state != PendingRelayDeliveryState::Ready {
        return Err(StorageError::InvalidRelayTransition);
    }
    Ok(Some(
        current
            .signer_principal
            .ok_or(StorageError::PendingRelayOwnershipUnknown)?,
    ))
}

// Compatibility callers still supply their original transport correlation ID.
// Resolve it only within the complete canonical identity and remote target kind.
fn resolve_pending_in_tx(
    tx: &Transaction<'_>,
    signer: iota_identity::PrincipalHandle,
    message_id: &str,
    frame_id: u32,
) -> Result<Option<PendingRelay>, StorageError> {
    let mut statement = tx.prepare(
        "SELECT id FROM pending_relays WHERE signer_principal = ?1 AND relay_message_id = ?2 AND frame_id = ?3 AND target_kind = 2",
    )?;
    let ids = statement
        .query_map(params![signer.0, message_id, i64::from(frame_id)], |row| {
            row.get::<_, i64>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    match ids.as_slice() {
        [] => Ok(None),
        [id] => relay_queue::load_in_tx(tx, *id),
        _ => Err(StorageError::AmbiguousRelayDelivery),
    }
}

pub fn acknowledge_iota_delivery(
    frame_id: u32,
    signer_principal: iota_identity::PrincipalHandle,
    _legacy_signer_id: Option<i64>,
    relay_message_id: &str,
    destination_accepted_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        if let Some(pending) =
            resolve_pending_in_tx(tx, signer_principal, relay_message_id, frame_id)?
        {
            acknowledge_pending_delivery_in_tx(
                tx,
                &pending,
                relay_message_id,
                destination_accepted_at,
            )?;
        }
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
        if let Some(pending) =
            resolve_pending_in_tx(tx, signer_principal, relay_message_id, frame_id)?
        {
            reject_pending_delivery_in_tx(tx, &pending, failure)?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use rusqlite::Connection;

    fn setup() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        relay_queue::dispatch_tests::setup(&connection);
        connection.execute_batch(
            "CREATE TABLE relay_inbox (signer_principal INTEGER, message_id TEXT, state TEXT, downstream_acked_at INTEGER);
             INSERT INTO relay_inbox VALUES (70, 'first', 'queued', NULL);
             CREATE TABLE relay_deferred_secrets (signer_principal INTEGER, message_id TEXT, storage_owner INTEGER,
                owner_principal INTEGER, legacy_chat_id TEXT, chat_id TEXT, secret_id TEXT, version INTEGER,
                encrypted_secret TEXT, kem_ciphertext TEXT, wrapping_scheme TEXT, created_at INTEGER, completed_at INTEGER);
              CREATE TABLE messages (id INTEGER, storage_owner INTEGER, relay_signer_principal INTEGER, relay_message_id TEXT, sent_by_self INTEGER);",
        ).unwrap();
        connection
    }

    fn state(tx: &Transaction<'_>) -> String {
        tx.query_row("SELECT state FROM relay_inbox", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn stale_acknowledgement_and_rejection_cannot_complete_takeover() {
        let mut connection = setup();
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let now = relay_queue::now_millis();
        let stale = relay_queue::dispatch_tests::claim(&tx, now - 100);
        assert!(!acknowledge_claimed_pending_delivery_in_tx(&tx, &stale, "first", 30).unwrap());
        assert!(!reject_claimed_pending_delivery_in_tx(&tx, &stale, "stale").unwrap());
        let current = relay_queue::dispatch_tests::claim(&tx, now + 60_000);
        assert!(!acknowledge_claimed_pending_delivery_in_tx(&tx, &stale, "first", 30).unwrap());
        assert!(!reject_claimed_pending_delivery_in_tx(&tx, &stale, "stale").unwrap());
        assert!(!acknowledge_pending_delivery_in_tx(&tx, &current.pending, "first", 30).unwrap());
        assert!(!reject_pending_delivery_in_tx(&tx, &current.pending, "unfenced").unwrap());
        assert_eq!(state(&tx), "queued");
        assert!(matches!(
            acknowledge_claimed_pending_delivery_in_tx(&tx, &current, "wrong", 30),
            Err(StorageError::PendingRelayConflict)
        ));
        let mut wrong = current.clone();
        wrong.pending.destination_principal = Some(iota_identity::PrincipalHandle(72));
        assert!(matches!(
            reject_claimed_pending_delivery_in_tx(&tx, &wrong, "wrong"),
            Err(StorageError::PendingRelayConflict)
        ));
        assert!(acknowledge_claimed_pending_delivery_in_tx(&tx, &current, "first", 30).unwrap());
        assert_eq!(state(&tx), "delivered");
        assert!(
            relay_queue::load_in_tx(&tx, current.pending.id)
                .unwrap()
                .is_none()
        );
        assert!(!acknowledge_claimed_pending_delivery_in_tx(&tx, &current, "first", 30).unwrap());
        assert!(!reject_claimed_pending_delivery_in_tx(&tx, &current, "late").unwrap());
        tx.commit().unwrap();
    }

    #[test]
    fn claimed_rejection_quarantines_only_exact_pending_and_releases_lease() {
        let mut connection = setup();
        let tx = connection.transaction().unwrap();
        let claimed = relay_queue::dispatch_tests::claim(&tx, relay_queue::now_millis() + 60_000);
        assert!(
            reject_claimed_pending_delivery_in_tx(&tx, &claimed, "destination_rejected").unwrap()
        );
        assert_eq!(state(&tx), "queued");
        let pending = relay_queue::load_in_tx(&tx, claimed.pending.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.delivery_state,
            PendingRelayDeliveryState::Quarantined
        );
        assert_eq!(pending.last_error.as_deref(), Some("destination_rejected"));
        let lease: (Option<String>, Option<i64>) = tx
            .query_row(
                "SELECT dispatch_owner, dispatch_deadline FROM pending_relays",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(lease, (None, None));
        assert!(!acknowledge_claimed_pending_delivery_in_tx(&tx, &claimed, "first", 30).unwrap());
        assert!(!reject_claimed_pending_delivery_in_tx(&tx, &claimed, "late").unwrap());
    }

    #[test]
    fn removed_or_paused_pending_work_cannot_complete_replay() {
        let mut connection = setup();
        let tx = connection.transaction().unwrap();
        let claimed = relay_queue::dispatch_tests::claim(&tx, relay_queue::now_millis() + 60_000);
        tx.execute("UPDATE pending_relays SET delivery_state = 'waiting_client', last_error = 'user_released'", []).unwrap();
        assert!(!acknowledge_claimed_pending_delivery_in_tx(&tx, &claimed, "first", 30).unwrap());
        assert!(!reject_claimed_pending_delivery_in_tx(&tx, &claimed, "late").unwrap());
        tx.execute("DELETE FROM pending_relays", []).unwrap();
        assert!(!acknowledge_claimed_pending_delivery_in_tx(&tx, &claimed, "first", 30).unwrap());
        assert!(!reject_claimed_pending_delivery_in_tx(&tx, &claimed, "late").unwrap());
        assert_eq!(state(&tx), "queued");
    }

    #[test]
    fn compatibility_resolution_excludes_historical_targets() {
        let mut connection = setup();
        let tx = connection.transaction().unwrap();
        let current = relay_queue::load_in_tx(&tx, 1).unwrap().unwrap();
        tx.execute("UPDATE pending_relays SET target_kind = 1, destination_id = 42, destination_authority_id = 'omega:historical', destination_node_id = NULL", []).unwrap();
        assert!(
            resolve_pending_in_tx(&tx, iota_identity::PrincipalHandle(70), "first", 42)
                .unwrap()
                .is_none()
        );
        assert!(!acknowledge_pending_delivery_in_tx(&tx, &current, "first", 30).unwrap());
        assert!(!reject_pending_delivery_in_tx(&tx, &current, "late").unwrap());
        assert_eq!(state(&tx), "queued");
        let historical: (i64, String) = tx
            .query_row(
                "SELECT target_kind, delivery_state FROM pending_relays WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(historical, (1, "ready".into()));
    }

    #[test]
    fn interrupted_claimed_acknowledgement_rolls_back_terminal_state() {
        let mut connection = setup();
        let tx = connection.transaction().unwrap();
        let claimed = relay_queue::dispatch_tests::claim(&tx, relay_queue::now_millis() + 60_000);
        tx.commit().unwrap();
        connection.execute_batch("CREATE TRIGGER interrupt_ack BEFORE DELETE ON pending_relays BEGIN SELECT RAISE(ABORT, 'interrupted'); END;").unwrap();
        let tx = connection.transaction().unwrap();
        assert!(acknowledge_claimed_pending_delivery_in_tx(&tx, &claimed, "first", 30).is_err());
        tx.rollback().unwrap();
        let tx = connection.transaction().unwrap();
        assert_eq!(state(&tx), "queued");
        assert!(relay_queue::verify_claim_in_tx(&tx, &claimed, relay_queue::now_millis()).unwrap());
        tx.execute("DROP TRIGGER interrupt_ack", []).unwrap();
        assert!(acknowledge_claimed_pending_delivery_in_tx(&tx, &claimed, "first", 30).unwrap());
        tx.commit().unwrap();
    }
}
