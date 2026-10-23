mod claims;
use crate::storage_error::StorageError;
use crate::util::db;
use claims::quarantine_row_in_tx;
pub(crate) use claims::verify_claim_in_tx;
pub use claims::{
    claim_ready, claim_ready_for_user, quarantine_claimed, record_retry_claimed, release_claim,
    verify_current_claim,
};
#[cfg(test)]
use claims::{
    claim_ready_for_user_in_tx, claim_ready_in_tx, quarantine_claimed_in_tx,
    record_retry_claimed_in_tx, release_claim_in_tx,
};
use iota_identity::{IotaNodeId, PrincipalHandle};
use rusqlite::{OptionalExtension, Transaction, params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchClaim {
    pub pending_id: i64,
    pub generation: i64,
    pub owner: String,
    /// Unix time in milliseconds. The claim expires at this instant.
    pub deadline: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedPendingRelay {
    pub pending: PendingRelay,
    pub claim: DispatchClaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRelay {
    pub id: i64,
    pub target: RelayTarget,
    pub frame: Vec<u8>,
    pub created_at: i64,
    pub frame_id: u32,
    pub type_map_version: String,
    pub relay_signer_id: Option<i64>,
    pub relay_destination_user_id: Option<i64>,
    pub signer_principal: Option<PrincipalHandle>,
    pub destination_principal: Option<PrincipalHandle>,
    pub relay_message_id: Option<String>,
    pub delivery_state: PendingRelayDeliveryState,
    pub last_error: Option<String>,
    pub attempt_count: i64,
    pub last_attempt_at: Option<i64>,
    pub next_attempt_at: i64,
}

impl PendingRelay {
    pub(crate) fn matches_immutable(&self, expected: &Self) -> bool {
        self.id == expected.id
            && self.target == expected.target
            && self.frame == expected.frame
            && self.frame_id == expected.frame_id
            && self.created_at == expected.created_at
            && self.type_map_version == expected.type_map_version
            && self.relay_signer_id == expected.relay_signer_id
            && self.relay_destination_user_id == expected.relay_destination_user_id
            && self.signer_principal == expected.signer_principal
            && self.destination_principal == expected.destination_principal
            && self.relay_message_id == expected.relay_message_id
    }
}

/// Historical kind 1 rows remain in storage, outside the active target API.
pub fn load_in_tx(tx: &Transaction<'_>, id: i64) -> Result<Option<PendingRelay>, StorageError> {
    Ok(tx.query_row(
        "SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at FROM pending_relays WHERE id = ?1 AND target_kind IN (0, 2)",
        [id], pending_relay_from_row,
    ).optional()?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayTarget {
    User(u64),
    Iota(IotaNodeId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingRelayDeliveryState {
    Ready,
    WaitingClient,
    Quarantined,
}

impl PendingRelayDeliveryState {
    fn from_db(value: String) -> Result<Self, rusqlite::Error> {
        match value.as_str() {
            "ready" => Ok(Self::Ready),
            "waiting_client" => Ok(Self::WaitingClient),
            "quarantined" => Ok(Self::Quarantined),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayIdentity {
    pub signer: PrincipalHandle,
    pub recipient: PrincipalHandle,
    pub message_id: String,
    pub legacy_signer_id: Option<i64>,
    pub legacy_recipient_id: Option<i64>,
}

pub fn enqueue(
    target: RelayTarget,
    relay: &RelayIdentity,
    frame: &[u8],
    created_at: i64,
    frame_id: u32,
    type_map_version: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        enqueue_in_tx(
            tx,
            target,
            relay,
            frame,
            created_at,
            frame_id,
            type_map_version,
        )
        .map(|_| ())
    })
}

pub fn enqueue_in_tx(
    tx: &Transaction<'_>,
    target: RelayTarget,
    relay: &RelayIdentity,
    frame: &[u8],
    created_at: i64,
    frame_id: u32,
    type_map_version: &str,
) -> Result<i64, StorageError> {
    if let RelayTarget::User(destination) = &target {
        let destination =
            i64::try_from(*destination).map_err(|_| StorageError::PendingRelayConflict)?;
        if Some(destination) != relay.legacy_recipient_id {
            return Err(StorageError::PendingRelayConflict);
        }
    }
    let (destination_id, target_kind, destination_node_id) = match &target {
        RelayTarget::User(user_id) => (
            i64::try_from(*user_id).map_err(|_| {
                StorageError::Other("relay destination ID exceeds SQLite range".into())
            })?,
            0_i64,
            None,
        ),
        RelayTarget::Iota(node) => (0, 2_i64, Some(node.as_str())),
    };
    // Historical kind 1 rows cannot be decoded as active targets, but still
    // reserve their outbound identity to prevent replaying quarantined work.
    if target_kind == 2 && tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pending_relays WHERE signer_principal = ?1 AND relay_message_id = ?2 AND target_kind = 1)",
        params![relay.signer.0, relay.message_id], |row| row.get::<_, bool>(0),
    )? {
        return Err(StorageError::PendingRelayConflict);
    }
    let mut statement = tx.prepare(
        "SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at FROM pending_relays WHERE signer_principal = ?1 AND relay_message_id = ?2 AND target_kind = ?3",
    )?;
    let existing = statement
        .query_map(
            params![relay.signer.0, relay.message_id, target_kind],
            pending_relay_from_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    match existing.as_slice() {
        [] => {}
        [record]
            if record.target == target
                && record.destination_principal == Some(relay.recipient)
                && record.relay_signer_id == relay.legacy_signer_id
                && record.relay_destination_user_id == relay.legacy_recipient_id
                && record.frame == frame
                && record.type_map_version == type_map_version =>
        {
            return Ok(record.id);
        }
        _ => return Err(StorageError::PendingRelayConflict),
    }
    tx.execute(
            "INSERT INTO pending_relays (destination_id, target_kind, relay_signer_id, relay_destination_user_id, relay_message_id, frame, created_at, frame_id, type_map_version, signer_principal, destination_principal, destination_node_id, destination_authority_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                destination_id,
                target_kind,
                relay.legacy_signer_id,
                relay.legacy_recipient_id,
                relay.message_id,
                frame,
                created_at,
                i64::from(frame_id),
                type_map_version,
                relay.signer.0,
                relay.recipient.0,
                destination_node_id,
                Option::<&str>::None,
            ],
    ).map_err(|error| {
        if error.sqlite_error().is_some_and(|error| error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE) {
            StorageError::PendingRelayConflict
        } else {
            StorageError::from(error)
        }
    })?;
    Ok(tx.last_insert_rowid())
}

pub fn list(limit: i64) -> Result<Vec<PendingRelay>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare(
            "SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at FROM pending_relays WHERE target_kind IN (0, 2) ORDER BY id LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit.clamp(1, 500)], |row| {
            let destination_id = row.get::<_, i64>(1)?;
            let target_kind = row.get::<_, i64>(2)?;
            let destination_id = u64::try_from(destination_id).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    "negative relay destination ID".into(),
                )
            })?;
            let target = match target_kind {
                0 => RelayTarget::User(destination_id),
                2 => RelayTarget::Iota(IotaNodeId::new(row.get::<_, String>(14)?).map_err(
                    |error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            14,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    },
                )?),
                _ => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Integer,
                        "invalid relay target kind".into(),
                    ));
                }
            };
            Ok(PendingRelay {
                id: row.get(0)?,
                target,
                frame: row.get(3)?,
                created_at: row.get(4)?,
                frame_id: u32::try_from(row.get::<_, i64>(5)?).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Integer,
                        "negative relay frame ID".into(),
                    )
                })?,
                type_map_version: row.get(6)?,
                relay_signer_id: row.get(7)?,
                relay_destination_user_id: row.get(8)?,
                signer_principal: row.get::<_, Option<i64>>(13)?.map(PrincipalHandle),
                destination_principal: row
                    .get::<_, Option<i64>>(12)?
                    .map(iota_identity::PrincipalHandle),
                relay_message_id: row.get(9)?,
                delivery_state: PendingRelayDeliveryState::from_db(row.get(10)?)?,
                last_error: row.get(11)?,
                attempt_count: row.get(16)?,
                last_attempt_at: row.get(17)?,
                next_attempt_at: row.get(18)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
}

/* Select only relays whose target and signer remain locally managed. This is
 * the delivery-authority check after user release, independent of row state. */
pub fn list_active(limit: i64) -> Result<Vec<PendingRelay>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare(
            "SELECT p.id, p.destination_id, p.target_kind, p.frame, p.created_at, p.frame_id, p.type_map_version, p.relay_signer_id, p.relay_destination_user_id, p.relay_message_id, p.delivery_state, p.last_error, p.destination_principal, p.signer_principal, p.destination_node_id, p.destination_authority_id, p.attempt_count, p.last_attempt_at, p.next_attempt_at FROM pending_relays p WHERE p.delivery_state = 'ready' AND p.next_attempt_at <= ?1
             AND EXISTS (SELECT 1 FROM hosted_principals h
                 JOIN users u ON u.user_id = h.local_user_id
                 JOIN user_residency r ON r.user_id = u.user_id
                 JOIN hosted_auth_state a ON a.local_user_id = u.user_id
                 JOIN principals principal ON principal.principal_pk = h.principal_handle
                 WHERE r.lifecycle_state = 'managed' AND a.enabled = 1 AND principal.retired_at IS NULL
                   AND ((p.target_kind = 0 AND u.user_id = p.destination_id AND h.principal_handle = p.destination_principal AND p.relay_destination_user_id = u.user_id AND p.signer_principal IS NOT NULL AND p.relay_message_id IS NOT NULL)
                     OR (p.target_kind = 2 AND h.principal_handle = p.signer_principal)))
             ORDER BY p.id LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![now_millis(), limit.clamp(1, 500)],
            pending_relay_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
}

pub fn list_without_relay_identity() -> Result<Vec<PendingRelay>, StorageError> {
    list_without_relay_identity_after(0, i64::MAX)
}

pub fn list_without_relay_identity_after(
    after_id: i64,
    limit: i64,
) -> Result<Vec<PendingRelay>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare("SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at FROM pending_relays WHERE id > ?1 AND target_kind IN (0, 2) AND (signer_principal IS NULL OR destination_principal IS NULL OR relay_message_id IS NULL) ORDER BY id LIMIT ?2")?;
        let rows = statement.query_map(
            params![after_id, limit.clamp(1, 500)],
            pending_relay_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
}

pub(crate) fn pending_relay_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<PendingRelay, rusqlite::Error> {
    let destination_id = u64::try_from(row.get::<_, i64>(1)?)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 0))?;
    let target = match row.get::<_, i64>(2)? {
        0 => RelayTarget::User(destination_id),
        2 => RelayTarget::Iota(
            IotaNodeId::new(row.get::<_, String>(14)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        _ => return Err(rusqlite::Error::IntegralValueOutOfRange(2, 0)),
    };
    Ok(PendingRelay {
        id: row.get(0)?,
        target,
        frame: row.get(3)?,
        created_at: row.get(4)?,
        frame_id: u32::try_from(row.get::<_, i64>(5)?)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, 0))?,
        type_map_version: row.get(6)?,
        relay_signer_id: row.get(7)?,
        relay_destination_user_id: row.get(8)?,
        signer_principal: row.get::<_, Option<i64>>(13)?.map(PrincipalHandle),
        destination_principal: row
            .get::<_, Option<i64>>(12)?
            .map(iota_identity::PrincipalHandle),
        relay_message_id: row.get(9)?,
        delivery_state: PendingRelayDeliveryState::from_db(row.get(10)?)?,
        last_error: row.get(11)?,
        attempt_count: row.get(16)?,
        last_attempt_at: row.get(17)?,
        next_attempt_at: row.get(18)?,
    })
}

pub fn record_retry(id: i64, now: i64, error: &str) -> Result<(), StorageError> {
    db::with_immediate_transaction(|connection| {
        let attempts = connection.query_row(
            "SELECT attempt_count FROM pending_relays WHERE id = ?1 AND dispatch_generation = 0 AND delivery_state = 'ready'",
            [id],
            |row| row.get::<_, i64>(0),
        ).optional()?;
        let Some(attempts) = attempts else {
            return Ok(());
        };
        let Some(next_attempts) = attempts.checked_add(1) else {
            quarantine_row_in_tx(connection, id, "dispatch_attempts_exhausted")?;
            return Ok(());
        };
        let exponent = u32::try_from(attempts.clamp(0, 6)).unwrap_or(6);
        let delay = 5_000_i64.saturating_mul(1_i64 << exponent).min(300_000);
        connection.execute(
            "UPDATE pending_relays SET attempt_count = ?5, last_attempt_at = ?2, next_attempt_at = ?3, last_error = ?4 WHERE id = ?1",
            params![id, now, now.saturating_add(delay), error, next_attempts],
        )?;
        Ok(())
    })
}

pub fn quarantine(id: i64, error: &str) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute(
            "UPDATE pending_relays SET delivery_state = 'quarantined', last_error = ?2 WHERE id = ?1 AND delivery_state = 'ready' AND dispatch_generation = 0",
            params![id, error],
        )?;
        Ok(())
    })
}

pub(crate) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

pub fn pause_client_deliveries(destination_user_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| pause_client_deliveries_in_tx(tx, destination_user_id))
}

fn pause_client_deliveries_in_tx(
    tx: &Transaction<'_>,
    destination_user_id: i64,
) -> Result<(), StorageError> {
    // Revoke the lease token so resuming cannot revive an old generation's authority.
    tx.execute(
            "UPDATE pending_relays SET delivery_state = 'waiting_client', last_error = 'awaiting_state_ack', dispatch_owner = NULL, dispatch_deadline = NULL WHERE target_kind = 0 AND destination_id = ?1 AND delivery_state = 'ready'",
            [destination_user_id],
        )?;
    Ok(())
}

pub fn resume_client_deliveries(destination_user_id: i64) -> Result<usize, StorageError> {
    db::with_db(|connection| {
        Ok(connection.execute("UPDATE pending_relays SET delivery_state = 'ready', last_error = NULL WHERE target_kind = 0 AND destination_id = ?1 AND delivery_state = 'waiting_client'", [destination_user_id])?)
    })
}

pub fn resume_managed_client_deliveries() -> Result<usize, StorageError> {
    db::with_db(|connection| {
        Ok(connection.execute("UPDATE pending_relays SET delivery_state = 'ready', last_error = NULL WHERE target_kind = 0 AND delivery_state = 'waiting_client' AND EXISTS (SELECT 1 FROM users u WHERE u.user_id = pending_relays.destination_id)", [])?)
    })
}

pub fn quarantine_target_mismatch(id: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute("UPDATE pending_relays SET delivery_state = 'quarantined', last_error = 'target_recipient_mismatch' WHERE id = ?1 AND dispatch_generation = 0", [id])?;
        Ok(())
    })
}

pub fn set_relay_identity(id: i64, relay: &RelayIdentity) -> Result<(), StorageError> {
    db::with_immediate_transaction(|connection| {
        let generation: i64 = connection.query_row(
            "SELECT dispatch_generation FROM pending_relays WHERE id = ?1",
            [id],
            |row| row.get(0),
        )?;
        if generation != 0 {
            return Ok(());
        }
        let target_kind = connection.query_row(
            "SELECT target_kind FROM pending_relays WHERE id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )?;
        if target_kind == 0 {
            let destination_id = connection.query_row(
                "SELECT destination_id FROM pending_relays WHERE id = ?1",
                [id],
                |row| row.get::<_, i64>(0),
            )?;
            if Some(destination_id) != relay.legacy_recipient_id {
                connection.execute(
                    "UPDATE pending_relays SET delivery_state = 'quarantined', last_error = 'target_recipient_mismatch' WHERE id = ?1",
                    [id],
                )?;
                return Ok(());
            }
        }
        connection.execute("UPDATE pending_relays SET relay_signer_id = ?2, relay_destination_user_id = ?3, relay_message_id = ?4, signer_principal = ?5, destination_principal = ?6 WHERE id = ?1", params![id, relay.legacy_signer_id, relay.legacy_recipient_id, relay.message_id, relay.signer.0, relay.recipient.0])?;
        Ok(())
    })
}

pub fn has_unclassified_relays() -> Result<bool, StorageError> {
    db::with_db(|connection| {
        connection
            .query_row("SELECT EXISTS(SELECT 1 FROM pending_relays WHERE delivery_state <> 'quarantined' AND (signer_principal IS NULL OR destination_principal IS NULL OR relay_message_id IS NULL))", [], |row| row.get(0))
            .map_err(Into::into)
    })
}

#[cfg(test)]
pub fn find_user_delivery_in_tx(
    tx: &Transaction<'_>,
    destination_id: i64,
    frame_id: u32,
) -> Result<Option<(i64, RelayIdentity)>, StorageError> {
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM pending_relays WHERE destination_id = ?1 AND target_kind = 0 AND frame_id = ?2",
        params![destination_id, i64::from(frame_id)],
        |row| row.get(0),
    )?;
    if count > 1 {
        return Err(StorageError::AmbiguousRelayDelivery);
    }
    tx.query_row(
        "SELECT id, relay_signer_id, relay_destination_user_id, relay_message_id, signer_principal, destination_principal FROM pending_relays WHERE destination_id = ?1 AND target_kind = 0 AND frame_id = ?2",
        params![destination_id, i64::from(frame_id)],
        |row| {
            let signer_id = row.get::<_, Option<i64>>(1)?;
            let destination_user_id = row.get::<_, Option<i64>>(2)?;
            let message_id = row.get::<_, Option<String>>(3)?;
            match (signer_id, destination_user_id, message_id) {
                (Some(signer_id), Some(destination_user_id), Some(message_id)) if destination_user_id == destination_id => {
                    let signer = row.get::<_, Option<i64>>(4)?.ok_or(rusqlite::Error::InvalidQuery)?;
                    let recipient = row.get::<_, Option<i64>>(5)?.ok_or(rusqlite::Error::InvalidQuery)?;
                    Ok((row.get(0)?, RelayIdentity {
                        signer: PrincipalHandle(signer),
                        recipient: PrincipalHandle(recipient),
                        message_id,
                        legacy_signer_id: Some(signer_id),
                        legacy_recipient_id: Some(destination_user_id),
                    }))
                }
                _ => Err(rusqlite::Error::InvalidQuery),
            }
        },
    ).optional().map_err(|error| match error {
        rusqlite::Error::InvalidQuery => StorageError::PendingRelayOwnershipUnknown,
        error => StorageError::Db(error),
    })
}

pub fn acknowledge_in_tx(tx: &Transaction<'_>, id: i64) -> Result<(), StorageError> {
    tx.execute(
        "DELETE FROM pending_relays WHERE id = ?1 AND dispatch_generation = 0",
        [id],
    )?;
    Ok(())
}

pub fn acknowledge(destination_id: u64, frame_id: u32) -> Result<bool, StorageError> {
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_immediate_transaction(|connection| {
        ensure_unique_frame_in_tx(connection, destination_id, 0, frame_id)?;
        let changed = connection.execute(
            "DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = 0 AND frame_id = ?2 AND dispatch_generation = 0",
            params![destination_id, i64::from(frame_id)],
        )?;
        Ok(changed == 1)
    })
}

pub fn delete(id: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute(
            "DELETE FROM pending_relays WHERE id = ?1 AND dispatch_generation = 0",
            params![id],
        )?;
        Ok(())
    })
}

fn ensure_unique_frame_in_tx(
    tx: &Transaction<'_>,
    destination: i64,
    kind: i64,
    frame: u32,
) -> Result<(), StorageError> {
    let count: i64 = tx.query_row("SELECT count(*) FROM pending_relays WHERE destination_id = ?1 AND target_kind = ?2 AND frame_id = ?3", params![destination, kind, i64::from(frame)], |row| row.get(0))?;
    if count > 1 {
        return Err(StorageError::AmbiguousRelayDelivery);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod dispatch_tests;
