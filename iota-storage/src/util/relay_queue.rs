use crate::storage_error::StorageError;
use crate::util::db;
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

/// Atomically leases due outbound work. User deliveries have a separate dispatcher.
/// The duration is a positive number of milliseconds, measured from acquisition.
pub fn claim_ready(
    limit: i64,
    lease_duration: i64,
) -> Result<Vec<ClaimedPendingRelay>, StorageError> {
    db::with_immediate_transaction(|tx| claim_ready_in_tx(tx, limit, lease_duration, now_millis()))
}

/// Leases one due client delivery only while its principal is hosted by this
/// managed user. The same ownership check runs again before using the claim.
pub fn claim_ready_for_user(
    user_id: i64,
    principal: PrincipalHandle,
    lease_duration: i64,
) -> Result<Option<ClaimedPendingRelay>, StorageError> {
    db::with_immediate_transaction(|tx| {
        claim_ready_for_user_in_tx(tx, user_id, principal, lease_duration, now_millis())
    })
}

fn claim_ready_for_user_in_tx(
    tx: &Transaction<'_>,
    user_id: i64,
    principal: PrincipalHandle,
    lease_duration: i64,
    now: i64,
) -> Result<Option<ClaimedPendingRelay>, StorageError> {
    if lease_duration <= 0 {
        return Err(StorageError::Other(
            "dispatch lease must be positive".into(),
        ));
    }
    let deadline = now
        .checked_add(lease_duration)
        .ok_or_else(|| StorageError::Other("dispatch deadline exhausted".into()))?;
    loop {
        let candidate = tx.query_row(
            "SELECT p.id, p.dispatch_generation FROM pending_relays p
         WHERE p.target_kind = 0 AND p.destination_id = ?1 AND p.destination_principal = ?2
           AND p.relay_destination_user_id = ?1 AND p.signer_principal IS NOT NULL AND p.relay_message_id IS NOT NULL
           AND p.delivery_state = 'ready' AND p.next_attempt_at <= ?3
           AND (p.dispatch_owner IS NULL OR p.dispatch_deadline <= ?3)
           AND EXISTS (SELECT 1 FROM users u
               JOIN hosted_principals h ON h.local_user_id = u.user_id
                JOIN user_residency r ON r.user_id = u.user_id
                JOIN hosted_auth_state a ON a.local_user_id = u.user_id
                JOIN principals principal ON principal.principal_pk = h.principal_handle
                WHERE u.user_id = ?1 AND h.principal_handle = ?2 AND r.lifecycle_state = 'managed'
                  AND a.enabled = 1 AND principal.retired_at IS NULL)
         ORDER BY p.id LIMIT 1",
            params![user_id, principal.0, now],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, rusqlite::types::Value>(1)?)),
        ).optional()?;
        let Some((id, previous_generation)) = candidate else {
            return Ok(None);
        };
        if let Some(claimed) = acquire_candidate_in_tx(tx, id, previous_generation, deadline)? {
            return Ok(Some(claimed));
        }
    }
}

fn quarantine_row_in_tx(tx: &Transaction<'_>, id: i64, code: &str) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE pending_relays SET delivery_state = 'quarantined', last_error = ?2, dispatch_owner = NULL, dispatch_deadline = NULL WHERE id = ?1",
        params![id, code],
    )?;
    Ok(())
}

/// Decode before leasing so a corrupt row cannot roll back healthy acquisitions.
fn acquire_candidate_in_tx(
    tx: &Transaction<'_>,
    id: i64,
    previous_generation: rusqlite::types::Value,
    deadline: i64,
) -> Result<Option<ClaimedPendingRelay>, StorageError> {
    let generation = match previous_generation {
        rusqlite::types::Value::Integer(value) if (0..i64::MAX).contains(&value) => value + 1,
        _ => {
            quarantine_row_in_tx(tx, id, "dispatch_generation_exhausted")?;
            return Ok(None);
        }
    };
    let pending = match load_in_tx(tx, id) {
        Ok(Some(pending)) => pending,
        Ok(None) => return Err(StorageError::PendingRelayConflict),
        Err(StorageError::Db(
            rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::InvalidQuery,
        )) => {
            quarantine_row_in_tx(tx, id, "dispatch_malformed_pending")?;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let owner = format!("{:032x}", rand::random::<u128>());
    tx.execute(
        "UPDATE pending_relays SET dispatch_generation = ?2, dispatch_owner = ?3, dispatch_deadline = ?4 WHERE id = ?1",
        params![id, generation, owner, deadline],
    )?;
    Ok(Some(ClaimedPendingRelay {
        pending,
        claim: DispatchClaim {
            pending_id: id,
            generation,
            owner,
            deadline,
        },
    }))
}

/// Rechecks the lease and current delivery authority immediately before send.
pub fn verify_current_claim(claimed: &ClaimedPendingRelay) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| verify_claim_in_tx(tx, claimed, now_millis()))
}

fn claim_ready_in_tx(
    tx: &Transaction<'_>,
    limit: i64,
    lease_duration: i64,
    now: i64,
) -> Result<Vec<ClaimedPendingRelay>, StorageError> {
    if lease_duration <= 0 {
        return Err(StorageError::Other(
            "dispatch lease must be positive".into(),
        ));
    }
    let deadline = now
        .checked_add(lease_duration)
        .ok_or_else(|| StorageError::Other("dispatch deadline exhausted".into()))?;
    // Prepared remote deliveries have a local sender effect. Inbound deliveries
    // target a local user, not another Iota. Numeric signer IDs are not ownership.
    // Key rotation preserves accepted work while the account remains enabled;
    // account disablement and principal retirement revoke delivery authority.
    let mut statement = tx.prepare(
        "SELECT p.id, p.dispatch_generation FROM pending_relays p WHERE p.delivery_state = 'ready' AND p.next_attempt_at <= ?1 AND p.target_kind = 2 AND (p.dispatch_owner IS NULL OR p.dispatch_deadline <= ?1)
         AND EXISTS (SELECT 1 FROM hosted_principals h
             JOIN users u ON u.user_id = h.local_user_id
             JOIN user_residency r ON r.user_id = u.user_id
             JOIN hosted_auth_state a ON a.local_user_id = u.user_id
             JOIN principals principal ON principal.principal_pk = h.principal_handle
             WHERE h.principal_handle = p.signer_principal AND r.lifecycle_state = 'managed'
               AND a.enabled = 1 AND principal.retired_at IS NULL) ORDER BY p.id LIMIT 1",
    )?;
    let mut claimed = Vec::new();
    while claimed.len() < limit.clamp(1, 500) as usize {
        let candidate = statement
            .query_row([now], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, rusqlite::types::Value>(1)?,
                ))
            })
            .optional()?;
        let Some((id, previous_generation)) = candidate else {
            break;
        };
        if let Some(work) = acquire_candidate_in_tx(tx, id, previous_generation, deadline)? {
            claimed.push(work);
        }
    }
    Ok(claimed)
}

/// A stale, expired, released or deleted claim is a no-op. Identity mismatches
/// remain conflicts rather than authorizing a different pending delivery.
pub(crate) fn verify_claim_in_tx(
    tx: &Transaction<'_>,
    claimed: &ClaimedPendingRelay,
    now: i64,
) -> Result<bool, StorageError> {
    if claimed.claim.pending_id != claimed.pending.id {
        return Err(StorageError::PendingRelayConflict);
    }
    let Some(current) = load_in_tx(tx, claimed.pending.id)? else {
        return Ok(false);
    };
    if !current.matches_immutable(&claimed.pending) {
        return Err(StorageError::PendingRelayConflict);
    }
    if let RelayTarget::User(destination) = current.target {
        let destination =
            i64::try_from(destination).map_err(|_| StorageError::PendingRelayConflict)?;
        let authorized = current.relay_destination_user_id == Some(destination)
            && current.relay_message_id.is_some()
            && tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users u
                   JOIN hosted_principals h ON h.local_user_id = u.user_id
                    JOIN user_residency r ON r.user_id = u.user_id
                    JOIN hosted_auth_state a ON a.local_user_id = u.user_id
                    JOIN principals principal ON principal.principal_pk = h.principal_handle
                    WHERE u.user_id = ?1 AND h.principal_handle = ?2 AND r.lifecycle_state = 'managed'
                      AND a.enabled = 1 AND principal.retired_at IS NULL)",
                params![destination, current.destination_principal.map(|principal| principal.0)],
                |row| row.get::<_, bool>(0),
            )?;
        if !authorized {
            return Ok(false);
        }
    } else if !tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM hosted_principals h
             JOIN users u ON u.user_id = h.local_user_id
             JOIN user_residency r ON r.user_id = u.user_id
             JOIN hosted_auth_state a ON a.local_user_id = u.user_id
             JOIN principals principal ON principal.principal_pk = h.principal_handle
             WHERE h.principal_handle = ?1 AND r.lifecycle_state = 'managed'
               AND a.enabled = 1 AND principal.retired_at IS NULL)",
        [current.signer_principal.map(|principal| principal.0)],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(false);
    }
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pending_relays WHERE id = ?1 AND dispatch_generation = ?2 AND dispatch_owner = ?3 AND dispatch_deadline = ?4 AND dispatch_deadline > ?5 AND delivery_state = 'ready' AND target_kind IN (0, 2) AND signer_principal IS NOT NULL)",
        params![claimed.claim.pending_id, claimed.claim.generation, claimed.claim.owner, claimed.claim.deadline, now],
        |row| row.get(0),
    )?)
}

/// Releases the lease while preserving its generation, so old responses stay fenced.
pub fn release_claim(claimed: &ClaimedPendingRelay) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| release_claim_in_tx(tx, claimed, now_millis()))
}

fn release_claim_in_tx(
    tx: &Transaction<'_>,
    claimed: &ClaimedPendingRelay,
    now: i64,
) -> Result<bool, StorageError> {
    if !verify_claim_in_tx(tx, claimed, now)? {
        return Ok(false);
    }
    tx.execute(
        "UPDATE pending_relays SET dispatch_owner = NULL, dispatch_deadline = NULL WHERE id = ?1",
        [claimed.pending.id],
    )?;
    Ok(true)
}

/// Records backoff and releases the claim. `now` is the attempt timestamp;
/// lease validity is independently checked against the storage clock.
pub fn record_retry_claimed(
    claimed: &ClaimedPendingRelay,
    now: i64,
    error: &str,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        record_retry_claimed_in_tx(tx, claimed, now, error, now_millis())
    })
}

fn record_retry_claimed_in_tx(
    tx: &Transaction<'_>,
    claimed: &ClaimedPendingRelay,
    attempted_at: i64,
    error: &str,
    now: i64,
) -> Result<bool, StorageError> {
    if !verify_claim_in_tx(tx, claimed, now)? {
        return Ok(false);
    }
    let attempts: i64 = tx.query_row(
        "SELECT attempt_count FROM pending_relays WHERE id = ?1",
        [claimed.pending.id],
        |row| row.get(0),
    )?;
    let Some(next_attempts) = attempts.checked_add(1) else {
        quarantine_row_in_tx(tx, claimed.pending.id, "dispatch_attempts_exhausted")?;
        return Ok(true);
    };
    let delay = 5_000_i64
        .saturating_mul(1_i64 << attempts.clamp(0, 6))
        .min(300_000);
    tx.execute(
        "UPDATE pending_relays SET attempt_count = ?2, last_attempt_at = ?3, next_attempt_at = ?4, last_error = ?5, dispatch_owner = NULL, dispatch_deadline = NULL WHERE id = ?1",
        params![claimed.pending.id, next_attempts, attempted_at, attempted_at.saturating_add(delay), error],
    )?;
    Ok(true)
}

/// Quarantines exactly this delivery and releases its claim.
pub fn quarantine_claimed(
    claimed: &ClaimedPendingRelay,
    error: &str,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| quarantine_claimed_in_tx(tx, claimed, error, now_millis()))
}

fn quarantine_claimed_in_tx(
    tx: &Transaction<'_>,
    claimed: &ClaimedPendingRelay,
    error: &str,
    now: i64,
) -> Result<bool, StorageError> {
    if !verify_claim_in_tx(tx, claimed, now)? {
        return Ok(false);
    }
    tx.execute("UPDATE pending_relays SET delivery_state = 'quarantined', last_error = ?2, dispatch_owner = NULL, dispatch_deadline = NULL WHERE id = ?1", params![claimed.pending.id, error])?;
    Ok(true)
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
pub(crate) mod dispatch_tests {
    use super::*;
    use rusqlite::{Connection, TransactionBehavior};

    pub(crate) fn setup(connection: &Connection) {
        connection.execute_batch(
            "CREATE TABLE pending_relays (
                id INTEGER PRIMARY KEY, destination_id INTEGER NOT NULL, target_kind INTEGER NOT NULL,
                frame BLOB NOT NULL, created_at INTEGER NOT NULL, frame_id INTEGER NOT NULL,
                type_map_version TEXT NOT NULL, relay_signer_id INTEGER, relay_destination_user_id INTEGER,
                relay_message_id TEXT, delivery_state TEXT NOT NULL DEFAULT 'ready', last_error TEXT,
                destination_principal INTEGER, signer_principal INTEGER, destination_node_id TEXT,
                destination_authority_id TEXT, attempt_count INTEGER NOT NULL DEFAULT 0,
                last_attempt_at INTEGER, next_attempt_at INTEGER NOT NULL DEFAULT 0,
                dispatch_generation INTEGER NOT NULL DEFAULT 0, dispatch_owner TEXT, dispatch_deadline INTEGER
            );
             CREATE TABLE users (user_id INTEGER PRIMARY KEY);
             CREATE TABLE hosted_principals (local_user_id INTEGER, principal_handle INTEGER);
             CREATE TABLE user_residency (user_id INTEGER PRIMARY KEY, lifecycle_state TEXT);
             CREATE TABLE hosted_auth_state (local_user_id INTEGER PRIMARY KEY, generation INTEGER, enabled INTEGER);
             CREATE TABLE principals (principal_pk INTEGER PRIMARY KEY, retired_at INTEGER);
             INSERT INTO users VALUES (7);
             INSERT INTO hosted_principals VALUES (7, 70);
             INSERT INTO hosted_auth_state VALUES (7, 1, 1), (8, 1, 1);
             INSERT INTO principals VALUES (70, NULL), (71, NULL);
             INSERT INTO user_residency VALUES (7, 'managed');",
        ).unwrap();
        connection.execute(
            "INSERT INTO pending_relays (destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, destination_principal, signer_principal, destination_node_id) VALUES (0, 2, X'0102', 10, 42, '1.0', 7, 8, 'first', 71, 70, ?1)",
            [format!("iota:v1:{}", "01".repeat(32))],
        ).unwrap();
    }

    pub(crate) fn claim(tx: &Transaction<'_>, now: i64) -> ClaimedPendingRelay {
        claim_ready_in_tx(tx, 1, 100, now).unwrap().remove(0)
    }

    #[test]
    fn concurrent_connections_claim_disjoint_work() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dispatch.sqlite");
        let connection = Connection::open(&path).unwrap();
        setup(&connection);
        connection.execute("INSERT INTO pending_relays SELECT 2, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, 'second', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1", []).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut connection = Connection::open(path).unwrap();
                    connection
                        .busy_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    barrier.wait();
                    let tx = connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .unwrap();
                    let work = claim(&tx, 10);
                    tx.commit().unwrap();
                    work
                })
            })
            .collect();
        let claims: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_ne!(claims[0].pending.id, claims[1].pending.id);
        assert_ne!(claims[0].claim.owner, claims[1].claim.owner);
        let tx = connection.unchecked_transaction().unwrap();
        assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
    }

    #[test]
    fn takeover_fences_retry_quarantine_and_release() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let first = claim(&tx, 10);
        assert!(claim_ready_in_tx(&tx, 1, 100, 109).unwrap().is_empty());
        assert!(!verify_claim_in_tx(&tx, &first, 110).unwrap());
        let second = claim(&tx, 110);
        assert_eq!(second.claim.generation, first.claim.generation + 1);
        assert_ne!(second.claim.owner, first.claim.owner);
        assert!(!record_retry_claimed_in_tx(&tx, &first, 110, "stale", 110).unwrap());
        assert!(!quarantine_claimed_in_tx(&tx, &first, "stale", 110).unwrap());
        assert!(!release_claim_in_tx(&tx, &first, 110).unwrap());
        assert!(record_retry_claimed_in_tx(&tx, &second, 110, "offline", 110).unwrap());
        assert!(!verify_claim_in_tx(&tx, &second, 110).unwrap());
        assert!(claim_ready_in_tx(&tx, 1, 100, 5109).unwrap().is_empty());
        let third = claim(&tx, 5110);
        assert_eq!(third.pending.attempt_count, 1);
        assert_eq!(third.pending.last_error.as_deref(), Some("offline"));
        assert!(release_claim_in_tx(&tx, &third, 5110).unwrap());
        assert!(!release_claim_in_tx(&tx, &third, 5110).unwrap());
        let fourth = claim(&tx, 5110);
        assert!(quarantine_claimed_in_tx(&tx, &fourth, "invalid", 5110).unwrap());
        assert!(claim_ready_in_tx(&tx, 1, 100, 10000).unwrap().is_empty());
        assert_eq!(
            load_in_tx(&tx, 1).unwrap().unwrap().delivery_state,
            PendingRelayDeliveryState::Quarantined
        );
    }

    #[test]
    fn exact_identity_and_owner_are_required() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection.transaction().unwrap();
        let original = claim(&tx, 10);
        let mut wrong = original.clone();
        wrong.claim.owner.push('x');
        assert!(!verify_claim_in_tx(&tx, &wrong, 10).unwrap());
        wrong = original.clone();
        wrong.claim.deadline += 1;
        assert!(!verify_claim_in_tx(&tx, &wrong, 10).unwrap());
        wrong = original.clone();
        wrong.pending.frame.push(3);
        assert!(matches!(
            verify_claim_in_tx(&tx, &wrong, 10),
            Err(StorageError::PendingRelayConflict)
        ));
        tx.execute("DELETE FROM pending_relays", []).unwrap();
        assert!(!verify_claim_in_tx(&tx, &original, 10).unwrap());
    }

    #[test]
    fn claims_exclude_users_unauthorized_and_not_ready_rows() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection.transaction().unwrap();
        for update in [
            "target_kind = 0, destination_id = 8",
            "target_kind = 2, signer_principal = NULL",
            "signer_principal = 70, delivery_state = 'waiting_client'",
            "delivery_state = 'quarantined'",
            "delivery_state = 'ready', next_attempt_at = 11",
        ] {
            tx.execute(&format!("UPDATE pending_relays SET {update}"), [])
                .unwrap();
            assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
        }
        tx.execute("UPDATE pending_relays SET next_attempt_at = 0, target_kind = 1, destination_authority_id = 'omega:test'", []).unwrap();
        assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
        tx.execute("UPDATE pending_relays SET target_kind = 2", [])
            .unwrap();
        assert_eq!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().len(), 1);
    }

    #[test]
    fn historical_targets_are_not_decoded_claimed_or_reenqueued() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection.transaction().unwrap();
        let current = load_in_tx(&tx, 1).unwrap().unwrap();
        // Old authority-scoped numeric targets do not carry a node identity.
        tx.execute("UPDATE pending_relays SET target_kind = 1, destination_id = 42, destination_authority_id = 'omega:historical', destination_node_id = NULL", []).unwrap();
        assert!(load_in_tx(&tx, 1).unwrap().is_none());
        assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
        assert!(matches!(
            enqueue_in_tx(
                &tx,
                current.target,
                &RelayIdentity {
                    signer: PrincipalHandle(70),
                    recipient: PrincipalHandle(71),
                    message_id: "first".into(),
                    legacy_signer_id: Some(7),
                    legacy_recipient_id: Some(8),
                },
                &current.frame,
                current.created_at,
                current.frame_id,
                &current.type_map_version
            ),
            Err(StorageError::PendingRelayConflict)
        ));
        let historical: (i64, i64, String, Option<String>, i64) = tx.query_row(
            "SELECT target_kind, destination_id, destination_authority_id, destination_node_id, dispatch_generation FROM pending_relays WHERE id = 1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap();
        assert_eq!(historical, (1, 42, "omega:historical".into(), None, 0));
    }

    #[test]
    fn active_targets_keep_their_persisted_kind_mapping() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection.transaction().unwrap();
        let node = IotaNodeId::new(format!("iota:v1:{}", "02".repeat(32))).unwrap();
        for (target, kind, message_id) in [
            (RelayTarget::User(8), 0, "user"),
            (RelayTarget::Iota(node), 2, "node"),
        ] {
            let id = enqueue_in_tx(
                &tx,
                target.clone(),
                &RelayIdentity {
                    signer: PrincipalHandle(70),
                    recipient: PrincipalHandle(71),
                    message_id: message_id.into(),
                    legacy_signer_id: Some(7),
                    legacy_recipient_id: Some(8),
                },
                &[3],
                20,
                43,
                "1.0",
            )
            .unwrap();
            assert_eq!(load_in_tx(&tx, id).unwrap().unwrap().target, target);
            assert_eq!(
                tx.query_row(
                    "SELECT target_kind FROM pending_relays WHERE id = ?1",
                    [id],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                kind
            );
        }
    }

    #[test]
    fn user_claims_require_current_hosting_and_fence_takeover() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        connection.execute_batch(
            "INSERT INTO users VALUES (8);
             INSERT INTO hosted_principals VALUES (8, 71);
             INSERT INTO user_residency VALUES (8, 'managed');
             UPDATE pending_relays SET target_kind = 0, destination_id = 8, destination_node_id = NULL;
             INSERT INTO pending_relays SELECT 2, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, 'second', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1;",
        ).unwrap();
        let tx = connection.transaction().unwrap();
        assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
        assert!(
            claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(72), 100, 10)
                .unwrap()
                .is_none()
        );
        assert!(
            claim_ready_for_user_in_tx(&tx, 9, PrincipalHandle(71), 100, 10)
                .unwrap()
                .is_none()
        );
        for duration in [0, -1, i64::MAX] {
            assert!(claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), duration, 10).is_err());
        }
        let first = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
            .unwrap()
            .unwrap();
        let second = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
            .unwrap()
            .unwrap();
        assert_ne!(first.pending.id, second.pending.id);
        assert!(
            claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
                .unwrap()
                .is_none()
        );
        assert!(verify_claim_in_tx(&tx, &first, 10).unwrap());
        tx.execute_batch("SAVEPOINT key_rotation").unwrap();
        tx.execute(
            "UPDATE hosted_auth_state SET generation = generation + 1 WHERE local_user_id = 8",
            [],
        )
        .unwrap();
        assert!(verify_claim_in_tx(&tx, &first, 10).unwrap());
        assert!(release_claim_in_tx(&tx, &first, 10).unwrap());
        assert!(
            claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
                .unwrap()
                .is_some()
        );
        tx.execute_batch("ROLLBACK TO key_rotation; RELEASE key_rotation")
            .unwrap();
        for update in [
            "UPDATE user_residency SET lifecycle_state = 'released'",
            "UPDATE hosted_principals SET principal_handle = 72",
            "UPDATE hosted_auth_state SET enabled = 0 WHERE local_user_id = 8",
            "UPDATE principals SET retired_at = 10 WHERE principal_pk = 71",
            "DELETE FROM users",
        ] {
            tx.execute_batch("SAVEPOINT ownership_change").unwrap();
            tx.execute(update, []).unwrap();
            assert!(!verify_claim_in_tx(&tx, &first, 10).unwrap());
            assert!(!record_retry_claimed_in_tx(&tx, &first, 10, "offline", 10).unwrap());
            assert!(!quarantine_claimed_in_tx(&tx, &first, "invalid", 10).unwrap());
            assert!(!release_claim_in_tx(&tx, &first, 10).unwrap());
            assert!(
                claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 110)
                    .unwrap()
                    .is_none()
            );
            tx.execute_batch("ROLLBACK TO ownership_change; RELEASE ownership_change")
                .unwrap();
        }
        assert!(!verify_claim_in_tx(&tx, &first, 110).unwrap());
        let takeover = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 110)
            .unwrap()
            .unwrap();
        assert_eq!(takeover.pending.id, first.pending.id);
        assert_eq!(takeover.claim.generation, first.claim.generation + 1);
        assert!(!record_retry_claimed_in_tx(&tx, &first, 110, "stale", 110).unwrap());
        assert!(!quarantine_claimed_in_tx(&tx, &first, "stale", 110).unwrap());
        assert!(!release_claim_in_tx(&tx, &first, 110).unwrap());
        assert!(record_retry_claimed_in_tx(&tx, &takeover, 110, "offline", 110).unwrap());
        assert!(!verify_claim_in_tx(&tx, &takeover, 110).unwrap());
        assert_eq!(
            load_in_tx(&tx, first.pending.id)
                .unwrap()
                .unwrap()
                .attempt_count,
            1
        );
    }

    #[test]
    fn exhausted_generations_and_invalid_leases_do_not_acquire() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection.transaction().unwrap();
        for duration in [0, -1, i64::MAX] {
            assert!(claim_ready_in_tx(&tx, 1, duration, 10).is_err());
        }
        for generation in [i64::MAX, -1] {
            tx.execute(
                "UPDATE pending_relays SET dispatch_generation = ?1",
                [generation],
            )
            .unwrap();
            tx.execute("UPDATE pending_relays SET delivery_state = 'ready'", [])
                .unwrap();
            assert!(claim_ready_in_tx(&tx, 1, 100, 10).unwrap().is_empty());
            let pending = load_in_tx(&tx, 1).unwrap().unwrap();
            assert_eq!(
                pending.delivery_state,
                PendingRelayDeliveryState::Quarantined
            );
            assert_eq!(
                pending.last_error.as_deref(),
                Some("dispatch_generation_exhausted")
            );
            assert_eq!(
                tx.query_row("SELECT dispatch_owner FROM pending_relays", [], |row| {
                    row.get::<_, Option<String>>(0)
                })
                .unwrap(),
                None
            );
        }
        tx.execute("UPDATE pending_relays SET delivery_state = 'ready', dispatch_generation = 0, attempt_count = 9223372036854775807", []).unwrap();
        let claimed = claim(&tx, 10);
        assert!(record_retry_claimed_in_tx(&tx, &claimed, 10, "offline", 10).unwrap());
        assert!(!verify_claim_in_tx(&tx, &claimed, 10).unwrap());
        let pending = load_in_tx(&tx, 1).unwrap().unwrap();
        assert_eq!(pending.attempt_count, i64::MAX);
        assert_eq!(pending.frame, claimed.pending.frame);
        assert_eq!(
            pending.last_error.as_deref(),
            Some("dispatch_attempts_exhausted")
        );
        assert_eq!(
            pending.delivery_state,
            PendingRelayDeliveryState::Quarantined
        );
        let lease: (Option<String>, Option<i64>) = tx
            .query_row(
                "SELECT dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(lease, (None, None));
    }

    #[test]
    fn poison_oldest_rows_do_not_starve_healthy_work() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        connection.execute("INSERT INTO pending_relays SELECT 2, destination_id, target_kind, X'03', created_at, -1, type_map_version, relay_signer_id, relay_destination_user_id, 'malformed', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1", []).unwrap();
        connection.execute("INSERT INTO pending_relays SELECT 3, destination_id, target_kind, X'04', created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, 'healthy', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1", []).unwrap();
        connection
            .execute(
                "UPDATE pending_relays SET dispatch_generation = 9223372036854775807 WHERE id = 1",
                [],
            )
            .unwrap();
        // Exercise both selectors. The limit counts healthy work, not poison rows.
        for local in [false, true] {
            let tx = connection.transaction().unwrap();
            let healthy = if local {
                tx.execute_batch("INSERT INTO users VALUES (8); INSERT INTO hosted_principals VALUES (8, 71); INSERT INTO user_residency VALUES (8, 'managed'); UPDATE pending_relays SET target_kind = 0, destination_id = 8;").unwrap();
                claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
                    .unwrap()
                    .unwrap()
            } else {
                claim_ready_in_tx(&tx, 1, 100, 10).unwrap().remove(0)
            };
            assert_eq!(healthy.pending.id, 3);
            for (id, bytes, code) in [
                (1, vec![1, 2], "dispatch_generation_exhausted"),
                (2, vec![3], "dispatch_malformed_pending"),
            ] {
                let row: (Vec<u8>, String, String, Option<String>, Option<i64>) = tx.query_row("SELECT frame, delivery_state, last_error, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).unwrap();
                assert_eq!(row, (bytes, "quarantined".into(), code.into(), None, None));
            }
            // Roll back so the other selector sees the same poison rows.
        }
    }

    #[test]
    fn remote_claims_require_canonical_current_origin_ownership() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection.transaction().unwrap();
        // The legacy signer number need not match the canonical local owner.
        tx.execute("UPDATE pending_relays SET relay_signer_id = 999", [])
            .unwrap();
        let now = now_millis();
        let work = claim_ready_in_tx(&tx, 1, 60_000, now).unwrap().remove(0);
        assert!(verify_claim_in_tx(&tx, &work, now).unwrap());
        tx.execute_batch("SAVEPOINT key_rotation").unwrap();
        tx.execute(
            "UPDATE hosted_auth_state SET generation = generation + 1 WHERE local_user_id = 7",
            [],
        )
        .unwrap();
        assert!(verify_claim_in_tx(&tx, &work, now).unwrap());
        assert!(release_claim_in_tx(&tx, &work, now).unwrap());
        assert_eq!(claim_ready_in_tx(&tx, 1, 60_000, now).unwrap().len(), 1);
        tx.execute_batch("ROLLBACK TO key_rotation; RELEASE key_rotation")
            .unwrap();
        for update in [
            "UPDATE user_residency SET lifecycle_state = 'released'",
            "UPDATE hosted_principals SET principal_handle = 999",
            "UPDATE hosted_auth_state SET enabled = 0 WHERE local_user_id = 7",
            "UPDATE principals SET retired_at = 10 WHERE principal_pk = 70",
            "DELETE FROM users",
        ] {
            tx.execute_batch("SAVEPOINT ownership").unwrap();
            tx.execute(update, []).unwrap();
            assert!(!verify_claim_in_tx(&tx, &work, now).unwrap());
            assert!(!record_retry_claimed_in_tx(&tx, &work, now, "offline", now).unwrap());
            assert!(!quarantine_claimed_in_tx(&tx, &work, "invalid", now).unwrap());
            assert!(!release_claim_in_tx(&tx, &work, now).unwrap());
            assert!(
                !super::super::downstream_relay::acknowledge_claimed_pending_delivery_in_tx(
                    &tx, &work, "first", now
                )
                .unwrap()
            );
            assert!(
                !super::super::downstream_relay::reject_claimed_pending_delivery_in_tx(
                    &tx, &work, "rejected"
                )
                .unwrap()
            );
            assert_eq!(
                load_in_tx(&tx, work.pending.id).unwrap().unwrap(),
                work.pending
            );
            assert!(
                claim_ready_in_tx(&tx, 1, 100, now + 60_000)
                    .unwrap()
                    .is_empty()
            );
            tx.execute_batch("ROLLBACK TO ownership; RELEASE ownership")
                .unwrap();
        }
        assert!(release_claim_in_tx(&tx, &work, now).unwrap());
        tx.execute(
            "UPDATE pending_relays SET signer_principal = 999, relay_signer_id = 7",
            [],
        )
        .unwrap();
        assert!(claim_ready_in_tx(&tx, 1, 100, 10).unwrap().is_empty());
    }

    #[test]
    fn pause_and_resume_cannot_revive_client_claim() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let tx = connection.transaction().unwrap();
        tx.execute_batch("INSERT INTO users VALUES (8); INSERT INTO hosted_principals VALUES (8, 71); INSERT INTO user_residency VALUES (8, 'managed'); UPDATE pending_relays SET target_kind = 0, destination_id = 8;").unwrap();
        let old = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
            .unwrap()
            .unwrap();
        pause_client_deliveries_in_tx(&tx, 8).unwrap();
        assert!(!verify_claim_in_tx(&tx, &old, 10).unwrap());
        tx.execute("UPDATE pending_relays SET delivery_state = 'ready', last_error = NULL WHERE delivery_state = 'waiting_client'", []).unwrap();
        assert!(!verify_claim_in_tx(&tx, &old, 10).unwrap());
        assert!(!record_retry_claimed_in_tx(&tx, &old, 10, "stale", 10).unwrap());
        assert!(!quarantine_claimed_in_tx(&tx, &old, "stale", 10).unwrap());
        let new = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
            .unwrap()
            .unwrap();
        assert_eq!(new.claim.generation, old.claim.generation + 1);
        assert!(verify_claim_in_tx(&tx, &new, 10).unwrap());
        assert!(!verify_claim_in_tx(&tx, &old, 10).unwrap());
    }

    #[test]
    fn reused_frames_are_ambiguous_before_mutation() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        connection.execute("INSERT INTO pending_relays (destination_id, target_kind, frame, created_at, frame_id, type_map_version) VALUES (0, 2, X'03', 20, 42, '1.0')", []).unwrap();
        let tx = connection.transaction().unwrap();
        assert!(matches!(
            ensure_unique_frame_in_tx(&tx, 0, 2, 42),
            Err(StorageError::AmbiguousRelayDelivery)
        ));
        assert_eq!(
            tx.query_row("SELECT count(*) FROM pending_relays", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}
