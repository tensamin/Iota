use super::*;

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

pub(super) fn claim_ready_for_user_in_tx(
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

pub(super) fn quarantine_row_in_tx(
    tx: &Transaction<'_>,
    id: i64,
    code: &str,
) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE pending_relays SET delivery_state = 'quarantined', last_error = ?2, dispatch_owner = NULL, dispatch_deadline = NULL WHERE id = ?1",
        params![id, code],
    )?;
    Ok(())
}

/// Decode before leasing so a corrupt row cannot roll back healthy acquisitions.
pub(super) fn acquire_candidate_in_tx(
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

pub(super) fn claim_ready_in_tx(
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

pub(super) fn release_claim_in_tx(
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

pub(super) fn record_retry_claimed_in_tx(
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

pub(super) fn quarantine_claimed_in_tx(
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
