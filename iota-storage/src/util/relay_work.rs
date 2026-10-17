use super::{db, e2ee_storage, relay_replay, sync};
use crate::storage_error::StorageError;
use iota_identity::PrincipalHandle;
use rusqlite::{OptionalExtension, Transaction, params};

/// Test builds can terminate a subprocess without running SQLite destructors.
/// Normal daemon builds contain no environment-controlled interruption path.
#[inline]
pub fn fault_point(boundary: &str, message_id: &str) {
    #[cfg(feature = "relay-fault-injection")]
    if std::env::var("IOTA_RELAY_FAULT_POINT").as_deref() == Ok(boundary)
        && std::env::var("IOTA_RELAY_FAULT_MESSAGE_ID").as_deref() == Ok(message_id)
    {
        std::process::exit(86);
    }
    #[cfg(not(feature = "relay-fault-injection"))]
    let _ = (boundary, message_id);
}

pub fn verify_owner_in_tx(
    tx: &Transaction<'_>,
    owner: i64,
    principal: PrincipalHandle,
) -> Result<(), StorageError> {
    let eligible: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM hosted_principals h JOIN users u ON u.user_id = h.local_user_id
         WHERE h.local_user_id = ?1 AND h.principal_handle = ?2
         AND NOT EXISTS(SELECT 1 FROM user_residency r WHERE r.user_id = ?1 AND (r.lifecycle_state <> 'managed' OR r.data_state = 'empty'))
         AND NOT EXISTS(SELECT 1 FROM pending_user_operations p WHERE p.user_id = ?1 AND p.operation = 'purge'))",
        params![owner, principal.0], |row| row.get(0),
    )?;
    if !eligible {
        return Err(StorageError::RelayOwnerUnavailable);
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeferredSecret {
    pub owner: i64,
    pub principal: PrincipalHandle,
    pub legacy_chat_id: Option<String>,
    pub secret: e2ee_storage::StoredChatSecret,
}

pub fn defer_secret_in_tx(
    tx: &Transaction<'_>,
    claim: &relay_replay::ProcessingClaim,
    action: &DeferredSecret,
) -> Result<(), StorageError> {
    verify_owner_in_tx(tx, action.owner, action.principal)?;
    let secret = &action.secret;
    tx.execute(
        "INSERT INTO relay_deferred_secrets(signer_principal, message_id, storage_owner, owner_principal,
         legacy_chat_id, chat_id, secret_id, version, encrypted_secret, kem_ciphertext, wrapping_scheme, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![claim.signer.0, claim.message_id, action.owner, action.principal.0, action.legacy_chat_id,
        secret.chat_id, secret.secret_id, secret.version, secret.encrypted_secret, secret.kem_ciphertext,
        secret.wrapping_scheme, secret.created_at],
    )?;
    Ok(())
}

pub fn complete_deferred_in_tx(
    tx: &Transaction<'_>,
    signer: PrincipalHandle,
    message_id: &str,
) -> Result<(), StorageError> {
    let actions = {
        let mut statement = tx.prepare(
            "SELECT storage_owner, owner_principal, legacy_chat_id, chat_id, secret_id, version,
             encrypted_secret, kem_ciphertext, wrapping_scheme, created_at FROM relay_deferred_secrets
             WHERE signer_principal = ?1 AND message_id = ?2 AND completed_at IS NULL",
        )?;
        statement
            .query_map(params![signer.0, message_id], |row| {
                let owner: i64 = row.get(0)?;
                Ok(DeferredSecret {
                    owner,
                    principal: PrincipalHandle(row.get(1)?),
                    legacy_chat_id: row.get(2)?,
                    secret: e2ee_storage::StoredChatSecret {
                        user_id: owner.to_string(),
                        chat_id: row.get(3)?,
                        secret_id: row.get(4)?,
                        version: row.get(5)?,
                        encrypted_secret: row.get(6)?,
                        kem_ciphertext: row.get(7)?,
                        wrapping_scheme: row.get(8)?,
                        created_at: row.get(9)?,
                        updated_at: sync::now_millis(),
                    },
                })
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for action in actions {
        verify_owner_in_tx(tx, action.owner, action.principal)?;
        if let Some(legacy_chat_id) = &action.legacy_chat_id {
            e2ee_storage::migrate_chat_secret_namespace_in_tx(
                tx,
                &action.secret.user_id,
                legacy_chat_id,
                &format!("chat:{legacy_chat_id}:main"),
                &action.secret.chat_id,
                &action.secret.secret_id,
            )?;
        }
        e2ee_storage::put_chat_secret_in_tx(tx, &action.secret)?;
        fault_point("after_deferred_secret_application", message_id);
        tx.execute("UPDATE relay_deferred_secrets SET completed_at = ?4 WHERE signer_principal = ?1 AND message_id = ?2 AND storage_owner = ?3 AND completed_at IS NULL",
            params![signer.0, message_id, action.owner, sync::now_millis()])?;
    }
    Ok(())
}

#[derive(Debug)]
pub struct AcceptedWork {
    pub signer: PrincipalHandle,
    pub message_id: String,
    pub state: relay_replay::RelayState,
    pub generation: i64,
    pub owner: Option<String>,
    pub prepared: Vec<u8>,
    pub attempts: i64,
}

pub fn incomplete(limit: i64) -> Result<Vec<AcceptedWork>, StorageError> {
    db::with_db(|conn| {
        block_invalid_metadata_on(conn)?;
        let mut stmt = conn.prepare("SELECT signer_principal, message_id, state, processing_generation, processing_owner, prepared_operation, recovery_attempts FROM relay_inbox WHERE prepared_operation IS NOT NULL AND recovery_status IN ('ready', 'retry') AND recovery_next_at <= ?1 AND (state IN ('received', 'applied') OR (state = 'processing' AND processing_deadline < ?1)) ORDER BY recovery_next_at, accepted_at LIMIT ?2")?;
        let rows = stmt
            .query_map(params![sync::now_millis(), limit.clamp(1, 500)], |row| {
                Ok((
                    PrincipalHandle(row.get(0)?),
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(signer, message_id, state, generation, owner, prepared, attempts)| {
                    Ok(AcceptedWork {
                        signer,
                        message_id,
                        state: relay_replay::RelayState::try_from(state.as_str())?,
                        generation,
                        owner,
                        prepared,
                        attempts,
                    })
                },
            )
            .collect()
    })
}

/// SQLite affinity permits text in integer columns. Quarantine it before typed batch decoding.
pub fn block_invalid_metadata_on(conn: &rusqlite::Connection) -> Result<(), StorageError> {
    let invalid = "prepared_operation IS NOT NULL AND (
        typeof(prepared_operation) <> 'blob' OR typeof(signer_principal) <> 'integer' OR signer_principal <= 0
        OR typeof(message_id) <> 'text' OR typeof(state) <> 'text'
        OR state NOT IN ('received','processing','applied','queued','delivered','rejected')
        OR typeof(processing_generation) <> 'integer' OR processing_generation < 0
        OR typeof(recovery_attempts) <> 'integer' OR recovery_attempts < 0
        OR typeof(recovery_next_at) <> 'integer'
        OR (recovery_last_attempt_at IS NOT NULL AND typeof(recovery_last_attempt_at) <> 'integer')
        OR (processing_owner IS NOT NULL AND typeof(processing_owner) <> 'text')
        OR (processing_deadline IS NOT NULL AND typeof(processing_deadline) <> 'integer')
        OR typeof(frame_id) <> 'integer' OR frame_id < 0 OR frame_id > 4294967295
        OR typeof(signer_id) <> 'integer' OR signer_id <= 0
        OR typeof(destination_id) <> 'integer' OR destination_id <= 0
        OR typeof(frame) <> 'blob' OR typeof(created_at) <> 'integer'
        OR typeof(accepted_at) <> 'integer' OR typeof(type_map_version) <> 'text')";
    let tx = conn.unchecked_transaction()?;
    // Unknown/corrupt ownership cannot justify a partial accepted-receipt snapshot.
    tx.execute(&format!("INSERT INTO relay_receipt_backfill_blocks(signer_principal,message_id,storage_owner,reason)
        SELECT signer_principal,message_id,0,'invalid_persisted_metadata' FROM relay_inbox
        WHERE {invalid} AND state IN ('applied','queued','delivered')
        ON CONFLICT(signer_principal,message_id,storage_owner) DO NOTHING"), [])?;
    tx.execute(&format!("UPDATE relay_inbox SET recovery_status = 'blocked', recovery_error_code = 'invalid_persisted_metadata' WHERE {invalid} AND (recovery_status <> 'blocked' OR recovery_error_code IS NOT 'invalid_persisted_metadata')"), [])?;
    tx.commit()?;
    Ok(())
}

pub enum RecoveryDisposition {
    Retry {
        next_attempt_at: i64,
        error_code: &'static str,
    },
    Blocked {
        error_code: &'static str,
    },
}

/// Scheduling is conditional on the observed application authority, never a replacement for it.
pub fn record_outcome(
    work: &AcceptedWork,
    disposition: RecoveryDisposition,
) -> Result<bool, StorageError> {
    let (mut status, mut next, mut code) = match disposition {
        RecoveryDisposition::Retry {
            next_attempt_at,
            error_code,
        } => ("retry", next_attempt_at, error_code),
        RecoveryDisposition::Blocked { error_code } => ("blocked", 0, error_code),
    };
    db::with_immediate_transaction(|tx| {
        let attempts = match work.attempts.checked_add(1) {
            Some(attempts) => attempts,
            None => {
                status = "blocked";
                next = 0;
                code = "recovery_attempts_exhausted";
                work.attempts
            }
        };
        Ok(tx.execute("UPDATE relay_inbox SET recovery_status = ?6, recovery_next_at = ?7, recovery_error_code = ?8, recovery_last_attempt_at = ?9, recovery_attempts = ?10 WHERE signer_principal = ?1 AND message_id = ?2 AND state = ?3 AND processing_generation = ?4 AND processing_owner IS ?5 AND recovery_attempts = ?11 AND recovery_status IN ('ready','retry')",
            params![work.signer.0, work.message_id, work.state.as_str(), work.generation, work.owner, status, next, code, sync::now_millis(), attempts, work.attempts])? == 1)
    })
}

pub fn resolve_outcome(work: &AcceptedWork) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute("UPDATE relay_inbox SET recovery_status = 'ready', recovery_next_at = 0, recovery_error_code = NULL WHERE signer_principal = ?1 AND message_id = ?2 AND processing_generation = ?3 AND state IN ('queued','delivered','rejected')", params![work.signer.0, work.message_id, work.generation])?;
        Ok(())
    })
}

#[derive(Debug, Default)]
pub struct RecoveryHealth {
    pub remaining: i64,
    pub eligible: i64,
    pub retrying: i64,
    pub blocked: i64,
    pub oldest_age_ms: i64,
    pub processing: i64,
    pub dispatch_active: i64,
    pub dispatch_expired: i64,
    pub pending: i64,
    pub pending_quarantined: i64,
    pub receipt_backfill_blocked: i64,
}

pub fn health() -> Result<RecoveryHealth, StorageError> {
    db::with_db(|conn| {
        let now = sync::now_millis();
        let mut health = conn.query_row(
            "WITH work AS (SELECT *, recovery_status IN ('ready','retry') AND recovery_next_at <= ?1
                AND (state IN ('received','applied') OR (state = 'processing' AND processing_deadline < ?1)) AS eligible
                FROM relay_inbox WHERE prepared_operation IS NOT NULL)
             SELECT COALESCE(SUM(eligible),0),
                COALESCE(SUM(recovery_status = 'retry' AND state IN ('received','processing','applied')),0),
                COALESCE(SUM(recovery_status = 'blocked'),0),
                COALESCE(?1 - MIN(CASE WHEN eligible THEN accepted_at END),0),
                COALESCE(SUM(state = 'processing' AND processing_deadline >= ?1),0),
                COALESCE(SUM(state IN ('received','processing','applied')),0) FROM work",
            [now], |r| Ok(RecoveryHealth { eligible:r.get(0)?, retrying:r.get(1)?, blocked:r.get(2)?, oldest_age_ms:r.get(3)?, processing:r.get(4)?, remaining:r.get(5)?, ..Default::default() }))?;
        (health.dispatch_active, health.dispatch_expired, health.pending, health.pending_quarantined) = conn.query_row("SELECT COALESCE(SUM(delivery_state = 'ready' AND dispatch_owner IS NOT NULL AND dispatch_deadline >= ?1),0), COALESCE(SUM(delivery_state = 'ready' AND dispatch_owner IS NOT NULL AND dispatch_deadline < ?1),0), COUNT(*), COALESCE(SUM(delivery_state = 'quarantined'),0) FROM pending_relays", [now], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        health.receipt_backfill_blocked = conn.query_row(
            "SELECT COUNT(*) FROM relay_receipt_backfill_blocks",
            [],
            |r| r.get(0),
        )?;
        Ok(health)
    })
}

pub fn take_over_abandoned_processing(
    work: &AcceptedWork,
    deadline: i64,
) -> Result<Option<relay_replay::ProcessingClaim>, StorageError> {
    if !matches!(
        work.state,
        relay_replay::RelayState::Received | relay_replay::RelayState::Processing
    ) || (work.state == relay_replay::RelayState::Processing && work.owner.is_none())
    {
        return Err(StorageError::InvalidRelayTransition);
    }
    db::with_immediate_transaction(|tx| {
        let generation = work
            .generation
            .checked_add(1)
            .ok_or(StorageError::RelayGenerationExhausted)?;
        let owner: String = tx.query_row("SELECT lower(hex(randomblob(32)))", [], |r| r.get(0))?;
        let acquired = tx.query_row(
            "UPDATE relay_inbox SET state = 'processing', processing_generation = ?3, processing_owner = ?4, processing_deadline = ?5
             WHERE signer_principal = ?1 AND message_id = ?2 AND state = ?6 AND processing_generation = ?7
              AND processing_owner IS ?8 AND (state = 'received' OR processing_deadline < ?9)
              AND recovery_status IN ('ready','retry') AND recovery_next_at <= ?9 AND recovery_attempts = ?10
              AND applied_at IS NULL AND downstream_acked_at IS NULL AND rejected_at IS NULL RETURNING processing_generation",
            params![work.signer.0, work.message_id, generation, owner, deadline, work.state.as_str(), work.generation, work.owner, sync::now_millis(), work.attempts],
            |row| row.get::<_, i64>(0),
        ).optional()?;
        Ok(acquired.map(|generation| relay_replay::ProcessingClaim {
            signer: work.signer,
            message_id: work.message_id.clone(),
            generation,
            owner,
        }))
    })
}

pub fn accepted_at(signer: PrincipalHandle, message_id: &str) -> Result<i64, StorageError> {
    db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT accepted_at FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2",
            params![signer.0, message_id],
            |r| r.get(0),
        )?)
    })
}
