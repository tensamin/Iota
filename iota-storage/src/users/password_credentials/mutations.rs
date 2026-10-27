use super::*;

fn record_in_tx(
    tx: &rusqlite::Transaction<'_>,
    user_id: i64,
    public_key: &str,
    generation: i64,
    operation: (&str, &[u8]),
    enabled: bool,
) -> Result<(), StorageError> {
    if operation.0.is_empty() || operation.0.len() > 128 || operation.1.len() != 32 {
        return Err(StorageError::Other(
            "invalid password operation identity".into(),
        ));
    }
    // No update path. Reusing an operation ID cannot replace its original result.
    tx.execute(
        "INSERT INTO user_password_mutations
         (user_id, operation_id, request_sha256, account_public_key, authorization_generation, enabled, committed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![user_id, operation.0, operation.1, public_key, generation, enabled, crate::util::sync::now_millis()],
    )?;
    Ok(())
}

pub fn commit_enrollment(
    credential: &PasswordCredential,
    public_key: &str,
    generation: i64,
    operation: (&str, &[u8]),
    fence: &PasswordAuthorization,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        if let Some(enabled) =
            outcome_on(tx, credential.user_id, public_key, generation, operation)?
        {
            return if enabled {
                Ok(())
            } else {
                Err(StorageError::PendingRelayConflict)
            };
        }
        if super::get_on(tx, credential.user_id)?.is_some() {
            return Err(StorageError::PendingRelayConflict);
        }
        verify_principal_on(tx, credential.user_id, public_key, fence)?;
        if credential.password_principal.as_deref()
            != Some(
                format!(
                    "{}#{}",
                    fence.principal.principal.authority.as_str(),
                    fence.principal.principal.user_id
                )
                .as_str(),
            )
        {
            return Err(StorageError::HostedAuthorizationDenied);
        }
        super::upsert_in_tx(tx, credential, public_key, Some(generation))?;
        record_in_tx(
            tx,
            credential.user_id,
            public_key,
            generation,
            operation,
            true,
        )
    })
}

pub fn commit_disable(
    user_id: i64,
    public_key: &str,
    generation: i64,
    operation: (&str, &[u8]),
    fence: &PasswordAuthorization,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        if let Some(enabled) = outcome_on(tx, user_id, public_key, generation, operation)? {
            return if !enabled {
                Ok(())
            } else {
                Err(StorageError::PendingRelayConflict)
            };
        }
        verify_principal_on(tx, user_id, public_key, fence)?;
        tx.execute(
            "DELETE FROM user_password_credentials WHERE user_id = ?1",
            [user_id],
        )?;
        record_in_tx(tx, user_id, public_key, generation, operation, false)
    })
}

/// None is an unknown outcome, never proof that an operation did not commit.
pub fn mutation_outcome(
    user_id: i64,
    public_key: &str,
    generation: i64,
    operation: (&str, &[u8]),
) -> Result<Option<bool>, StorageError> {
    db::with_db(|conn| outcome_on(conn, user_id, public_key, generation, operation))
}

fn outcome_on(
    conn: &rusqlite::Connection,
    user_id: i64,
    public_key: &str,
    generation: i64,
    operation: (&str, &[u8]),
) -> Result<Option<bool>, StorageError> {
    if operation.0.is_empty() || operation.0.len() > 128 || operation.1.len() != 32 {
        return Err(StorageError::PendingRelayConflict);
    }
    let authorized: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users u JOIN hosted_auth_state a ON a.local_user_id=u.user_id
         WHERE u.user_id=?1 AND u.public_key=?2 AND a.generation=?3 AND a.enabled=1)",
        params![user_id, public_key, generation],
        |row| row.get(0),
    )?;
    if !authorized {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    let row: Option<(Vec<u8>, String, i64, bool)> = conn.query_row(
        "SELECT request_sha256,account_public_key,authorization_generation,enabled FROM user_password_mutations WHERE user_id=?1 AND operation_id=?2",
        params![user_id, operation.0], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional()?;
    match row {
        None => Ok(None),
        Some((digest, key, recorded_generation, enabled))
            if digest == operation.1 && key == public_key && recorded_generation == generation =>
        {
            Ok(Some(enabled))
        }
        Some(_) => Err(StorageError::PendingRelayConflict),
    }
}
