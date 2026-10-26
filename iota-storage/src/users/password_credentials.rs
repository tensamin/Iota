use rusqlite::{OptionalExtension, params};

use crate::{storage_error::StorageError, util::db};

mod mutations;
pub use mutations::{commit_disable, commit_enrollment, mutation_outcome};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordCredential {
    pub user_id: i64,
    pub opaque_profile: i64,
    pub opaque_record: Vec<u8>,
    pub encrypted_tu_credential: Vec<u8>,
    pub account_public_key_sha256: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub setup_sha256: Option<Vec<u8>>,
    pub password_principal: Option<String>,
    pub password_iota_id: Option<i64>,
}

pub fn get(user_id: i64) -> Result<Option<PasswordCredential>, StorageError> {
    db::with_db(|conn| get_on(conn, user_id))
}

fn get_on(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<Option<PasswordCredential>, StorageError> {
    conn.query_row(
            "SELECT user_id, opaque_profile, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at, setup_sha256, password_principal, password_iota_id FROM user_password_credentials WHERE user_id = ?1",
            params![user_id],
            |row| Ok(PasswordCredential {
                user_id: row.get(0)?, opaque_profile: row.get(1)?, opaque_record: row.get(2)?, encrypted_tu_credential: row.get(3)?,
                account_public_key_sha256: row.get(4)?, created_at: row.get(5)?, updated_at: row.get(6)?,
                setup_sha256: row.get(7)?, password_principal: row.get(8)?, password_iota_id: row.get(9)?,
            }),
        ).optional().map_err(Into::into)
}

pub fn exists(user_id: i64) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_password_credentials WHERE user_id = ?1)",
            params![user_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
    })
}

pub fn any() -> Result<bool, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_password_credentials)",
            [],
            |row| row.get(0),
        )
        .map_err(Into::into)
    })
}

/// Inspect credential bytes and the current account key in one SQLite snapshot.
/// The visitor must not perform network I/O or write to the database.
pub fn inspect_all(
    mut inspect: impl FnMut(&PasswordCredential, Option<&str>),
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT c.user_id, c.opaque_profile, c.opaque_record, c.encrypted_tu_credential,
                    c.account_public_key_sha256, c.created_at, c.updated_at, c.setup_sha256,
                    c.password_principal, c.password_iota_id, u.public_key
             FROM user_password_credentials c LEFT JOIN users u ON u.user_id = c.user_id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let credential = PasswordCredential {
                user_id: row.get(0)?,
                opaque_profile: row.get(1)?,
                opaque_record: row.get(2)?,
                encrypted_tu_credential: row.get(3)?,
                account_public_key_sha256: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                setup_sha256: row.get(7)?,
                password_principal: row.get(8)?,
                password_iota_id: row.get(9)?,
            };
            let public_key: Option<String> = row.get(10)?;
            inspect(&credential, public_key.as_deref());
        }
        Ok(())
    })
}

/// Legacy rows have no evidence tying them to a particular setup file.
pub fn validate_setup_binding(fingerprint: &[u8]) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        let mismatch: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_password_credentials WHERE setup_sha256 IS NOT NULL AND setup_sha256 != ?1)",
            params![fingerprint], |row| row.get(0),
        )?;
        if mismatch {
            return Err(StorageError::Other(
                "OPAQUE setup does not match enrolled credentials".into(),
            ));
        }
        let legacy: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_password_credentials WHERE setup_sha256 IS NULL OR password_principal IS NULL OR password_iota_id IS NULL)",
            [],
            |row| row.get(0),
        )?;
        Ok(!legacy)
    })
}

pub fn upsert_if_account_key_matches(
    credential: &PasswordCredential,
    expected_public_key: &str,
) -> Result<(), StorageError> {
    upsert_checked(credential, expected_public_key, None)
}

pub fn authorization(user_id: i64) -> Result<(String, i64), StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT u.public_key, a.generation FROM users u JOIN hosted_auth_state a ON a.local_user_id = u.user_id WHERE u.user_id = ?1 AND a.enabled = 1",
            params![user_id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?.ok_or(StorageError::HostedAuthorizationDenied)
    })
}

pub fn upsert_if_authorized(
    credential: &PasswordCredential,
    expected_public_key: &str,
    generation: i64,
) -> Result<(), StorageError> {
    upsert_checked(credential, expected_public_key, Some(generation))
}

fn upsert_checked(
    credential: &PasswordCredential,
    expected_public_key: &str,
    generation: Option<i64>,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        upsert_in_tx(tx, credential, expected_public_key, generation)
    })
}

fn upsert_in_tx(
    tx: &rusqlite::Transaction<'_>,
    credential: &PasswordCredential,
    expected_public_key: &str,
    generation: Option<i64>,
) -> Result<(), StorageError> {
    let current: Option<String> = tx
        .query_row(
            "SELECT public_key FROM users WHERE user_id = ?1",
            params![credential.user_id],
            |row| row.get(0),
        )
        .optional()?;
    if current.as_deref() != Some(expected_public_key) {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    if let Some(generation) = generation {
        let authorized: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM hosted_auth_state WHERE local_user_id = ?1 AND enabled = 1 AND generation = ?2)",
                params![credential.user_id, generation], |row| row.get(0),
            )?;
        if !authorized {
            return Err(StorageError::HostedAuthorizationDenied);
        }
    }
    tx.execute(
            "INSERT INTO user_password_credentials (user_id, opaque_profile, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at, setup_sha256, password_principal, password_iota_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(user_id) DO UPDATE SET
                opaque_profile = excluded.opaque_profile,
                opaque_record = excluded.opaque_record,
                encrypted_tu_credential = excluded.encrypted_tu_credential,
                account_public_key_sha256 = excluded.account_public_key_sha256,
                updated_at = excluded.updated_at,
                setup_sha256 = excluded.setup_sha256,
                password_principal = excluded.password_principal,
                password_iota_id = excluded.password_iota_id",
            params![credential.user_id, credential.opaque_profile, credential.opaque_record, credential.encrypted_tu_credential,
                credential.account_public_key_sha256, credential.created_at, credential.updated_at,
                credential.setup_sha256, credential.password_principal, credential.password_iota_id],
        )?;
    Ok(())
}

/// Credential-release linearization point. A successful immediate transaction
/// grants release of exactly this snapshot, even if disablement commits later.
/// It does not promise cancellation of ciphertext already in transit.
pub fn authorize_release(
    credential: &PasswordCredential,
    expected_public_key: &str,
    generation: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let authorized: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users u JOIN hosted_auth_state a ON a.local_user_id = u.user_id
             WHERE u.user_id = ?1 AND u.public_key = ?2 AND a.enabled = 1 AND a.generation = ?3)",
            params![credential.user_id, expected_public_key, generation], |row| row.get(0),
        )?;
        if !authorized || get_on(tx, credential.user_id)?.as_ref() != Some(credential) {
            return Err(StorageError::HostedAuthorizationDenied);
        }
        Ok(())
    })
}

pub fn delete(user_id: i64) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        Ok(conn.execute(
            "DELETE FROM user_password_credentials WHERE user_id = ?1",
            params![user_id],
        )? != 0)
    })
}

pub fn delete_if_authorized(
    user_id: i64,
    expected_public_key: &str,
    generation: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let authorized: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users u JOIN hosted_auth_state a ON a.local_user_id = u.user_id WHERE u.user_id = ?1 AND u.public_key = ?2 AND a.generation = ?3 AND a.enabled = 1)",
            params![user_id, expected_public_key, generation], |row| row.get(0),
        )?;
        if !authorized {
            return Err(StorageError::HostedAuthorizationDenied);
        }
        tx.execute(
            "DELETE FROM user_password_credentials WHERE user_id = ?1",
            params![user_id],
        )?;
        Ok(())
    })
}
