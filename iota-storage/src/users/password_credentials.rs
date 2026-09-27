use rusqlite::{OptionalExtension, params};

use crate::{storage_error::StorageError, util::db};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordCredential {
    pub user_id: i64,
    pub protocol_version: i64,
    pub credential_format_version: i64,
    pub opaque_record: Vec<u8>,
    pub encrypted_tu_credential: Vec<u8>,
    pub account_public_key_sha256: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub fn get(user_id: i64) -> Result<Option<PasswordCredential>, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT user_id, protocol_version, credential_format_version, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at FROM user_password_credentials WHERE user_id = ?1",
            params![user_id],
            |row| Ok(PasswordCredential {
                user_id: row.get(0)?, protocol_version: row.get(1)?, credential_format_version: row.get(2)?,
                opaque_record: row.get(3)?, encrypted_tu_credential: row.get(4)?,
                account_public_key_sha256: row.get(5)?, created_at: row.get(6)?, updated_at: row.get(7)?,
            }),
        ).optional().map_err(Into::into)
    })
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

pub fn upsert(credential: &PasswordCredential) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "INSERT INTO user_password_credentials (user_id, protocol_version, credential_format_version, opaque_record, encrypted_tu_credential, account_public_key_sha256, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(user_id) DO UPDATE SET
                protocol_version = excluded.protocol_version,
                credential_format_version = excluded.credential_format_version,
                opaque_record = excluded.opaque_record,
                encrypted_tu_credential = excluded.encrypted_tu_credential,
                account_public_key_sha256 = excluded.account_public_key_sha256,
                updated_at = excluded.updated_at",
            params![credential.user_id, credential.protocol_version, credential.credential_format_version,
                credential.opaque_record, credential.encrypted_tu_credential,
                credential.account_public_key_sha256, credential.created_at, credential.updated_at],
        )?;
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
