use crate::{storage_error::StorageError, util::db};
use rusqlite::{OptionalExtension, params};

pub fn remove_expired(now: i64) -> Result<usize, StorageError> {
    db::with_db(
        |conn| Ok(conn.execute("DELETE FROM call_envelopes WHERE expires_at <= ?1", [now])?),
    )
}

pub fn start_expiry_cleanup() {
    tokio::spawn(async {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as i64)
                .unwrap_or_default();
            if let Err(error) = remove_expired(now) {
                eprintln!("Call envelope cleanup failed: {error}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

#[derive(Clone)]
pub struct CallEnvelope {
    pub recipient_id: i64,
    pub call_id: String,
    pub owner_omikron_id: i64,
    pub inviter_id: i64,
    pub created_at: i64,
    pub expires_at: i64,
    pub secret_id: String,
    pub version_number: i64,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub wrapping_scheme: String,
}

pub fn store(envelope: &CallEnvelope, now: i64) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute("DELETE FROM call_envelopes WHERE expires_at <= ?1", [now])?;
        let existing: Option<(i64, i64, i64, String, i64, Vec<u8>, Vec<u8>, String)> = tx.query_row(
            "SELECT owner_omikron_id, inviter_id, created_at, secret_id, version_number, encrypted_secret, kem_ciphertext, wrapping_scheme FROM call_envelopes WHERE recipient_id = ?1 AND call_id = ?2",
            params![envelope.recipient_id, envelope.call_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        ).optional()?;
        if let Some((owner, inviter, created, id, version, encrypted, kem, scheme)) = existing {
            return Ok(owner == envelope.owner_omikron_id
                && inviter == envelope.inviter_id
                && created == envelope.created_at
                && id == envelope.secret_id
                && version == envelope.version_number
                && encrypted == envelope.encrypted_secret
                && kem == envelope.kem_ciphertext
                && scheme == envelope.wrapping_scheme);
        }
        tx.execute(
            "INSERT INTO call_envelopes (recipient_id, call_id, owner_omikron_id, inviter_id, created_at, expires_at, secret_id, version_number, encrypted_secret, kem_ciphertext, wrapping_scheme) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![envelope.recipient_id, envelope.call_id, envelope.owner_omikron_id, envelope.inviter_id, envelope.created_at, envelope.expires_at, envelope.secret_id, envelope.version_number, envelope.encrypted_secret, envelope.kem_ciphertext, envelope.wrapping_scheme],
        )?;
        Ok(true)
    })
}

pub fn get(
    recipient_id: i64,
    call_id: &str,
    owner: i64,
    now: i64,
) -> Result<Option<CallEnvelope>, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT recipient_id, call_id, owner_omikron_id, inviter_id, created_at, expires_at, secret_id, version_number, encrypted_secret, kem_ciphertext, wrapping_scheme FROM call_envelopes WHERE recipient_id = ?1 AND call_id = ?2 AND owner_omikron_id = ?3 AND expires_at > ?4",
            params![recipient_id, call_id, owner, now],
            |row| Ok(CallEnvelope {
                recipient_id: row.get(0)?, call_id: row.get(1)?, owner_omikron_id: row.get(2)?, inviter_id: row.get(3)?, created_at: row.get(4)?, expires_at: row.get(5)?, secret_id: row.get(6)?, version_number: row.get(7)?, encrypted_secret: row.get(8)?, kem_ciphertext: row.get(9)?, wrapping_scheme: row.get(10)?,
            }),
        ).optional().map_err(Into::into)
    })
}
