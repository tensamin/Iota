//! Ciphertext-only delivery records. Call authorization and epoch readiness are
//! owned by Omikron. Staging never makes a key retrievable before activation.
use crate::{storage_error::StorageError, util::db};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const WRAPPING_SCHEME: &str = "mtp-call-secret-kem-chacha20poly1305-hkdf-sha256-v1";
const MAX_TTL_MS: i64 = 3 * 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallId {
    pub owner_authority: String,
    pub id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub authority: String,
    pub user_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    pub call_id: CallId,
    pub recipient: Principal,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub operation_id: Uuid,
    #[serde(flatten)]
    pub key: Key,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub secret_id: String,
    pub wrapping_scheme: String,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub operation_id: Uuid,
    #[serde(flatten)]
    pub key: Key,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Staged,
    Available,
    Revoked,
    Expired,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Delivery {
    pub state: State,
    pub envelope: Option<Stage>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid envelope request")]
    Invalid,
    #[error("envelope or operation conflicts with existing state")]
    Conflict,
    #[error("envelope not found")]
    NotFound,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

pub(crate) fn migrate(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS call_epoch_envelopes (
        owner TEXT NOT NULL, call_id TEXT NOT NULL, recipient TEXT NOT NULL,
        user_id INTEGER NOT NULL, epoch INTEGER NOT NULL, local_user_id INTEGER NOT NULL,
        owner_omikron_id INTEGER NOT NULL, state TEXT NOT NULL,
        expires_at INTEGER NOT NULL, fingerprint BLOB, payload TEXT,
        PRIMARY KEY(owner, call_id, recipient, user_id, epoch)
    );
    CREATE INDEX IF NOT EXISTS call_epoch_expiry ON call_epoch_envelopes(expires_at);
    CREATE TABLE IF NOT EXISTS call_epoch_operations (
        owner TEXT NOT NULL, operation_id TEXT NOT NULL, fingerprint BLOB NOT NULL,
        PRIMARY KEY(owner, operation_id)
    );",
    )?;
    Ok(())
}

fn canonical_authority(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|key| {
        key.len() == 64
            && key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

impl Key {
    pub fn validate(&self, allow_legacy_epoch: bool) -> bool {
        canonical_authority(&self.call_id.owner_authority, "omikron-key:")
            && canonical_authority(&self.recipient.authority, "omega-key:")
            && !self.call_id.id.is_nil()
            && self.recipient.user_id > 0
            && self.recipient.user_id <= i64::MAX as u64
            && (self.epoch > 0 || allow_legacy_epoch)
            && self.epoch <= i64::MAX as u64
    }
}

impl Stage {
    fn validate(&self, now: i64) -> bool {
        self.key.validate(false)
            && !self.operation_id.is_nil()
            && self.created_at_ms >= 0
            && self.created_at_ms <= now.saturating_add(60_000)
            && self.expires_at_ms > now
            && self.expires_at_ms > self.created_at_ms
            && self.expires_at_ms.saturating_sub(self.created_at_ms) <= MAX_TTL_MS
            && !self.secret_id.is_empty()
            && self.secret_id.len() <= 256
            && self.wrapping_scheme == WRAPPING_SCHEME
            && !self.encrypted_secret.is_empty()
            && self.encrypted_secret.len() <= 1024
            && !self.kem_ciphertext.is_empty()
            && self.kem_ciphertext.len() <= 4096
    }
}

/// Check residency within the same transaction as the ciphertext operation.
fn hosted(conn: &Connection, local_user: i64) -> Result<bool, StorageError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users u
        JOIN user_residency r ON r.user_id = u.user_id
        JOIN hosted_auth_state a ON a.local_user_id = u.user_id
        WHERE u.user_id = ?1 AND r.lifecycle_state = 'managed' AND a.enabled = 1)",
        [local_user],
        |row| row.get(0),
    )?)
}

pub fn recipient_is_hosted(local_user: i64) -> Result<bool, StorageError> {
    db::with_db(|conn| hosted(conn, local_user))
}

fn expire_in(conn: &Connection, now: i64) -> Result<usize, StorageError> {
    Ok(conn.execute(
        "UPDATE call_epoch_envelopes SET state = 'expired', payload = NULL
        WHERE expires_at <= ?1 AND state IN ('staged', 'available')",
        [now],
    )?)
}

pub fn expire(now: i64) -> Result<usize, StorageError> {
    db::with_db(|conn| expire_in(conn, now))
}

fn read(
    conn: &Connection,
    key: &Key,
    owner: i64,
    local_user: i64,
) -> Result<Option<Delivery>, StorageError> {
    conn.query_row(
        "SELECT state, payload FROM call_epoch_envelopes
        WHERE owner = ?1 AND call_id = ?2 AND recipient = ?3 AND user_id = ?4
        AND epoch = ?5 AND owner_omikron_id = ?6 AND local_user_id = ?7",
        params![
            key.call_id.owner_authority,
            key.call_id.id.to_string(),
            key.recipient.authority,
            key.recipient.user_id as i64,
            key.epoch as i64,
            owner,
            local_user
        ],
        |row| {
            let state: String = row.get(0)?;
            let state = match state.as_str() {
                "staged" => State::Staged,
                "available" => State::Available,
                "revoked" => State::Revoked,
                "expired" => State::Expired,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            let payload: Option<String> = row.get(1)?;
            let envelope = if state == State::Available {
                Some(
                    serde_json::from_str(payload.as_deref().ok_or(rusqlite::Error::InvalidQuery)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                )
            } else {
                None
            };
            Ok(Delivery { state, envelope })
        },
    )
    .optional()
    .map_err(Into::into)
}

/// Operation IDs are scoped to canonical owner authority across all calls and
/// recipients. Reusing one for any different mutation is a conflict.
fn operation(
    conn: &Connection,
    key: &Key,
    id: Uuid,
    kind: &str,
    payload: &str,
) -> Result<bool, StorageError> {
    let fingerprint = Sha256::digest(format!("{kind}\n{payload}").as_bytes()).to_vec();
    let previous: Option<Vec<u8>> = conn
        .query_row(
            "SELECT fingerprint FROM call_epoch_operations
        WHERE owner = ?1 AND operation_id = ?2",
            params![key.call_id.owner_authority, id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(previous) = previous {
        return Ok(previous == fingerprint);
    }
    conn.execute(
        "INSERT INTO call_epoch_operations VALUES (?1, ?2, ?3)",
        params![key.call_id.owner_authority, id.to_string(), fingerprint],
    )?;
    Ok(true)
}

pub fn stage(value: &Stage, owner: i64, local_user: i64, now: i64) -> Result<Delivery, Error> {
    if !value.validate(now) || owner <= 0 || local_user <= 0 {
        return Err(Error::Invalid);
    }
    let payload = serde_json::to_string(value).map_err(|_| Error::Invalid)?;
    // The operation ID is not part of ciphertext identity. Identical staging
    // under a new operation ID is allowed, but no metadata may change.
    let mut identity = value.clone();
    identity.operation_id = Uuid::nil();
    let fingerprint =
        Sha256::digest(serde_json::to_vec(&identity).map_err(|_| Error::Invalid)?).to_vec();
    db::with_immediate_transaction(|tx| {
        stage_in(tx, value, owner, local_user, now, &payload, &fingerprint)
    })?
}

fn stage_in(
    conn: &Connection,
    value: &Stage,
    owner: i64,
    local_user: i64,
    now: i64,
    payload: &str,
    fingerprint: &[u8],
) -> Result<Result<Delivery, Error>, StorageError> {
    if !hosted(conn, local_user)? {
        return Ok(Err(Error::Invalid));
    }
    expire_in(conn, now)?;
    let key = &value.key;
    let binding: Option<(i64, i64)> = conn
        .query_row(
            "SELECT owner_omikron_id, local_user_id FROM call_epoch_envelopes
        WHERE owner = ?1 AND call_id = ?2 AND recipient = ?3 AND user_id = ?4 AND epoch = ?5",
            params![
                key.call_id.owner_authority,
                key.call_id.id.to_string(),
                key.recipient.authority,
                key.recipient.user_id as i64,
                key.epoch as i64
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if binding.is_some_and(|binding| binding != (owner, local_user)) {
        return Ok(Err(Error::Conflict));
    }
    if let Some(delivery) = read(conn, key, owner, local_user)? {
        let previous: Option<Vec<u8>> = conn.query_row(
            "SELECT fingerprint FROM call_epoch_envelopes
            WHERE owner = ?1 AND call_id = ?2 AND recipient = ?3 AND user_id = ?4 AND epoch = ?5",
            params![
                key.call_id.owner_authority,
                key.call_id.id.to_string(),
                key.recipient.authority,
                key.recipient.user_id as i64,
                key.epoch as i64
            ],
            |r| r.get(0),
        )?;
        if previous.as_deref() != Some(fingerprint)
            || matches!(delivery.state, State::Revoked | State::Expired)
        {
            return Ok(Err(Error::Conflict));
        }
        if !operation(conn, key, value.operation_id, "stage", payload)? {
            return Ok(Err(Error::Conflict));
        }
        return Ok(Ok(Delivery {
            state: delivery.state,
            envelope: None,
        }));
    }
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM call_epoch_envelopes WHERE local_user_id = ?1
        AND state IN ('staged', 'available')",
        [local_user],
        |r| r.get(0),
    )?;
    if count >= 256 {
        return Ok(Err(Error::Invalid));
    }
    // Check operation before inserting, so conflicting retries cannot mutate state.
    if !operation(conn, key, value.operation_id, "stage", payload)? {
        return Ok(Err(Error::Conflict));
    }
    conn.execute("INSERT INTO call_epoch_envelopes VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'staged', ?8, ?9, ?10)",
        params![key.call_id.owner_authority, key.call_id.id.to_string(), key.recipient.authority,
            key.recipient.user_id as i64, key.epoch as i64, local_user, owner, value.expires_at_ms, fingerprint, payload])?;
    Ok(Ok(Delivery {
        state: State::Staged,
        envelope: None,
    }))
}

pub fn get(key: &Key, owner: i64, local_user: i64, now: i64) -> Result<Delivery, Error> {
    if !key.validate(false) || owner <= 0 || local_user <= 0 {
        return Err(Error::Invalid);
    }
    db::with_immediate_transaction(|tx| {
        if !hosted(tx, local_user)? {
            return Ok(Err(Error::Invalid));
        }
        expire_in(tx, now)?;
        Ok(read(tx, key, owner, local_user)?.ok_or(Error::NotFound))
    })?
}

pub fn mutate(
    value: &Mutation,
    activate: bool,
    owner: i64,
    local_user: i64,
    now: i64,
) -> Result<Delivery, Error> {
    if !value.key.validate(!activate)
        || value.operation_id.is_nil()
        || owner <= 0
        || local_user <= 0
    {
        return Err(Error::Invalid);
    }
    let payload = serde_json::to_string(value).map_err(|_| Error::Invalid)?;
    db::with_immediate_transaction(|tx| {
        mutate_in(tx, value, activate, owner, local_user, now, &payload)
    })?
}

fn mutate_in(
    conn: &Connection,
    value: &Mutation,
    activate: bool,
    owner: i64,
    local_user: i64,
    now: i64,
    payload: &str,
) -> Result<Result<Delivery, Error>, StorageError> {
    if !hosted(conn, local_user)? {
        return Ok(Err(Error::Invalid));
    }
    expire_in(conn, now)?;
    let key = &value.key;
    let Some(delivery) = read(conn, key, owner, local_user)? else {
        if activate {
            return Ok(Err(Error::NotFound));
        }
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM call_epoch_envelopes
            WHERE owner = ?1 AND call_id = ?2 AND recipient = ?3 AND user_id = ?4 AND epoch = ?5)",
            params![
                key.call_id.owner_authority,
                key.call_id.id.to_string(),
                key.recipient.authority,
                key.recipient.user_id as i64,
                key.epoch as i64
            ],
            |r| r.get(0),
        )?;
        if exists || !operation(conn, key, value.operation_id, "revoke", payload)? {
            return Ok(Err(Error::Conflict));
        }
        // A revoke racing ahead of delivery must fence the delayed stage too.
        conn.execute("INSERT INTO call_epoch_envelopes VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'revoked', ?8, NULL, NULL)",
            params![key.call_id.owner_authority, key.call_id.id.to_string(), key.recipient.authority,
                key.recipient.user_id as i64, key.epoch as i64, local_user, owner, now])?;
        if key.epoch == 0 {
            revoke_legacy(conn, key, owner, local_user)?;
        }
        return Ok(Ok(Delivery {
            state: State::Revoked,
            envelope: None,
        }));
    };
    if activate && matches!(delivery.state, State::Expired | State::Revoked) {
        return Ok(Err(Error::Conflict));
    }
    if !operation(
        conn,
        key,
        value.operation_id,
        if activate { "activate" } else { "revoke" },
        payload,
    )? {
        return Ok(Err(Error::Conflict));
    }
    let state = if activate {
        State::Available
    } else {
        State::Revoked
    };
    if key.epoch == 0 {
        revoke_legacy(conn, key, owner, local_user)?;
    }
    conn.execute("UPDATE call_epoch_envelopes SET state = ?6, payload = CASE WHEN ?6 = 'revoked' THEN NULL ELSE payload END
        WHERE owner = ?1 AND call_id = ?2 AND recipient = ?3 AND user_id = ?4 AND epoch = ?5",
        params![key.call_id.owner_authority, key.call_id.id.to_string(), key.recipient.authority,
            key.recipient.user_id as i64, key.epoch as i64, if activate { "available" } else { "revoked" }])?;
    Ok(Ok(Delivery {
        state,
        envelope: None,
    }))
}

fn revoke_legacy(
    conn: &Connection,
    key: &Key,
    owner: i64,
    local_user: i64,
) -> Result<(), StorageError> {
    // Legacy wire input allowed all UUID spellings accepted by the parser.
    // Compare parsed UUIDs so noncanonical historical rows are erased too.
    let mut statement = conn.prepare(
        "SELECT call_id FROM call_envelopes WHERE recipient_id = ?1 AND owner_omikron_id = ?2",
    )?;
    let ids = statement
        .query_map(params![local_user, owner], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for id in ids {
        if Uuid::parse_str(&id).ok() == Some(key.call_id.id) {
            conn.execute("DELETE FROM call_envelopes WHERE recipient_id = ?1 AND owner_omikron_id = ?2 AND call_id = ?3",
                params![local_user, owner, id])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
