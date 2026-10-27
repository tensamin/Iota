//! Durable, immutable recipient-envelope evidence. Callers must authenticate the
//! original sealed operation before staging or importing an escrow.
use super::{db, e2ee_storage, relay_work, sync};
use crate::storage_error::StorageError;
use iota_identity::relay_protocol::{ConversationPair, Principal};
use iota_identity::{AuthorityId, LocalUserId, PrincipalId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = include_str!("chat_secret_recovery/schema.sql");
pub mod initial_proposals;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappingNamespace {
    pub chat_id: String,
    pub secret_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OriginalRecipientId {
    Principal(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayFormat {
    NativeMtpSealedV1,
    TauSignedRelayV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientEnvelope {
    pub owner: PrincipalId,
    pub recipient_id: OriginalRecipientId,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escrow {
    pub first: PrincipalId,
    pub second: PrincipalId,
    pub version: i64,
    pub namespace: WrappingNamespace,
    pub wrapping_scheme: String,
    pub signer: PrincipalId,
    pub message_id: String,
    pub original_frame: Vec<u8>,
    pub original_type_map_version: String,
    pub original_type_map_fingerprint: String,
    pub format: RelayFormat,
    pub operation_digest: Vec<u8>,
    pub envelopes: [RecipientEnvelope; 2],
    pub created_at: i64,
}

fn invalid() -> StorageError {
    StorageError::InvalidRelayPayload("chat secret recovery evidence")
}

/// Canonical JSON global key, never a database-local principal handle.
pub fn principal_key(principal: &PrincipalId) -> Result<String, StorageError> {
    let principal = Principal::try_from(principal).map_err(|_| invalid())?;
    serde_json::to_string(&principal).map_err(|_| invalid())
}

pub fn sorted_pair(
    first: &PrincipalId,
    second: &PrincipalId,
) -> Result<[PrincipalId; 2], StorageError> {
    let pair = protocol_pair(first, second)?;
    Ok([
        PrincipalId::try_from(pair.first).map_err(|_| invalid())?,
        PrincipalId::try_from(pair.second).map_err(|_| invalid())?,
    ])
}

fn protocol_pair(
    first: &PrincipalId,
    second: &PrincipalId,
) -> Result<ConversationPair, StorageError> {
    ConversationPair::new(
        Principal::try_from(first).map_err(|_| invalid())?,
        Principal::try_from(second).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())
}

/// Matches Tau's global principal namespace across independent SQLite databases.
pub fn canonical_chat_id(
    first: &PrincipalId,
    second: &PrincipalId,
) -> Result<String, StorageError> {
    protocol_pair(first, second)?
        .chat_id()
        .map_err(|_| invalid())
}

/// The format tag prevents interpreting a native sealed frame as Tau signed JSON.
pub fn operation_digest(format: RelayFormat, original_frame: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(match format {
        RelayFormat::NativeMtpSealedV1 => b"mtp-sealed-v1\0".as_slice(),
        RelayFormat::TauSignedRelayV1 => b"tau-signed-relay-v1\0".as_slice(),
    });
    digest.update(original_frame);
    digest.finalize().to_vec()
}

impl Escrow {
    pub fn validate(&self) -> Result<(), StorageError> {
        if iota_identity::relay_protocol::dictionary_fingerprint(&self.original_type_map_version)
            .ok()
            .as_deref()
            != Some(self.original_type_map_fingerprint.as_str())
        {
            return Err(invalid());
        }
        let version_valid = self
            .original_type_map_version
            .split_once('.')
            .and_then(|(major, minor)| {
                Some((major.parse::<u16>().ok()?, minor.parse::<u16>().ok()?))
            })
            .is_some_and(|(major, minor)| {
                self.original_type_map_version == format!("{major}.{minor}")
            });
        if sorted_pair(&self.first, &self.second)? != [self.first.clone(), self.second.clone()]
            || self.version <= 0
            || self.namespace.chat_id.is_empty()
            || self.namespace.secret_id.is_empty()
            || self.wrapping_scheme.is_empty()
            || self.original_frame.is_empty()
            || self.original_type_map_version.len() > 11
            || !version_valid
            || self.message_id.is_empty()
            || self.message_id.len() > 256
            || (self.signer != self.first && self.signer != self.second)
            || self.operation_digest != operation_digest(self.format, &self.original_frame)
            || self.envelopes[0].owner != self.first
            || self.envelopes[1].owner != self.second
        {
            return Err(invalid());
        }
        if self.namespace.chat_id != canonical_chat_id(&self.first, &self.second)?
            || self.namespace.secret_id
                != e2ee_storage::principal_secret_id(&self.namespace.chat_id)
        {
            return Err(invalid());
        }
        for envelope in &self.envelopes {
            if envelope.encrypted_secret.is_empty() || envelope.kem_ciphertext.is_empty() {
                return Err(invalid());
            }
            match &envelope.recipient_id {
                OriginalRecipientId::Principal(value)
                    if *value == principal_key(&envelope.owner)? => {}
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }
}

fn check_fences(connection: &Connection, first: &str, second: &str) -> Result<(), StorageError> {
    let fenced: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM chat_secret_erasure_fences WHERE principal IN (?1,?2))",
        params![first, second],
        |row| row.get(0),
    )?;
    if fenced {
        return Err(StorageError::RelayOwnerUnavailable);
    }
    Ok(())
}

/// Stages both original recipient copies atomically. Exact retries are idempotent.
/// Conflicting metadata or provenance never overwrites an existing epoch.
pub fn stage_escrow_in_tx(tx: &Transaction<'_>, escrow: &Escrow) -> Result<(), StorageError> {
    escrow.validate()?;
    let first = principal_key(&escrow.first)?;
    let second = principal_key(&escrow.second)?;
    check_fences(tx, &first, &second)?;
    let bytes = serde_json::to_vec(escrow).map_err(|_| invalid())?;
    let evidence_digest = Sha256::digest(&bytes).to_vec();
    let marker:Option<Vec<u8>>=tx.query_row("SELECT evidence_digest FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2 AND version=?3",params![first,second,escrow.version],|row| row.get(0)).optional()?;
    if marker
        .as_ref()
        .is_some_and(|digest| *digest != evidence_digest)
    {
        return Err(StorageError::ChatSecretConflict);
    }
    let existing: Option<Vec<u8>> = tx.query_row("SELECT evidence FROM chat_secret_escrows WHERE first_principal=?1 AND second_principal=?2 AND version=?3", params![first, second, escrow.version], |row| row.get(0)).optional()?;
    if existing.as_ref().is_some_and(|existing| *existing != bytes) {
        return Err(StorageError::ChatSecretConflict);
    }
    tx.execute("INSERT INTO chat_secret_epochs(first_principal,second_principal,version,evidence_digest,state) VALUES(?1,?2,?3,?4,'pending') ON CONFLICT(first_principal,second_principal,version) DO NOTHING",params![first,second,escrow.version,evidence_digest])?;
    if existing.is_some() {
        return Ok(());
    }
    tx.execute("INSERT INTO chat_secret_escrows(first_principal,second_principal,version,evidence,state,signer,message_id) VALUES(?1,?2,?3,?4,'pending',?5,?6)", params![first, second, escrow.version, bytes, principal_key(&escrow.signer)?, escrow.message_id])?;
    Ok(())
}

/// Only an accepted destination transaction or exact authenticated downstream
/// acknowledgement may promote pending evidence. Promotion inserts no owner row.
pub fn commit_escrow_in_tx(tx: &Transaction<'_>, escrow: &Escrow) -> Result<(), StorageError> {
    stage_escrow_in_tx(tx, escrow)?;
    tx.execute("UPDATE chat_secret_escrows SET state='committed' WHERE first_principal=?1 AND second_principal=?2 AND version=?3 AND state='pending'", params![principal_key(&escrow.first)?, principal_key(&escrow.second)?, escrow.version])?;
    tx.execute("UPDATE chat_secret_epochs SET state='committed' WHERE first_principal=?1 AND second_principal=?2 AND version=?3 AND state='pending'", params![principal_key(&escrow.first)?, principal_key(&escrow.second)?, escrow.version])?;
    Ok(())
}

/// Call only after the exact immutable downstream delivery and authenticated
/// terminal rejection have been verified. A losing pending proposal is not
/// authority over a peer's different, historically committed original epoch.
/// Its signed frame remains quarantined in relay storage for diagnostics.
pub fn quarantine_pending_escrow_in_tx(
    tx: &Transaction<'_>,
    signer: iota_identity::PrincipalHandle,
    message_id: &str,
) -> Result<(), StorageError> {
    let (authority, user_id): (String, i64) = tx.query_row(
        "SELECT authority_id,remote_user_id FROM principals WHERE principal_pk=?1",
        [signer.0],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let principal = PrincipalId {
        authority: AuthorityId::new(authority).map_err(|_| invalid())?,
        user_id: u64::try_from(user_id).map_err(|_| invalid())?,
    };
    let signer_key = principal_key(&principal)?;
    let bytes:Option<Vec<u8>>=tx.query_row("SELECT evidence FROM chat_secret_escrows WHERE signer=?1 AND message_id=?2 AND state='pending'",params![signer_key,message_id],|row| row.get(0)).optional()?;
    let Some(bytes) = bytes else {
        return Ok(());
    };
    let escrow: Escrow = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    escrow.validate()?;
    if escrow.signer != principal || escrow.message_id != message_id {
        return Err(StorageError::PendingRelayConflict);
    }
    let digest = Sha256::digest(&bytes).to_vec();
    let first = principal_key(&escrow.first)?;
    let second = principal_key(&escrow.second)?;
    let marker:Option<(Vec<u8>,String)>=tx.query_row("SELECT evidence_digest,state FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2 AND version=?3",params![first,second,escrow.version],|row| Ok((row.get(0)?,row.get(1)?))).optional()?;
    if marker.as_ref().is_some_and(|(stored, _)| *stored != digest) {
        return Err(StorageError::ChatSecretConflict);
    }
    let old_digest:Option<Vec<u8>>=tx.query_row("SELECT operation_digest FROM chat_secret_rejected_proposals WHERE signer=?1 AND message_id=?2",params![signer_key,message_id],|row| row.get(0)).optional()?;
    if old_digest.is_some_and(|old| old != escrow.operation_digest) {
        return Err(StorageError::PendingRelayConflict);
    }
    tx.execute("INSERT INTO chat_secret_rejected_proposals(signer,message_id,first_principal,second_principal,operation_digest,rejected_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(signer,message_id) DO NOTHING",params![signer_key,message_id,first,second,escrow.operation_digest,sync::now_millis()])?;
    tx.execute("DELETE FROM chat_secret_escrows WHERE signer=?1 AND message_id=?2 AND evidence=?3 AND state='pending'",params![signer_key,message_id,bytes])?;
    tx.execute("DELETE FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2 AND version=?3 AND evidence_digest=?4 AND state='pending'",params![first,second,escrow.version,digest])?;
    Ok(())
}

pub fn escrow_for_recovery_on(
    connection: &Connection,
    first: &PrincipalId,
    second: &PrincipalId,
    owner: &PrincipalId,
    version: Option<i64>,
) -> Result<Option<Escrow>, StorageError> {
    let pair = sorted_pair(first, second)?;
    if owner != &pair[0] && owner != &pair[1] {
        return Err(StorageError::MessageUnauthorized);
    }
    let first = principal_key(&pair[0])?;
    let second = principal_key(&pair[1])?;
    check_fences(connection, &first, &second)?;
    if version.is_some_and(|version| version <= 0) {
        return Err(invalid());
    }
    let version=match version {
        Some(version)=>Some(version),
        None=>connection.query_row("SELECT MAX(version) FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2 AND state='committed'",params![first,second],|row| row.get(0))?,
    };
    let bytes: Option<(Vec<u8>,i64)> = connection.query_row("SELECT evidence,version FROM chat_secret_escrows WHERE first_principal=?1 AND second_principal=?2 AND (?3 IS NULL OR version=?3) AND state='committed' ORDER BY version DESC LIMIT 1", params![first, second, version], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
    bytes
        .map(|(bytes,stored_version)| {
            let escrow: Escrow = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            escrow.validate()?;
            if escrow.first!=pair[0] || escrow.second!=pair[1] || escrow.version!=stored_version {return Err(StorageError::ChatSecretConflict);}
            let marker:Option<(Vec<u8>,String)>=connection.query_row("SELECT evidence_digest,state FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2 AND version=?3",params![first,second,stored_version],|row| Ok((row.get(0)?,row.get(1)?))).optional()?;
            if marker!=Some((Sha256::digest(&bytes).to_vec(),"committed".into())) {return Err(StorageError::ChatSecretConflict);}
            Ok(escrow)
        })
        .transpose()
}

/// Returns committed evidence only. Pending or quarantined operations are never recovery authority.
pub fn escrow_for_recovery(
    first: &PrincipalId,
    second: &PrincipalId,
    owner: &PrincipalId,
    version: Option<i64>,
) -> Result<Option<Escrow>, StorageError> {
    db::with_db(|connection| escrow_for_recovery_on(connection, first, second, owner, version))
}

#[derive(Clone, Debug, Default)]
pub struct PairAcceptance {
    pub latest_committed_version: Option<i64>,
    pub has_pending: bool,
}

/// Positive acceptance evidence survives a lost escrow row. Neither empty field
/// proves a pair was never accepted, especially for pre-v66 databases. Callers
/// must not use absence as authorization to generate a replacement initial key.
pub fn pair_acceptance_on(
    connection: &Connection,
    first: &PrincipalId,
    second: &PrincipalId,
) -> Result<PairAcceptance, StorageError> {
    let pair = sorted_pair(first, second)?;
    let first = principal_key(&pair[0])?;
    let second = principal_key(&pair[1])?;
    check_fences(connection, &first, &second)?;
    Ok(connection.query_row("SELECT MAX(CASE WHEN state='committed' THEN version END),COALESCE(MAX(state='pending'),0) FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2",params![first,second],|row| Ok(PairAcceptance{latest_committed_version:row.get(0)?,has_pending:row.get(1)?}))?)
}

pub fn pending_initial_proposal_on(
    connection: &Connection,
    first: &PrincipalId,
    second: &PrincipalId,
) -> Result<bool, StorageError> {
    let pair = sorted_pair(first, second)?;
    Ok(connection.query_row("SELECT EXISTS(SELECT 1 FROM initial_secret_proposals WHERE first_principal=?1 AND second_principal=?2 AND state IN ('awaiting_peer_proof','verifying'))", params![principal_key(&pair[0])?, principal_key(&pair[1])?], |row| row.get(0))?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochState {
    Pending,
    Committed,
}

pub fn epoch_state_on(
    connection: &Connection,
    first: &PrincipalId,
    second: &PrincipalId,
    epoch: i64,
) -> Result<Option<EpochState>, StorageError> {
    if epoch <= 0 {
        return Err(invalid());
    }
    let pair = sorted_pair(first, second)?;
    let state: Option<String> = connection.query_row("SELECT state FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2 AND version=?3", params![principal_key(&pair[0])?, principal_key(&pair[1])?, epoch], |row| row.get(0)).optional()?;
    match state.as_deref() {
        None => Ok(None),
        Some("pending") => Ok(Some(EpochState::Pending)),
        Some("committed") => Ok(Some(EpochState::Committed)),
        Some(_) => Err(invalid()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializationState {
    Empty,
    ExactPendingProposal,
    Accepted,
    Conflict,
}

// Force both equality keys of the migration-built index. No JSON work or
// history-dependent filtering may precede the 501-row availability bound.
const INITIALIZATION_INBOX_SQL: &str =
    "SELECT signer_principal,message_id,state,prepared_operation,initial_secret_ambiguous
    FROM relay_inbox INDEXED BY relay_inbox_initial_secret
    WHERE signer_principal IN (?1,?2) AND initial_secret_chat_id IN ('',?3)
        AND prepared_operation IS NOT NULL AND state!='rejected'
    LIMIT 501";

/// Initialization-only absence check. Read/recovery paths must never translate
/// Empty into ErrorNotSet or serve an ExactPendingProposal as accepted evidence.
/// Run again inside the acceptance transaction after the authenticated peer
/// handshake, with current canonical homes and owner authorization rechecked.
pub fn initialization_state_on(
    connection: &Connection,
    first: &PrincipalId,
    second: &PrincipalId,
    proposal_digest: Option<&[u8]>,
) -> Result<InitializationState, StorageError> {
    if proposal_digest.is_some_and(|digest| digest.len() != 32) {
        return Err(invalid());
    }
    let pair = sorted_pair(first, second)?;
    let first_key = principal_key(&pair[0])?;
    let second_key = principal_key(&pair[1])?;
    check_fences(connection, &first_key, &second_key)?;
    let acceptance = pair_acceptance_on(connection, &pair[0], &pair[1])?;
    if acceptance.latest_committed_version.is_some() {
        return Ok(InitializationState::Accepted);
    }
    let chat_id = canonical_chat_id(&pair[0], &pair[1])?;
    let owner_row: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM chat_secrets WHERE chat_id=?1 AND secret_id=?2)",
        params![chat_id, e2ee_storage::principal_secret_id(&chat_id)],
        |row| row.get(0),
    )?;
    if owner_row {
        return Ok(InitializationState::Accepted);
    }
    let mut pending = false;
    let mut conflict = false;
    let proposal: Option<Vec<u8>> = connection.query_row(
        "SELECT operation_digest FROM initial_secret_proposals WHERE first_principal=?1 AND second_principal=?2 AND state IN ('awaiting_peer_proof','verifying')",
        params![first_key, second_key], |row| row.get(0),
    ).optional()?;
    if let Some(digest) = proposal {
        pending = true;
        conflict = proposal_digest != Some(digest.as_slice());
    }
    let mut statement=connection.prepare("SELECT evidence,state FROM chat_secret_escrows WHERE first_principal=?1 AND second_principal=?2 ORDER BY version")?;
    let rows = statement
        .query_map(params![first_key, second_key], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (bytes, state) in rows {
        if state == "committed" {
            return Ok(InitializationState::Accepted);
        }
        let evidence: Escrow = match serde_json::from_slice(&bytes) {
            Ok(evidence) => evidence,
            Err(_) => return Ok(InitializationState::Conflict),
        };
        if evidence.validate().is_err() || evidence.first != pair[0] || evidence.second != pair[1] {
            return Ok(InitializationState::Conflict);
        }
        pending = true;
        conflict |=
            evidence.version != 1 || proposal_digest != Some(evidence.operation_digest.as_slice());
    }
    if acceptance.has_pending && !pending {
        conflict = true;
    }

    let handles = {
        let mut statement=connection.prepare("SELECT principal_pk FROM principals WHERE (authority_id=?1 AND remote_user_id=?2) OR (authority_id=?3 AND remote_user_id=?4) ORDER BY principal_pk")?;
        statement
            .query_map(
                params![
                    pair[0].authority.as_str(),
                    pair[0].user_id as i64,
                    pair[1].authority.as_str(),
                    pair[1].user_id as i64
                ],
                |row| row.get::<_, i64>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    if handles.len() != 2 {
        return Ok(InitializationState::Conflict);
    }
    let mut statement = connection.prepare(INITIALIZATION_INBOX_SQL)?;
    let rows = statement
        .query_map(params![handles[0], handles[1], chat_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, bool>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 500 {
        return Err(StorageError::Other(
            "initial secret evidence scan exceeds limit".into(),
        ));
    }
    for (signer, message_id, state, bytes, ambiguous) in rows {
        if ambiguous {
            conflict = true;
            continue;
        }
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                conflict = true;
                continue;
            }
        };
        let stored = if value.get("schema_version").is_some() {
            if value["schema_version"] != "1" {
                conflict = true;
                continue;
            }
            &value["operation"]
        } else {
            &value
        };
        if stored.pointer("/operation/SetChatSecret").is_none() {
            conflict = true;
            continue;
        }
        let (Ok(signer_id), Ok(recipient_id)) = (
            serde_json::from_value::<PrincipalId>(stored["signer_identity"].clone()),
            serde_json::from_value::<PrincipalId>(stored["recipient_identity"].clone()),
        ) else {
            conflict = true;
            continue;
        };
        if sorted_pair(&signer_id, &recipient_id).ok().as_ref() != Some(&pair) {
            continue;
        }
        let remote = stored.pointer("/delivery/Remote").is_some();
        if matches!(state.as_str(), "applied" | "queued" | "delivered") {
            if !remote || state == "delivered" {
                return Ok(InitializationState::Accepted);
            }
            let finalized:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM relay_deferred_secrets WHERE signer_principal=?1 AND message_id=?2 AND completed_at IS NOT NULL)",params![signer,message_id],|row| row.get(0))?;
            if finalized {
                return Ok(InitializationState::Accepted);
            }
        }
        let rejected:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM chat_secret_rejected_proposals WHERE signer=?1 AND message_id=?2)",params![principal_key(&signer_id)?,message_id],|row| row.get(0))?;
        if remote && rejected {
            continue;
        }
        // An unfinalized origin operation is a proposal, not acceptance.
        pending = true;
        let digest = stored
            .pointer("/secret_escrow/operation_digest")
            .and_then(|digest| serde_json::from_value::<Vec<u8>>(digest.clone()).ok());
        conflict |= stored
            .pointer("/operation/SetChatSecret/version")
            .and_then(serde_json::Value::as_i64)
            != Some(1)
            || digest.as_deref().is_none()
            || digest.as_deref() != proposal_digest;
    }
    Ok(if conflict {
        InitializationState::Conflict
    } else if pending {
        InitializationState::ExactPendingProposal
    } else {
        InitializationState::Empty
    })
}

pub fn canonical_owner_on(
    connection: &Connection,
    owner: LocalUserId,
) -> Result<PrincipalId, StorageError> {
    let (authority, user_id): (String, i64) = connection.query_row("SELECT p.authority_id,p.remote_user_id FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=?1", [owner.0], |row| Ok((row.get(0)?,row.get(1)?))).optional()?.ok_or(StorageError::RelayOwnerUnavailable)?;
    let principal = PrincipalId {
        authority: AuthorityId::new(&authority).map_err(|_| invalid())?,
        user_id: u64::try_from(user_id).map_err(|_| invalid())?,
    };
    principal_key(&principal)?;
    Ok(principal)
}

pub fn canonical_owner(owner: LocalUserId) -> Result<PrincipalId, StorageError> {
    db::with_db(|connection| canonical_owner_on(connection, owner))
}

fn verify_local_owner(
    tx: &Transaction<'_>,
    owner: LocalUserId,
) -> Result<PrincipalId, StorageError> {
    let handle = tx
        .query_row(
            "SELECT principal_handle FROM hosted_principals WHERE local_user_id=?1",
            [owner.0],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(StorageError::RelayOwnerUnavailable)?;
    relay_work::verify_owner_in_tx(tx, owner.0, iota_identity::PrincipalHandle(handle))?;
    canonical_owner_on(tx, owner)
}

/// Restores only an exact committed recipient envelope. Unlike ordinary writes,
/// historical restoration may fill a deleted epoch without synthesizing predecessors.
/// Importing a peer response requires verifying its original frame first, then
/// calling commit_escrow_in_tx in this same transaction.
pub fn recover_owner_envelope_in_tx(
    tx: &Transaction<'_>,
    owner: LocalUserId,
    escrow: &Escrow,
) -> Result<e2ee_storage::StoredChatSecret, StorageError> {
    let principal = verify_local_owner(tx, owner)?;
    let committed = escrow_for_recovery_on(
        tx,
        &escrow.first,
        &escrow.second,
        &principal,
        Some(escrow.version),
    )?
    .ok_or(StorageError::MissingRelayDependency)?;
    if committed != *escrow {
        return Err(StorageError::ChatSecretConflict);
    }
    let envelope = escrow
        .envelopes
        .iter()
        .find(|copy| copy.owner == principal)
        .ok_or(StorageError::MessageUnauthorized)?;
    let chat_id = canonical_chat_id(&escrow.first, &escrow.second)?;
    let record = e2ee_storage::StoredChatSecret {
        user_id: owner.0.to_string(),
        secret_id: e2ee_storage::principal_secret_id(&chat_id),
        chat_id,
        version: escrow.version,
        encrypted_secret: envelope.encrypted_secret.clone(),
        kem_ciphertext: envelope.kem_ciphertext.clone(),
        wrapping_scheme: escrow.wrapping_scheme.clone(),
        created_at: escrow.created_at,
        updated_at: sync::now_millis(),
    };
    let existing = e2ee_storage::get_chat_secret_on(
        tx,
        &e2ee_storage::ChatSecretQuery {
            user_id: record.user_id.clone(),
            chat_id: record.chat_id.clone(),
            secret_id: Some(record.secret_id.clone()),
            version: Some(record.version),
        },
    )?;
    if let Some(existing) = existing {
        if existing.encrypted_secret != record.encrypted_secret
            || existing.kem_ciphertext != record.kem_ciphertext
            || existing.wrapping_scheme != record.wrapping_scheme
        {
            return Err(StorageError::ChatSecretConflict);
        }
    } else {
        tx.execute("INSERT INTO chat_secrets(user_id,chat_id,secret_id,version,encrypted_secret,kem_ciphertext,wrapping_scheme,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![record.user_id, record.chat_id, record.secret_id, record.version, record.encrypted_secret, record.kem_ciphertext, record.wrapping_scheme, record.created_at, record.updated_at])?;
        // Restoration is a new availability transition, not an accepted replay.
        // Advance the durable cursor so already-connected sessions see it too.
        tx.execute("DELETE FROM chat_secret_outbox WHERE storage_owner=?1 AND owner_principal=?2 AND chat_id=?3 AND version=?4",params![owner.0,principal_key(&principal)?,record.chat_id,record.version])?;
    }
    enqueue_secret_available_in_tx(tx, owner, escrow)?;
    Ok(record)
}

#[derive(Clone, Debug)]
pub struct SecretAvailable {
    pub id: i64,
    pub owner: LocalUserId,
    pub principal: PrincipalId,
    pub peer: PrincipalId,
    pub namespace: WrappingNamespace,
    pub chat_id: String,
    pub secret_id: String,
    pub version: i64,
}

/// Durable dedup survives dispatch acknowledgement. Events contain no secret bytes.
pub fn enqueue_secret_available_in_tx(
    tx: &Transaction<'_>,
    owner: LocalUserId,
    escrow: &Escrow,
) -> Result<(), StorageError> {
    let principal = verify_local_owner(tx, owner)?;
    let committed = escrow_for_recovery_on(
        tx,
        &escrow.first,
        &escrow.second,
        &principal,
        Some(escrow.version),
    )?
    .ok_or(StorageError::MissingRelayDependency)?;
    if committed != *escrow {
        return Err(StorageError::ChatSecretConflict);
    }
    let chat_id = canonical_chat_id(&escrow.first, &escrow.second)?;
    let peer = if principal == escrow.first {
        &escrow.second
    } else {
        &escrow.first
    };
    let envelope = escrow
        .envelopes
        .iter()
        .find(|copy| copy.owner == principal)
        .ok_or(StorageError::MessageUnauthorized)?;
    let secret = e2ee_storage::get_chat_secret_on(
        tx,
        &e2ee_storage::ChatSecretQuery {
            user_id: owner.0.to_string(),
            chat_id: chat_id.clone(),
            secret_id: Some(e2ee_storage::principal_secret_id(&chat_id)),
            version: Some(escrow.version),
        },
    )?
    .ok_or(StorageError::MissingRelayDependency)?;
    if secret.encrypted_secret != envelope.encrypted_secret
        || secret.kem_ciphertext != envelope.kem_ciphertext
        || secret.wrapping_scheme != escrow.wrapping_scheme
    {
        return Err(StorageError::ChatSecretConflict);
    }
    tx.execute("INSERT INTO chat_secret_outbox(storage_owner,owner_principal,chat_id,secret_id,version,peer_principal,wrapping_chat_id,wrapping_secret_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(storage_owner,owner_principal,chat_id,version) DO NOTHING", params![owner.0, principal_key(&principal)?, chat_id, e2ee_storage::principal_secret_id(&chat_id), escrow.version,principal_key(peer)?,escrow.namespace.chat_id,escrow.namespace.secret_id])?;
    Ok(())
}

pub fn pending_notifications(
    owner: LocalUserId,
    limit: usize,
) -> Result<Vec<SecretAvailable>, StorageError> {
    notifications(owner, 0, limit, true)
}

/// Per-connection cursor, independent of global dispatch acknowledgement. Each
/// active session can consume the same event. Reconnects use available_envelopes.
pub fn events_for_owner_after(
    owner: LocalUserId,
    after: i64,
    limit: usize,
) -> Result<Vec<SecretAvailable>, StorageError> {
    notifications(owner, after, limit, false)
}

fn notifications(
    owner: LocalUserId,
    after: i64,
    limit: usize,
    pending_only: bool,
) -> Result<Vec<SecretAvailable>, StorageError> {
    db::with_db(|connection| {
        let principal = canonical_owner_on(connection, owner)?;
        let mut statement = connection.prepare("SELECT id,chat_id,secret_id,version,peer_principal,wrapping_chat_id,wrapping_secret_id FROM chat_secret_outbox WHERE storage_owner=?1 AND owner_principal=?2 AND id>?4 AND (?5=0 OR dispatched_at IS NULL) ORDER BY id LIMIT ?3")?;
        let rows = statement
            .query_map(
                params![
                    owner.0,
                    principal_key(&principal)?,
                    limit.clamp(1, 500) as i64,
                    after,
                    pending_only
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(id, chat_id, secret_id, version, peer, wrapping_chat_id, wrapping_secret_id)| {
                    Ok(SecretAvailable {
                        id,
                        owner,
                        principal: principal.clone(),
                        peer: serde_json::from_str(&peer).map_err(|_| invalid())?,
                        namespace: WrappingNamespace {
                            chat_id: wrapping_chat_id,
                            secret_id: wrapping_secret_id,
                        },
                        chat_id,
                        secret_id,
                        version,
                    })
                },
            )
            .collect()
    })
}

pub fn acknowledge_notification(owner: LocalUserId, id: i64) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        let principal = verify_local_owner(tx, owner)?;
        Ok(tx.execute("UPDATE chat_secret_outbox SET dispatched_at=?4 WHERE id=?1 AND storage_owner=?2 AND owner_principal=?3 AND dispatched_at IS NULL", params![id,owner.0,principal_key(&principal)?,sync::now_millis()])? == 1)
    })
}

#[derive(Clone, Debug)]
pub struct AvailableEnvelope {
    pub escrow: Escrow,
    pub envelope: RecipientEnvelope,
    pub secret: e2ee_storage::StoredChatSecret,
}

/// Bounded committed snapshot. Missing owner rows remain unavailable until the
/// recovery coordinator restores them; escrow alone is not a readable owner row.
pub fn available_envelopes(
    owner: LocalUserId,
    limit: usize,
) -> Result<Vec<AvailableEnvelope>, StorageError> {
    db::with_db(|connection| {
        let tx = connection.unchecked_transaction()?;
        let principal = verify_local_owner(&tx, owner)?;
        let key = principal_key(&principal)?;
        let mut statement = tx.prepare("SELECT evidence FROM chat_secret_escrows WHERE state='committed' AND (first_principal=?1 OR second_principal=?1) ORDER BY first_principal,second_principal,version LIMIT ?2")?;
        let rows = statement
            .query_map(params![key, limit.clamp(1, 500) as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut result = Vec::new();
        for bytes in rows {
            let escrow: Escrow = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            escrow.validate()?;
            if escrow_for_recovery_on(
                &tx,
                &escrow.first,
                &escrow.second,
                &principal,
                Some(escrow.version),
            )?
            .as_ref()
                != Some(&escrow)
            {
                return Err(StorageError::ChatSecretConflict);
            }
            check_fences(
                &tx,
                &principal_key(&escrow.first)?,
                &principal_key(&escrow.second)?,
            )?;
            let chat_id = canonical_chat_id(&escrow.first, &escrow.second)?;
            if let Some(secret) = e2ee_storage::get_chat_secret_on(
                &tx,
                &e2ee_storage::ChatSecretQuery {
                    user_id: owner.0.to_string(),
                    secret_id: Some(e2ee_storage::principal_secret_id(&chat_id)),
                    chat_id,
                    version: Some(escrow.version),
                },
            )? {
                let envelope = escrow
                    .envelopes
                    .iter()
                    .find(|copy| copy.owner == principal)
                    .ok_or_else(invalid)?
                    .clone();
                if secret.encrypted_secret != envelope.encrypted_secret
                    || secret.kem_ciphertext != envelope.kem_ciphertext
                    || secret.wrapping_scheme != escrow.wrapping_scheme
                {
                    return Err(StorageError::ChatSecretConflict);
                }
                result.push(AvailableEnvelope {
                    escrow,
                    envelope,
                    secret,
                });
            }
        }
        Ok(result)
    })
}

static CHANGES: once_cell::sync::Lazy<tokio::sync::watch::Sender<u64>> =
    once_cell::sync::Lazy::new(|| tokio::sync::watch::channel(0).0);
pub fn subscribe_changes() -> tokio::sync::watch::Receiver<u64> {
    CHANGES.subscribe()
}
/// Call only after the transaction commits. Database-backed outbox remains authoritative.
pub fn notify_change() {
    CHANGES.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
}

#[derive(Clone, Debug)]
pub struct RecoveryJob {
    pub id: i64,
    pub owner: LocalUserId,
    pub first: PrincipalId,
    pub second: PrincipalId,
    pub version: Option<i64>,
    pub nonce: Vec<u8>,
    pub attempts: i64,
    pub next_at: i64,
}

pub fn enqueue_recovery_in_tx(
    tx: &Transaction<'_>,
    owner: LocalUserId,
    first: &PrincipalId,
    second: &PrincipalId,
    version: Option<i64>,
    nonce: &[u8],
    now: i64,
) -> Result<i64, StorageError> {
    let principal = verify_local_owner(tx, owner)?;
    let pair = sorted_pair(first, second)?;
    if !pair.contains(&principal) || version.is_some_and(|v| v <= 0) || nonce.len() != 32 {
        return Err(invalid());
    }
    let first = principal_key(&pair[0])?;
    let second = principal_key(&pair[1])?;
    check_fences(tx, &first, &second)?;
    tx.execute("INSERT INTO chat_secret_recovery_jobs(storage_owner,owner_principal,first_principal,second_principal,version,nonce,next_at) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(storage_owner,owner_principal,first_principal,second_principal,version) DO UPDATE SET nonce=excluded.nonce,next_at=excluded.next_at,attempts=0,last_error=NULL,done_at=NULL WHERE chat_secret_recovery_jobs.done_at IS NOT NULL",params![owner.0,principal_key(&principal)?,first,second,version.unwrap_or(0),nonce,now])?;
    Ok(tx.query_row("SELECT id FROM chat_secret_recovery_jobs WHERE storage_owner=?1 AND owner_principal=?2 AND first_principal=?3 AND second_principal=?4 AND version=?5",params![owner.0,principal_key(&principal)?,first,second,version.unwrap_or(0)],|row| row.get(0))?)
}

pub fn recovery_jobs(limit: usize) -> Result<Vec<RecoveryJob>, StorageError> {
    db::with_db(|connection| {
        let mut statement=connection.prepare("SELECT id,storage_owner,first_principal,second_principal,version,nonce,attempts,next_at FROM chat_secret_recovery_jobs WHERE done_at IS NULL AND next_at<=?1 ORDER BY next_at,id LIMIT ?2")?;
        let rows = statement
            .query_map(
                params![sync::now_millis(), limit.clamp(1, 500) as i64],
                recovery_job_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[derive(Debug)]
pub struct RecoveryHealth {
    pub queue_depth: i64,
    pub oldest_due_age_ms: Option<i64>,
    pub deferred_initial_proposals: i64,
    pub rejected_initial_proposals: i64,
    pub pending_notifications: i64,
}

pub fn recovery_health() -> Result<RecoveryHealth, StorageError> {
    db::with_db(|connection| {
        let tx = connection.unchecked_transaction()?;
        let now = sync::now_millis();
        let (queue_depth, oldest): (i64, Option<i64>) = tx.query_row(
            "SELECT count(*),MIN(CASE WHEN next_at<=?1 THEN next_at END) FROM chat_secret_recovery_jobs WHERE done_at IS NULL", [now],
            |row| Ok((row.get(0)?,row.get(1)?)))?;
        let (deferred_initial_proposals,rejected_initial_proposals) = tx.query_row(
            "SELECT COALESCE(SUM(state IN ('awaiting_peer_proof','verifying')),0),COALESCE(SUM(state='rejected'),0) FROM initial_secret_proposals", [],
            |row| Ok((row.get(0)?,row.get(1)?)))?;
        Ok(RecoveryHealth {
            queue_depth,
            oldest_due_age_ms: oldest.map(|oldest| now.saturating_sub(oldest)),
            deferred_initial_proposals,
            rejected_initial_proposals,
            pending_notifications: tx.query_row(
                "SELECT count(*) FROM chat_secret_outbox WHERE dispatched_at IS NULL",
                [],
                |row| row.get(0),
            )?,
        })
    })
}

fn recovery_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecoveryJob> {
    let principal = |column| {
        let value: String = row.get(column)?;
        serde_json::from_str(&value).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
    };
    let version: i64 = row.get(4)?;
    Ok(RecoveryJob {
        id: row.get(0)?,
        owner: LocalUserId(row.get(1)?),
        first: principal(2)?,
        second: principal(3)?,
        version: (version != 0).then_some(version),
        nonce: row.get(5)?,
        attempts: row.get(6)?,
        next_at: row.get(7)?,
    })
}

pub fn recovery_job_by_id(id: i64) -> Result<Option<RecoveryJob>, StorageError> {
    db::with_db(|connection| recovery_job_by_id_on(connection, id))
}

fn recovery_job_by_id_on(
    connection: &Connection,
    id: i64,
) -> Result<Option<RecoveryJob>, StorageError> {
    Ok(connection.query_row(
        "SELECT id,storage_owner,first_principal,second_principal,version,nonce,attempts,next_at FROM chat_secret_recovery_jobs WHERE id=?1 AND done_at IS NULL",
        [id], recovery_job_row,
    ).optional()?)
}

pub fn retry_recovery_job(
    job: &RecoveryJob,
    next_at: i64,
    error: &str,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        let principal = verify_local_owner(tx, job.owner)?;
        Ok(tx.execute("UPDATE chat_secret_recovery_jobs SET attempts=attempts+1,next_at=?4,last_error=?5 WHERE id=?1 AND nonce=?2 AND attempts=?3 AND done_at IS NULL AND attempts<9223372036854775807 AND storage_owner=?6 AND owner_principal=?7 AND next_at=?8",params![job.id,job.nonce,job.attempts,next_at,error,job.owner.0,principal_key(&principal)?,job.next_at])?==1)
    })
}

/// Reserve a due attempt across workers/processes. Cancellation or crash leaves
/// the same nonce resumable after the bounded processing deadline.
pub fn begin_recovery_attempt(job: &RecoveryJob) -> Result<Option<RecoveryJob>, StorageError> {
    db::with_immediate_transaction(|tx| {
        let principal = verify_local_owner(tx, job.owner)?;
        let now = sync::now_millis();
        let deadline = now.saturating_add(30_000);
        let changed = tx.execute("UPDATE chat_secret_recovery_jobs SET next_at=?4 WHERE id=?1 AND nonce=?2 AND attempts=?3 AND next_at=?5 AND next_at<=?6 AND done_at IS NULL AND storage_owner=?7 AND owner_principal=?8",
            params![job.id,job.nonce,job.attempts,deadline,job.next_at,now,job.owner.0,principal_key(&principal)?])?;
        Ok((changed == 1).then(|| RecoveryJob {
            next_at: deadline,
            ..job.clone()
        }))
    })
}

pub fn complete_recovery_job_in_tx(
    tx: &Transaction<'_>,
    job: &RecoveryJob,
) -> Result<bool, StorageError> {
    let principal = verify_local_owner(tx, job.owner)?;
    Ok(tx.execute("UPDATE chat_secret_recovery_jobs SET done_at=?4 WHERE id=?1 AND nonce=?2 AND attempts=?3 AND done_at IS NULL AND storage_owner=?5 AND owner_principal=?6 AND next_at=?7",params![job.id,job.nonce,job.attempts,sync::now_millis(),job.owner.0,principal_key(&principal)?,job.next_at])?==1)
}

/// Erasure is a permanent global-principal fence. Old peer proofs cannot
/// repopulate data after purge, account deletion, or local-ID reassignment.
pub fn purge_owner_in_tx(tx: &Transaction<'_>, owner: LocalUserId) -> Result<(), StorageError> {
    let principal = canonical_owner_on(tx, owner)?;
    let key = principal_key(&principal)?;
    tx.execute(
        "INSERT OR IGNORE INTO chat_secret_erasure_fences(principal,erased_at) VALUES(?1,?2)",
        params![key, sync::now_millis()],
    )?;
    tx.execute(
        "DELETE FROM chat_secret_escrows WHERE first_principal=?1 OR second_principal=?1",
        [&key],
    )?;
    tx.execute(
        "DELETE FROM chat_secret_epochs WHERE first_principal=?1 OR second_principal=?1",
        [&key],
    )?;
    tx.execute("DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=?1 OR first_principal=?2 OR second_principal=?2",params![owner.0,key])?;
    tx.execute(
        "DELETE FROM initial_secret_proposals WHERE first_principal=?1 OR second_principal=?1",
        [&key],
    )?;
    tx.execute("DELETE FROM chat_secret_outbox WHERE storage_owner=?1 OR owner_principal=?2 OR peer_principal=?2",params![owner.0,key])?;
    tx.execute("DELETE FROM chat_secret_rejected_proposals WHERE first_principal=?1 OR second_principal=?1",[key])?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
