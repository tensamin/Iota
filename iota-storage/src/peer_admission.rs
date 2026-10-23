use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iota_identity::peer_introduction::{
    PeerAdmissionReceipt, PeerChallengeResponse, PeerIntroductionLimits, PeerIntroductionRequest,
    PeerTrust, descriptor_digest,
};
use iota_identity::{IdentityError, IotaNodeId, PublicKeyBundle, SignedNodeDescriptor};
use rand::RngCore;
use rusqlite::{OptionalExtension, params};

use crate::{storage_error::StorageError, util::db};

static CHANGES: once_cell::sync::Lazy<tokio::sync::watch::Sender<u64>> =
    once_cell::sync::Lazy::new(|| tokio::sync::watch::channel(0).0);

pub fn changes() -> tokio::sync::watch::Receiver<u64> {
    CHANGES.subscribe()
}

pub(crate) fn notify_change() {
    CHANGES.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
}

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS federation_peer_challenges (
    challenge_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, descriptor_hash BLOB NOT NULL,
    nonce TEXT NOT NULL, responder_node TEXT NOT NULL, origin TEXT NOT NULL, authority_locator TEXT,
    expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_peer_challenge_expiry ON federation_peer_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_peer_challenge_origin ON federation_peer_challenges(origin,expires_at);
CREATE TABLE IF NOT EXISTS federation_peer_admissions (
    node_id TEXT PRIMARY KEY, auth_hint INTEGER NOT NULL, public_key TEXT NOT NULL,
    descriptor TEXT NOT NULL, admitted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('provisional','established','revoked')),
    descriptor_rev INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_peer_admissions_hint ON federation_peer_admissions(auth_hint,expires_at);";

fn storage(error: impl std::fmt::Display) -> IdentityError {
    IdentityError::Storage(error.to_string())
}
fn reject(reason: &str) -> StorageError {
    StorageError::Other(reason.into())
}

pub fn issue_challenge(
    descriptor: &SignedNodeDescriptor,
    responder: &IotaNodeId,
    origin: std::net::IpAddr,
    locator: Option<&iota_identity::AuthorityLocator>,
    limits: &PeerIntroductionLimits,
    now: i64,
) -> Result<PeerChallengeResponse, IdentityError> {
    descriptor.clone().verify(None, now)?;
    let digest = descriptor_digest(descriptor)?;
    let random = || {
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    };
    let challenge = PeerChallengeResponse {
        challenge_id: random(),
        nonce: random(),
        expires_at: now.saturating_add(limits.challenge_lifetime_ms),
        responder_node: responder.clone(),
    };
    db::with_immediate_transaction(|tx| {
        tx.execute("DELETE FROM federation_peer_challenges WHERE expires_at <= ?1", [now])?;
        let (total, per_origin): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(origin = ?1),0) FROM federation_peer_challenges",
            [origin.to_string()], |r| Ok((r.get(0)?,r.get(1)?)))?;
        if total as usize >= limits.max_pending_challenges || per_origin as usize >= limits.max_challenges_per_origin {
            return Err(reject("peer challenge quota exceeded"));
        }
        tx.execute("INSERT INTO federation_peer_challenges(challenge_id,node_id,descriptor_hash,nonce,responder_node,origin,expires_at,authority_locator) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![challenge.challenge_id,descriptor.descriptor.node.as_str(),digest.as_slice(),challenge.nonce,responder.as_str(),origin.to_string(),challenge.expires_at,locator.map(iota_identity::AuthorityLocator::as_str)])?;
        Ok(())
    }).map_err(storage)?;
    Ok(challenge)
}

pub fn redeem(
    request: PeerIntroductionRequest,
    limits: &PeerIntroductionLimits,
    now: i64,
) -> Result<PeerAdmissionReceipt, IdentityError> {
    let challenge = db::with_db(|db| {
        db.query_row("SELECT nonce,expires_at,responder_node FROM federation_peer_challenges WHERE challenge_id = ?1 AND consumed_at IS NULL AND expires_at > ?2",
            params![request.challenge_id,now], |r| Ok((r.get::<_, String>(0)?,r.get::<_, i64>(1)?,r.get::<_, String>(2)?)))
            .optional()?.ok_or_else(|| reject("unknown, expired or consumed peer challenge"))
    }).map_err(storage)?;
    let challenge = PeerChallengeResponse {
        challenge_id: request.challenge_id.clone(),
        nonce: challenge.0,
        expires_at: challenge.1,
        responder_node: IotaNodeId::new(challenge.2)?,
    };
    let signed = request.verify(&challenge)?;
    let node = &signed.descriptor.node;
    if node == &challenge.responder_node {
        return Err(IdentityError::KeyPinMismatch);
    }
    let hash = descriptor_digest(&signed)?;
    let key = signed
        .descriptor
        .public_keys
        .try_to_base64()
        .map_err(storage)?;
    let encoded = serde_json::to_string(&signed.to_wire_v1()?).map_err(storage)?;
    let receipt = db::with_immediate_transaction(|tx| {
        let now=now.max(crate::util::sync::now_millis());
        let verified=signed.clone().verify(None,now).map_err(|e|reject(&e.to_string()))?;
        let now=now.max(crate::util::sync::now_millis());
        let until=now.saturating_add(limits.admission_lifetime_ms).min(signed.descriptor.valid_until.unwrap_or(i64::MAX));
        if until<=now { return Err(reject("peer descriptor expired before admission")); }
        check_candidate(tx, node, &key, signed.descriptor.revision, now)?;
        tx.execute("DELETE FROM federation_peer_admissions WHERE status='provisional' AND expires_at<=?1 AND node_id!=?2",params![now,node.as_str()])?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM federation_peer_admissions WHERE node_id!=?1", [node.as_str()], |r| r.get(0))?;
        if count as usize >= limits.max_admissions { return Err(reject("peer admission quota exceeded")); }
        if tx.execute("UPDATE federation_peer_challenges SET consumed_at = ?2 WHERE challenge_id = ?1 AND consumed_at IS NULL AND expires_at > ?2 AND node_id = ?3 AND descriptor_hash = ?4",
            params![request.challenge_id,now,node.as_str(),hash.as_slice()])? != 1 {
            return Err(reject("peer challenge already consumed or descriptor changed"));
        }
        // Re-introduction may renew an expired lease, never a live lease or a revocation.
        tx.execute("INSERT INTO federation_peer_admissions(node_id,auth_hint,public_key,descriptor,admitted_at,expires_at,status,descriptor_rev) VALUES(?1,?2,?3,?4,?5,?6,'provisional',?7)
            ON CONFLICT(node_id) DO UPDATE SET descriptor=excluded.descriptor,
                admitted_at=CASE WHEN federation_peer_admissions.expires_at<=?5 THEN excluded.admitted_at ELSE federation_peer_admissions.admitted_at END,
                expires_at=CASE WHEN federation_peer_admissions.status='established' THEN ?8 WHEN federation_peer_admissions.expires_at<=?5 THEN excluded.expires_at ELSE federation_peer_admissions.expires_at END,
                descriptor_rev=excluded.descriptor_rev
            WHERE federation_peer_admissions.status!='revoked' AND federation_peer_admissions.public_key=excluded.public_key AND federation_peer_admissions.descriptor_rev<=excluded.descriptor_rev",
            params![node.as_str(),node.mtp_authentication_hint() as i64,key,encoded,now,until,verified.descriptor().revision,verified.descriptor().valid_until.unwrap_or(i64::MAX)])?;
        let established: bool = tx.query_row("SELECT status='established' FROM federation_peer_admissions WHERE node_id=?1",[node.as_str()],|r|r.get(0))?;
        if established {
            let endpoints=serde_json::to_string(&verified.descriptor().direct_endpoints).map_err(|e|reject(&e.to_string()))?;
            let relays=serde_json::to_string(&verified.descriptor().relay_hints).map_err(|e|reject(&e.to_string()))?;
            crate::node_directory::SqliteNodeDirectory::upsert_in_tx(tx,&verified,&endpoints,&relays,&key)?;
        }
        let expires_at = tx.query_row("SELECT expires_at FROM federation_peer_admissions WHERE node_id=?1", [node.as_str()], |r| r.get(0))?;
        Ok(PeerAdmissionReceipt { node: node.clone(), expires_at })
    }).map_err(storage)?;
    notify_change();
    Ok(receipt)
}

/// Validate the proof before doing any domain discovery or recording a trusted node.
pub fn proven_locator(
    request: &PeerIntroductionRequest,
    now: i64,
) -> Result<Option<iota_identity::AuthorityLocator>, IdentityError> {
    let row = db::with_db(|db| {
        db.query_row("SELECT nonce,expires_at,responder_node,authority_locator,descriptor_hash,node_id FROM federation_peer_challenges WHERE challenge_id=?1 AND consumed_at IS NULL AND expires_at>?2",
            params![request.challenge_id,now], |r| Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,String>(5)?)))
            .optional()?.ok_or_else(|| reject("unknown, expired or consumed peer challenge"))
    }).map_err(storage)?;
    let challenge = PeerChallengeResponse {
        challenge_id: request.challenge_id.clone(),
        nonce: row.0,
        expires_at: row.1,
        responder_node: IotaNodeId::new(row.2)?,
    };
    let signed = request.verify(&challenge)?;
    signed.clone().verify(None, now)?;
    if row.4 != descriptor_digest(&signed)? || row.5 != signed.descriptor.node.as_str() {
        return Err(IdentityError::KeyPinMismatch);
    }
    row.3.map(iota_identity::AuthorityLocator::new).transpose()
}

fn check_candidate(
    tx: &rusqlite::Transaction<'_>,
    node: &IotaNodeId,
    key: &str,
    revision: i64,
    now: i64,
) -> Result<(), StorageError> {
    let mut stmt = tx.prepare("SELECT node_id,public_key FROM federation_peer_admissions WHERE auth_hint=?1 AND (expires_at>?2 OR status='revoked')
        UNION ALL SELECT n.node_id,k.public_key FROM node_directory n JOIN node_keys k ON k.node_id=n.node_id WHERE n.authentication_hint=?1 AND k.source_revision=n.descriptor_revision")?;
    for entry in stmt.query_map(params![node.mtp_authentication_hint() as i64, now], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (n, k) = entry?;
        if n != node.as_str() || k != key {
            return Err(reject(
                "peer key or authentication hint conflicts with established identity",
            ));
        }
    }
    let revoked: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM federation_peer_admissions WHERE node_id=?1 AND (status='revoked' OR descriptor_rev>?2))", params![node.as_str(),revision], |r| r.get(0))?;
    let rollback: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM node_directory WHERE node_id=?1 AND descriptor_revision>?2)",
        params![node.as_str(), revision],
        |r| r.get(0),
    )?;
    if revoked || rollback {
        return Err(reject("revoked peer or descriptor rollback"));
    }
    Ok(())
}

/// Resolve all live candidates in one snapshot, including ambiguity across both stores.
pub fn key_for_peer_authentication_hint(
    hint: u64,
) -> Result<Option<PublicKeyBundle>, IdentityError> {
    db::with_db(|db| peer_key_on(db, hint, crate::util::sync::now_millis())).map_err(storage)
}

fn peer_key_on(
    db: &rusqlite::Connection,
    hint: u64,
    now: i64,
) -> Result<Option<PublicKeyBundle>, StorageError> {
    let mut stmt = db.prepare("SELECT n.node_id,k.public_key FROM node_directory n JOIN node_keys k ON k.node_id=n.node_id AND k.source_revision=n.descriptor_revision
            WHERE n.authentication_hint=?1 AND (n.descriptor_valid_until IS NULL OR n.descriptor_valid_until>?2) AND k.valid_from<=?2 AND (k.valid_until IS NULL OR k.valid_until>?2)
            AND NOT EXISTS(SELECT 1 FROM federation_peer_admissions a WHERE a.node_id=n.node_id AND a.status IN ('revoked','provisional'))
            UNION SELECT node_id,public_key FROM federation_peer_admissions WHERE auth_hint=?1 AND expires_at>?2 AND status='provisional'")?;
    let keys = stmt
        .query_map(params![hint as i64, now], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if keys.len() > 1 {
        return Err(reject("ambiguous peer authentication hint"));
    }
    keys.into_iter()
        .next()
        .map(|(node, key)| {
            let key = PublicKeyBundle::from_base64(&key).map_err(|e| reject(&e.to_string()))?;
            let derived = IotaNodeId::from_public_keys(&key).map_err(|e| reject(&e.to_string()))?;
            if derived.as_str() != node || derived.mtp_authentication_hint() != hint {
                return Err(reject("stored peer key does not match its node or hint"));
            }
            Ok(key)
        })
        .transpose()
}

/// Read the admission and directory in one snapshot without promoting a candidate.
pub fn trust_for_peer(
    node: &IotaNodeId,
    key: &PublicKeyBundle,
    now: i64,
) -> Result<PeerTrust, IdentityError> {
    if IotaNodeId::from_public_keys(key)? != *node {
        return Err(IdentityError::KeyPinMismatch);
    }
    db::with_immediate_transaction(|tx| {
        trust_in_tx(tx, node, key, now.max(crate::util::sync::now_millis()))
    })
    .map_err(storage)
}

fn trust_in_tx(
    tx: &rusqlite::Transaction<'_>,
    node: &IotaNodeId,
    key: &PublicKeyBundle,
    now: i64,
) -> Result<PeerTrust, StorageError> {
    let actual = key.try_to_base64().map_err(|e| reject(&e.to_string()))?;
    let resolved = peer_key_on(tx, node.mtp_authentication_hint(), now)?
        .ok_or_else(|| reject("no live peer authentication key"))?;
    if resolved
        .try_to_base64()
        .map_err(|e| reject(&e.to_string()))?
        != actual
    {
        return Err(reject("peer authentication key changed"));
    }
    let admission: Option<(String,String,i64,String,i64,i64)> = tx.query_row(
        "SELECT descriptor,public_key,expires_at,status,descriptor_rev,admitted_at FROM federation_peer_admissions WHERE node_id=?1",
        [node.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
    if let Some((encoded, stored, expires_at, status, revision, admitted_at)) = admission {
        if status == "revoked" || stored != actual {
            return Err(reject("peer revoked or admission key changed"));
        }
        if status == "provisional" {
            if expires_at <= now {
                return Err(reject("peer admission expired"));
            }
            let wire: iota_identity::NodeDescriptorWireV1 =
                serde_json::from_str(&encoded).map_err(|e| reject(&e.to_string()))?;
            let verified = wire
                .parse()
                .and_then(|signed| signed.verify(None, now))
                .map_err(|e| reject(&e.to_string()))?;
            let descriptor = verified.descriptor();
            if descriptor.node != *node
                || descriptor.revision != revision
                || descriptor
                    .public_keys
                    .try_to_base64()
                    .map_err(|e| reject(&e.to_string()))?
                    != stored
                || descriptor
                    .valid_until
                    .is_some_and(|until| expires_at > until)
            {
                return Err(reject("invalid provisional descriptor binding"));
            }
            check_candidate(tx, node, &actual, revision, now)?;
            return Ok(PeerTrust::Provisional {
                node: node.clone(),
                revision,
                admitted_at,
                expires_at,
            });
        }
    }
    let (revision, valid_until) = tx.query_row(
        "SELECT descriptor_revision,descriptor_valid_until FROM node_directory WHERE node_id=?1",
        [node.as_str()],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?)),
    )?;
    if valid_until.is_some_and(|until| until <= now) {
        return Err(reject("peer descriptor expired"));
    }
    Ok(PeerTrust::Established {
        node: node.clone(),
        revision,
        valid_until,
    })
}

/// Promote exactly the lease checked for this authenticated transport. A newer
/// lease cannot revive a stale admission; a competing promotion is idempotent.
pub fn promote(
    trust: &PeerTrust,
    key: &PublicKeyBundle,
    now: i64,
) -> Result<PeerTrust, IdentityError> {
    let node = trust.node();
    if IotaNodeId::from_public_keys(key)? != *node {
        return Err(IdentityError::KeyPinMismatch);
    }
    let established=db::with_immediate_transaction(|tx| {
        let now=now.max(crate::util::sync::now_millis());
        let current=trust_in_tx(tx,node,key,now)?;
        if let PeerTrust::Established { revision, .. }=&current {
            if let PeerTrust::Provisional { admitted_at,.. }=trust {
                let current_admission:Option<i64>=tx.query_row("SELECT admitted_at FROM federation_peer_admissions WHERE node_id=?1",[node.as_str()],|r|r.get(0)).optional()?;
                if current_admission!=Some(*admitted_at) { return Err(reject("provisional peer lease was replaced before promotion")); }
            }
            let observed_revision=match trust { PeerTrust::Established { revision,.. } | PeerTrust::Provisional { revision,.. }=>revision };
            if revision<observed_revision { return Err(reject("peer descriptor rolled back during admission")); }
            return Ok(current);
        }
        if &current!=trust { return Err(reject("provisional peer lease changed during admission")); }
        let row: Option<(String,String,i64,String)> = tx.query_row("SELECT descriptor,public_key,expires_at,status FROM federation_peer_admissions WHERE node_id=?1", [node.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let Some((encoded,stored,until,status)) = row else { return Err(reject("peer admission disappeared")); };
        if status=="revoked" { return Err(reject("peer revoked")); }
        if until<=now { return Err(reject("peer admission expired")); }
        let actual = key.try_to_base64().map_err(|e| reject(&e.to_string()))?;
        if stored!=actual { return Err(reject("peer admission key changed")); }
        let wire: iota_identity::NodeDescriptorWireV1 = serde_json::from_str(&encoded).map_err(|e| reject(&e.to_string()))?;
        let verified = wire.parse().and_then(|s| s.verify(None,now)).map_err(|e| reject(&e.to_string()))?;
        let now=now.max(crate::util::sync::now_millis());
        if until<=now || verified.descriptor().valid_until.is_some_and(|deadline|deadline<=now) {
            return Err(reject("peer admission expired during verification"));
        }
        if verified.descriptor().node!=*node || verified.descriptor().public_keys.try_to_base64().map_err(|e|reject(&e.to_string()))?!=stored {
            return Err(reject("peer admission descriptor and authenticated key disagree"));
        }
        check_candidate(tx,node,&actual,verified.descriptor().revision,now)?;
        let endpoints = serde_json::to_string(&verified.descriptor().direct_endpoints).map_err(|e| reject(&e.to_string()))?;
        let relays = serde_json::to_string(&verified.descriptor().relay_hints).map_err(|e| reject(&e.to_string()))?;
        crate::node_directory::SqliteNodeDirectory::upsert_in_tx(tx,&verified,&endpoints,&relays,&actual)?;
        tx.execute("UPDATE federation_peer_admissions SET status='established',expires_at=?2 WHERE node_id=?1 AND status='provisional'", params![node.as_str(),verified.descriptor().valid_until.unwrap_or(i64::MAX)])?;
        trust_in_tx(tx,node,key,now)
    }).map_err(storage)?;
    if matches!(trust, PeerTrust::Provisional { .. }) {
        notify_change();
    }
    Ok(established)
}

pub fn is_revoked(node: &IotaNodeId) -> Result<bool, IdentityError> {
    db::with_db(|db| Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM federation_peer_admissions WHERE node_id=?1 AND status='revoked')", [node.as_str()], |r| r.get(0))?)).map_err(storage)
}

pub fn revoke(node: &IotaNodeId) -> Result<(), IdentityError> {
    db::with_immediate_transaction(|tx| {
        // A tombstone prevents subsequent discovery or introduction from restoring access.
        tx.execute("INSERT INTO federation_peer_admissions(node_id,auth_hint,public_key,descriptor,admitted_at,expires_at,status,descriptor_rev) VALUES(?1,?2,'','',0,0,'revoked',0)
            ON CONFLICT(node_id) DO UPDATE SET status='revoked'", params![node.as_str(),node.mtp_authentication_hint() as i64])?;
        Ok(())
    }).map_err(storage)?;
    notify_change();
    Ok(())
}
