use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{storage_error::StorageError, util::db};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS relay_mailbox (
    destination_node TEXT NOT NULL, envelope_id BLOB NOT NULL, sender_node TEXT NOT NULL,
    encrypted_frame BLOB, frame_hash BLOB NOT NULL, type_map_version TEXT NOT NULL,
    stored_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    lease_owner BLOB, lease_until INTEGER, acceptance BLOB,
    PRIMARY KEY(destination_node,envelope_id)
);
CREATE INDEX IF NOT EXISTS idx_mailbox_delivery ON relay_mailbox(destination_node,expires_at,stored_at);
CREATE INDEX IF NOT EXISTS idx_mailbox_sender ON relay_mailbox(sender_node,expires_at);";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MailboxLimits {
    pub max_frame_bytes: usize,
    pub max_entries: usize,
    pub max_entries_per_sender: usize,
    pub max_entries_per_destination: usize,
    pub max_total_bytes: usize,
    pub ttl_ms: i64,
}

impl Default for MailboxLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 4 * 1024 * 1024,
            max_entries: 10_000,
            max_entries_per_sender: 100,
            max_entries_per_destination: 1000,
            max_total_bytes: 256 * 1024 * 1024,
            ttl_ms: 24 * 60 * 60 * 1000,
        }
    }
}

pub struct MailboxEnvelope {
    pub destination: String,
    pub sender: String,
    pub id: Vec<u8>,
    pub frame: Vec<u8>,
    pub type_map_version: String,
}

pub struct ClaimedEnvelope {
    pub envelope: MailboxEnvelope,
    owner: Vec<u8>,
    deadline: i64,
}

/// None means durably stored, not accepted by the destination. Some is its prior acceptance.
pub fn store(
    envelope: &MailboxEnvelope,
    limits: &MailboxLimits,
    now: i64,
) -> Result<Option<Vec<u8>>, StorageError> {
    use sha2::{Digest, Sha256};
    if envelope.frame.len() > limits.max_frame_bytes {
        return Err(StorageError::Other("mailbox frame too large".into()));
    }
    let hash = Sha256::digest(&envelope.frame).to_vec();
    db::with_immediate_transaction(|tx| {
        tx.execute("DELETE FROM relay_mailbox WHERE expires_at<=?1", [now])?;
        let prior: Option<(String,Vec<u8>,Option<Vec<u8>>)> = tx.query_row("SELECT sender_node,frame_hash,acceptance FROM relay_mailbox WHERE destination_node=?1 AND envelope_id=?2",
            params![envelope.destination,envelope.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((sender, prior, acceptance)) = prior {
            if sender != envelope.sender || prior != hash {
                return Err(StorageError::Other(
                    "mailbox immutable envelope conflict".into(),
                ));
            }
            return Ok(acceptance);
        }
        let (count,bytes,sender,destination): (i64,i64,i64,i64) = tx.query_row("SELECT COUNT(*),COALESCE(SUM(COALESCE(LENGTH(encrypted_frame),0)+COALESCE(LENGTH(acceptance),0)),0),COALESCE(SUM(sender_node=?1),0),COALESCE(SUM(destination_node=?2),0) FROM relay_mailbox",
            params![envelope.sender,envelope.destination],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        if count as usize >= limits.max_entries
            || sender as usize >= limits.max_entries_per_sender
            || destination as usize >= limits.max_entries_per_destination
            || (bytes as usize).saturating_add(envelope.frame.len()) > limits.max_total_bytes
        {
            return Err(StorageError::Other("mailbox quota exceeded".into()));
        }
        tx.execute("INSERT INTO relay_mailbox(destination_node,envelope_id,sender_node,encrypted_frame,frame_hash,type_map_version,stored_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![envelope.destination,envelope.id,envelope.sender,envelope.frame,hash,envelope.type_map_version,now,now.saturating_add(limits.ttl_ms)])?;
        Ok(None)
    })
}

pub fn claim(destination: &str, now: i64) -> Result<Option<ClaimedEnvelope>, StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute("DELETE FROM relay_mailbox WHERE expires_at<=?1", [now])?;
        let next = tx.query_row("SELECT envelope_id,sender_node,encrypted_frame,type_map_version FROM relay_mailbox WHERE destination_node=?1 AND expires_at>?2 AND acceptance IS NULL AND (lease_until IS NULL OR lease_until<=?2) ORDER BY stored_at,envelope_id LIMIT 1",
            params![destination,now], |r| Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,String>(3)?))).optional()?;
        let Some((id, sender, frame, type_map_version)) = next else {
            return Ok(None);
        };
        let mut owner = vec![0; 32];
        rand::rngs::OsRng.fill_bytes(&mut owner);
        let deadline = now.saturating_add(60_000);
        tx.execute("UPDATE relay_mailbox SET lease_owner=?3,lease_until=?4 WHERE destination_node=?1 AND envelope_id=?2",params![destination,id,owner,deadline])?;
        Ok(Some(ClaimedEnvelope {
            envelope: MailboxEnvelope {
                destination: destination.into(),
                id,
                sender,
                frame,
                type_map_version,
            },
            owner,
            deadline,
        }))
    })
}

/// Accept only a response authenticated and correlated by the router's destination transport.
pub fn acknowledge(
    claim: &ClaimedEnvelope,
    acceptance: &[u8],
    limits: &MailboxLimits,
    now: i64,
) -> Result<bool, StorageError> {
    if acceptance.len() > 64 * 1024 {
        return Err(StorageError::Other("mailbox acceptance too large".into()));
    }
    db::with_immediate_transaction(|tx| {
        let total:i64=tx.query_row("SELECT COALESCE(SUM(COALESCE(LENGTH(encrypted_frame),0)+COALESCE(LENGTH(acceptance),0)),0) FROM relay_mailbox",[],|r|r.get(0))?;
        if (total as usize)
            .saturating_sub(claim.envelope.frame.len())
            .saturating_add(acceptance.len())
            > limits.max_total_bytes
        {
            return Err(StorageError::Other(
                "mailbox acceptance exceeds disk quota".into(),
            ));
        }
        Ok(tx.execute("UPDATE relay_mailbox SET acceptance=?5,encrypted_frame=NULL,lease_owner=NULL,lease_until=NULL WHERE destination_node=?1 AND envelope_id=?2 AND lease_owner=?3 AND lease_until=?4 AND lease_until>?6 AND expires_at>?6 AND acceptance IS NULL",
        params![claim.envelope.destination,claim.envelope.id,claim.owner,claim.deadline,acceptance,now])?==1)
    })
}

pub fn retry(claim: &ClaimedEnvelope, now: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute("UPDATE relay_mailbox SET lease_owner=NULL,lease_until=?5 WHERE destination_node=?1 AND envelope_id=?2 AND lease_owner=?3 AND lease_until=?4 AND acceptance IS NULL",
            params![claim.envelope.destination,claim.envelope.id,claim.owner,claim.deadline,now.saturating_add(5000)])?;
        Ok(())
    })
}
