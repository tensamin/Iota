use iota_identity::{IdentityError, node_transition::VerifiedNodeTransition};
use rusqlite::{OptionalExtension, params};

use crate::{storage_error::StorageError, util::db};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS node_transitions (
    previous_node TEXT PRIMARY KEY, replacement_node TEXT NOT NULL,
    previous_descriptor_revision INTEGER NOT NULL, effective_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL, proof TEXT NOT NULL, accepted_at INTEGER NOT NULL
);";

/// Record continuity without rebinding old principal IDs, discovery domains or chat secrets.
/// Callers must resolve the new authority's principals separately.
pub fn record(verified: &VerifiedNodeTransition, now: i64) -> Result<(), IdentityError> {
    let transition = verified.transition();
    if transition.expires_at <= now || transition.effective_at > now {
        return Err(IdentityError::InvalidDescriptor(
            "expired or future transition".into(),
        ));
    }
    let encoded =
        serde_json::to_string(transition).map_err(|e| IdentityError::Storage(e.to_string()))?;
    db::with_immediate_transaction(|tx| {
        let revision: Option<i64> = tx.query_row("SELECT descriptor_revision FROM node_directory WHERE node_id=?1", [transition.previous_node.as_str()],|r| r.get(0)).optional()?;
        if revision!=Some(transition.previous_descriptor_revision) { return Err(StorageError::Other("transition does not match established descriptor revision".into())); }
        let prior: Option<String> = tx.query_row("SELECT proof FROM node_transitions WHERE previous_node=?1",[transition.previous_node.as_str()],|r| r.get(0)).optional()?;
        if prior.as_ref().is_some_and(|proof| proof!=&encoded) { return Err(StorageError::Other("divergent node transition".into())); }
        tx.execute("INSERT OR IGNORE INTO node_transitions(previous_node,replacement_node,previous_descriptor_revision,effective_at,expires_at,proof,accepted_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![transition.previous_node.as_str(),transition.replacement_node.as_str(),transition.previous_descriptor_revision,transition.effective_at,transition.expires_at,encoded,now])?;
        tx.execute("INSERT INTO federation_peer_admissions(node_id,auth_hint,public_key,descriptor,admitted_at,expires_at,status,descriptor_rev) VALUES(?1,?2,'','',?3,?3,'revoked',?4)
            ON CONFLICT(node_id) DO UPDATE SET status='revoked'",params![transition.previous_node.as_str(),transition.previous_node.mtp_authentication_hint() as i64,now,transition.previous_descriptor_revision])?;
        Ok(())
    }).map_err(|e| IdentityError::Storage(e.to_string()))?;
    crate::peer_admission::notify_change();
    Ok(())
}
