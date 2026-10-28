//! Account-scoped encrypted file metadata and consent-based replica state.
pub mod replication;
mod sharing;
pub use sharing::{apply_offer_in_tx, apply_revoke_in_tx};

use crate::{
    storage_error::StorageError,
    util::{db, sync},
};
use iota_identity::{
    PrincipalHandle,
    relay_protocol::{Principal, files::*},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

// Used by the legacy asset endpoints too. A guessed replica asset ID must not
// bypass consent, revocation, expiry, or an account's blocklist.
pub(crate) const ASSET_ACCESS: &str = "(NOT EXISTS(SELECT 1 FROM file_managed_assets m WHERE m.storage_user_id=user_assets.user_id AND m.asset_id=user_assets.asset_id) OR EXISTS(SELECT 1 FROM file_versions v JOIN hosted_principals h ON h.local_user_id=v.storage_user_id JOIN principals p ON p.principal_pk=v.origin_principal AND p.retired_at IS NULL WHERE v.storage_user_id=user_assets.user_id AND v.asset_id=user_assets.asset_id AND v.state='ready' AND (v.origin_principal=h.principal_handle OR (EXISTS(SELECT 1 FROM file_share_grants g WHERE g.storage_user_id=v.storage_user_id AND g.origin_principal=v.origin_principal AND g.file_id=v.file_id AND g.version=v.version AND g.recipient_principal=h.principal_handle AND g.state='accepted' AND g.expires_at>CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)) AND NOT EXISTS(SELECT 1 FROM blocked_users b WHERE b.user_id=v.storage_user_id AND b.blocked_principal=v.origin_principal)))))";

pub(crate) fn invalid() -> StorageError {
    StorageError::InvalidRelayPayload("file request")
}
pub(crate) fn encode(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_string(value).map_err(|_| invalid())
}
pub(crate) fn decode<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    serde_json::from_str(value).map_err(|_| invalid())
}
pub(crate) fn check(ok: bool) -> Result<(), StorageError> {
    if ok { Ok(()) } else { Err(invalid()) }
}
pub(crate) fn handle_on(conn: &Connection, principal: &Principal) -> Result<i64, StorageError> {
    principal.validate().map_err(|_| invalid())?;
    conn.query_row("SELECT principal_pk FROM principals WHERE authority_id=?1 AND remote_user_id=?2 AND retired_at IS NULL",
        params![principal.authority, i64::try_from(principal.user_id).map_err(|_| invalid())?], |r| r.get(0))
        .optional()?.ok_or(StorageError::MessageUnauthorized)
}

pub(crate) fn stored_handle_on(
    conn: &Connection,
    principal: &Principal,
) -> Result<i64, StorageError> {
    principal.validate().map_err(|_| invalid())?;
    conn.query_row(
        "SELECT principal_pk FROM principals WHERE authority_id=?1 AND remote_user_id=?2",
        params![
            principal.authority,
            i64::try_from(principal.user_id).map_err(|_| invalid())?
        ],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(StorageError::MessageUnauthorized)
}
pub fn owner_principal_on(conn: &Connection, owner: i64) -> Result<Principal, StorageError> {
    conn.query_row("SELECT p.authority_id,p.remote_user_id FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle JOIN hosted_auth_state a ON a.local_user_id=h.local_user_id WHERE h.local_user_id=?1 AND p.retired_at IS NULL AND a.enabled=1", [owner], |r| {
        Ok(Principal { authority: r.get(0)?, user_id: r.get::<_, i64>(1)? as u64 })
    }).optional()?.ok_or(StorageError::MessageUnauthorized)
}
pub(crate) fn change(
    tx: &Transaction<'_>,
    owner: i64,
    kind: &str,
    payload: &impl Serialize,
) -> Result<(), StorageError> {
    tx.execute(
        "INSERT INTO file_changes(storage_user_id,kind,payload) VALUES(?1,?2,?3)",
        params![owner, kind, encode(payload)?],
    )?;
    Ok(())
}
pub(crate) fn not_deleted(
    conn: &Connection,
    owner: i64,
    origin: i64,
    file: &str,
) -> Result<(), StorageError> {
    let deleted: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM file_tombstones WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3)", params![owner,origin,file], |r| r.get(0))?;
    check(!deleted)
}
fn private_folder(conn: &Connection, owner: i64, folder: &str) -> Result<(), StorageError> {
    if folder == "private" {
        return Ok(());
    }
    let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM file_folders WHERE storage_user_id=?1 AND folder_id=?2 AND deleted=0)", params![owner,folder], |r| r.get(0))?;
    check(exists)
}

pub fn folder_put(owner: i64, folder: &Folder) -> Result<(), StorageError> {
    check(
        valid_id(&folder.folder_id)
            && folder.folder_id != "private"
            && folder.revision > 0
            && !folder.encrypted_name.is_empty()
            && folder.encrypted_name.len() <= MAX_METADATA_BYTES,
    )?;
    db::with_immediate_transaction(|tx| {
        owner_principal_on(tx, owner)?;
        private_folder(tx, owner, &folder.parent_folder_id)?;
        let payload = encode(folder)?;
        let previous: Option<(i64,String,i64)> = tx.query_row("SELECT revision,payload,deleted FROM file_folders WHERE storage_user_id=?1 AND folder_id=?2", params![owner,folder.folder_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((revision, old, deleted)) = &previous {
            if *deleted == 0 && old == &payload {
                return Ok(());
            }
            check(*deleted == 0 && revision.checked_add(1) == Some(folder.revision))?;
        } else {
            check(folder.revision == 1)?;
        }
        // Walk the proposed ancestry in the same write transaction. Bound depth.
        let mut parent = folder.parent_folder_id.clone();
        for depth in 0..=128 {
            check(parent != folder.folder_id && depth < 128)?;
            if parent == "private" {
                break;
            }
            parent = tx.query_row("SELECT parent_folder_id FROM file_folders WHERE storage_user_id=?1 AND folder_id=?2 AND deleted=0", params![owner,parent], |r| r.get(0))?;
        }
        tx.execute("INSERT INTO file_folders(storage_user_id,folder_id,parent_folder_id,revision,payload) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(storage_user_id,folder_id) DO UPDATE SET parent_folder_id=excluded.parent_folder_id,revision=excluded.revision,payload=excluded.payload", params![owner,folder.folder_id,folder.parent_folder_id,folder.revision,payload])?;
        change(tx, owner, "folder", folder)
    })
}

pub fn placement_put(owner: i64, placement: &Placement) -> Result<(), StorageError> {
    check(
        valid_id(&placement.placement_id)
            && valid_id(&placement.file_id)
            && placement.revision > 0
            && placement.encrypted_metadata.len() >= 40
            && placement.encrypted_metadata.len() <= MAX_METADATA_BYTES,
    )?;
    db::with_immediate_transaction(|tx| {
        let own = owner_principal_on(tx, owner)?;
        let origin = handle_on(tx, &placement.origin)?;
        not_deleted(tx, owner, origin, &placement.file_id)?;
        if let Some(chat) = placement.folder_id.strip_prefix("chat:") {
            let grant: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM file_share_grants WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND chat_id=?4 AND state IN ('offered','accepted') AND expires_at>?5)", params![owner,origin,placement.file_id,chat,sync::now_millis()], |r| r.get(0))?;
            check(grant)?;
        } else {
            check(own == placement.origin)?;
            private_folder(tx, owner, &placement.folder_id)?;
        }
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND state!='deleted')", params![owner,origin,placement.file_id], |r| r.get(0))?;
        check(exists)?;
        let payload = encode(placement)?;
        let old: Option<(i64,String,i64)> = tx.query_row("SELECT revision,payload,deleted FROM file_placements WHERE storage_user_id=?1 AND placement_id=?2", params![owner,placement.placement_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((revision, previous, deleted)) = old {
            if deleted == 0 && previous == payload {
                return Ok(());
            }
            check(deleted == 0 && revision.checked_add(1) == Some(placement.revision))?;
        } else {
            check(placement.revision == 1)?;
        }
        tx.execute("INSERT INTO file_placements(storage_user_id,placement_id,origin_principal,file_id,folder_id,revision,payload) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(storage_user_id,placement_id) DO UPDATE SET origin_principal=excluded.origin_principal,file_id=excluded.file_id,folder_id=excluded.folder_id,revision=excluded.revision,payload=excluded.payload", params![owner,placement.placement_id,origin,placement.file_id,placement.folder_id,placement.revision,payload])?;
        change(tx, owner, "placement", placement)
    })
}

pub fn entry_delete(owner: i64, entry: &DeleteEntry, folder: bool) -> Result<(), StorageError> {
    check(valid_id(&entry.id) && entry.expected_revision > 0)?;
    db::with_immediate_transaction(|tx| {
        owner_principal_on(tx, owner)?;
        let table = if folder {
            "file_folders"
        } else {
            "file_placements"
        };
        let key = if folder { "folder_id" } else { "placement_id" };
        let old: Option<(i64, i64)> = tx
            .query_row(
                &format!(
                    "SELECT revision,deleted FROM {table} WHERE storage_user_id=?1 AND {key}=?2"
                ),
                params![owner, entry.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((revision, deleted)) = old else {
            return Err(invalid());
        };
        check(revision == entry.expected_revision)?;
        if deleted != 0 {
            return Ok(());
        }
        if folder {
            for query in [
                "SELECT EXISTS(SELECT 1 FROM file_folders WHERE storage_user_id=?1 AND parent_folder_id=?2 AND deleted=0)",
                "SELECT EXISTS(SELECT 1 FROM file_placements WHERE storage_user_id=?1 AND folder_id=?2 AND deleted=0)",
            ] {
                check(!tx.query_row(query, params![owner, entry.id], |r| r.get::<_, bool>(0))?)?;
            }
        }
        tx.execute(
            &format!("UPDATE {table} SET deleted=1 WHERE storage_user_id=?1 AND {key}=?2"),
            params![owner, entry.id],
        )?;
        change(
            tx,
            owner,
            if folder {
                "folder_deleted"
            } else {
                "placement_deleted"
            },
            entry,
        )
    })
}

/// Register file intent so an upload stranded before logical publication can be
/// collected without treating unrelated background assets as abandoned files.
pub fn upload_start(owner: i64, request: &FileUploadStart) -> Result<Value, StorageError> {
    db::with_db(|conn| {
        owner_principal_on(conn, owner)?;
        Ok(())
    })?;
    let status = crate::util::user_assets::start(
        owner,
        &request.upload_id,
        &request.asset_id,
        request.size,
        &request.sha256,
        "application/octet-stream",
    )?;
    let registered = db::with_immediate_transaction(|tx| {
        owner_principal_on(tx, owner)?;
        let conflicting: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM user_assets a WHERE user_id=?1 AND asset_id=?2 AND (published_upload_id IS NOT ?3 OR NOT EXISTS(SELECT 1 FROM file_managed_assets m WHERE m.storage_user_id=?1 AND m.asset_id=?2)))",params![owner,request.asset_id,request.upload_id],|r|r.get(0))?;
        check(!conflicting)?;
        tx.execute(
            "INSERT OR IGNORE INTO file_managed_assets(storage_user_id,asset_id) VALUES(?1,?2)",
            params![owner, request.asset_id],
        )?;
        Ok(())
    });
    if let Err(error) = registered {
        let _ = crate::util::user_assets::abort(owner, &request.upload_id);
        return Err(error);
    }
    Ok(
        json!({"upload_id":status.upload_id,"asset_id":status.asset_id,"size":status.size,"sha256":status.sha256,"offset":status.offset,"state":status.state}),
    )
}

pub fn publish(owner: i64, publish: &PublishVersion) -> Result<(), StorageError> {
    publish.manifest.validate().map_err(|_| invalid())?;
    let m = &publish.manifest;
    check(m.key.version.checked_sub(1) == Some(publish.expected_predecessor))?;
    db::with_immediate_transaction(|tx| {
        let own = owner_principal_on(tx, owner)?;
        check(own == m.key.origin && own == m.envelope.recipient)?;
        let origin = handle_on(tx, &own)?;
        not_deleted(tx, owner, origin, &m.key.file_id)?;
        let payload = encode(m)?;
        let previous: Option<(String,Option<String>)> = tx.query_row("SELECT manifest,asset_id FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4", params![owner,origin,m.key.file_id,m.key.version], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((old, asset)) = previous {
            return check(old == payload && asset.as_deref() == Some(&publish.asset_id));
        }
        let latest: i64 = tx.query_row("SELECT COALESCE(MAX(version),0) FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3", params![owner,origin,m.key.file_id], |r| r.get(0))?;
        check(latest == publish.expected_predecessor)?;
        let asset: Option<(i64,Vec<u8>,String)> = tx.query_row("SELECT size,sha256,mime_type FROM user_assets WHERE user_id=?1 AND asset_id=?2 AND deleted=0", params![owner,publish.asset_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (size, hash, mime) = asset.ok_or_else(invalid)?;
        check(
            size == m.ciphertext_size
                && hash == m.ciphertext_sha256
                && mime == "application/octet-stream",
        )?;
        tx.execute("INSERT INTO file_versions(storage_user_id,origin_principal,file_id,version,manifest,asset_id,state) VALUES(?1,?2,?3,?4,?5,?6,'ready')", params![owner,origin,m.key.file_id,m.key.version,payload,publish.asset_id])?;
        tx.execute(
            "INSERT OR IGNORE INTO file_managed_assets(storage_user_id,asset_id) VALUES(?1,?2)",
            params![owner, publish.asset_id],
        )?;
        change(tx, owner, "version", m)
    })
}

pub fn delete_file(owner: i64, file_id: &str) -> Result<(), StorageError> {
    check(valid_id(file_id))?;
    db::with_immediate_transaction(|tx| {
        let own = owner_principal_on(tx, owner)?;
        let origin = handle_on(tx, &own)?;
        let shared: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM file_share_grants WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND state IN ('offered','accepted') AND expires_at>?4)", params![owner,origin,file_id,sync::now_millis()], |r| r.get(0))?;
        check(!shared)?;
        tx.execute(
            "INSERT OR IGNORE INTO file_tombstones VALUES(?1,?2,?3)",
            params![owner, origin, file_id],
        )?;
        tx.execute("DELETE FROM file_replication_jobs WHERE version_id IN (SELECT id FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3)", params![owner,origin,file_id])?;
        tx.execute("UPDATE file_versions SET asset_id=NULL,state='deleted' WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3", params![owner,origin,file_id])?;
        tx.execute("UPDATE user_assets SET deleted=1 WHERE user_id=?1 AND asset_id IN (SELECT asset_id FROM file_managed_assets WHERE storage_user_id=?1) AND NOT EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=?1 AND v.asset_id=user_assets.asset_id)",[owner])?;
        tx.execute("UPDATE file_placements SET deleted=1 WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3", params![owner,origin,file_id])?;
        change(
            tx,
            owner,
            "file_deleted",
            &json!({"origin": own,"file_id":file_id}),
        )
    })
}

pub fn rewrap(owner: i64, request: &RewrapKey) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let own = owner_principal_on(tx, owner)?;
        check(request.envelope.recipient == own)?;
        if request.key.origin != own {
            sharing::require_recipient_on(tx, owner, &request.key)?;
        }
        let (id, mut manifest, _, _) = version_on(tx, owner, &request.key)?;
        if manifest.envelope == request.envelope {
            return Ok(());
        }
        if manifest.envelope.key_id != request.expected_key_id {
            return Err(StorageError::RevisionConflict);
        }
        manifest.envelope = request.envelope.clone();
        manifest.validate().map_err(|_| invalid())?;
        tx.execute(
            "UPDATE file_versions SET manifest=?2 WHERE id=?1",
            params![id, encode(&manifest)?],
        )?;
        change(tx, owner, "key_envelope", &manifest)
    })
}

pub fn metadata_put(owner: i64, request: &MetadataUpdate) -> Result<(), StorageError> {
    check(
        request.expected_revision > 0
            && !request.manifest_ciphertext.is_empty()
            && request.manifest_ciphertext.len() <= MAX_METADATA_BYTES,
    )?;
    db::with_immediate_transaction(|tx| {
        check(owner_principal_on(tx, owner)? == request.key.origin)?;
        let (id, mut manifest, _, _) = version_on(tx, owner, &request.key)?;
        if manifest.manifest_ciphertext == request.manifest_ciphertext {
            return Ok(());
        }
        let revision: i64 = tx.query_row(
            "SELECT metadata_revision FROM file_versions WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        if revision != request.expected_revision {
            return Err(StorageError::RevisionConflict);
        }
        let revision = revision.checked_add(1).ok_or_else(invalid)?;
        manifest.manifest_ciphertext = request.manifest_ciphertext.clone();
        tx.execute(
            "UPDATE file_versions SET manifest=?2,metadata_revision=?3 WHERE id=?1",
            params![id, encode(&manifest)?, revision],
        )?;
        change(
            tx,
            owner,
            "metadata",
            &json!({"manifest":manifest,"metadata_revision":revision}),
        )
    })
}

pub(crate) fn version_on(
    conn: &Connection,
    owner: i64,
    key: &FileKey,
) -> Result<(i64, FileManifest, Option<String>, String), StorageError> {
    key.validate().map_err(|_| invalid())?;
    let origin = handle_on(conn, &key.origin)?;
    not_deleted(conn, owner, origin, &key.file_id)?;
    let (id,payload,asset,state): (i64,String,Option<String>,String) = conn.query_row("SELECT id,manifest,asset_id,state FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND state!='deleted'", params![owner,origin,key.file_id,key.version], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?.ok_or(StorageError::MissingRelayDependency)?;
    Ok((id, decode(&payload)?, asset, state))
}

pub fn manifest(owner: i64, key: &FileKey) -> Result<Value, StorageError> {
    db::with_db(|conn| {
        let own = owner_principal_on(conn, owner)?;
        let (id, manifest, asset, state) = version_on(conn, owner, key)?;
        if own != key.origin {
            sharing::require_recipient_on(conn, owner, key)?;
        }
        let metadata_revision: i64 = conn.query_row(
            "SELECT metadata_revision FROM file_versions WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        let progress: Option<(i64,i64,Option<String>,i64)> = conn.query_row("SELECT COALESCE(u.received,0),j.attempts,j.last_error,j.next_attempt_at FROM file_replication_jobs j LEFT JOIN user_asset_uploads u ON u.user_id=?1 AND u.upload_id=j.upload_id WHERE j.version_id=?2",params![owner,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let proof: Option<String> = conn.query_row("SELECT proof FROM file_share_grants WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND state IN ('offered','accepted') AND expires_at>?5 ORDER BY revision DESC LIMIT 1",params![owner,handle_on(conn,&key.origin)?,key.file_id,key.version,sync::now_millis()],|r|r.get(0)).optional()?.flatten();
        let reserved: i64 = conn.query_row("SELECT COALESCE(SUM(size),0) FROM user_asset_uploads WHERE user_id=?1 AND state='uploading'",[owner],|r|r.get(0))?;
        Ok(
            json!({"manifest":manifest,"proof":proof.map(|proof|decode::<Value>(&proof)).transpose()?,"metadata_revision":metadata_revision,"asset_id":asset,"state":state,"transfer":progress.map(|(offset,attempts,error,next_attempt_at)|json!({"offset":offset,"attempts":attempts,"error":error,"next_attempt_at":next_attempt_at})),"reserved_bytes":reserved}),
        )
    })
}

pub fn list_page(owner: i64, page: &ListPage) -> Result<Value, StorageError> {
    check(page.after >= 0)?;
    db::with_db(|conn| {
        owner_principal_on(conn, owner)?;
        let mut items = Vec::new();
        let mut next = page.after;
        let (sql, filter) = if page.namespace == "folders" {
            (
                "SELECT id,payload FROM file_folders WHERE storage_user_id=?1 AND parent_folder_id=?2 AND deleted=0 AND id>?3 ORDER BY id LIMIT ?4",
                page.folder_id.as_str(),
            )
        } else if page.namespace == "private" {
            private_folder(conn, owner, &page.folder_id)?;
            (
                "SELECT id,payload FROM file_placements WHERE storage_user_id=?1 AND folder_id=?2 AND deleted=0 AND id>?3 ORDER BY id LIMIT ?4",
                page.folder_id.as_str(),
            )
        } else if let Some(chat) = page.namespace.strip_prefix("chat:") {
            (
                "SELECT g.id,g.manifest FROM file_share_grants g WHERE g.storage_user_id=?1 AND g.chat_id=?2 AND g.state IN ('offered','accepted') AND g.expires_at > CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) AND g.id>?3 AND NOT EXISTS(SELECT 1 FROM file_share_grants newer WHERE newer.storage_user_id=g.storage_user_id AND newer.origin_principal=g.origin_principal AND newer.file_id=g.file_id AND newer.chat_id=g.chat_id AND newer.version>g.version AND newer.state IN ('offered','accepted') AND newer.expires_at>CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)) AND NOT EXISTS(SELECT 1 FROM file_placements p WHERE p.storage_user_id=g.storage_user_id AND p.origin_principal=g.origin_principal AND p.file_id=g.file_id AND p.folder_id='chat:'||g.chat_id AND p.deleted=0 AND json_extract(p.payload,'$.hidden')=1) ORDER BY g.id LIMIT ?4",
                chat,
            )
        } else if page.namespace == "versions" {
            return versions_page(conn, owner, page);
        } else if page.namespace == "shares" {
            return shares_page(conn, owner, page);
        } else {
            return Err(invalid());
        };
        let mut stmt = conn.prepare(sql)?;
        for row in stmt.query_map(
            params![owner, filter, page.after, PAGE_SIZE as i64 + 1],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )? {
            let (id, payload) = row?;
            if items.len() == PAGE_SIZE {
                return Ok(json!({"items":items,"next":next}));
            }
            next = id;
            items.push(decode::<Value>(&payload)?);
        }
        Ok(json!({"items":items,"next":null}))
    })
}

fn versions_page(conn: &Connection, owner: i64, page: &ListPage) -> Result<Value, StorageError> {
    let own = owner_principal_on(conn, owner)?;
    let principal = page.origin.as_ref().unwrap_or(&own);
    let origin = handle_on(conn, principal)?;
    let mut statement = conn.prepare("SELECT id,manifest FROM file_versions v WHERE storage_user_id=?1 AND file_id=?2 AND origin_principal=?3 AND state!='deleted' AND id>?4 AND (?6 OR (EXISTS(SELECT 1 FROM file_share_grants g WHERE g.storage_user_id=v.storage_user_id AND g.origin_principal=v.origin_principal AND g.file_id=v.file_id AND g.version=v.version AND g.state IN ('offered','accepted') AND g.expires_at>?7) AND NOT EXISTS(SELECT 1 FROM blocked_users b WHERE b.user_id=?1 AND b.blocked_principal=?3))) ORDER BY id LIMIT ?5")?;
    let mut items = Vec::new();
    let mut next = page.after;
    let mut more = false;
    for row in statement.query_map(
        params![
            owner,
            page.folder_id,
            origin,
            page.after,
            PAGE_SIZE as i64 + 1,
            principal == &own,
            sync::now_millis()
        ],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
    )? {
        let (id, payload) = row?;
        let m: FileManifest = decode(&payload)?;
        if items.len() == PAGE_SIZE {
            more = true;
            break;
        }
        next = id;
        items.push(m);
    }
    Ok(json!({"items":items,"next":if more { Some(next) } else { None }}))
}

fn shares_page(conn: &Connection, owner: i64, page: &ListPage) -> Result<Value, StorageError> {
    let own = owner_principal_on(conn, owner)?;
    let origin = page.origin.as_ref().unwrap_or(&own);
    let origin_handle = handle_on(conn, origin)?;
    let mut statement = conn.prepare("SELECT g.id,g.version,g.chat_id,g.revision,g.state,g.expires_at,p.authority_id,p.remote_user_id FROM file_share_grants g JOIN principals p ON p.principal_pk=g.recipient_principal WHERE g.storage_user_id=?1 AND g.file_id=?2 AND g.origin_principal=?3 AND g.id>?4 ORDER BY g.id LIMIT ?5")?;
    let mut items = Vec::new();
    let mut next = page.after;
    let mut more = false;
    for row in statement.query_map(
        params![
            owner,
            page.folder_id,
            origin_handle,
            page.after,
            PAGE_SIZE as i64 + 1
        ],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)?,
            ))
        },
    )? {
        let (id, version, chat_id, revision, state, expires_at, authority, user_id) = row?;
        if items.len() == PAGE_SIZE {
            more = true;
            break;
        }
        next = id;
        items.push(json!({"key":{"origin":origin,"file_id":page.folder_id,"version":version},"chat_id":chat_id,"grant_revision":revision,"state":state,"expires_at":expires_at,"recipient":{"authority":authority,"user_id":user_id}}));
    }
    Ok(json!({"items":items,"next":if more {Some(next)} else {None}}))
}

pub fn changes(owner: i64, page: &ChangesPage) -> Result<Value, StorageError> {
    check(page.after >= 0)?;
    db::with_db(|conn| {
        owner_principal_on(conn, owner)?;
        let head: i64 = conn.query_row(
            "SELECT COALESCE(MAX(sequence),0) FROM file_changes WHERE storage_user_id=?1",
            [owner],
            |r| r.get(0),
        )?;
        let upper = page.upper.unwrap_or(head);
        check(upper >= page.after && upper <= head)?;
        let mut statement = conn.prepare("SELECT sequence,kind,payload FROM file_changes WHERE storage_user_id=?1 AND sequence>?2 AND sequence<=?3 ORDER BY sequence LIMIT ?4")?;
        let mut events = Vec::new();
        let mut next = page.after;
        let mut more = false;
        for row in statement.query_map(
            params![owner, page.after, upper, PAGE_SIZE as i64 + 1],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )? {
            let (sequence, kind, payload) = row?;
            if events.len() == PAGE_SIZE {
                more = true;
                break;
            }
            next = sequence;
            events.push(
                json!({"sequence":sequence,"kind":kind,"payload":decode::<Value>(&payload)?}),
            );
        }
        Ok(json!({"events":events,"next":if more {next} else {upper},"upper":upper,"more":more}))
    })
}

/// Expired/blocked replicas lose their local entitlement. Blob collection waits
/// a day after the last reference, so racing downloads and restore can settle.
pub fn maintenance() -> Result<(), StorageError> {
    crate::util::user_assets::cleanup_abandoned()?;
    let now = sync::now_millis();
    db::with_immediate_transaction(|tx| {
        let mut statement = tx.prepare("SELECT v.storage_user_id,v.manifest FROM file_versions v JOIN hosted_principals h ON h.local_user_id=v.storage_user_id WHERE v.origin_principal!=h.principal_handle AND v.state IN ('ready','transferring','failed') AND (EXISTS(SELECT 1 FROM principals p WHERE p.principal_pk=v.origin_principal AND p.retired_at IS NOT NULL) OR EXISTS(SELECT 1 FROM blocked_users b WHERE b.user_id=v.storage_user_id AND b.blocked_principal=v.origin_principal) OR NOT EXISTS(SELECT 1 FROM file_share_grants g WHERE g.storage_user_id=v.storage_user_id AND g.origin_principal=v.origin_principal AND g.file_id=v.file_id AND g.version=v.version AND g.state='accepted' AND g.expires_at>?1)) LIMIT 128")?;
        let replicas = statement
            .query_map([now], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (owner, payload) in replicas {
            let manifest: FileManifest = decode(&payload)?;
            let origin = stored_handle_on(tx, &manifest.key.origin)?;
            tx.execute("UPDATE file_share_grants SET state='rejected' WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND state='accepted'",params![owner,origin,manifest.key.file_id,manifest.key.version])?;
            sharing::retire_replica_in_tx(tx, owner, &manifest.key)?;
            change(tx, owner, "replica_expired", &manifest.key)?;
        }
        tx.execute("UPDATE file_managed_assets SET released_at=NULL WHERE EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=file_managed_assets.storage_user_id AND v.asset_id=file_managed_assets.asset_id) OR EXISTS(SELECT 1 FROM user_asset_uploads u WHERE u.user_id=file_managed_assets.storage_user_id AND u.asset_id=file_managed_assets.asset_id AND u.state='uploading') OR EXISTS(SELECT 1 FROM file_replication_jobs j JOIN file_versions v ON v.id=j.version_id WHERE v.storage_user_id=file_managed_assets.storage_user_id AND j.asset_id=file_managed_assets.asset_id)",[])?;
        tx.execute("UPDATE file_managed_assets SET released_at=?1 WHERE released_at IS NULL AND NOT EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=file_managed_assets.storage_user_id AND v.asset_id=file_managed_assets.asset_id) AND NOT EXISTS(SELECT 1 FROM user_asset_uploads u WHERE u.user_id=file_managed_assets.storage_user_id AND u.asset_id=file_managed_assets.asset_id AND u.state='uploading') AND NOT EXISTS(SELECT 1 FROM file_replication_jobs j JOIN file_versions v ON v.id=j.version_id WHERE v.storage_user_id=file_managed_assets.storage_user_id AND j.asset_id=file_managed_assets.asset_id)",[now])?;
        Ok(())
    })?;
    let garbage = db::with_db(|conn| {
        let mut statement = conn.prepare("SELECT storage_user_id,asset_id FROM file_managed_assets WHERE released_at<?1 LIMIT 128")?;
        Ok(statement
            .query_map([now - 24 * 60 * 60 * 1000], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?)
    })?;
    for (owner, asset) in garbage {
        // delete's transaction rechecks pinned references through the trigger.
        if crate::util::user_assets::delete(owner, &asset).is_ok() {
            db::with_db(|conn| {
                conn.execute("DELETE FROM file_managed_assets WHERE storage_user_id=?1 AND asset_id=?2 AND released_at<?3",params![owner,asset,now-24*60*60*1000])?;
                Ok(())
            })?;
        }
    }
    Ok(())
}

pub(crate) fn purge_in_tx(tx: &Transaction<'_>, owner: i64) -> Result<(), StorageError> {
    tx.execute("DELETE FROM file_replication_jobs WHERE version_id IN (SELECT id FROM file_versions WHERE storage_user_id=?1)",[owner])?;
    for table in [
        "file_versions",
        "file_tombstones",
        "file_folders",
        "file_placements",
        "file_share_grants",
        "file_changes",
        "file_managed_assets",
        "file_transfer_usage",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE storage_user_id=?1"),
            [owner],
        )?;
    }
    Ok(())
}
