use super::*;
use crate::util::user_assets;

pub struct Job {
    pub id: i64,
    pub owner: i64,
    pub manifest: FileManifest,
    pub upload_id: String,
    pub asset_id: String,
    pub source_node: String,
    pub request: ReplicaRead,
}

pub fn accept(owner: i64, key: &FileKey) -> Result<(), StorageError> {
    let (manifest, existing, failed) = db::with_db(|conn| {
        sharing::require_grant_on(conn, owner, key, true)?;
        let (id, m, _, state) = version_on(conn, owner, key)?;
        let existing: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM file_replication_jobs WHERE version_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        Ok((m, existing || state == "ready", state == "failed"))
    })?;
    if existing && failed {
        cancel(owner, key)?;
        return accept(owner, key);
    }
    if existing {
        return Ok(());
    }
    let upload = uuid::Uuid::new_v4().to_string();
    let asset = uuid::Uuid::new_v4().to_string();
    user_assets::start(
        owner,
        &upload,
        &asset,
        manifest.ciphertext_size,
        &manifest.ciphertext_sha256,
        "application/octet-stream",
    )?;
    let result = db::with_immediate_transaction(|tx| {
        sharing::require_grant_on(tx, owner, key, true)?;
        let (id, _, _, _) = version_on(tx, owner, key)?;
        let origin = handle_on(tx, &key.origin)?;
        let inserted = tx.execute("INSERT OR IGNORE INTO file_replication_jobs(version_id,upload_id,asset_id) VALUES(?1,?2,?3)",params![id,upload,asset])?;
        if inserted == 0 {
            return Ok(false);
        }
        tx.execute(
            "INSERT OR IGNORE INTO file_managed_assets(storage_user_id,asset_id) VALUES(?1,?2)",
            params![owner, asset],
        )?;
        tx.execute("UPDATE file_share_grants SET state='accepted' WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND state IN ('offered','rejected') AND expires_at>?5",params![owner,origin,key.file_id,key.version,sync::now_millis()])?;
        tx.execute(
            "UPDATE file_versions SET state='transferring' WHERE id=?1",
            [id],
        )?;
        change(tx, owner, "replica_transferring", key)?;
        Ok(true)
    });
    if !matches!(result, Ok(true)) {
        user_assets::abort(owner, &upload)?;
    }
    result.map(|_| ())
}

pub fn cancel(owner: i64, key: &FileKey) -> Result<(), StorageError> {
    let uploads = db::with_immediate_transaction(|tx| {
        sharing::require_grant_on(tx, owner, key, true)?;
        let (id, _, _, _) = version_on(tx, owner, key)?;
        let upload: Option<String> = tx
            .query_row(
                "SELECT upload_id FROM file_replication_jobs WHERE version_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        tx.execute("UPDATE file_share_grants SET state='rejected' WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4",params![owner,handle_on(tx,&key.origin)?,key.file_id,key.version])?;
        sharing::retire_replica_in_tx(tx, owner, key)?;
        change(tx, owner, "replica_cancelled", key)?;
        Ok(upload)
    })?;
    if let Some(upload) = uploads {
        user_assets::abort(owner, &upload)?;
    }
    Ok(())
}

pub fn jobs() -> Result<Vec<Job>, StorageError> {
    db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT v.id,v.storage_user_id,v.manifest,j.upload_id,j.asset_id,g.source_node,g.chat_id,g.revision FROM file_replication_jobs j JOIN file_versions v ON v.id=j.version_id JOIN file_share_grants g ON g.storage_user_id=v.storage_user_id AND g.origin_principal=v.origin_principal AND g.file_id=v.file_id AND g.version=v.version JOIN hosted_principals h ON h.local_user_id=v.storage_user_id AND h.principal_handle=g.recipient_principal WHERE g.state='accepted' AND g.expires_at>?1 AND j.next_attempt_at<=?1 GROUP BY v.id ORDER BY j.next_attempt_at,v.id LIMIT 8")?;
        let rows = stmt.query_map([sync::now_millis()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })?;
        let mut jobs = Vec::new();
        for row in rows {
            let (id, owner, payload, upload_id, asset_id, source_node, chat_id, grant_revision) =
                row?;
            let manifest: FileManifest = decode(&payload)?;
            jobs.push(Job {
                id,
                owner,
                request: ReplicaRead {
                    key: manifest.key.clone(),
                    recipient: manifest.envelope.recipient.clone(),
                    chat_id,
                    grant_revision,
                    offset: 0,
                },
                manifest,
                upload_id,
                asset_id,
                source_node,
            });
        }
        Ok(jobs)
    })
}

pub fn progress(job: &Job) -> Result<i64, StorageError> {
    db::with_db(|conn| {
        sharing::require_recipient_on(conn, job.owner, &job.manifest.key)?;
        let valid: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM file_replication_jobs WHERE version_id=?1 AND upload_id=?2)",params![job.id,job.upload_id],|r|r.get(0))?;
        check(valid)
    })?;
    let m = &job.manifest;
    // start is idempotent and recreates reservations after abandoned-upload GC.
    let offset = user_assets::start(
        job.owner,
        &job.upload_id,
        &job.asset_id,
        m.ciphertext_size,
        &m.ciphertext_sha256,
        "application/octet-stream",
    )?
    .offset;
    let result = db::with_immediate_transaction(|tx| {
        sharing::require_recipient_on(tx, job.owner, &job.manifest.key)?;
        let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM file_replication_jobs WHERE version_id=?1 AND upload_id=?2)",params![job.id,job.upload_id],|r|r.get(0))?;
        check(valid)?;
        let changed = tx.execute(
            "UPDATE file_versions SET state='transferring' WHERE id=?1 AND state='failed'",
            [job.id],
        )?;
        if changed != 0 {
            change(tx, job.owner, "replica_transferring", &job.manifest.key)?;
        }
        Ok(offset)
    });
    if result.is_err() {
        let _ = user_assets::abort(job.owner, &job.upload_id);
    }
    result
}

pub fn append(job: &Job, offset: i64, bytes: &[u8]) -> Result<(), StorageError> {
    db::with_db(|conn| sharing::require_recipient_on(conn, job.owner, &job.manifest.key))?;
    check(!bytes.is_empty() && bytes.len() <= REPLICA_CHUNK_BYTES)?;
    user_assets::append(job.owner, &job.upload_id, offset, bytes)?;
    Ok(())
}

pub fn complete(job: &Job) -> Result<(), StorageError> {
    let (asset, _) = user_assets::commit(job.owner, &job.upload_id)?;
    db::with_immediate_transaction(|tx| {
        sharing::require_recipient_on(tx, job.owner, &job.manifest.key)?;
        let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM file_replication_jobs WHERE version_id=?1 AND upload_id=?2)",params![job.id,job.upload_id],|r|r.get(0))?;
        check(
            valid
                && asset.size == job.manifest.ciphertext_size
                && asset.sha256 == job.manifest.ciphertext_sha256,
        )?;
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM user_assets WHERE user_id=?1 AND asset_id=?2 AND deleted=0 AND sha256=?3)",params![job.owner,asset.asset_id,asset.sha256],|r|r.get(0))?;
        check(exists)?;
        tx.execute(
            "UPDATE file_versions SET asset_id=?2,state='ready' WHERE id=?1",
            params![job.id, asset.asset_id],
        )?;
        tx.execute(
            "DELETE FROM file_replication_jobs WHERE version_id=?1",
            [job.id],
        )?;
        change(tx, job.owner, "replica_ready", &job.manifest.key)
    })
}

pub fn failed(job: &Job) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let changed = tx.execute("UPDATE file_replication_jobs SET attempts=MIN(attempts+1,30),next_attempt_at=?2+MIN(300000,1000*(1<<MIN(attempts,8))),last_error='transfer_unavailable' WHERE version_id=?1 AND upload_id=?3",params![job.id,sync::now_millis(),job.upload_id])?;
        if changed != 0 {
            tx.execute(
                "UPDATE file_versions SET state='failed' WHERE id=?1",
                [job.id],
            )?;
            change(tx, job.owner, "replica_failed", &job.manifest.key)?;
        }
        Ok(())
    })
}

/// Called only after peer authentication. Authorization is rechecked per range.
pub fn read(request: &ReplicaRead, peer_node: Option<&str>) -> Result<Vec<u8>, StorageError> {
    let (owner, asset) = db::with_immediate_transaction(|conn| {
        request.key.validate().map_err(|_| invalid())?;
        let origin = handle_on(conn, &request.key.origin)?;
        let recipient = handle_on(conn, &request.recipient)?;
        let owner: i64 = conn.query_row("SELECT h.local_user_id FROM hosted_principals h JOIN hosted_auth_state a ON a.local_user_id=h.local_user_id WHERE h.principal_handle=?1 AND a.enabled=1",[origin],|r|r.get(0)).optional()?.ok_or(StorageError::MessageUnauthorized)?;
        check(
            request.chat_id
                == iota_identity::relay_protocol::canonical_chat_id(
                    &request.key.origin,
                    &request.recipient,
                ),
        )?;
        let recipient_home: Option<String> = conn.query_row("SELECT home FROM principals WHERE principal_pk=?1 AND retired_at IS NULL AND descriptor_valid_until>?2",params![recipient,sync::now_millis()],|r|r.get(0)).optional()?.flatten();
        if let Some(node) = peer_node {
            check(recipient_home.as_deref() == Some(format!("iota:{node}").as_str()))?;
        } else {
            let local: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM hosted_principals h JOIN hosted_auth_state a ON a.local_user_id=h.local_user_id WHERE h.principal_handle=?1 AND a.enabled=1)",[recipient],|r|r.get(0))?;
            check(local)?;
        }
        let allowed: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM file_share_grants WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND recipient_principal=?5 AND chat_id=?6 AND revision=?7 AND state IN ('offered','accepted') AND expires_at>?8 AND NOT EXISTS(SELECT 1 FROM blocked_users WHERE user_id=?1 AND blocked_principal=?5))",params![owner,origin,request.key.file_id,request.key.version,recipient,request.chat_id,request.grant_revision,sync::now_millis()],|r|r.get(0))?;
        if !allowed {
            return Err(StorageError::MessageUnauthorized);
        }
        let (_, _, asset, state) = version_on(conn, owner, &request.key)?;
        check(state == "ready")?;
        let day = sync::now_millis() / (24 * 60 * 60 * 1000);
        let usage: Option<(i64,i64)> = conn.query_row("SELECT day,bytes FROM file_transfer_usage WHERE storage_user_id=?1 AND recipient_principal=?2",params![owner,recipient],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let used = usage.filter(|u| u.0 == day).map_or(0, |u| u.1);
        let used = used
            .checked_add(REPLICA_CHUNK_BYTES as i64)
            .ok_or_else(invalid)?;
        if used
            > crate::util::config_util::CONFIG
                .load()
                .storage_limits
                .max_user_asset_bytes
                .saturating_mul(4)
        {
            return Err(StorageError::AssetResourceLimit(
                "daily_file_transfer_bytes",
            ));
        }
        conn.execute("INSERT INTO file_transfer_usage VALUES(?1,?2,?3,?4) ON CONFLICT(storage_user_id,recipient_principal) DO UPDATE SET day=excluded.day,bytes=excluded.bytes",params![owner,recipient,day,used])?;
        Ok((owner, asset.ok_or_else(invalid)?))
    })?;
    let (_, bytes) = user_assets::read_chunk(owner, &asset, request.offset, REPLICA_CHUNK_BYTES)?
        .ok_or_else(invalid)?;
    Ok(bytes)
}
