use super::*;

fn same_content(a: &FileManifest, b: &FileManifest) -> bool {
    a.key == b.key
        && a.ciphertext_sha256 == b.ciphertext_sha256
        && a.ciphertext_size == b.ciphertext_size
        && a.crypto_format == b.crypto_format
}

pub fn apply_offer_in_tx(
    tx: &Transaction<'_>,
    owner: i64,
    signer: PrincipalHandle,
    recipient: PrincipalHandle,
    offer: &ShareOffer,
    sent_by_self: bool,
    source_node: Option<&str>,
) -> Result<(), StorageError> {
    offer.manifest.validate().map_err(|_| invalid())?;
    let m = &offer.manifest;
    check(
        handle_on(tx, &m.key.origin)? == signer.0
            && handle_on(tx, &m.envelope.recipient)? == recipient.0
            && m.key.origin != m.envelope.recipient
            && offer.chat_id
                == iota_identity::relay_protocol::canonical_chat_id(
                    &m.key.origin,
                    &m.envelope.recipient,
                )
            && offer.grant_revision > 0
            && offer.expires_at > sync::now_millis()
            && offer.expires_at <= 9_007_199_254_740_991,
    )?;
    let local = owner_principal_on(tx, owner)?;
    check(
        local
            == if sent_by_self {
                m.key.origin.clone()
            } else {
                m.envelope.recipient.clone()
            },
    )?;
    not_deleted(tx, owner, signer.0, &m.key.file_id)?;
    let old: Option<(i64,String,Option<String>,i64)> = tx.query_row("SELECT revision,state,manifest,expires_at FROM file_share_grants WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND recipient_principal=?5 AND chat_id=?6", params![owner,signer.0,m.key.file_id,m.key.version,recipient.0,offer.chat_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let payload = encode(m)?;
    if let Some((revision, state, previous, expires_at)) = old {
        if revision > offer.grant_revision {
            return Ok(());
        }
        if revision == offer.grant_revision {
            return check(
                state != "revoked"
                    && previous.as_deref() == Some(&payload)
                    && expires_at == offer.expires_at,
            );
        }
    }
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM file_share_grants WHERE storage_user_id=?1 AND state IN ('offered','accepted')", [owner], |r| r.get(0))?;
    if count >= 4096 {
        return Err(StorageError::AssetResourceLimit("max_file_grants"));
    }
    if sent_by_self {
        let (_, own, asset, state) = version_on(tx, owner, &m.key)?;
        check(
            same_content(m, &own)
                && m.manifest_ciphertext == own.manifest_ciphertext
                && asset.is_some()
                && state == "ready",
        )?;
    } else {
        check(source_node.is_some())?;
        let existing: Option<String> = tx.query_row("SELECT manifest FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4", params![owner,signer.0,m.key.file_id,m.key.version], |r| r.get(0)).optional()?;
        if let Some(existing) = existing {
            // Rotation may replace only this recipient's wrapped key. The
            // signed content descriptor remains immutable across grant revisions.
            let previous: FileManifest = decode(&existing)?;
            check(
                same_content(&previous, m) && previous.envelope.recipient == m.envelope.recipient,
            )?;
            tx.execute("UPDATE file_versions SET manifest=?5 WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4",params![owner,signer.0,m.key.file_id,m.key.version,payload])?;
        } else {
            tx.execute("INSERT INTO file_versions(storage_user_id,origin_principal,file_id,version,manifest,state) VALUES(?1,?2,?3,?4,?5,'pending')", params![owner,signer.0,m.key.file_id,m.key.version,payload])?;
        }
    }
    tx.execute("INSERT INTO file_share_grants(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id,revision,state,expires_at,manifest,source_node,proof) VALUES(?1,?2,?3,?4,?5,?6,?7,'offered',?8,?9,?10,?11) ON CONFLICT(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id) DO UPDATE SET revision=excluded.revision,state=CASE WHEN file_share_grants.state='accepted' THEN 'accepted' ELSE 'offered' END,expires_at=excluded.expires_at,manifest=excluded.manifest,source_node=excluded.source_node,proof=excluded.proof", params![owner,signer.0,m.key.file_id,m.key.version,recipient.0,offer.chat_id,offer.grant_revision,offer.expires_at,payload,source_node,encode(offer)?])?;
    change(tx, owner, "share_offered", offer)
}

pub fn apply_revoke_in_tx(
    tx: &Transaction<'_>,
    owner: i64,
    signer: PrincipalHandle,
    recipient: PrincipalHandle,
    revoke: &ShareRevoke,
    recipient_identity: &Principal,
    sent_by_self: bool,
) -> Result<(), StorageError> {
    revoke.key.validate().map_err(|_| invalid())?;
    check(
        handle_on(tx, &revoke.key.origin)? == signer.0
            && &revoke.recipient == recipient_identity
            && revoke.grant_revision > 0
            && revoke.chat_id
                == iota_identity::relay_protocol::canonical_chat_id(
                    &revoke.key.origin,
                    recipient_identity,
                ),
    )?;
    let old: Option<(i64,String)> = tx.query_row("SELECT revision,state FROM file_share_grants WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND recipient_principal=?5 AND chat_id=?6", params![owner,signer.0,revoke.key.file_id,revoke.key.version,recipient.0,revoke.chat_id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((revision, state)) = old {
        if revision > revoke.grant_revision
            || (revision == revoke.grant_revision && state == "revoked")
        {
            return Ok(());
        }
        check(revision < revoke.grant_revision)?;
    }
    // A revocation may precede the corresponding offer. Preserve that fence.
    tx.execute("INSERT INTO file_share_grants(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id,revision,state,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,'revoked',0) ON CONFLICT(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id) DO UPDATE SET revision=excluded.revision,state='revoked'", params![owner,signer.0,revoke.key.file_id,revoke.key.version,recipient.0,revoke.chat_id,revoke.grant_revision])?;
    if !sent_by_self {
        retire_replica_in_tx(tx, owner, &revoke.key)?;
    }
    change(tx, owner, "share_revoked", revoke)
}

pub(crate) fn require_recipient_on(
    conn: &Connection,
    owner: i64,
    key: &FileKey,
) -> Result<(), StorageError> {
    require_grant_on(conn, owner, key, false)
}

pub(crate) fn require_grant_on(
    conn: &Connection,
    owner: i64,
    key: &FileKey,
    allow_rejected: bool,
) -> Result<(), StorageError> {
    let own = owner_principal_on(conn, owner)?;
    let recipient = handle_on(conn, &own)?;
    let origin = handle_on(conn, &key.origin)?;
    let allowed: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM file_share_grants g WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND recipient_principal=?5 AND (state IN ('offered','accepted') OR (?7 AND state='rejected')) AND expires_at>?6 AND NOT EXISTS(SELECT 1 FROM blocked_users b WHERE b.user_id=?1 AND b.blocked_principal=?2))", params![owner,origin,key.file_id,key.version,recipient,sync::now_millis(),allow_rejected], |r| r.get(0))?;
    if !allowed {
        return Err(StorageError::MessageUnauthorized);
    }
    Ok(())
}

pub(crate) fn retire_replica_in_tx(
    tx: &Transaction<'_>,
    owner: i64,
    key: &FileKey,
) -> Result<(), StorageError> {
    let origin = stored_handle_on(tx, &key.origin)?;
    let allowed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM file_share_grants WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4 AND state='accepted' AND expires_at>?5)", params![owner,origin,key.file_id,key.version,sync::now_millis()], |r| r.get(0))?;
    if !allowed {
        tx.execute("UPDATE user_assets SET deleted=1 WHERE user_id=?1 AND asset_id IN (SELECT j.asset_id FROM file_replication_jobs j JOIN file_versions v ON v.id=j.version_id WHERE v.storage_user_id=?1 AND v.origin_principal=?2 AND v.file_id=?3 AND v.version=?4) AND NOT EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=?1 AND v.asset_id=user_assets.asset_id)",params![owner,origin,key.file_id,key.version])?;
        tx.execute("DELETE FROM user_asset_uploads WHERE user_id=?1 AND state='uploading' AND upload_id IN (SELECT j.upload_id FROM file_replication_jobs j JOIN file_versions v ON v.id=j.version_id WHERE v.storage_user_id=?1 AND v.origin_principal=?2 AND v.file_id=?3 AND v.version=?4)",params![owner,origin,key.file_id,key.version])?;
        tx.execute("DELETE FROM file_replication_jobs WHERE version_id IN (SELECT id FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4)", params![owner,origin,key.file_id,key.version])?;
        let asset: Option<String> = tx.query_row("SELECT asset_id FROM file_versions WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4", params![owner,origin,key.file_id,key.version], |r| r.get(0)).optional()?.flatten();
        tx.execute("UPDATE file_versions SET asset_id=NULL,state='pending' WHERE storage_user_id=?1 AND origin_principal=?2 AND file_id=?3 AND version=?4", params![owner,origin,key.file_id,key.version])?;
        if let Some(asset) = asset {
            tx.execute("UPDATE user_assets SET deleted=1 WHERE user_id=?1 AND asset_id=?2 AND NOT EXISTS(SELECT 1 FROM file_versions WHERE storage_user_id=?1 AND asset_id=?2)", params![owner,asset])?;
        }
    }
    Ok(())
}
