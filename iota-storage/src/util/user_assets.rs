use crate::storage_error::StorageError;
use crate::util::{config_util::CONFIG, db, sync};
use rand::RngCore;
use rusqlite::{OptionalExtension, Row, params};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};

pub const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const ABANDONED_UPLOAD_MS: i64 = 24 * 60 * 60 * 1_000;
const CLEANUP_INTERVAL_MS: i64 = 15 * 60 * 1_000;
static LAST_CLEANUP: AtomicI64 = AtomicI64::new(0);

#[derive(Debug, Clone)]
pub struct UserAssetMetadata {
    pub id: i64,
    pub user_id: i64,
    pub asset_id: String,
    pub size: i64,
    pub sha256: Vec<u8>,
    pub mime_type: String,
    pub revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct UploadStatus {
    pub upload_id: String,
    pub asset_id: String,
    pub size: i64,
    pub sha256: Vec<u8>,
    pub mime_type: String,
    pub offset: i64,
    pub state: String,
    pub revision: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub committed_at: Option<i64>,
}

fn asset_dir() -> Result<PathBuf, StorageError> {
    let path = iota_util::file_util::storage_directory().join("assets");
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn random_file_name() -> String {
    let mut bytes = [0_u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate(user_id: i64, asset_id: &str, upload_id: Option<&str>) -> Result<(), StorageError> {
    if user_id <= 0 || asset_id.is_empty() || asset_id.len() > 256 {
        return Err(StorageError::Other("invalid asset owner or id".into()));
    }
    if upload_id.is_some_and(|id| id.is_empty() || id.len() > 128) {
        return Err(StorageError::Other("invalid upload id".into()));
    }
    Ok(())
}

fn upload_from_row(row: &Row<'_>) -> rusqlite::Result<(UploadStatus, String)> {
    Ok((
        UploadStatus {
            upload_id: row.get(0)?,
            asset_id: row.get(2)?,
            size: row.get(4)?,
            sha256: row.get(5)?,
            mime_type: row.get(6)?,
            offset: row.get(7)?,
            state: row.get(8)?,
            revision: row.get(9)?,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
            committed_at: row.get(12)?,
        },
        row.get(3)?,
    ))
}

fn metadata_from_row(row: &Row<'_>) -> rusqlite::Result<UserAssetMetadata> {
    Ok(UserAssetMetadata {
        id: row.get(0)?,
        user_id: row.get(1)?,
        asset_id: row.get(2)?,
        size: row.get(4)?,
        sha256: row.get(5)?,
        mime_type: row.get(6)?,
        revision: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn load_upload(
    user_id: i64,
    upload_id: &str,
) -> Result<Option<(UploadStatus, String)>, StorageError> {
    db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT upload_id, user_id, asset_id, file_name, size, sha256, mime_type, received, state, revision, created_at, updated_at, committed_at FROM user_asset_uploads WHERE user_id = ?1 AND upload_id = ?2",
            params![user_id, upload_id],
            upload_from_row,
        ).optional()?)
    })
}

fn reconcile_offset(
    user_id: i64,
    mut status: UploadStatus,
    file_name: &str,
) -> Result<UploadStatus, StorageError> {
    if status.state != "uploading" {
        return Ok(status);
    }
    let actual = i64::try_from(fs::metadata(asset_dir()?.join(file_name))?.len())
        .map_err(|_| StorageError::Other("upload file exceeds supported size".into()))?;
    if actual > status.size {
        return Err(StorageError::Other(
            "upload file exceeds declared size".into(),
        ));
    }
    if actual != status.offset {
        let now = sync::now_millis();
        db::with_db(|conn| {
            conn.execute(
                "UPDATE user_asset_uploads SET received = ?3, updated_at = ?4 WHERE user_id = ?1 AND upload_id = ?2 AND state = 'uploading'",
                params![user_id, status.upload_id, actual, now],
            )?;
            Ok(())
        })?;
        status.offset = actual;
        status.updated_at = now;
    }
    Ok(status)
}

pub fn start(
    user_id: i64,
    upload_id: &str,
    asset_id: &str,
    size: i64,
    sha256: &[u8],
    mime_type: &str,
) -> Result<UploadStatus, StorageError> {
    validate(user_id, asset_id, Some(upload_id))?;
    if size < 0 || sha256.len() != 32 || mime_type.is_empty() || mime_type.len() > 255 {
        return Err(StorageError::Other("invalid asset metadata".into()));
    }
    let config = CONFIG.load();
    let limits = &config.storage_limits;
    if size > limits.max_asset_bytes {
        return Err(StorageError::AssetResourceLimit("max_asset_bytes"));
    }
    cleanup_if_due()?;
    if let Some((status, file_name)) = load_upload(user_id, upload_id)? {
        if status.asset_id != asset_id
            || status.size != size
            || status.sha256 != sha256
            || status.mime_type != mime_type
        {
            return Err(StorageError::Other(
                "upload id already has different metadata".into(),
            ));
        }
        return reconcile_offset(user_id, status, &file_name);
    }

    let file_name = random_file_name();
    let directory = asset_dir()?;
    let required_free = limits
        .min_free_asset_storage_bytes
        .checked_add(
            u64::try_from(size).map_err(|_| StorageError::Other("invalid asset size".into()))?,
        )
        .ok_or_else(|| StorageError::Other("filesystem reservation overflow".into()))?;
    if fs2::available_space(&directory)? < required_free {
        return Err(StorageError::AssetResourceLimit(
            "min_free_asset_storage_bytes",
        ));
    }
    let path = directory.join(&file_name);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .sync_all()?;
    let now = sync::now_millis();
    let inserted = db::with_immediate_transaction(|tx| {
        let committed: i64 = tx.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM user_assets WHERE user_id = ?1 AND deleted = 0",
            [user_id],
            |row| row.get(0),
        )?;
        let (reserved, active): (i64, i64) = tx.query_row(
            "SELECT COALESCE(SUM(size), 0), COUNT(*) FROM user_asset_uploads WHERE user_id = ?1 AND state = 'uploading'",
            [user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if usize::try_from(active)
            .ok()
            .is_none_or(|count| count >= limits.max_active_asset_uploads_per_user)
        {
            return Err(StorageError::AssetResourceLimit(
                "max_active_asset_uploads_per_user",
            ));
        }
        let proposed = committed
            .checked_add(reserved)
            .and_then(|value| value.checked_add(size))
            .ok_or_else(|| StorageError::Other("asset quota accounting overflow".into()))?;
        if proposed > limits.max_user_asset_bytes {
            return Err(StorageError::AssetResourceLimit("max_user_asset_bytes"));
        }
        tx.execute(
            "INSERT INTO user_asset_uploads (upload_id, user_id, asset_id, file_name, size, sha256, mime_type, received, state, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 'uploading', ?8, ?8)",
            params![upload_id, user_id, asset_id, file_name, size, sha256, mime_type, now],
        )?;
        Ok(())
    });
    if let Err(error) = inserted {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(UploadStatus {
        upload_id: upload_id.into(),
        asset_id: asset_id.into(),
        size,
        sha256: sha256.into(),
        mime_type: mime_type.into(),
        offset: 0,
        state: "uploading".into(),
        revision: None,
        created_at: now,
        updated_at: now,
        committed_at: None,
    })
}

pub fn status(user_id: i64, upload_id: &str) -> Result<Option<UploadStatus>, StorageError> {
    let Some((status, file_name)) = load_upload(user_id, upload_id)? else {
        return Ok(None);
    };
    reconcile_offset(user_id, status, &file_name).map(Some)
}

pub fn append(
    user_id: i64,
    upload_id: &str,
    offset: i64,
    chunk: &[u8],
) -> Result<UploadStatus, StorageError> {
    if chunk.is_empty() || chunk.len() > MAX_CHUNK_BYTES {
        return Err(StorageError::Other("invalid asset chunk size".into()));
    }
    let Some((status, file_name)) = load_upload(user_id, upload_id)? else {
        return Err(StorageError::Other("upload not found".into()));
    };
    let status = reconcile_offset(user_id, status, &file_name)?;
    let chunk_len = i64::try_from(chunk.len())
        .map_err(|_| StorageError::Other("asset chunk length overflow".into()))?;
    let end = offset
        .checked_add(chunk_len)
        .ok_or_else(|| StorageError::Other("asset chunk offset overflow".into()))?;
    if status.state != "uploading" || offset != status.offset || end > status.size {
        return Err(StorageError::Other(
            "asset chunk offset does not match acknowledged offset".into(),
        ));
    }
    let path = asset_dir()?.join(file_name);
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(chunk)?;
    file.sync_data()?;
    let received = end;
    let now = sync::now_millis();
    db::with_db(|conn| {
        conn.execute(
            "UPDATE user_asset_uploads SET received = ?3, updated_at = ?4 WHERE user_id = ?1 AND upload_id = ?2 AND state = 'uploading'",
            params![user_id, upload_id, received, now],
        )?;
        Ok(())
    })?;
    Ok(UploadStatus {
        offset: received,
        updated_at: now,
        ..status
    })
}

pub fn commit(user_id: i64, upload_id: &str) -> Result<(UserAssetMetadata, bool), StorageError> {
    let Some((status, file_name)) = load_upload(user_id, upload_id)? else {
        return Err(StorageError::Other("upload not found".into()));
    };
    if status.state == "committed" {
        return Ok((
            UserAssetMetadata {
                id: 0,
                user_id,
                asset_id: status.asset_id,
                size: status.size,
                sha256: status.sha256,
                mime_type: status.mime_type,
                revision: status.revision.ok_or_else(|| {
                    StorageError::Other("committed upload has no revision".into())
                })?,
                created_at: status.created_at,
                updated_at: status.committed_at.unwrap_or(status.updated_at),
            },
            false,
        ));
    }
    let status = reconcile_offset(user_id, status, &file_name)?;
    if status.offset != status.size {
        return Err(StorageError::Other("upload is incomplete".into()));
    }
    let path = asset_dir()?.join(&file_name);
    let mut file = File::open(&path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    if hash.finalize().as_slice() != status.sha256 {
        return Err(StorageError::Other("asset SHA-256 mismatch".into()));
    }

    let now = sync::now_millis();
    let (metadata, replaced_file) = db::with_immediate_transaction(|tx| {
        let existing = tx.query_row(
            "SELECT id, file_name, created_at FROM user_assets WHERE user_id = ?1 AND asset_id = ?2",
            params![user_id, status.asset_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)),
        ).optional()?;
        let id = if let Some(existing) = &existing {
            existing.0
        } else {
            tx.execute(
                "INSERT INTO user_assets (user_id, asset_id, file_name, size, sha256, mime_type, revision, created_at, updated_at, published_upload_id, deleted) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7, ?8, 0)",
                params![user_id, status.asset_id, file_name, status.size, status.sha256, status.mime_type, now, upload_id],
            )?;
            tx.last_insert_rowid()
        };
        let revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::UserAsset,
            id,
            sync::Operation::Upsert,
        )?;
        let created_at = existing.as_ref().map(|value| value.2).unwrap_or(now);
        tx.execute(
            "UPDATE user_assets SET file_name = ?2, size = ?3, sha256 = ?4, mime_type = ?5, revision = ?6, updated_at = ?7, published_upload_id = ?8, deleted = 0 WHERE id = ?1",
            params![id, file_name, status.size, status.sha256, status.mime_type, revision, now, upload_id],
        )?;
        tx.execute(
            "UPDATE user_asset_uploads SET state = 'committed', revision = ?3, updated_at = ?4, committed_at = ?4 WHERE user_id = ?1 AND upload_id = ?2",
            params![user_id, upload_id, revision, now],
        )?;
        Ok((
            UserAssetMetadata {
                id,
                user_id,
                asset_id: status.asset_id.clone(),
                size: status.size,
                sha256: status.sha256.clone(),
                mime_type: status.mime_type.clone(),
                revision,
                created_at,
                updated_at: now,
            },
            existing
                .map(|value| value.1)
                .filter(|old| old != &file_name),
        ))
    })?;
    if let Some(old) = replaced_file {
        let _ = fs::remove_file(asset_dir()?.join(old));
    }
    Ok((metadata, true))
}

pub fn abort(user_id: i64, upload_id: &str) -> Result<bool, StorageError> {
    let upload = load_upload(user_id, upload_id)?;
    let Some((status, file_name)) = upload else {
        return Ok(false);
    };
    if status.state == "committed" {
        return Ok(false);
    }
    db::with_db(|conn| {
        conn.execute("DELETE FROM user_asset_uploads WHERE user_id = ?1 AND upload_id = ?2 AND state = 'uploading'", params![user_id, upload_id])?;
        Ok(())
    })?;
    match fs::remove_file(asset_dir()?.join(file_name)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

pub const ASSET_PAGE_SIZE: i64 = 128;

pub fn list_page(
    user_id: i64,
    after_id: Option<i64>,
) -> Result<(Vec<UserAssetMetadata>, Option<i64>), StorageError> {
    if user_id <= 0 || after_id.is_some_and(|id| id <= 0) {
        return Err(StorageError::Other("invalid asset list cursor".into()));
    }
    cleanup_if_due()?;
    db::with_db(|conn| {
        let mut statement = conn.prepare("SELECT id, user_id, asset_id, file_name, size, sha256, mime_type, revision, created_at, updated_at FROM user_assets WHERE user_id = ?1 AND deleted = 0 AND id < ?2 ORDER BY id DESC LIMIT ?3")?;
        let mut items = statement
            .query_map(
                params![user_id, after_id.unwrap_or(i64::MAX), ASSET_PAGE_SIZE + 1],
                metadata_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let next = if items.len() > ASSET_PAGE_SIZE as usize {
            items.pop();
            items.last().map(|asset| asset.id)
        } else {
            None
        };
        Ok((items, next))
    })
}

pub fn list(user_id: i64) -> Result<Vec<UserAssetMetadata>, StorageError> {
    cleanup_if_due()?;
    db::with_db(|conn| {
        let mut statement = conn.prepare("SELECT id, user_id, asset_id, file_name, size, sha256, mime_type, revision, created_at, updated_at FROM user_assets WHERE user_id = ?1 AND deleted = 0 ORDER BY updated_at DESC")?;
        statement
            .query_map([user_id], metadata_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    })
}

pub fn read_chunk(
    user_id: i64,
    asset_id: &str,
    offset: i64,
    amount: usize,
) -> Result<Option<(UserAssetMetadata, Vec<u8>)>, StorageError> {
    validate(user_id, asset_id, None)?;
    if offset < 0 || amount == 0 || amount > MAX_CHUNK_BYTES {
        return Err(StorageError::Other("invalid asset chunk range".into()));
    }
    let value = db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT id, user_id, asset_id, file_name, size, sha256, mime_type, revision, created_at, updated_at FROM user_assets WHERE user_id = ?1 AND asset_id = ?2 AND deleted = 0",
            params![user_id, asset_id],
            |row| Ok((metadata_from_row(row)?, row.get::<_, String>(3)?)),
        ).optional()?)
    })?;
    let Some((metadata, file_name)) = value else {
        return Ok(None);
    };
    if offset > metadata.size {
        return Err(StorageError::Other("asset offset exceeds size".into()));
    }
    let mut file = File::open(asset_dir()?.join(file_name))?;
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut bytes = vec![0; amount.min((metadata.size - offset) as usize)];
    file.read_exact(&mut bytes)?;
    Ok(Some((metadata, bytes)))
}

pub fn delete(user_id: i64, asset_id: &str) -> Result<Option<UserAssetMetadata>, StorageError> {
    validate(user_id, asset_id, None)?;
    let deleted = db::with_immediate_transaction(|tx| {
        let value = tx.query_row(
            "SELECT id, user_id, asset_id, file_name, size, sha256, mime_type, revision, created_at, updated_at FROM user_assets WHERE user_id = ?1 AND asset_id = ?2 AND deleted = 0",
            params![user_id, asset_id],
            |row| Ok((metadata_from_row(row)?, row.get::<_, String>(3)?)),
        ).optional()?;
        let Some((mut metadata, file_name)) = value else {
            return Ok(None);
        };
        metadata.revision = sync::record_event(
            tx,
            user_id,
            sync::EntityType::UserAsset,
            metadata.id,
            sync::Operation::Delete,
        )?;
        metadata.updated_at = sync::now_millis();
        tx.execute(
            "UPDATE user_assets SET deleted = 1, revision = ?2, updated_at = ?3 WHERE id = ?1",
            params![metadata.id, metadata.revision, metadata.updated_at],
        )?;
        Ok(Some((metadata, file_name)))
    })?;
    let Some((metadata, file_name)) = deleted else {
        return Ok(None);
    };
    let _ = fs::remove_file(asset_dir()?.join(file_name));
    Ok(Some(metadata))
}

pub fn purge_user(user_id: i64) -> Result<(), StorageError> {
    let files = db::with_immediate_transaction(|tx| {
        let mut files = HashSet::new();
        for query in [
            "SELECT file_name FROM user_assets WHERE user_id = ?1",
            "SELECT file_name FROM user_asset_uploads WHERE user_id = ?1",
        ] {
            let mut statement = tx.prepare(query)?;
            for file in statement.query_map([user_id], |row| row.get::<_, String>(0))? {
                files.insert(file?);
            }
        }
        tx.execute("DELETE FROM user_assets WHERE user_id = ?1", [user_id])?;
        tx.execute(
            "DELETE FROM user_asset_uploads WHERE user_id = ?1",
            [user_id],
        )?;
        Ok(files)
    })?;
    let directory = asset_dir()?;
    for file in files {
        match fs::remove_file(directory.join(file)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn cleanup_if_due() -> Result<(), StorageError> {
    let now = sync::now_millis();
    let previous = LAST_CLEANUP.load(Ordering::Relaxed);
    if now - previous < CLEANUP_INTERVAL_MS
        || LAST_CLEANUP
            .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return Ok(());
    }
    let cutoff = now - ABANDONED_UPLOAD_MS;
    let abandoned = db::with_db(|conn| {
        let mut statement = conn.prepare("SELECT file_name FROM user_asset_uploads WHERE state = 'uploading' AND updated_at < ?1")?;
        let files = statement
            .query_map([cutoff], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        conn.execute(
            "DELETE FROM user_asset_uploads WHERE state = 'uploading' AND updated_at < ?1",
            [cutoff],
        )?;
        Ok(files)
    })?;
    let dir = asset_dir()?;
    for file in abandoned {
        let _ = fs::remove_file(dir.join(file));
    }
    let referenced = db::with_db(|conn| {
        let mut files = HashSet::new();
        for query in [
            "SELECT file_name FROM user_assets WHERE deleted = 0",
            "SELECT file_name FROM user_asset_uploads WHERE state = 'uploading'",
        ] {
            let mut statement = conn.prepare(query)?;
            for file in statement.query_map([], |row| row.get::<_, String>(0))? {
                files.insert(file?);
            }
        }
        Ok(files)
    })?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && !referenced.contains(&entry.file_name().to_string_lossy().into_owned())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}
