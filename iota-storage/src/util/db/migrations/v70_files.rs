use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 70 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS file_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            storage_user_id INTEGER NOT NULL,
            origin_principal INTEGER NOT NULL,
            file_id TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            manifest TEXT NOT NULL,
            metadata_revision INTEGER NOT NULL DEFAULT 1,
            asset_id TEXT,
            state TEXT NOT NULL CHECK(state IN ('pending','transferring','ready','failed','deleted')),
            UNIQUE(storage_user_id,origin_principal,file_id,version)
        );
        CREATE TABLE IF NOT EXISTS file_tombstones (
            storage_user_id INTEGER NOT NULL, origin_principal INTEGER NOT NULL, file_id TEXT NOT NULL,
            PRIMARY KEY(storage_user_id,origin_principal,file_id)
        );
        CREATE INDEX IF NOT EXISTS file_version_asset ON file_versions(storage_user_id,asset_id);
        CREATE TABLE IF NOT EXISTS file_folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            folder_id TEXT NOT NULL, parent_folder_id TEXT NOT NULL,
            revision INTEGER NOT NULL, payload TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
            UNIQUE(storage_user_id,folder_id)
        );
        CREATE INDEX IF NOT EXISTS file_folder_parent ON file_folders(storage_user_id,parent_folder_id,deleted,id);
        CREATE TABLE IF NOT EXISTS file_placements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            placement_id TEXT NOT NULL, origin_principal INTEGER NOT NULL, file_id TEXT NOT NULL,
            folder_id TEXT NOT NULL, revision INTEGER NOT NULL, payload TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            UNIQUE(storage_user_id,placement_id)
        );
        CREATE INDEX IF NOT EXISTS file_placement_folder ON file_placements(storage_user_id,folder_id,deleted,id);
        CREATE TABLE IF NOT EXISTS file_share_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            origin_principal INTEGER NOT NULL, file_id TEXT NOT NULL, version INTEGER NOT NULL,
            recipient_principal INTEGER NOT NULL, chat_id TEXT NOT NULL, revision INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('offered','accepted','revoked','rejected')),
            expires_at INTEGER NOT NULL, manifest TEXT, source_node TEXT,
            proof TEXT,
            UNIQUE(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id)
        );
        CREATE INDEX IF NOT EXISTS file_grant_chat ON file_share_grants(storage_user_id,chat_id,state,id);
        CREATE TABLE IF NOT EXISTS file_replication_jobs (
            version_id INTEGER PRIMARY KEY, upload_id TEXT NOT NULL, asset_id TEXT NOT NULL,
            next_attempt_at INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS file_changes (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            kind TEXT NOT NULL, payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS file_replication_schedule ON file_replication_jobs(next_attempt_at,version_id);
        CREATE INDEX IF NOT EXISTS file_changes_owner ON file_changes(storage_user_id,sequence);
        CREATE TABLE IF NOT EXISTS file_managed_assets (
            storage_user_id INTEGER NOT NULL, asset_id TEXT NOT NULL,
            released_at INTEGER,
            PRIMARY KEY(storage_user_id,asset_id)
        );
        CREATE TABLE IF NOT EXISTS file_transfer_usage (
            storage_user_id INTEGER NOT NULL, recipient_principal INTEGER NOT NULL,
            day INTEGER NOT NULL, bytes INTEGER NOT NULL,
            PRIMARY KEY(storage_user_id,recipient_principal)
        );"
    )?;
    let assets: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_assets')",
        [],
        |r| r.get(0),
    )?;
    if assets {
        tx.execute_batch("CREATE TRIGGER IF NOT EXISTS file_asset_immutable BEFORE UPDATE ON user_assets
        WHEN EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=OLD.user_id AND v.asset_id=OLD.asset_id)
          AND (NEW.file_name!=OLD.file_name OR NEW.sha256!=OLD.sha256 OR NEW.size!=OLD.size OR NEW.deleted!=OLD.deleted)
        BEGIN SELECT RAISE(ABORT,'file version asset is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS file_asset_pinned BEFORE DELETE ON user_assets
        WHEN EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=OLD.user_id AND v.asset_id=OLD.asset_id)
        BEGIN SELECT RAISE(ABORT,'file version asset is referenced'); END;"
        )?;
    }
    tx.pragma_update(None, "user_version", 70)?;
    tx.commit()?;
    Ok(())
}
