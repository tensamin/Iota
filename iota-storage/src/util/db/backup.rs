use super::*;

/* Verify the persistent database before the pool is initialized. A corrupt
 * database is moved aside rather than opened again, preserving material for
 * operator recovery while allowing the daemon to report the failed storage. */
pub fn verify_and_backup_database() -> Result<(), StorageError> {
    let storage_dir = iota_util::file_util::storage_directory();
    std::fs::create_dir_all(&storage_dir)?;
    let path = storage_dir.join(format!("{DB_NAME}.sqlite3"));
    if !path.exists() {
        return Ok(());
    }

    let connection = Connection::open(&path)?;
    connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
    connection.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        let recovery = storage_dir.join("recovery");
        std::fs::create_dir_all(&recovery)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for suffix in ["", "-wal", "-shm"] {
            let source = PathBuf::from(format!("{}{}", path.display(), suffix));
            if source.exists() {
                let destination = recovery.join(format!("{DB_NAME}.sqlite3.{timestamp}{suffix}"));
                std::fs::rename(source, destination)?;
            }
        }
        return Err(StorageError::Other(format!(
            "database integrity check failed ({integrity}); moved database files to {}",
            recovery.display()
        )));
    }
    let backup_dir = storage_dir.join("backups");
    std::fs::create_dir_all(&backup_dir)?;
    let backup = backup_dir.join(format!("{DB_NAME}.sqlite3"));
    let temporary = backup_dir.join(format!(".{DB_NAME}.sqlite3.tmp"));
    let mut destination = Connection::open(&temporary)?;
    rusqlite::backup::Backup::new(&connection, &mut destination)?.run_to_completion(
        128,
        Duration::from_millis(10),
        None,
    )?;
    drop(destination);
    std::fs::File::open(&temporary)?.sync_all()?;
    std::fs::rename(temporary, backup)?;
    Ok(())
}

/// Create a new paired recovery snapshot. The setup is immutable while Iota is
/// running; the SQLite backup API includes committed WAL contents.
pub fn backup_password_recovery(
    identity: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), StorageError> {
    use sha2::{Digest, Sha256};
    let setup_path = identity.with_file_name("password-auth.setup");
    let setup = zeroizing_setup(&setup_path)?;
    let fingerprint = Sha256::digest(setup.as_slice());
    let staging = destination.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    std::fs::create_dir(&staging)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;
    }
    let result = (|| {
        with_db(|source| {
            let mut target = Connection::open(staging.join("messages.sqlite3"))?;
            rusqlite::backup::Backup::new(source, &mut target)?.run_to_completion(
                128,
                Duration::from_millis(10),
                None,
            )?;
            validate_recovery_database(&target, &fingerprint)?;
            Ok(())
        })?;
        if std::fs::read(&setup_path)? != setup.as_slice() {
            return Err(StorageError::Other(
                "OPAQUE setup changed during backup".into(),
            ));
        }
        iota_util::atomic_file::replace_private(&staging.join("password-auth.setup"), &setup, 0)?;
        std::fs::File::open(staging.join("messages.sqlite3"))?.sync_all()?;
        if destination.exists() {
            return Err(StorageError::Other(
                "backup destination already exists".into(),
            ));
        }
        std::fs::rename(&staging, destination)?;
        Ok(())
    })();
    if result.is_err() {
        // Only files created by this invocation are removed.
        let _ = std::fs::remove_file(staging.join("messages.sqlite3"));
        let _ = std::fs::remove_file(staging.join("password-auth.setup"));
        let _ = std::fs::remove_dir(&staging);
    }
    result
}

fn zeroizing_setup(path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>, StorageError> {
    let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
    iota_opaque::opaque::deserialize_server_setup(&bytes)
        .map_err(|error| StorageError::Other(error.to_string()))?;
    Ok(bytes)
}

fn validate_recovery_database(
    connection: &Connection,
    fingerprint: &[u8],
) -> Result<bool, StorageError> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(StorageError::Other(
            "recovery database failed integrity check".into(),
        ));
    }
    let metadata_columns: i64 = connection.query_row(
        "SELECT count(*) FROM pragma_table_info('user_password_credentials') WHERE name IN ('setup_sha256', 'password_principal', 'password_iota_id')",
        [], |row| row.get(0),
    )?;
    if metadata_columns != 3 {
        return Ok(false);
    }
    let mismatch: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM user_password_credentials WHERE setup_sha256 IS NOT NULL AND setup_sha256 != ?1)",
        [fingerprint], |row| row.get(0),
    )?;
    if mismatch {
        return Err(StorageError::Other(
            "recovery setup does not match password credentials".into(),
        ));
    }
    let legacy: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM user_password_credentials WHERE setup_sha256 IS NULL OR password_principal IS NULL OR password_iota_id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    Ok(!legacy)
}

/// Validate a pair before stopped-service restoration. False means legacy
/// provenance is unverified, not that the pair is known to be correct.
pub fn validate_password_recovery(snapshot: &std::path::Path) -> Result<bool, StorageError> {
    use sha2::{Digest, Sha256};
    let setup = zeroizing_setup(&snapshot.join("password-auth.setup"))?;
    let database = Connection::open_with_flags(
        snapshot.join("messages.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    validate_recovery_database(&database, &Sha256::digest(setup.as_slice()))
}

/// Restore into a new directory, never over a running or existing database.
/// Stop Iota, then configure its identity/storage overrides to the returned pair.
pub fn restore_password_recovery(
    snapshot: &std::path::Path,
    destination: &std::path::Path,
) -> Result<bool, StorageError> {
    let verified = validate_password_recovery(snapshot)?;
    std::fs::create_dir(destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))?;
    }
    let setup = zeroizing_setup(&snapshot.join("password-auth.setup"))?;
    iota_util::atomic_file::replace_private(&destination.join("password-auth.setup"), &setup, 0)?;
    let source = Connection::open_with_flags(
        snapshot.join("messages.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut target = Connection::open(destination.join("messages.sqlite3"))?;
    rusqlite::backup::Backup::new(&source, &mut target)?.run_to_completion(
        128,
        Duration::from_millis(10),
        None,
    )?;
    drop(target);
    std::fs::File::open(destination.join("messages.sqlite3"))?.sync_all()?;
    validate_password_recovery(destination)?;
    Ok(verified)
}

pub(super) fn db_file_path(db_name: &str) -> PathBuf {
    let storage_dir = iota_util::file_util::storage_directory();
    // Creating storage belongs to initialization/connection setup, never to a
    // configuration read.
    std::fs::create_dir_all(&storage_dir).expect("create Iota storage directory");
    storage_dir.join(format!("{db_name}.sqlite3"))
}
