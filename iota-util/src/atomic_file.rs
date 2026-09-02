use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMPORARY_ID: AtomicU64 = AtomicU64::new(0);

/* Persist small state files without exposing a partially written version after
 * a crash. Backups give operators a local recovery point for keys and config. */
pub fn replace(path: &Path, contents: &[u8], backup_limit: usize) -> io::Result<()> {
    replace_with_mode(path, contents, backup_limit, false)
}

pub fn replace_private(path: &Path, contents: &[u8], backup_limit: usize) -> io::Result<()> {
    replace_with_mode(path, contents, backup_limit, true)
}

/* Create exported secret material without replacing an existing destination.
 * Operators must choose another path explicitly if a file already exists. */
pub fn create_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "export file has no parent directory",
        )
    })?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = set_private_permissions(path, true) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    let write_result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        if !parent.as_os_str().is_empty() {
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if write_result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    write_result
}

fn replace_with_mode(
    path: &Path,
    contents: &[u8],
    backup_limit: usize,
    private: bool,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "persistent file has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;

    if backup_limit > 0 && path.is_file() {
        create_backup(path, backup_limit)?;
    }

    let temporary = temporary_path(path)?;
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_private_permissions(&temporary, private)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, private: bool) -> io::Result<()> {
    if private {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _private: bool) -> io::Result<()> {
    Ok(())
}

fn create_backup(path: &Path, backup_limit: usize) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "persistent file has no parent directory",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "persistent file has no name")
    })?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let id = TEMPORARY_ID.fetch_add(1, Ordering::Relaxed);
    let backup = parent.join(format!(
        ".{}.backup-{timestamp}-{id}",
        name.to_string_lossy()
    ));
    fs::copy(path, &backup)?;
    File::open(&backup)?.sync_all()?;
    sync_directory(parent)?;

    let prefix = format!(".{}.backup-", name.to_string_lossy());
    let mut backups = fs::read_dir(parent)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .collect::<Vec<_>>();
    backups.sort_by_key(|entry| entry.file_name());
    let obsolete = backups.len().saturating_sub(backup_limit);
    for entry in backups.into_iter().take(obsolete) {
        fs::remove_file(entry.path())?;
    }
    Ok(())
}

fn temporary_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "persistent file has no parent directory",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "persistent file has no name")
    })?;
    let id = TEMPORARY_ID.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        id
    )))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{create_private, replace};

    #[test]
    fn replace_preserves_a_previous_version_as_a_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        replace(&path, b"first", 2).unwrap();
        replace(&path, b"second", 2).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let backups = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".state.backup-")
            })
            .count();
        assert_eq!(backups, 1);
    }

    #[test]
    fn create_private_refuses_to_replace_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alice.tu");
        create_private(&path, b"first").unwrap();

        assert_eq!(
            create_private(&path, b"second").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(path).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn create_private_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alice.tu");
        create_private(&path, b"secret").unwrap();

        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
