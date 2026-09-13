use super::UserEntry;
use ratatool::TextInputState;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

#[derive(Clone, Debug)]
pub struct CredentialExportState {
    pub user: UserEntry,
    pub destination: TextInputState,
    pub error: Option<String>,
}

impl CredentialExportState {
    pub fn new(user: UserEntry) -> Self {
        Self {
            user,
            destination: TextInputState::default(),
            error: None,
        }
    }
}

/* Export credentials with owner-only permissions and refuse to replace an
 * existing destination so a typo cannot destroy another file. */
pub fn write_private_export(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "export path has no parent"))?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::write_private_export;

    #[test]
    fn export_refuses_to_replace_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alice.tu");
        write_private_export(&path, b"first").unwrap();

        assert_eq!(
            write_private_export(&path, b"second").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(path).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn export_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alice.tu");
        write_private_export(&path, b"secret").unwrap();

        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
