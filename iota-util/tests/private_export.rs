use iota_util::atomic_file::create_private;

#[test]
fn private_export_refuses_to_replace_existing_file() {
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
fn private_export_uses_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alice.tu");
    create_private(&path, b"secret").unwrap();

    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
