use std::sync::{Arc, Barrier};

use iota_storage::{
    users::{
        password_credentials::{self, PasswordCredential},
        user_manager,
    },
    util::db,
};
use sha2::{Digest, Sha256};

#[test]
fn enrollment_rotation_disable_and_paired_recovery_are_serialized() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().join("storage"));
    db::initialize_database().unwrap();
    db::with_db(|connection| {
        connection.execute("INSERT INTO users (user_id, username, public_key, created_at) VALUES (7, 'alice', 'old', 1)", [])?;
        Ok(())
    }).unwrap();
    let setup = iota_opaque::opaque::generate_server_setup();
    let setup_bytes = iota_opaque::opaque::serialize_server_setup(&setup);
    let credential = PasswordCredential {
        user_id: 7,
        opaque_profile: 1,
        opaque_record: vec![1],
        encrypted_tu_credential: vec![2],
        account_public_key_sha256: vec![3; 32],
        created_at: 1,
        updated_at: 1,
        setup_sha256: Some(Sha256::digest(&setup_bytes).to_vec()),
        password_principal: Some("omega#7".into()),
        password_iota_id: Some(11),
    };
    let authorized = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        let enrollment = scope.spawn(|| {
            let (key, generation) = password_credentials::authorization(7).unwrap();
            authorized.wait();
            resume.wait();
            password_credentials::upsert_if_authorized(&credential, &key, generation)
        });
        authorized.wait();
        let mut profile = user_manager::get_user(7).unwrap().unwrap();
        profile.public_key = "new".into();
        user_manager::update_user(profile).unwrap();
        resume.wait();
        assert!(enrollment.join().unwrap().is_err());
    });
    assert!(password_credentials::get(7).unwrap().is_none());
    // A rotate-away-and-back must not revive an old authorization generation.
    assert!(password_credentials::upsert_if_authorized(&credential, "new", 1).is_err());
    let (key, generation) = password_credentials::authorization(7).unwrap();
    password_credentials::upsert_if_authorized(&credential, &key, generation).unwrap();
    password_credentials::delete(7).unwrap();
    assert!(password_credentials::get(7).unwrap().is_none());
    password_credentials::delete(7).unwrap();
    password_credentials::upsert_if_authorized(&credential, &key, generation).unwrap();
    assert_eq!(
        password_credentials::get(7).unwrap(),
        Some(credential.clone())
    );
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let enroll = scope.spawn(|| {
            barrier.wait();
            password_credentials::upsert_if_authorized(&credential, &key, generation)
        });
        barrier.wait();
        password_credentials::delete(7).unwrap();
        enroll.join().unwrap().unwrap();
    });
    let result = password_credentials::get(7).unwrap();
    assert!(result.is_none() || result == Some(credential.clone()));
    password_credentials::upsert_if_authorized(&credential, &key, generation).unwrap();

    let identity = directory.path().join("identity.keyring");
    std::fs::write(identity.with_file_name("password-auth.setup"), &setup_bytes).unwrap();
    let snapshot = directory.path().join("snapshot");
    db::backup_password_recovery(&identity, &snapshot).unwrap();
    assert!(db::validate_password_recovery(&snapshot).unwrap());
    let restored = directory.path().join("restored");
    assert!(db::restore_password_recovery(&snapshot, &restored).unwrap());
    assert!(db::validate_password_recovery(&restored).unwrap());
    let restored_db = rusqlite::Connection::open(restored.join("messages.sqlite3")).unwrap();
    assert_eq!(
        restored_db
            .query_row(
                "SELECT opaque_record FROM user_password_credentials WHERE user_id = 7",
                [],
                |row| row.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
        credential.opaque_record
    );
    assert!(db::restore_password_recovery(&snapshot, &restored).is_err());
    // Restoration validation must reject a different, perfectly valid setup.
    let wrong = iota_opaque::opaque::generate_server_setup();
    std::fs::write(
        snapshot.join("password-auth.setup"),
        iota_opaque::opaque::serialize_server_setup(&wrong),
    )
    .unwrap();
    assert!(db::validate_password_recovery(&snapshot).is_err());
    std::fs::write(snapshot.join("password-auth.setup"), b"corrupt").unwrap();
    assert!(db::validate_password_recovery(&snapshot).is_err());
    std::fs::remove_file(snapshot.join("password-auth.setup")).unwrap();
    assert!(db::validate_password_recovery(&snapshot).is_err());
}
