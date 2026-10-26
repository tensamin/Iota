use iota_storage::{
    users::{
        password_credentials::{self, PasswordCredential},
        user_manager,
    },
    util::db,
};
use std::sync::{Arc, Barrier};

#[test]
fn lost_ack_receipts_and_release_snapshots_are_atomic_and_erasure_fenced() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().join("storage"));
    db::initialize_database().unwrap();
    db::with_db(|conn| {
        conn.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'alice','account-key',1)", [])?;
        conn.execute("INSERT INTO user_residency(user_id,username,lifecycle_state,data_state,credential_origin,updated_at) VALUES(7,'alice','managed','present','external',1)", [])?;
        Ok(())
    }).unwrap();
    let (key, generation) = password_credentials::authorization(7).unwrap();
    let credential = PasswordCredential {
        user_id: 7,
        opaque_profile: 1,
        opaque_record: vec![1],
        encrypted_tu_credential: vec![2],
        account_public_key_sha256: vec![3; 32],
        created_at: 1,
        updated_at: 1,
        setup_sha256: Some(vec![4; 32]),
        password_principal: Some("omega:test#7".into()),
        password_iota_id: Some(11),
    };
    // Simulate losing the response after SQLite committed. A separate read
    // recovers the receipt without re-running an enrollment or changing bytes.
    password_credentials::commit_enrollment(&credential, &key, generation, ("finish-1", &[1; 32]))
        .unwrap();
    assert_eq!(
        password_credentials::mutation_outcome(7, &key, generation, ("finish-1", &[1; 32]))
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        password_credentials::mutation_outcome(7, &key, generation, ("finish-1", &[2; 32]))
            .unwrap(),
        None
    );
    assert_eq!(
        password_credentials::mutation_outcome(7, &key, generation, ("unknown", &[1; 32])).unwrap(),
        None
    );
    let mut alternate = credential.clone();
    alternate.encrypted_tu_credential = vec![99];
    assert!(
        password_credentials::commit_enrollment(
            &alternate,
            &key,
            generation,
            ("finish-1", &[2; 32])
        )
        .is_err()
    );
    assert_eq!(
        password_credentials::get(7).unwrap(),
        Some(credential.clone())
    );

    let released = Arc::new(Barrier::new(2));
    let deliver = Arc::new(Barrier::new(2));
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            password_credentials::authorize_release(&credential, &key, generation).unwrap();
            released.wait();
            deliver.wait();
            sender
                .send(credential.encrypted_tu_credential.clone())
                .unwrap();
        });
        released.wait();
        password_credentials::commit_disable(7, &key, generation, ("disable-1", &[3; 32])).unwrap();
        assert!(password_credentials::authorize_release(&credential, &key, generation).is_err());
        deliver.wait();
        // The release was granted before disablement. Delivery may be delayed;
        // disablement does not promise recall of an already-granted response.
        assert_eq!(receiver.recv().unwrap(), credential.encrypted_tu_credential);
    });
    assert_eq!(
        password_credentials::mutation_outcome(7, &key, generation, ("disable-1", &[3; 32]))
            .unwrap(),
        Some(false)
    );
    assert!(password_credentials::get(7).unwrap().is_none());
    assert!(
        password_credentials::commit_enrollment(
            &credential,
            &key,
            generation,
            ("finish-1", &[1; 32])
        )
        .is_err()
    );
    assert!(password_credentials::get(7).unwrap().is_none());
    // A key rotation fences both release and historical receipt disclosure.
    let mut profile = user_manager::get_user(7).unwrap().unwrap();
    profile.public_key = "rotated-key".into();
    user_manager::update_user(profile).unwrap();
    assert!(password_credentials::authorize_release(&credential, &key, generation).is_err());
    assert_eq!(
        password_credentials::mutation_outcome(7, &key, generation, ("finish-1", &[1; 32]))
            .unwrap(),
        None
    );
    assert_eq!(
        db::with_db(|conn| Ok(conn.query_row(
            "SELECT count(*) FROM user_password_mutations",
            [],
            |row| row.get::<_, i64>(0)
        )?))
        .unwrap(),
        0
    );
}
