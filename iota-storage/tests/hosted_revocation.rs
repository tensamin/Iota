use iota_identity::{
    AuthorityKind, HostedAuthorizationLease, LocalNodeIdentity, LocalUserDescriptor, LocalUserId,
    PrincipalHome,
};
use iota_storage::{hosted_auth, identity::SqlitePrincipalStore, util::db};

#[test]
fn failed_durable_revocation_immediately_denies_clones_and_retry_persists_it() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    db::initialize_database().unwrap();
    let node = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let user = LocalUserDescriptor {
        id: LocalUserId(1),
        username: "alice".into(),
        display_name: None,
        public_key: node.public_keys().try_to_base64().unwrap(),
    };
    db::with_db(|connection| {
        connection.execute("INSERT INTO users (user_id, username, public_key, created_at) VALUES (1, 'alice', ?1, 1)", [&user.public_key])?;
        Ok(())
    }).unwrap();
    SqlitePrincipalStore
        .ensure_local_principal(
            node.authority_id(),
            AuthorityKind::Iota,
            &user,
            PrincipalHome::Iota(node.node_id().clone()),
            iota_storage::util::sync::now_millis(),
        )
        .unwrap();
    hosted_auth::maintain_server("revocation-test", true).unwrap();
    let lease = HostedAuthorizationLease {
        connection_id: "revocation-test-connection".into(),
        server_instance: "revocation-test".into(),
        identity: hosted_auth::resolve(user.id).unwrap().0,
    };
    hosted_auth::register(&lease).unwrap();
    let cloned = lease.clone();
    db::with_db(|connection| {
        connection.execute_batch("CREATE TRIGGER fail_revocation BEFORE UPDATE ON hosted_connection_authorizations BEGIN SELECT RAISE(ABORT, 'injected revocation failure'); END;")?;
        Ok(())
    }).unwrap();
    assert!(hosted_auth::remove(&lease.connection_id).is_err());
    assert!(hosted_auth::verify(&cloned).is_err());
    assert_eq!(
        hosted_auth::verify_batch(std::slice::from_ref(&cloned)).unwrap(),
        vec![lease.connection_id.clone()]
    );
    db::with_immediate_transaction(|tx| {
        assert!(hosted_auth::verify_in_tx(tx, &cloned).is_err());
        let revoked: bool = tx.query_row(
            "SELECT revoked FROM hosted_connection_authorizations WHERE connection_id = ?1",
            [&lease.connection_id],
            |row| row.get(0),
        )?;
        assert!(!revoked);
        tx.execute_batch("DROP TRIGGER fail_revocation;")?;
        Ok(())
    })
    .unwrap();
    hosted_auth::remove(&lease.connection_id).unwrap();
    assert!(hosted_auth::verify(&cloned).is_err());
    db::with_db(|connection| {
        let revoked: bool = connection.query_row(
            "SELECT revoked FROM hosted_connection_authorizations WHERE connection_id = ?1",
            [&lease.connection_id],
            |row| row.get(0),
        )?;
        assert!(revoked);
        Ok(())
    })
    .unwrap();
}
