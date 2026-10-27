use iota_identity::*;
use iota_storage::{
    identity::{SqlitePrincipalStore, bind_omega_authority, bind_verified_omega_hosted_principal},
    util::db,
};
use mtp::crypto::Keyring;

#[test]
fn omega_host_binding_requires_signed_snapshot_and_matching_live_account_key() {
    let root = std::path::Path::new("/tmp/opencode")
        .join(format!("omega-host-binding-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    iota_util::file_util::configure_storage_directory(root);
    db::initialize_database().unwrap();
    let authority = Keyring::generate();
    let authority_id = AuthorityId::for_omega(&authority.public_key_bundle()).unwrap();
    bind_omega_authority(&authority_id).unwrap();
    let home = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let account = Keyring::generate().public_key_bundle();
    let now = iota_storage::util::sync::now_millis();
    let node = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: home.node_id().clone(),
            public_keys: home.public_keys(),
            direct_endpoints: vec![],
            relay_hints: vec![],
            revision: 1,
            valid_until: Some(now + 60_000),
        },
        &home,
    )
    .unwrap();
    let signed = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: authority_id,
                user_id: 42,
            },
            authority_kind: AuthorityKind::Omega,
            username: Some("signed-owner".into()),
            display_name: None,
            public_keys: vec![account.clone()],
            home: PrincipalHome::Iota(home.node_id().clone()),
            revision: 1,
            issued_at: now,
            valid_until: Some(now + 60_000),
        },
        &authority,
    )
    .unwrap();
    let snapshot = signed
        .verify_snapshot(&authority.public_key_bundle(), None, node, None, now)
        .unwrap();
    let store = SqlitePrincipalStore;
    let handle = store
        .upsert_remote_descriptor(snapshot.principal_descriptor())
        .unwrap();
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(42,'signed-owner',?1,0)",[account.try_to_base64().unwrap()])?;
        Ok(())
    }).unwrap();
    assert!(
        store
            .principal_for_local_user(LocalUserId(42))
            .unwrap()
            .is_none()
    );
    let other_node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    assert!(bind_verified_omega_hosted_principal(&snapshot, other_node.node_id()).is_err());
    assert!(
        store
            .principal_for_local_user(LocalUserId(42))
            .unwrap()
            .is_none()
    );
    bind_verified_omega_hosted_principal(&snapshot, home.node_id()).unwrap();
    assert_eq!(
        store.principal_for_local_user(LocalUserId(42)).unwrap(),
        Some(handle)
    );
    // Repeating a verified observation does not mint a local descriptor revision.
    bind_verified_omega_hosted_principal(&snapshot, home.node_id()).unwrap();
    assert_eq!(
        store
            .get_principal(handle)
            .unwrap()
            .unwrap()
            .descriptor_revision,
        1
    );

    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE users SET public_key=?1 WHERE user_id=42",
            [Keyring::generate()
                .public_key_bundle()
                .try_to_base64()
                .unwrap()],
        )?;
        Ok(())
    })
    .unwrap();
    let after_rekey = store.principal_for_local_user(LocalUserId(42)).unwrap();
    assert!(bind_verified_omega_hosted_principal(&snapshot, home.node_id()).is_err());
    assert_eq!(
        store.principal_for_local_user(LocalUserId(42)).unwrap(),
        after_rekey
    );
}
