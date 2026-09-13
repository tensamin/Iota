use iota_daemon_lib::accounts::{AccountAuthority, CreateUserRequest, LocalIotaAccountAuthority};
use iota_identity::{LocalNodeIdentity, LocalUserId, PrincipalStore};
use iota_storage::identity::SqlitePrincipalStore;

#[tokio::test]
async fn standalone_accounts_survive_identity_reload_and_do_not_reuse_deleted_ids() {
    let root = tempfile::tempdir().unwrap();
    let storage = root.path().join("storage");
    iota_util::file_util::configure_storage_directory(storage);
    iota_storage::util::db::initialize_database().unwrap();
    let identity_path = root.path().join("identity/iota.mk");
    let identity = LocalNodeIdentity::load_or_create(&identity_path, None).unwrap();
    let authority = LocalIotaAccountAuthority::new(identity.clone());

    let alice = authority
        .create_user(CreateUserRequest {
            username: "alice".into(),
        })
        .await
        .unwrap();
    let alice_principal = SqlitePrincipalStore
        .principal_for_local_user(alice.user)
        .unwrap()
        .and_then(|handle| SqlitePrincipalStore.get_principal(handle).unwrap())
        .unwrap();
    let credential = iota_util::file_util::read_user_credential("alice")
        .unwrap()
        .unwrap();

    let restarted_identity = LocalNodeIdentity::load_or_create(&identity_path, None).unwrap();
    assert_eq!(restarted_identity.node_id(), identity.node_id());
    let restarted = LocalIotaAccountAuthority::new(restarted_identity);
    let restored_principal = SqlitePrincipalStore
        .principal_for_local_user(LocalUserId(alice.user.0))
        .unwrap()
        .and_then(|handle| SqlitePrincipalStore.get_principal(handle).unwrap())
        .unwrap();
    assert_eq!(restored_principal.principal, alice_principal.principal);

    restarted
        .delete_user(alice.user, credential.as_bytes())
        .await
        .unwrap();
    let bob = restarted
        .create_user(CreateUserRequest {
            username: "bob".into(),
        })
        .await
        .unwrap();
    assert!(bob.user.0 > alice.user.0);
    assert!(
        SqlitePrincipalStore
            .get_by_canonical_id(&alice_principal.principal)
            .unwrap()
            .is_some()
    );
}
