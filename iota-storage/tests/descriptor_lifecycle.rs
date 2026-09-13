use iota_identity::{
    AuthorityKind, LocalNodeIdentity, LocalUserDescriptor, LocalUserId, PrincipalHome, PrincipalId,
    PrincipalStore, VerifiedPrincipalDescriptor,
};
use iota_storage::identity::SqlitePrincipalStore;
use mtp::crypto::Keyring;

#[test]
fn local_descriptor_revision_persists_changes_and_retirement() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    iota_storage::util::db::initialize_database().unwrap();

    let identity = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let user_key = Keyring::generate();
    let mut user = LocalUserDescriptor {
        id: LocalUserId(9),
        username: "alice".into(),
        display_name: None,
        public_key: user_key.public_key_bundle().try_to_base64().unwrap(),
    };
    iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "INSERT INTO users (user_id, username, public_key, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![user.id.0, user.username, user.public_key, 1_i64],
        )?;
        Ok(())
    })
    .unwrap();

    let store = SqlitePrincipalStore;
    let home = PrincipalHome::Iota(identity.node_id().clone());
    store
        .ensure_local_principal(
            identity.authority_id(),
            AuthorityKind::Iota,
            &user,
            home.clone(),
            1_000,
        )
        .unwrap();
    let first = store.local_principal_descriptor(user.id).unwrap();
    assert_eq!(first.revision, 0);

    store
        .ensure_local_principal(
            identity.authority_id(),
            AuthorityKind::Iota,
            &user,
            home.clone(),
            1_001,
        )
        .unwrap();
    assert_eq!(
        store.local_principal_descriptor(user.id).unwrap().revision,
        0
    );

    user.display_name = Some("Alice".into());
    store
        .ensure_local_principal(
            identity.authority_id(),
            AuthorityKind::Iota,
            &user,
            home.clone(),
            1_002,
        )
        .unwrap();
    assert_eq!(
        store.local_principal_descriptor(user.id).unwrap().revision,
        1
    );

    let replacement_key = Keyring::generate().public_key_bundle();
    user.public_key = replacement_key.try_to_base64().unwrap();
    store
        .ensure_local_principal(
            identity.authority_id(),
            AuthorityKind::Iota,
            &user,
            home.clone(),
            1_003,
        )
        .unwrap();
    let rotated = store.local_principal_descriptor(user.id).unwrap();
    assert_eq!(rotated.revision, 2);
    assert_eq!(rotated.public_keys.len(), 1);
    assert_eq!(
        rotated.public_keys[0].try_to_base64().unwrap(),
        replacement_key.try_to_base64().unwrap()
    );

    let renewal_at = rotated.valid_until.unwrap() - 1;
    store
        .ensure_local_principal(
            identity.authority_id(),
            AuthorityKind::Iota,
            &user,
            home,
            renewal_at,
        )
        .unwrap();
    let renewed = store.local_principal_descriptor(user.id).unwrap();
    assert_eq!(renewed.revision, 3);
    let mut conflicting = renewed.clone();
    conflicting.display_name = Some("Changed without revision".into());
    assert!(
        store
            .upsert_remote_descriptor(
                &VerifiedPrincipalDescriptor::from_trusted_authority(conflicting).unwrap()
            )
            .is_err()
    );

    store
        .retire_local_principal(user.id, renewal_at + 1)
        .unwrap();
    assert!(store.local_principal_descriptor(user.id).is_err());
    let principal = PrincipalId {
        authority: identity.authority_id().clone(),
        user_id: 9,
    };
    let retired = store.get_by_canonical_id(&principal).unwrap().unwrap();
    assert_eq!(retired.descriptor_revision, 4);
    assert!(
        store
            .upsert_remote_descriptor(
                &VerifiedPrincipalDescriptor::from_trusted_authority(first).unwrap()
            )
            .is_err()
    );
}
