use iota_identity::{
    AuthorityLocator, LocalNodeIdentity, NodeDescriptor, NodeDirectory, NodeIdentityResolver,
    SignedNodeDescriptor,
};
use iota_storage::node_directory::SqliteNodeDirectory;
use mtp::crypto::Keyring;

#[tokio::test]
async fn node_directory_persists_identity_revision_endpoints_and_pins() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    iota_storage::util::db::initialize_database().unwrap();

    let identity = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let endpoint = AuthorityLocator::new("iota.example.org:443").unwrap();
    let relay = AuthorityLocator::new("relay.example.org:443").unwrap();
    let now = iota_storage::util::sync::now_millis();
    let signed = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: identity.node_id().clone(),
            public_keys: identity.public_keys(),
            direct_endpoints: vec![endpoint.clone()],
            relay_hints: vec![relay.clone()],
            revision: 1,
            valid_until: Some(now + 60_000),
        },
        &identity,
    )
    .unwrap();
    let verified = signed.verify(None, now).unwrap();
    SqliteNodeDirectory
        .upsert_node_descriptor(&verified)
        .unwrap();
    SqliteNodeDirectory
        .pin_endpoint(&endpoint, identity.node_id(), now)
        .unwrap();
    let certificate = b"test certificate";
    SqliteNodeDirectory
        .pin_endpoint_certificate(&endpoint, certificate)
        .unwrap();
    SqliteNodeDirectory
        .record_successful_endpoint(identity.node_id(), &endpoint)
        .unwrap();

    let resolved = SqliteNodeDirectory
        .resolve_node(identity.node_id())
        .await
        .unwrap();
    assert_eq!(resolved.descriptor_revision, 1);
    assert_eq!(resolved.direct_endpoints, vec![endpoint.clone()]);
    assert_eq!(resolved.relay_hints, vec![relay]);
    assert_eq!(resolved.last_successful_endpoint, Some(endpoint.clone()));
    assert_eq!(
        SqliteNodeDirectory.pinned_node(&endpoint).unwrap(),
        Some(identity.node_id().clone())
    );
    assert_eq!(
        SqliteNodeDirectory
            .pinned_endpoint_certificate(&endpoint)
            .unwrap(),
        Some(certificate.to_vec())
    );
    assert!(
        SqliteNodeDirectory
            .pin_endpoint_certificate(&endpoint, b"changed certificate")
            .is_err()
    );

    let stale = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: identity.node_id().clone(),
            public_keys: identity.public_keys(),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
            revision: 0,
            valid_until: Some(now + 60_000),
        },
        &identity,
    )
    .unwrap()
    .verify(None, now)
    .unwrap();
    assert!(SqliteNodeDirectory.upsert_node_descriptor(&stale).is_err());

    let conflicting = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: identity.node_id().clone(),
            public_keys: identity.public_keys(),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: Some(now + 60_000),
        },
        &identity,
    )
    .unwrap()
    .verify(None, now)
    .unwrap();
    assert!(
        SqliteNodeDirectory
            .upsert_node_descriptor(&conflicting)
            .is_err()
    );

    let other = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    assert!(
        SqliteNodeDirectory
            .pin_endpoint(&endpoint, other.node_id(), now + 1)
            .is_err()
    );
}
