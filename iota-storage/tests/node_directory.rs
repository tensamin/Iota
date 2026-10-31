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
    let verified = signed.clone().verify(None, now).unwrap();
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

    let snapshot = || {
        iota_storage::util::db::with_db(|db| {
            Ok(db.query_row(
                "SELECT n.descriptor_revision,n.last_resolved_at,k.valid_from,k.valid_until FROM node_directory n JOIN node_keys k ON k.node_id=n.node_id AND k.source_revision=n.descriptor_revision WHERE n.node_id=?1",
                [identity.node_id().as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, Option<i64>>(3)?)),
            )?)
        }).unwrap()
    };
    let original = snapshot();
    let older = signed.clone().verify(Some(1), now - 1).unwrap();
    SqliteNodeDirectory.upsert_node_descriptor(&older).unwrap();
    assert_eq!(
        snapshot(),
        original,
        "older duplicate must not alter freshness or key validity"
    );
    let newer = signed.clone().verify(Some(1), now + 10).unwrap();
    SqliteNodeDirectory.upsert_node_descriptor(&newer).unwrap();
    assert_eq!(snapshot(), (1, now + 10, original.2, original.3));
    SqliteNodeDirectory.upsert_node_descriptor(&newer).unwrap();
    assert_eq!(snapshot(), (1, now + 10, original.2, original.3));

    // Both observations are verified before either commits. Force the older
    // lookup to finish last without relying on thread timing or sleeps.
    let older = signed.clone().verify(Some(1), now + 20).unwrap();
    let newer = signed.verify(Some(1), now + 30).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let (committed, wait) = std::sync::mpsc::channel();
    let old_thread = std::thread::spawn({
        let barrier = barrier.clone();
        move || {
            barrier.wait();
            wait.recv().unwrap();
            SqliteNodeDirectory.upsert_node_descriptor(&older).unwrap();
        }
    });
    let new_thread = std::thread::spawn(move || {
        barrier.wait();
        SqliteNodeDirectory.upsert_node_descriptor(&newer).unwrap();
        committed.send(()).unwrap();
    });
    old_thread.join().unwrap();
    new_thread.join().unwrap();
    assert_eq!(snapshot(), (1, now + 30, original.2, original.3));
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
    let hint = identity.node_id().mtp_authentication_hint();
    assert!(
        SqliteNodeDirectory
            .key_for_authentication_hint(hint)
            .unwrap()
            .is_some()
    );
    // Inject a canonical-format collision at the storage boundary. Producing
    // two real full-key fingerprints with the same hint is impractical in a test.
    let mut collision = identity.node_id().as_str().to_owned();
    let last = collision.pop().unwrap();
    collision.push(if last == '0' { '1' } else { '0' });
    let collision_id = iota_identity::IotaNodeId::new(&collision).unwrap();
    assert_eq!(collision_id.mtp_authentication_hint(), hint);
    iota_storage::util::db::with_db(|db| {
        db.execute("INSERT INTO node_directory SELECT ?2, descriptor_revision, descriptor_valid_until, direct_endpoints, relay_hints, last_successful_endpoint, last_resolved_at, authentication_hint FROM node_directory WHERE node_id = ?1", rusqlite::params![identity.node_id().as_str(), collision])?;
        db.execute("INSERT INTO node_keys SELECT ?2, public_key, valid_from, valid_until, source_revision FROM node_keys WHERE node_id = ?1", rusqlite::params![identity.node_id().as_str(), collision])?;
        Ok(())
    }).unwrap();
    assert!(
        SqliteNodeDirectory
            .key_for_authentication_hint(hint)
            .is_err()
    );
    iota_storage::util::db::with_db(|db| {
        db.execute(
            "UPDATE node_directory SET descriptor_valid_until = 0 WHERE node_id = ?1",
            [&collision],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(
        SqliteNodeDirectory
            .key_for_authentication_hint(hint)
            .unwrap()
            .is_some()
    );
    iota_storage::util::db::with_db(|db| {
        db.execute(
            "UPDATE node_keys SET valid_until = 0 WHERE node_id = ?1",
            [identity.node_id().as_str()],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(
        SqliteNodeDirectory
            .key_for_authentication_hint(hint)
            .unwrap()
            .is_none()
    );

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
