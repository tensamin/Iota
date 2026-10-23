use iota_identity::peer_introduction::{PeerIntroductionLimits, PeerIntroductionRequest};
use iota_identity::{
    AuthorityDirectory, AuthorityLocator, LocalNodeIdentity, NodeDescriptor, SignedNodeDescriptor,
};
use iota_storage::{
    authority_directory::SqliteAuthorityDirectory, node_directory::SqliteNodeDirectory,
    peer_admission, relay_mailbox, util::db,
};
use mtp::crypto::Keyring;
use std::sync::Arc;

fn descriptor(identity: &LocalNodeIdentity, now: i64) -> SignedNodeDescriptor {
    SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: identity.node_id().clone(),
            public_keys: identity.public_keys(),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: Some(now + 3_600_000),
        },
        identity,
    )
    .unwrap()
}

#[test]
fn federation_leases_pins_mailbox_and_transitions_are_durable_and_fenced() {
    if let Ok(root) = std::env::var("TENSAMIN_FEDERATION_STATE_REOPEN") {
        iota_util::file_util::configure_storage_directory(root.into());
        db::initialize_database().unwrap();
        let node =
            iota_identity::IotaNodeId::new(std::env::var("TENSAMIN_FEDERATION_NODE").unwrap())
                .unwrap();
        assert_eq!(
            SqliteAuthorityDirectory
                .locators_for(&iota_identity::AuthorityId::for_iota(&node))
                .unwrap(),
            vec![AuthorityLocator::new("a.example").unwrap()]
        );
        assert!(peer_admission::is_revoked(&node).unwrap());
        return;
    }
    let root = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(root.path().to_owned());
    db::initialize_database().unwrap();
    let now = iota_storage::util::sync::now_millis();
    let a = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let b = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let signed = descriptor(&a, now);
    let limits = PeerIntroductionLimits::default();
    assert!(
        peer_admission::key_for_peer_authentication_hint(a.node_id().mtp_authentication_hint())
            .unwrap()
            .is_none()
    );
    let issue = || {
        peer_admission::issue_challenge(
            &signed,
            b.node_id(),
            "192.0.2.1".parse().unwrap(),
            None,
            &limits,
            now,
        )
        .unwrap()
    };
    let challenge = issue();
    assert!(
        peer_admission::key_for_peer_authentication_hint(a.node_id().mtp_authentication_hint())
            .unwrap()
            .is_none()
    );
    let proof = PeerIntroductionRequest::sign(&challenge, &signed, &a).unwrap();
    for mutation in 0..4 {
        let mut changed = challenge.clone();
        match mutation {
            0 => changed.nonce.push('x'),
            1 => changed.responder_node = a.node_id().clone(),
            2 => changed.expires_at += 1,
            _ => changed.challenge_id.push('x'),
        }
        assert!(proof.verify(&changed).is_err());
    }
    let mut changed = proof.clone();
    changed.descriptor.revision += 1;
    assert!(peer_admission::redeem(changed, &limits, now).is_err());
    let receipt = peer_admission::redeem(proof.clone(), &limits, now).unwrap();
    assert!(peer_admission::redeem(proof, &limits, now).is_err());
    let key =
        peer_admission::key_for_peer_authentication_hint(a.node_id().mtp_authentication_hint())
            .unwrap()
            .unwrap();
    assert_eq!(
        iota_identity::IotaNodeId::from_public_keys(&key).unwrap(),
        *a.node_id()
    );
    let duplicate = PeerIntroductionRequest::sign(&issue(), &signed, &a).unwrap();
    assert_eq!(
        peer_admission::redeem(duplicate, &limits, now + 1)
            .unwrap()
            .expires_at,
        receipt.expires_at
    );
    let expired = issue();
    assert!(
        peer_admission::redeem(
            PeerIntroductionRequest::sign(&expired, &signed, &a).unwrap(),
            &limits,
            expired.expires_at
        )
        .is_err()
    );

    // Distinct descriptor keys colliding in the host's truncated lookup fail closed.
    let collision = descriptor(&b, now).verify(None, now).unwrap();
    SqliteNodeDirectory.upsert(&collision).unwrap();
    db::with_db(|db| {
        db.execute(
            "UPDATE node_directory SET authentication_hint=?1 WHERE node_id=?2",
            rusqlite::params![
                a.node_id().mtp_authentication_hint() as i64,
                b.node_id().as_str()
            ],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(
        peer_admission::key_for_peer_authentication_hint(a.node_id().mtp_authentication_hint())
            .is_err()
    );
    assert!(
        peer_admission::redeem(
            PeerIntroductionRequest::sign(&issue(), &signed, &a).unwrap(),
            &limits,
            now
        )
        .is_err()
    );
    db::with_db(|db| {
        db.execute(
            "UPDATE node_directory SET authentication_hint=?1 WHERE node_id=?2",
            rusqlite::params![
                b.node_id().mtp_authentication_hint() as i64,
                b.node_id().as_str()
            ],
        )?;
        Ok(())
    })
    .unwrap();
    use iota_identity::peer_introduction::PeerTrust;
    SqliteNodeDirectory
        .upsert(&signed.clone().verify(None, now).unwrap())
        .unwrap();
    let candidate = peer_admission::trust_for_peer(a.node_id(), &a.public_keys(), now).unwrap();
    assert!(
        matches!(candidate,PeerTrust::Provisional { expires_at,.. } if expires_at==receipt.expires_at)
    );
    assert!(
        peer_admission::trust_for_peer(a.node_id(), &a.public_keys(), receipt.expires_at).is_err()
    );
    assert!(peer_admission::promote(&candidate, &a.public_keys(), receipt.expires_at).is_err());
    let established = peer_admission::promote(&candidate, &a.public_keys(), now).unwrap();
    assert!(matches!(established, PeerTrust::Established { .. }));
    assert_eq!(
        peer_admission::promote(&candidate, &a.public_keys(), now).unwrap(),
        established
    );
    let locator = AuthorityLocator::new("a.example").unwrap();
    SqliteAuthorityDirectory
        .record_verified_iota(&locator, a.authority_id(), a.node_id(), now)
        .unwrap();
    assert!(
        SqliteAuthorityDirectory
            .record_verified_iota(&locator, b.authority_id(), b.node_id(), now)
            .is_err()
    );
    assert_eq!(
        SqliteNodeDirectory.pinned_node_record(&locator).unwrap(),
        Some(a.node_id().clone())
    );

    let concurrent = issue();
    let proof = Arc::new(PeerIntroductionRequest::sign(&concurrent, &signed, &a).unwrap());
    let start = Arc::new(std::sync::Barrier::new(3));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let proof = proof.clone();
            let start = start.clone();
            let limits = limits.clone();
            std::thread::spawn(move || {
                start.wait();
                peer_admission::redeem((*proof).clone(), &limits, now).is_ok()
            })
        })
        .collect();
    start.wait();
    assert_eq!(
        handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );

    let limits = relay_mailbox::MailboxLimits::default();
    let mut envelope = relay_mailbox::MailboxEnvelope {
        destination: b.node_id().as_str().into(),
        sender: a.node_id().as_str().into(),
        id: vec![7; 32],
        frame: vec![1, 2, 3],
        type_map_version: "1.0".into(),
    };
    assert!(
        relay_mailbox::store(&envelope, &limits, now)
            .unwrap()
            .is_none()
    );
    assert!(
        relay_mailbox::store(&envelope, &limits, now + 1)
            .unwrap()
            .is_none()
    );
    envelope.frame.push(4);
    assert!(relay_mailbox::store(&envelope, &limits, now).is_err());
    let first = relay_mailbox::claim(b.node_id().as_str(), now)
        .unwrap()
        .unwrap();
    assert!(
        relay_mailbox::claim(b.node_id().as_str(), now)
            .unwrap()
            .is_none()
    );
    let takeover = relay_mailbox::claim(b.node_id().as_str(), now + 60_000)
        .unwrap()
        .unwrap();
    assert!(!relay_mailbox::acknowledge(&first, b"ack", &limits, now + 60_000).unwrap());
    let tight = relay_mailbox::MailboxLimits {
        max_total_bytes: 2,
        ..limits.clone()
    };
    assert!(relay_mailbox::acknowledge(&takeover, b"ack", &tight, now + 60_001).is_err());
    assert!(
        relay_mailbox::acknowledge(&takeover, &vec![0; 64 * 1024 + 1], &limits, now + 60_001)
            .is_err()
    );
    assert!(relay_mailbox::acknowledge(&takeover, b"ack", &limits, now + 60_001).unwrap());
    envelope.frame.pop();
    assert_eq!(
        relay_mailbox::store(&envelope, &limits, now + 60_002).unwrap(),
        Some(b"ack".to_vec())
    );
    assert!(
        relay_mailbox::claim(b.node_id().as_str(), now + 60_002)
            .unwrap()
            .is_none()
    );

    let transition =
        iota_identity::node_transition::NodeTransition::sign(&a, &b, 1, now, now + 60_000).unwrap();
    let verified = transition
        .clone()
        .verify(&a.public_keys(), &b.public_keys(), now)
        .unwrap();
    iota_storage::node_transition::record(&verified, now).unwrap();
    iota_storage::node_transition::record(&verified, now).unwrap();
    assert!(peer_admission::is_revoked(a.node_id()).unwrap());
    assert!(
        peer_admission::key_for_peer_authentication_hint(a.node_id().mtp_authentication_hint())
            .unwrap()
            .is_none()
    );
    let c = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let divergent =
        iota_identity::node_transition::NodeTransition::sign(&a, &c, 1, now, now + 60_000)
            .unwrap()
            .verify(&a.public_keys(), &c.public_keys(), now)
            .unwrap();
    assert!(iota_storage::node_transition::record(&divergent, now).is_err());
    let mut tampered = transition;
    tampered.replacement_node = c.node_id().clone();
    assert!(
        tampered
            .verify(&a.public_keys(), &c.public_keys(), now)
            .is_err()
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("federation_leases_pins_mailbox_and_transitions_are_durable_and_fenced")
        .env("TENSAMIN_FEDERATION_STATE_REOPEN", root.path())
        .env("TENSAMIN_FEDERATION_NODE", a.node_id().as_str())
        .status()
        .unwrap();
    assert!(status.success());
}
