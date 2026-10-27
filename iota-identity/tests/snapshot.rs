use iota_identity::*;
use mtp::crypto::Keyring;

#[test]
fn snapshot_binds_authority_subject_home_revisions_and_separate_freshness_windows() {
    let authority = Keyring::generate();
    let home = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let now = 1_000_000;
    let node = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: home.node_id().clone(),
            public_keys: home.public_keys(),
            direct_endpoints: vec![],
            relay_hints: vec![],
            revision: 3,
            valid_until: Some(now + 60_000),
        },
        &home,
    )
    .unwrap();
    let principal = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: AuthorityId::for_omega(&authority.public_key_bundle()).unwrap(),
                user_id: 42,
            },
            authority_kind: AuthorityKind::Omega,
            username: None,
            display_name: None,
            public_keys: vec![Keyring::generate().public_key_bundle()],
            home: PrincipalHome::Iota(home.node_id().clone()),
            revision: 5,
            valid_until: Some(now + 60_000),
            issued_at: now,
        },
        &authority,
    )
    .unwrap();
    let snapshot = principal
        .clone()
        .verify_snapshot(
            &authority.public_key_bundle(),
            Some(5),
            node.clone(),
            Some(3),
            now,
        )
        .unwrap();
    assert!(snapshot.fresh_for_read(now + 30_001));
    assert!(!snapshot.fresh_for_mutation(now + 30_001));
    assert!(!snapshot.fresh_for_read(now + 60_000));
    assert_eq!(snapshot.principal_descriptor().descriptor().revision, 5);
    assert_eq!(snapshot.home_descriptor().descriptor().revision, 3);
    assert!(!snapshot.principal_proof().authority_signature.is_empty());
    assert!(
        principal
            .clone()
            .verify_snapshot(
                &Keyring::generate().public_key_bundle(),
                Some(5),
                node.clone(),
                Some(3),
                now
            )
            .is_err()
    );
    assert!(
        principal
            .clone()
            .verify_snapshot(
                &authority.public_key_bundle(),
                Some(6),
                node.clone(),
                Some(3),
                now
            )
            .is_err()
    );
    assert!(
        principal
            .clone()
            .verify_snapshot(
                &authority.public_key_bundle(),
                Some(5),
                node.clone(),
                Some(4),
                now
            )
            .is_err()
    );
    let mut tampered = node;
    tampered.node_signature[0] ^= 1;
    assert!(
        principal
            .verify_snapshot(
                &authority.public_key_bundle(),
                Some(5),
                tampered,
                Some(3),
                now
            )
            .is_err()
    );
}
