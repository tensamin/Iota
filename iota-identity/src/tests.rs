use super::*;

#[test]
fn authority_scopes_equal_numeric_user_ids() {
    let first = PrincipalId {
        authority: AuthorityId::new("omega:first").unwrap(),
        user_id: 7,
    };
    let second = PrincipalId {
        authority: AuthorityId::new("omega:second").unwrap(),
        user_id: 7,
    };
    assert_ne!(first, second);
}

#[test]
fn signed_iota_descriptor_verifies_authority_revision_and_expiry() {
    let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let user = mtp::crypto::Keyring::generate();
    let descriptor = PrincipalDescriptor {
        principal: PrincipalId {
            authority: authority.authority_id().clone(),
            user_id: 7,
        },
        authority_kind: AuthorityKind::Iota,
        username: Some("alice".into()),
        display_name: None,
        public_keys: vec![user.public_key_bundle()],
        home: PrincipalHome::Iota(authority.node_id().clone()),
        revision: 3,
        valid_until: Some(200),
        issued_at: 100,
    };
    let signed = SignedPrincipalDescriptor::sign(descriptor, &authority.keyring()).unwrap();

    let verified = signed
        .clone()
        .verify(
            authority.authority_id(),
            &authority.public_keys(),
            Some(3),
            150,
        )
        .unwrap();
    assert_eq!(verified.descriptor().principal.user_id, 7);
    assert_eq!(verified.resolved_at(), 150);
    assert!(
        signed
            .clone()
            .verify(
                authority.authority_id(),
                &authority.public_keys(),
                Some(4),
                150,
            )
            .is_err()
    );
    assert!(
        signed
            .verify(
                authority.authority_id(),
                &authority.public_keys(),
                None,
                200,
            )
            .is_err()
    );
}

#[test]
fn principal_descriptor_wire_round_trip_preserves_signed_binary_meaning() {
    let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let signed = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: authority.authority_id().clone(),
                user_id: 7,
            },
            authority_kind: AuthorityKind::Iota,
            username: Some("alice".into()),
            display_name: Some("Alice".into()),
            public_keys: vec![mtp::crypto::Keyring::generate().public_key_bundle()],
            home: PrincipalHome::Iota(authority.node_id().clone()),
            revision: 4,
            valid_until: Some(500),
            issued_at: 100,
        },
        &authority.keyring(),
    )
    .unwrap();
    let wire = signed.to_wire_v1().unwrap();
    let json = serde_json::to_vec(&wire).unwrap();
    let parsed: PrincipalDescriptorWireV1 = serde_json::from_slice(&json).unwrap();
    let verified = parsed
        .parse()
        .unwrap()
        .verify(
            authority.authority_id(),
            &authority.public_keys(),
            None,
            200,
        )
        .unwrap();
    assert_eq!(verified.descriptor().revision, 4);
    assert_eq!(verified.descriptor().display_name.as_deref(), Some("Alice"));
}

#[test]
fn descriptor_signature_rejects_modified_identity() {
    let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let mut signed = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: authority.authority_id().clone(),
                user_id: 7,
            },
            authority_kind: AuthorityKind::Iota,
            username: Some("alice".into()),
            display_name: None,
            public_keys: vec![mtp::crypto::Keyring::generate().public_key_bundle()],
            home: PrincipalHome::Iota(authority.node_id().clone()),
            revision: 1,
            valid_until: None,
            issued_at: 100,
        },
        &authority.keyring(),
    )
    .unwrap();
    signed.descriptor.principal.user_id = 8;

    assert!(
        signed
            .verify(
                authority.authority_id(),
                &authority.public_keys(),
                None,
                101,
            )
            .is_err()
    );
}

#[test]
fn signed_node_descriptor_binds_node_id_and_endpoints() {
    let identity = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let signed = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: identity.node_id().clone(),
            public_keys: identity.public_keys(),
            direct_endpoints: vec![AuthorityLocator::new("iota.example.org:8443").unwrap()],
            relay_hints: vec![AuthorityLocator::new("relay.example.org:9443").unwrap()],
            revision: 2,
            valid_until: Some(200),
        },
        &identity,
    )
    .unwrap();
    let verified = signed.clone().verify(Some(2), 150).unwrap();
    assert_eq!(
        verified.descriptor().direct_endpoints[0].as_str(),
        "iota.example.org:8443"
    );

    let mut modified = signed;
    modified.descriptor.direct_endpoints =
        vec![AuthorityLocator::new("attacker.example.org:8443").unwrap()];
    assert!(modified.verify(None, 150).is_err());
}

#[test]
fn node_descriptor_wire_round_trip_keeps_endpoint_signature_valid() {
    let identity = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let signed = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: identity.node_id().clone(),
            public_keys: identity.public_keys(),
            direct_endpoints: vec![AuthorityLocator::new("iota.example.org:1984").unwrap()],
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: Some(500),
        },
        &identity,
    )
    .unwrap();
    let wire = signed.to_wire_v1().unwrap();
    let json = serde_json::to_vec(&wire).unwrap();
    let parsed: NodeDescriptorWireV1 = serde_json::from_slice(&json).unwrap();
    let verified = parsed.parse().unwrap().verify(None, 200).unwrap();
    assert_eq!(verified.descriptor().revision, 1);
}

#[test]
fn discovery_document_binds_iota_id_to_public_key() {
    let identity = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let document = AuthorityDiscoveryDocument {
        version: 1,
        service: AuthorityKind::Iota,
        authority_id: identity.authority_id().clone(),
        node_id: Some(identity.node_id().clone()),
        public_key: identity.public_keys().try_to_base64().unwrap(),
        protocols: vec!["mtp-relay".into()],
        node_descriptor: Some("/federation/v1/node".into()),
        direct_endpoints: vec![AuthorityLocator::new("iota.example.org:8443").unwrap()],
        relay_hints: Vec::new(),
    };
    assert_eq!(
        document.verify().unwrap().node_id,
        Some(identity.node_id().clone())
    );

    let mut mismatched = AuthorityDiscoveryDocument {
        version: 1,
        service: AuthorityKind::Iota,
        authority_id: identity.authority_id().clone(),
        node_id: Some(identity.node_id().clone()),
        public_key: mtp::crypto::Keyring::generate()
            .public_key_bundle()
            .try_to_base64()
            .unwrap(),
        protocols: vec!["mtp-relay".into()],
        node_descriptor: Some("/federation/v1/node".into()),
        direct_endpoints: Vec::new(),
        relay_hints: Vec::new(),
    };
    assert!(mismatched.clone().verify().is_err());
    mismatched.protocols.clear();
    assert!(mismatched.verify().is_err());
}

#[test]
fn discovery_document_binds_omega_id_to_public_key() {
    let keyring = mtp::crypto::Keyring::generate();
    let public_keys = keyring.public_key_bundle();
    let document = AuthorityDiscoveryDocument {
        version: 1,
        service: AuthorityKind::Omega,
        authority_id: AuthorityId::for_omega(&public_keys).unwrap(),
        node_id: None,
        public_key: public_keys.try_to_base64().unwrap(),
        protocols: vec!["identity-http-v1".into()],
        node_descriptor: None,
        direct_endpoints: Vec::new(),
        relay_hints: Vec::new(),
    };
    assert!(document.verify().is_ok());
}

#[test]
fn identifiers_reject_empty_values() {
    assert!(AuthorityId::new("  ").is_err());
    assert!(IotaNodeId::new(String::new()).is_err());
    assert!(IotaNodeId::new("node-a").is_err());
    assert!(AuthorityLocator::new(" ").is_err());
}

#[test]
fn parses_user_addresses() {
    let key = mtp::crypto::Keyring::generate().public_key_bundle();
    let encoded_key = key.try_to_base64().unwrap();
    let username = UserAddress::parse("alice@IOTA.Example.Org:443").unwrap();
    let numeric = UserAddress::parse("51@192.0.2.20").unwrap();
    let numeric_domain = UserAddress::parse("51@iota.example.org").unwrap();
    let omega = UserAddress::parse("alice@omega.example.org").unwrap();
    let numeric_pinned =
        UserAddress::parse(&format!("51::{encoded_key}@omega.example.org")).unwrap();
    let pinned = UserAddress::parse(&format!("alice::{encoded_key}@[2001:DB8::1]:8443")).unwrap();

    assert_eq!(username.selector, UserSelector::Username("alice".into()));
    assert_eq!(username.authority.unwrap().as_str(), "iota.example.org:443");
    assert_eq!(numeric.selector, UserSelector::UserId(51));
    assert_eq!(numeric.authority.unwrap().as_str(), "192.0.2.20");
    assert_eq!(numeric_domain.selector, UserSelector::UserId(51));
    assert_eq!(
        numeric_domain.authority.unwrap().as_str(),
        "iota.example.org"
    );
    assert_eq!(omega.authority.unwrap().as_str(), "omega.example.org");
    assert_eq!(numeric_pinned.selector, UserSelector::UserId(51));
    assert!(numeric_pinned.public_key_pin.is_some());
    assert_eq!(pinned.authority.unwrap().as_str(), "[2001:db8::1]:8443");
    assert_eq!(
        pinned.public_key_pin.unwrap().try_as_bytes().unwrap(),
        key.try_as_bytes().unwrap()
    );
}

#[test]
fn numeric_only_selectors_are_user_ids() {
    assert_eq!(
        UserAddress::parse("00051").unwrap().selector,
        UserSelector::UserId(51)
    );
    assert_eq!(
        UserAddress::parse("51alice").unwrap().selector,
        UserSelector::Username("51alice".into())
    );
}

#[test]
fn parses_local_and_bracketed_ipv6_addresses() {
    let local = UserAddress::parse("alice").unwrap();
    let ipv6 = UserAddress::parse("alice@[2001:DB8::1]").unwrap();
    let ipv4 = AuthorityLocator::new("192.0.2.10:443").unwrap();
    let domain = AuthorityLocator::new("iota.example:443").unwrap();

    assert!(local.authority.is_none());
    let ipv6 = ipv6.authority.unwrap();
    assert_eq!(ipv6.as_str(), "[2001:db8::1]");
    assert!(ipv6.is_ip_literal());
    assert!(ipv4.is_ip_literal());
    assert!(!domain.is_ip_literal());
}

#[test]
fn rejects_malformed_user_addresses() {
    for address in [
        "",
        "@example.org",
        "alice@",
        "alice@@example.org",
        "alice::not-a-key@example.org",
        "alice::@example.org",
    ] {
        assert!(UserAddress::parse(address).is_err(), "accepted {address}");
    }
}

#[test]
fn node_identity_is_stable_across_reload() {
    let path = std::env::temp_dir().join(format!(
        "iota-node-identity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let first = LocalNodeIdentity::load_or_create(&path, None).unwrap();
    let second = LocalNodeIdentity::load_or_create(&path, None).unwrap();

    assert_eq!(first.node_id(), second.node_id());
    assert_eq!(first.authority_id(), second.authority_id());
    assert_eq!(
        IotaNodeId::from_public_keys(&first.public_keys()).unwrap(),
        *first.node_id()
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn legacy_omega_route_is_not_a_cryptographic_iota_identity() {
    let authority = AuthorityId::omega_legacy("omega-a.example").unwrap();
    let home = PrincipalHome::LegacyOmegaIota {
        omega: authority,
        iota_id: 42,
    };
    assert!(matches!(
        home,
        PrincipalHome::LegacyOmegaIota { iota_id: 42, .. }
    ));
}

#[test]
fn descriptor_expiry_is_exclusive() {
    let resolved = ResolvedPrincipal {
        principal: PrincipalId {
            authority: AuthorityId::new("omega:example").unwrap(),
            user_id: 1,
        },
        handle: PrincipalHandle(1),
        username: None,
        public_keys: Vec::new(),
        home: PrincipalHome::Unknown,
        descriptor_revision: 1,
        valid_until: Some(100),
        resolved_at: 1,
    };
    assert!(resolved.is_valid_at(99));
    assert!(!resolved.is_valid_at(100));
}

#[test]
fn offline_cache_policy_enforces_its_staleness_limit() {
    let policy = OfflineResolutionPolicy::AllowUnexpired {
        max_staleness: Duration::from_secs(1),
    };

    assert!(policy.allows_cached(1_000, 2_000));
    assert!(!policy.allows_cached(1_000, 2_001));
    assert!(!OfflineResolutionPolicy::RejectStale.allows_cached(1_000, 1_000));
}
