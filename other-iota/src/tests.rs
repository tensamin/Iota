use super::*;
use iota_identity::{
    LocalNodeIdentity, NodeDescriptor, NodeIdentityResolver, PrincipalDescriptor, PrincipalHandle,
    PrincipalHome, SignedNodeDescriptor, SignedPrincipalDescriptor, VerifiedNodeDescriptor,
    VerifiedPrincipalDescriptor,
};
use mtp::codec::CommunicationType;
use std::sync::Mutex;

fn node() -> IotaNodeId {
    iota_identity::LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate())
        .expect("generated identity is valid")
        .node_id()
        .clone()
}

#[test]
fn route_publication_fails_when_the_registry_is_poisoned() {
    let router = Arc::new(DirectPeerRouter::default());
    let poisoning = router.clone();
    let _ = std::thread::spawn(move || {
        let _guard = poisoning.peers.write().unwrap();
        panic!("poison route registry");
    })
    .join();
    assert!(router.register(node(), Arc::new(AcceptingPeer)).is_err());
}

#[test]
fn nonpreferred_and_stale_connections_cannot_remove_the_selected_route() {
    let router = DirectPeerRouter::default();
    let node = node();
    let old = router
        .register_selected(node.clone(), Arc::new(AcceptingPeer), false)
        .unwrap()
        .unwrap();
    let selected = router
        .register_selected(node.clone(), Arc::new(AcceptingPeer), true)
        .unwrap()
        .unwrap();
    assert!(
        router
            .register_selected(node.clone(), Arc::new(AcceptingPeer), false)
            .unwrap()
            .is_none()
    );
    router.unregister(&node, old);
    assert!(router.has_connection(&node));
    router.unregister(&node, selected);
    assert!(!router.has_connection(&node));
}

#[test]
fn captured_der_certificate_is_stored_as_valid_pem() {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let pem = certificate_to_pem(certificate.der().to_vec()).unwrap();
    reqwest::Certificate::from_pem(&pem).unwrap();
}

struct AcceptingPeer;

#[async_trait]
impl DirectPeerConnection for AcceptingPeer {
    async fn send_relay(&self, _: CommunicationValue) -> Result<RouteOutcome, RouteError> {
        Ok(RouteOutcome::Accepted {
            relay_message_id: "relay-a".into(),
            destination_accepted_at: 42,
        })
    }
}

#[tokio::test]
async fn direct_router_uses_the_connection_registered_for_the_node() {
    let router = DirectPeerRouter::default();
    let node = node();
    router
        .register(node.clone(), Arc::new(AcceptingPeer))
        .unwrap();

    let outcome = router
        .route(
            &RouteDestination::Iota(node),
            CommunicationValue::new(CommunicationType::Relay),
        )
        .await
        .expect("registered peer is routable");
    assert!(matches!(outcome, RouteOutcome::Accepted { .. }));
}

#[tokio::test]
async fn direct_router_reports_an_unknown_node_as_no_route() {
    let router = DirectPeerRouter::default();
    let node = node();
    let error = router
        .route(
            &RouteDestination::Iota(node.clone()),
            CommunicationValue::new(CommunicationType::Relay),
        )
        .await
        .expect_err("unregistered peer has no route");
    assert!(matches!(error, RouteError::NoRoute(found) if found == node));
}

#[test]
fn simultaneous_dials_choose_one_connection_direction() {
    let first = node();
    let second = node();
    assert_ne!(first, second);
    assert_ne!(
        prefers_inbound(&first, &second),
        prefers_inbound(&second, &first)
    );
}

struct MemoryPrincipals {
    values: Mutex<HashMap<PrincipalId, ResolvedPrincipal>>,
}

impl PrincipalStore for MemoryPrincipals {
    fn get_principal(
        &self,
        handle: PrincipalHandle,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?
            .values()
            .find(|principal| principal.handle == handle)
            .cloned())
    }

    fn get_by_canonical_id(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?
            .get(principal)
            .cloned())
    }

    fn get_by_username(
        &self,
        authority: &AuthorityId,
        username: &str,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?
            .values()
            .find(|principal| {
                &principal.principal.authority == authority
                    && principal.username.as_deref() == Some(username)
            })
            .cloned())
    }

    fn upsert_remote_descriptor(
        &self,
        descriptor: &VerifiedPrincipalDescriptor,
    ) -> Result<PrincipalHandle, IdentityError> {
        let descriptor_value = descriptor.descriptor();
        let mut values = self
            .values
            .lock()
            .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?;
        if values
            .get(&descriptor_value.principal)
            .is_some_and(|current| current.descriptor_revision > descriptor_value.revision)
        {
            return Err(IdentityError::Storage("stale descriptor".into()));
        }
        let handle = values
            .get(&descriptor_value.principal)
            .map(|principal| principal.handle)
            .unwrap_or(PrincipalHandle(values.len() as i64 + 1));
        values.insert(
            descriptor_value.principal.clone(),
            ResolvedPrincipal {
                principal: descriptor_value.principal.clone(),
                handle,
                username: descriptor_value.username.clone(),
                public_keys: descriptor_value.public_keys.clone(),
                home: descriptor_value.home.clone(),
                descriptor_revision: descriptor_value.revision,
                valid_until: descriptor_value.valid_until,
                resolved_at: descriptor.resolved_at(),
            },
        );
        Ok(handle)
    }

    fn signing_keys(&self, principal: &PrincipalId) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        self.get_by_canonical_id(principal)?
            .map(|principal| principal.public_keys)
            .ok_or(IdentityError::NotFound)
    }
}

struct MemoryNodes {
    values: Mutex<HashMap<IotaNodeId, iota_identity::ResolvedNodeIdentity>>,
    pins: Mutex<HashMap<AuthorityLocator, IotaNodeId>>,
    certificates: Mutex<HashMap<AuthorityLocator, Vec<u8>>>,
}

#[async_trait]
impl iota_identity::NodeIdentityResolver for MemoryNodes {
    async fn resolve_node(
        &self,
        node: &IotaNodeId,
    ) -> Result<iota_identity::ResolvedNodeIdentity, IdentityError> {
        self.values
            .lock()
            .map_err(|_| IdentityError::Storage("node lock is poisoned".into()))?
            .get(node)
            .cloned()
            .ok_or(IdentityError::NotFound)
    }
}

impl NodeDirectory for MemoryNodes {
    fn upsert_node_descriptor(
        &self,
        descriptor: &VerifiedNodeDescriptor,
    ) -> Result<(), IdentityError> {
        let value = descriptor.descriptor();
        self.values
            .lock()
            .map_err(|_| IdentityError::Storage("node lock is poisoned".into()))?
            .insert(
                value.node.clone(),
                iota_identity::ResolvedNodeIdentity {
                    node: value.node.clone(),
                    public_keys: vec![value.public_keys.clone()],
                    descriptor_revision: value.revision,
                    valid_until: value.valid_until,
                    direct_endpoints: value.direct_endpoints.clone(),
                    relay_hints: value.relay_hints.clone(),
                    last_successful_endpoint: None,
                    resolved_at: descriptor.resolved_at(),
                },
            );
        Ok(())
    }

    fn pin_endpoint(
        &self,
        endpoint: &AuthorityLocator,
        node: &IotaNodeId,
        _: i64,
    ) -> Result<(), IdentityError> {
        let mut pins = self
            .pins
            .lock()
            .map_err(|_| IdentityError::Storage("pin lock is poisoned".into()))?;
        if pins.get(endpoint).is_some_and(|pinned| pinned != node) {
            return Err(IdentityError::InvalidDescriptor(
                "endpoint node identity changed from its TOFU pin".into(),
            ));
        }
        pins.insert(endpoint.clone(), node.clone());
        Ok(())
    }

    fn pinned_node(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<IotaNodeId>, IdentityError> {
        Ok(self
            .pins
            .lock()
            .map_err(|_| IdentityError::Storage("pin lock is poisoned".into()))?
            .get(endpoint)
            .cloned())
    }

    fn pin_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
        certificate: &[u8],
    ) -> Result<(), IdentityError> {
        let mut certificates = self
            .certificates
            .lock()
            .map_err(|_| IdentityError::Storage("certificate lock is poisoned".into()))?;
        if certificates
            .get(endpoint)
            .is_some_and(|pinned| pinned != certificate)
        {
            return Err(IdentityError::InvalidDescriptor(
                "endpoint TLS certificate changed from its TOFU pin".into(),
            ));
        }
        certificates.insert(endpoint.clone(), certificate.to_vec());
        Ok(())
    }

    fn pinned_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<Vec<u8>>, IdentityError> {
        Ok(self
            .certificates
            .lock()
            .map_err(|_| IdentityError::Storage("certificate lock is poisoned".into()))?
            .get(endpoint)
            .cloned())
    }

    fn record_successful_endpoint(
        &self,
        _: &IotaNodeId,
        _: &AuthorityLocator,
    ) -> Result<(), IdentityError> {
        Ok(())
    }
}

struct FakeFederationClient {
    authority: Mutex<DiscoveredAuthority>,
    node: Mutex<NodeDescriptorWireV1>,
    principal: Mutex<PrincipalDescriptorWireV1>,
    certificate: Mutex<Vec<u8>>,
}

#[async_trait]
impl FederationIdentityClient for FakeFederationClient {
    async fn discover(&self, _: &AuthorityLocator) -> Result<DiscoveredAuthority, IdentityError> {
        self.authority
            .lock()
            .map(|authority| authority.clone())
            .map_err(|_| IdentityError::Storage("authority lock is poisoned".into()))
    }

    async fn node_descriptor(
        &self,
        _: &AuthorityLocator,
        _: &str,
    ) -> Result<FetchedNodeDescriptor, IdentityError> {
        let descriptor = self
            .node
            .lock()
            .map_err(|_| IdentityError::Storage("node lock is poisoned".into()))?
            .clone();
        let certificate = self
            .certificate
            .lock()
            .map_err(|_| IdentityError::Storage("certificate lock is poisoned".into()))?
            .clone();
        Ok(FetchedNodeDescriptor {
            descriptor,
            tls_certificate: Some(certificate),
        })
    }

    async fn principal_descriptor(
        &self,
        _: &AuthorityLocator,
        _: &UserSelector,
    ) -> Result<PrincipalDescriptorWireV1, IdentityError> {
        self.principal
            .lock()
            .map(|principal| principal.clone())
            .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))
    }
}

type RemoteFixture = (
    Arc<RemoteIotaResolver>,
    Arc<FakeFederationClient>,
    Arc<MemoryPrincipals>,
    Arc<MemoryNodes>,
    AuthorityLocator,
    PrincipalId,
    PublicKeyBundle,
);

fn remote_fixture(principal_revision: i64) -> RemoteFixture {
    let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let user = mtp::crypto::Keyring::generate();
    let locator = AuthorityLocator::new("192.0.2.10").unwrap();
    let node = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: authority.node_id().clone(),
            public_keys: authority.public_keys(),
            direct_endpoints: vec![locator.clone()],
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: Some(now_millis() + 60_000),
        },
        &authority,
    )
    .unwrap()
    .to_wire_v1()
    .unwrap();
    let principal_id = PrincipalId {
        authority: authority.authority_id().clone(),
        user_id: 7,
    };
    let principal = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: principal_id.clone(),
            authority_kind: AuthorityKind::Iota,
            username: Some("alice".into()),
            display_name: None,
            public_keys: vec![user.public_key_bundle()],
            home: PrincipalHome::Iota(authority.node_id().clone()),
            revision: principal_revision,
            valid_until: Some(now_millis() + 60_000),
            issued_at: now_millis(),
        },
        &authority.keyring(),
    )
    .unwrap()
    .to_wire_v1()
    .unwrap();
    let client = Arc::new(FakeFederationClient {
        authority: Mutex::new(DiscoveredAuthority {
            service: AuthorityKind::Iota,
            authority_id: authority.authority_id().clone(),
            node_id: Some(authority.node_id().clone()),
            public_keys: authority.public_keys(),
            protocols: vec!["identity-http-v1".into()],
            node_descriptor: Some("/federation/v1/node".into()),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
        }),
        node: Mutex::new(node),
        principal: Mutex::new(principal),
        certificate: Mutex::new(b"test certificate".to_vec()),
    });
    let principals = Arc::new(MemoryPrincipals {
        values: Mutex::new(HashMap::new()),
    });
    let nodes = Arc::new(MemoryNodes {
        values: Mutex::new(HashMap::new()),
        pins: Mutex::new(HashMap::new()),
        certificates: Mutex::new(HashMap::new()),
    });
    let resolver = Arc::new(RemoteIotaResolver::new(
        client.clone(),
        principals.clone(),
        nodes.clone(),
    ));
    (
        resolver,
        client,
        principals,
        nodes,
        locator,
        principal_id,
        user.public_key_bundle(),
    )
}

#[tokio::test]
async fn discovery_cache_tracks_verified_generation_and_deadline() {
    let (resolver, client, _, nodes, locator, _, _) = remote_fixture(1);
    let authority = resolver.authority(&locator, true).await.unwrap();
    // Discovery alone never creates a verified cache entry.
    assert!(resolver.authorities.read().unwrap().is_empty());
    resolver
        .refresh(&locator, &authority, &UserSelector::UserId(7))
        .await
        .unwrap();
    client.authority.lock().unwrap().protocols = vec!["changed".into()];
    assert_eq!(
        resolver.authority(&locator, true).await.unwrap().protocols,
        authority.protocols
    );
    let fresh = RemoteIotaResolver::new(client.clone(), resolver.principals.clone(), nodes.clone())
        .with_discovery_freshness(std::time::Duration::ZERO);
    fresh
        .refresh(&locator, &authority, &UserSelector::UserId(7))
        .await
        .unwrap();
    assert_eq!(
        fresh.authority(&locator, true).await.unwrap().protocols,
        vec!["changed"]
    );
    let node = authority.node_id.as_ref().unwrap();
    nodes
        .values
        .lock()
        .unwrap()
        .get_mut(node)
        .unwrap()
        .descriptor_revision += 1;
    assert_eq!(
        resolver.authority(&locator, true).await.unwrap().protocols,
        vec!["changed"]
    );
    assert_ne!(
        resolver
            .authorities
            .read()
            .unwrap()
            .get(&locator)
            .unwrap()
            .descriptor_revision,
        nodes
            .values
            .lock()
            .unwrap()
            .get(node)
            .unwrap()
            .descriptor_revision
    );
}

#[tokio::test]
async fn discovery_refresh_rejects_identity_change_and_removed_trust() {
    let (resolver, client, _, nodes, locator, _, _) = remote_fixture(1);
    let authority = resolver.authority(&locator, true).await.unwrap();
    resolver
        .refresh(&locator, &authority, &UserSelector::UserId(7))
        .await
        .unwrap();
    nodes.pins.lock().unwrap().remove(&locator);
    assert_eq!(
        resolver.authority(&locator, true).await.unwrap_err(),
        IdentityError::KeyPinMismatch
    );
    nodes
        .pins
        .lock()
        .unwrap()
        .insert(locator.clone(), authority.node_id.clone().unwrap());
    resolver
        .authorities
        .write()
        .unwrap()
        .get_mut(&locator)
        .unwrap()
        .verified_at = 0;
    client.authority.lock().unwrap().node_id = Some(
        IotaNodeId::from_public_keys(&mtp::crypto::Keyring::generate().public_key_bundle())
            .unwrap(),
    );
    assert!(matches!(
        resolver.authority(&locator, true).await.unwrap_err(),
        IdentityError::InvalidDescriptor(_)
    ));
}

#[tokio::test]
async fn remote_iota_resolves_username_id_and_key_pin() {
    let (resolver, _, _, _, locator, principal, key) = remote_fixture(1);
    for selector in [
        UserSelector::Username("alice".into()),
        UserSelector::UserId(7),
    ] {
        let resolved = resolver
            .resolve_address(
                &UserAddress {
                    selector,
                    public_key_pin: Some(key.clone()),
                    authority: Some(locator.clone()),
                },
                &ResolutionContext {
                    allow_network: true,
                    ..ResolutionContext::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(resolved.principal, principal);
    }
}

#[tokio::test]
async fn remote_iota_rejects_wrong_key_pin() {
    let (resolver, _, _, _, locator, _, _) = remote_fixture(1);
    let error = resolver
        .resolve_address(
            &UserAddress {
                selector: UserSelector::UserId(7),
                public_key_pin: Some(mtp::crypto::Keyring::generate().public_key_bundle()),
                authority: Some(locator.clone()),
            },
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error, IdentityError::KeyPinMismatch);
}

#[tokio::test]
async fn remote_iota_rejects_wrong_authority_signature() {
    let (resolver, client, _, _, locator, _, _) = remote_fixture(1);
    let descriptor = client
        .principal
        .lock()
        .unwrap()
        .clone()
        .parse()
        .unwrap()
        .descriptor;
    *client.principal.lock().unwrap() =
        SignedPrincipalDescriptor::sign(descriptor, &mtp::crypto::Keyring::generate())
            .unwrap()
            .to_wire_v1()
            .unwrap();

    let authority = client.discover(&locator).await.unwrap();
    let error = resolver
        .refresh(&locator, &authority, &UserSelector::UserId(7))
        .await
        .unwrap_err();
    assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
}

#[tokio::test]
async fn remote_iota_rejects_stale_principal_revision() {
    let (resolver, client, principals, _, locator, _, _) = remote_fixture(1);
    let mut current = client
        .principal
        .lock()
        .unwrap()
        .clone()
        .parse()
        .unwrap()
        .descriptor;
    current.revision = 2;
    principals
        .upsert_remote_descriptor(
            &VerifiedPrincipalDescriptor::from_trusted_authority(current).unwrap(),
        )
        .unwrap();

    let authority = client.discover(&locator).await.unwrap();
    let error = resolver
        .refresh(&locator, &authority, &UserSelector::UserId(7))
        .await
        .unwrap_err();
    assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
}

#[tokio::test]
async fn remote_iota_uses_valid_cached_descriptor_offline() {
    let (resolver, client, principals, nodes, locator, principal, _) = remote_fixture(1);
    let address = UserAddress {
        selector: UserSelector::UserId(7),
        public_key_pin: None,
        authority: Some(locator),
    };
    resolver
        .resolve_address(
            &address,
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
        .unwrap();

    let restarted = RemoteIotaResolver::new(client, principals, nodes);
    let cached = restarted
        .resolve_address(&address, &ResolutionContext::default())
        .await
        .unwrap();
    assert_eq!(cached.principal, principal);
}

#[tokio::test]
async fn remote_iota_rejects_discovery_node_mismatch() {
    let (resolver, client, _, _, locator, _, _) = remote_fixture(1);
    client.authority.lock().unwrap().node_id = Some(node());

    let error = resolver
        .resolve_address(
            &UserAddress {
                selector: UserSelector::UserId(7),
                public_key_pin: None,
                authority: Some(locator),
            },
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
}

#[tokio::test]
async fn raw_ip_bootstrap_rejects_changed_tofu_node() {
    let (resolver, _, _, nodes, locator, _, _) = remote_fixture(1);
    nodes.pins.lock().unwrap().insert(locator.clone(), node());

    let error = resolver
        .resolve_address(
            &UserAddress {
                selector: UserSelector::UserId(7),
                public_key_pin: None,
                authority: Some(locator),
            },
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
}

#[tokio::test]
async fn raw_ip_bootstrap_accepts_explicit_node_key_pin() {
    let (resolver, client, _, nodes, locator, principal, _) = remote_fixture(1);
    let key = client
        .node
        .lock()
        .unwrap()
        .clone()
        .parse()
        .unwrap()
        .descriptor
        .public_keys;
    let pinned = resolver.pin_public_key(&locator, &key).unwrap();

    let resolved = resolver
        .resolve_address(
            &UserAddress {
                selector: UserSelector::UserId(7),
                public_key_pin: None,
                authority: Some(locator.clone()),
            },
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.principal, principal);
    assert!(matches!(resolved.home, PrincipalHome::Iota(home) if home == pinned));
    assert_eq!(
        nodes.pinned_endpoint_certificate(&locator).unwrap(),
        Some(b"test certificate".to_vec())
    );
    let resolved_at = nodes.resolve_node(&pinned).await.unwrap().resolved_at;

    *client.certificate.lock().unwrap() = b"changed certificate".to_vec();
    let authority = client.discover(&locator).await.unwrap();
    assert!(
        resolver
            .refresh(&locator, &authority, &UserSelector::UserId(7))
            .await
            .is_err()
    );
    assert_eq!(
        nodes.resolve_node(&pinned).await.unwrap().resolved_at,
        resolved_at
    );
}

#[tokio::test]
async fn remote_omega_resolves_principal_and_hosting_iota() {
    let omega = mtp::crypto::Keyring::generate();
    let omega_authority = AuthorityId::for_omega(&omega.public_key_bundle()).unwrap();
    let hosting_iota = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
    let user = mtp::crypto::Keyring::generate();
    let locator = AuthorityLocator::new("omega.example.org").unwrap();
    let node = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: hosting_iota.node_id().clone(),
            public_keys: hosting_iota.public_keys(),
            direct_endpoints: vec![AuthorityLocator::new("iota.example.org").unwrap()],
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: Some(now_millis() + 60_000),
        },
        &hosting_iota,
    )
    .unwrap()
    .to_wire_v1()
    .unwrap();
    let principal_id = PrincipalId {
        authority: omega_authority.clone(),
        user_id: 7,
    };
    let principal = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: principal_id.clone(),
            authority_kind: AuthorityKind::Omega,
            username: Some("alice".into()),
            display_name: None,
            public_keys: vec![user.public_key_bundle()],
            home: PrincipalHome::Iota(hosting_iota.node_id().clone()),
            revision: 1,
            valid_until: Some(now_millis() + 60_000),
            issued_at: now_millis(),
        },
        &omega,
    )
    .unwrap()
    .to_wire_v1()
    .unwrap()
    .with_home_node(node);
    let client = Arc::new(FakeFederationClient {
        authority: Mutex::new(DiscoveredAuthority {
            service: AuthorityKind::Omega,
            authority_id: omega_authority,
            node_id: None,
            public_keys: omega.public_key_bundle(),
            protocols: vec!["identity-http-v1".into()],
            node_descriptor: None,
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
        }),
        node: Mutex::new(
            SignedNodeDescriptor::sign(
                NodeDescriptor {
                    node: hosting_iota.node_id().clone(),
                    public_keys: hosting_iota.public_keys(),
                    direct_endpoints: Vec::new(),
                    relay_hints: Vec::new(),
                    revision: 1,
                    valid_until: Some(now_millis() + 60_000),
                },
                &hosting_iota,
            )
            .unwrap()
            .to_wire_v1()
            .unwrap(),
        ),
        principal: Mutex::new(principal),
        certificate: Mutex::new(b"test certificate".to_vec()),
    });
    let principals = Arc::new(MemoryPrincipals {
        values: Mutex::new(HashMap::new()),
    });
    let nodes = Arc::new(MemoryNodes {
        values: Mutex::new(HashMap::new()),
        pins: Mutex::new(HashMap::new()),
        certificates: Mutex::new(HashMap::new()),
    });
    let resolver = RemoteOmegaResolver::new(client, principals, nodes.clone());

    let resolved = resolver
        .resolve_address(
            &UserAddress {
                selector: UserSelector::Username("alice".into()),
                public_key_pin: Some(user.public_key_bundle()),
                authority: Some(locator),
            },
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.principal, principal_id);
    assert!(nodes.resolve_node(hosting_iota.node_id()).await.is_ok());
}
