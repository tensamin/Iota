use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::federated_relay::FederatedRelayV2;
use iota_connection::relay_service::{RelayNodeIdentity, RelayService};
use iota_identity::{
    AuthorityLocator, IdentityError, IdentityResolver, IotaNodeId, LocalNodeIdentity,
    LocalUserDescriptor, LocalUserId, LocalUserStore, NodeDirectory, NodeIdentityResolver,
    PrincipalDescriptor, PrincipalHandle, PrincipalHome, PrincipalId, PrincipalStore,
    PublicKeyBundle, ResolutionContext, ResolvedNodeIdentity, ResolvedPrincipal,
    SignedPrincipalDescriptor, UserAddress,
};
use iota_storage::identity::SqlitePrincipalStore;
use iota_storage::util::{chat_files, e2ee_storage};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::Keyring;
use mtp::host::{AuthenticationPolicy, HostConfig};
use mtp::webserver::{MTPWebServer, WebServerConfig};
use other_iota::{DirectPeerRouter, LocalDeliverySink, PeerManager};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, RwLock};

struct StoreResolver;

#[async_trait]
impl IdentityResolver for StoreResolver {
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        SqlitePrincipalStore
            .get_by_canonical_id(principal)?
            .ok_or(IdentityError::NotFound)
    }

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        SqlitePrincipalStore.signing_keys(principal)
    }
}

struct HostedRecipient {
    principal: PrincipalHandle,
}

impl LocalUserStore for HostedRecipient {
    fn get_local_user(&self, _: LocalUserId) -> Result<Option<LocalUserDescriptor>, IdentityError> {
        Ok(None)
    }

    fn get_local_user_by_username(
        &self,
        _: &str,
    ) -> Result<Option<LocalUserDescriptor>, IdentityError> {
        Ok(None)
    }

    fn is_hosted_here(&self, id: LocalUserId) -> Result<bool, IdentityError> {
        Ok(id == LocalUserId(1))
    }

    fn local_user_for_principal(
        &self,
        principal: PrincipalHandle,
    ) -> Result<Option<LocalUserId>, IdentityError> {
        Ok((principal == self.principal).then_some(LocalUserId(1)))
    }

    fn principal_for_local_user(
        &self,
        user: LocalUserId,
    ) -> Result<Option<PrincipalHandle>, IdentityError> {
        Ok((user == LocalUserId(1)).then_some(self.principal))
    }
}

struct TestNodeIdentity(LocalNodeIdentity);

#[async_trait]
impl RelayNodeIdentity for TestNodeIdentity {
    async fn keyring(&self) -> Option<Arc<Keyring>> {
        Some(self.0.keyring())
    }

    fn node_id(&self) -> Option<IotaNodeId> {
        Some(self.0.node_id().clone())
    }
}

struct NoRoute;

#[async_trait]
impl PeerRouter for NoRoute {
    async fn route(
        &self,
        destination: &RouteDestination,
        _: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        match destination {
            RouteDestination::Iota(node) => Err(RouteError::NoRoute(node.clone())),
            RouteDestination::LegacyOmegaIota { .. } => Ok(RouteOutcome::Retryable {
                reason: "legacy route is unavailable".into(),
            }),
        }
    }
}

#[derive(Default)]
struct MemoryNodes {
    nodes: RwLock<HashMap<IotaNodeId, ResolvedNodeIdentity>>,
    certificates: RwLock<HashMap<AuthorityLocator, Vec<u8>>>,
}

#[async_trait]
impl NodeIdentityResolver for MemoryNodes {
    async fn resolve_node(&self, node: &IotaNodeId) -> Result<ResolvedNodeIdentity, IdentityError> {
        self.nodes
            .read()
            .map_err(|_| IdentityError::Storage("node lock is poisoned".into()))?
            .get(node)
            .cloned()
            .ok_or(IdentityError::NotFound)
    }
}

impl NodeDirectory for MemoryNodes {
    fn upsert_node_descriptor(
        &self,
        _: &iota_identity::VerifiedNodeDescriptor,
    ) -> Result<(), IdentityError> {
        Ok(())
    }

    fn pin_endpoint(
        &self,
        _: &AuthorityLocator,
        _: &IotaNodeId,
        _: i64,
    ) -> Result<(), IdentityError> {
        Ok(())
    }

    fn pinned_node(&self, _: &AuthorityLocator) -> Result<Option<IotaNodeId>, IdentityError> {
        Ok(None)
    }

    fn pin_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
        certificate: &[u8],
    ) -> Result<(), IdentityError> {
        self.certificates
            .write()
            .map_err(|_| IdentityError::Storage("certificate lock is poisoned".into()))?
            .insert(endpoint.clone(), certificate.to_vec());
        Ok(())
    }

    fn pinned_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<Vec<u8>>, IdentityError> {
        Ok(self
            .certificates
            .read()
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

#[derive(Default)]
struct Deliveries(Mutex<Vec<(PrincipalHandle, CommunicationValue)>>);

#[async_trait]
impl LocalDeliverySink for Deliveries {
    async fn deliver(&self, recipient: PrincipalHandle, frame: CommunicationValue) {
        self.0.lock().unwrap().push((recipient, frame));
    }
}

fn verified_principal(
    authority: &LocalNodeIdentity,
    user: &Keyring,
    user_id: u64,
) -> iota_identity::VerifiedPrincipalDescriptor {
    let now = iota_storage::util::sync::now_millis();
    SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: authority.authority_id().clone(),
                user_id,
            },
            authority_kind: iota_identity::AuthorityKind::Iota,
            username: Some("alice".into()),
            display_name: None,
            public_keys: vec![user.public_key_bundle()],
            home: PrincipalHome::Iota(authority.node_id().clone()),
            revision: 1,
            valid_until: Some(now + 60_000),
            issued_at: now,
        },
        &authority.keyring(),
    )
    .unwrap()
    .verify(
        authority.authority_id(),
        &authority.public_keys(),
        None,
        now,
    )
    .unwrap()
}

fn resolved_node(
    identity: &LocalNodeIdentity,
    direct_endpoints: Vec<AuthorityLocator>,
) -> ResolvedNodeIdentity {
    ResolvedNodeIdentity {
        node: identity.node_id().clone(),
        public_keys: vec![identity.public_keys()],
        descriptor_revision: 1,
        valid_until: None,
        direct_endpoints,
        relay_hints: Vec::new(),
        last_successful_endpoint: None,
        resolved_at: iota_storage::util::sync::now_millis(),
    }
}

fn certificate() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let certificate = params.self_signed(&key_pair).unwrap();
    (
        certificate.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
}

async fn start_peer_server(
    port: u16,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
    client: &LocalNodeIdentity,
    host: &LocalNodeIdentity,
    manager: Arc<PeerManager>,
) -> (
    AuthorityLocator,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let client_key = client.public_keys();
    let client_hint = client.node_id().mtp_authentication_hint();
    let host_keyring = Keyring::from_bytes(&host.keyring().try_to_bytes().unwrap()).unwrap();
    let host = HostConfig::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        certificate,
        private_key,
    )
    .with_authentication(
        host_keyring,
        Box::new(move |client_id, _| {
            let public_key = (client_id == client_hint).then(|| client_key.clone());
            Box::pin(async move { public_key })
        }),
        Box::new(|_, _| Box::pin(async { 0 })),
    )
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
    let mut server = MTPWebServer::new(host, WebServerConfig::new())
        .await
        .unwrap();
    let endpoint = AuthorityLocator::new(server.local_addr().to_string()).unwrap();
    let (shutdown, mut shutdown_requested) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_requested => {
                    server.shutdown().await;
                    break;
                }
                accepted = server.accept() => match accepted {
                    Ok(Some(connection)) => {
                        let manager = manager.clone();
                        tokio::spawn(async move {
                            web_server::MtpConnectionHandler::accept(manager.as_ref(), connection)
                                .await;
                        });
                    }
                    Ok(None) => break,
                    Err(_) => continue,
                }
            }
        }
    });
    (endpoint, shutdown, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_peer_delivers_relay_v2_to_same_numeric_user_on_another_iota() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    iota_storage::util::db::initialize_database().unwrap();

    let iota_a = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let iota_b = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let user_a = Keyring::generate();
    let user_b = Keyring::generate();
    let principal_a = verified_principal(&iota_a, &user_a, 1);
    let principal_b = verified_principal(&iota_b, &user_b, 1);
    let handle_a = SqlitePrincipalStore
        .upsert_remote_descriptor(&principal_a)
        .unwrap();
    let handle_b = SqlitePrincipalStore
        .upsert_remote_descriptor(&principal_b)
        .unwrap();
    assert_ne!(handle_a, handle_b);

    let chat_id = e2ee_storage::principal_chat_id(handle_a, handle_b).unwrap();
    e2ee_storage::put_chat_secret(e2ee_storage::StoredChatSecret {
        user_id: "1".into(),
        secret_id: e2ee_storage::principal_secret_id(&chat_id),
        chat_id,
        version: 1,
        encrypted_secret: vec![1],
        kem_ciphertext: vec![2],
        wrapping_scheme: "test".into(),
        created_at: 1,
        updated_at: 1,
    })
    .unwrap();

    let resolver: Arc<dyn IdentityResolver> = Arc::new(StoreResolver);
    let local_users: Arc<dyn LocalUserStore> = Arc::new(HostedRecipient {
        principal: handle_b,
    });
    let relay_b = Arc::new(
        RelayService::new(local_users, Arc::new(NoRoute), None)
            .with_federation(resolver, Arc::new(TestNodeIdentity(iota_b.clone()))),
    );
    let deliveries = Arc::new(Deliveries::default());
    let nodes_b = Arc::new(MemoryNodes::default());
    nodes_b
        .nodes
        .write()
        .unwrap()
        .insert(iota_a.node_id().clone(), resolved_node(&iota_a, Vec::new()));
    let router_b = Arc::new(DirectPeerRouter::default());
    let manager_b = Arc::new(PeerManager::new(
        iota_b.clone(),
        nodes_b.clone(),
        router_b,
        relay_b.clone(),
        deliveries.clone(),
    ));

    let (certificate, private_key) = certificate();
    let (endpoint, shutdown, server_task) = start_peer_server(
        0,
        certificate.clone(),
        private_key.clone(),
        &iota_a,
        &iota_b,
        manager_b.clone(),
    )
    .await;

    let wrong_nodes = Arc::new(MemoryNodes::default());
    wrong_nodes.nodes.write().unwrap().insert(
        iota_b.node_id().clone(),
        ResolvedNodeIdentity {
            public_keys: vec![Keyring::generate().public_key_bundle()],
            ..resolved_node(&iota_b, vec![endpoint.clone()])
        },
    );
    let wrong_manager = Arc::new(PeerManager::new(
        iota_a.clone(),
        wrong_nodes,
        Arc::new(DirectPeerRouter::default()),
        relay_b.clone(),
        Arc::new(Deliveries::default()),
    ));
    assert!(
        wrong_manager
            .connect(
                iota_b.node_id().clone(),
                &endpoint,
                Some(certificate.clone()),
            )
            .await
            .is_err()
    );

    let nodes_a = Arc::new(MemoryNodes::default());
    nodes_a.nodes.write().unwrap().insert(
        iota_b.node_id().clone(),
        resolved_node(&iota_b, vec![endpoint.clone()]),
    );
    nodes_a
        .pin_endpoint_certificate(&endpoint, &certificate)
        .unwrap();
    let router_a = Arc::new(DirectPeerRouter::default());
    let manager_a = Arc::new(PeerManager::new(
        iota_a.clone(),
        nodes_a.clone(),
        router_a.clone(),
        relay_b,
        Arc::new(Deliveries::default()),
    ));
    router_a.attach_manager(&manager_a);
    manager_a.connect_best(iota_b.node_id()).await.unwrap();

    let content = CommunicationValue::new(CommunicationType::MessageSend)
        .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into()))
        .add_typed_default(DataType::SendTime, DataValue::SignedNumber(10))
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1));
    let frame = FederatedRelayV2::sign(
        principal_a.descriptor().principal.clone(),
        principal_b.descriptor().principal.clone(),
        iota_b.node_id().clone(),
        "a-to-b".into(),
        10,
        content,
        &user_a,
    )
    .unwrap()
    .into_frame(7)
    .unwrap();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        router_a.route(&RouteDestination::Iota(iota_b.node_id().clone()), frame),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        outcome,
        RouteOutcome::Accepted {
            ref relay_message_id,
            ..
        } if relay_message_id == "a-to-b"
    ));

    let messages = chat_files::get_messages_for_principal(1, handle_a, 0, 10).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, "ciphertext");
    {
        let delivered = deliveries.0.lock().unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, handle_b);
        assert!(delivered[0].1.is_type(CommunicationType::MessageLive));
    }

    shutdown.send(()).unwrap();
    server_task.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while router_a.has_connection(iota_b.node_id()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let restarted_relay_b = Arc::new(
        RelayService::new(
            Arc::new(HostedRecipient {
                principal: handle_b,
            }),
            Arc::new(NoRoute),
            None,
        )
        .with_federation(
            Arc::new(StoreResolver),
            Arc::new(TestNodeIdentity(iota_b.clone())),
        ),
    );
    let restarted_manager_b = Arc::new(PeerManager::new(
        iota_b.clone(),
        nodes_b,
        Arc::new(DirectPeerRouter::default()),
        restarted_relay_b,
        deliveries,
    ));
    let (restarted_endpoint, shutdown, server_task) = start_peer_server(
        0,
        certificate.clone(),
        private_key,
        &iota_a,
        &iota_b,
        restarted_manager_b,
    )
    .await;
    nodes_a
        .nodes
        .write()
        .unwrap()
        .get_mut(iota_b.node_id())
        .unwrap()
        .direct_endpoints = vec![restarted_endpoint.clone()];
    nodes_a
        .pin_endpoint_certificate(&restarted_endpoint, &certificate)
        .unwrap();
    let router_a = Arc::new(DirectPeerRouter::default());
    let restarted_relay_a = Arc::new(
        RelayService::new(
            Arc::new(HostedRecipient {
                principal: handle_a,
            }),
            Arc::new(NoRoute),
            None,
        )
        .with_federation(
            Arc::new(StoreResolver),
            Arc::new(TestNodeIdentity(iota_a.clone())),
        ),
    );
    let manager_a = Arc::new(PeerManager::new(
        iota_a.clone(),
        nodes_a,
        router_a.clone(),
        restarted_relay_a,
        Arc::new(Deliveries::default()),
    ));
    router_a.attach_manager(&manager_a);

    let second = FederatedRelayV2::sign(
        principal_a.descriptor().principal.clone(),
        principal_b.descriptor().principal.clone(),
        iota_b.node_id().clone(),
        "a-to-b-after-reconnect".into(),
        11,
        CommunicationValue::new(CommunicationType::MessageSend)
            .add_typed_default(DataType::Content, DataValue::Str("second".into()))
            .add_typed_default(DataType::SendTime, DataValue::SignedNumber(11))
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1)),
        &user_a,
    )
    .unwrap()
    .into_frame(8)
    .unwrap();
    let outcome = router_a
        .route(&RouteDestination::Iota(iota_b.node_id().clone()), second)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        RouteOutcome::Accepted {
            ref relay_message_id,
            ..
        } if relay_message_id == "a-to-b-after-reconnect"
    ));
    assert_eq!(
        chat_files::get_messages_for_principal(1, handle_a, 0, 10)
            .unwrap()
            .len(),
        2
    );

    shutdown.send(()).unwrap();
    server_task.await.unwrap();
}
