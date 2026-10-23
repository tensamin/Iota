use async_trait::async_trait;
use client::{ClientConnectionManager, ConnectionGateway};
use iota_auth::{HostedSessionRegistrar, SessionManager};
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::federated_relay::FederatedRelay;
use iota_connection::relay_service::{RelayNodeIdentity, RelayService};
use iota_identity::{
    AuthorityKind, IdentityError, IdentityResolver, IotaNodeId, LocalNodeIdentity,
    LocalUserDescriptor, LocalUserId, LocalUserStore, NodeDirectory, PrincipalDescriptor,
    PrincipalHome, PrincipalId, PrincipalStore, PublicKeyBundle, ResolutionContext,
    ResolvedPrincipal, SignedPrincipalDescriptor, UserAddress,
};
use iota_storage::identity::{SqliteLocalUserStore, SqlitePrincipalStore};
use iota_storage::util::e2ee_storage;
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::Keyring;
use mtp::host::{AuthenticationPolicy, HostConfig};
use mtp::webserver::{MTPWebServer, WebServerConfig};
use other_iota::LocalDeliverySink;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

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

#[derive(Default)]
struct AcceptingRouter {
    frames: Mutex<Vec<CommunicationValue>>,
    pause: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

#[async_trait]
impl PeerRouter for AcceptingRouter {
    async fn route(
        &self,
        _: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let Some(DataValue::Bytes(payload)) = frame.get_data(DataType::SecurePayload) else {
            panic!("expected protected relay payload");
        };
        let relay_message_id =
            iota_connection::federated_relay::protocol::RelayWire::from_json(payload)
                .unwrap()
                .message_id;
        self.frames.lock().unwrap().push(frame);
        let pause = self.pause.lock().unwrap().take();
        if let Some((reached, resume)) = pause {
            reached.send(()).unwrap();
            resume.await.unwrap();
        }
        Ok(RouteOutcome::Accepted {
            relay_message_id,
            destination_accepted_at: 20,
        })
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosted_client_loads_state_originates_relay_and_receives_delivery() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    iota_storage::util::db::initialize_database().unwrap();

    let local_node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let mut remote_node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    while remote_node.node_id().as_str() >= local_node.node_id().as_str() {
        remote_node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    }
    let local_key = Keyring::generate();
    let remote_key = Keyring::generate();
    let local_user = LocalUserDescriptor {
        id: LocalUserId(1),
        username: "alice".into(),
        display_name: None,
        public_key: local_key.public_key_bundle().try_to_base64().unwrap(),
    };
    iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "INSERT INTO users (user_id, username, public_key, created_at) VALUES (1, 'alice', ?1, 1)",
            [&local_user.public_key],
        )?;
        connection.execute(
            "INSERT INTO user_residency (user_id, username, lifecycle_state, data_state, updated_at) VALUES (1, 'alice', 'managed', 'present', 1)",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    let now = iota_storage::util::sync::now_millis();
    let local_handle = SqlitePrincipalStore
        .ensure_local_principal(
            local_node.authority_id(),
            AuthorityKind::Iota,
            &local_user,
            PrincipalHome::Iota(local_node.node_id().clone()),
            now,
        )
        .unwrap();
    let remote_descriptor = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: remote_node.authority_id().clone(),
                user_id: 1,
            },
            authority_kind: AuthorityKind::Iota,
            username: Some("bob".into()),
            display_name: None,
            public_keys: vec![remote_key.public_key_bundle()],
            home: PrincipalHome::Iota(remote_node.node_id().clone()),
            revision: 1,
            valid_until: Some(now + 60_000),
            issued_at: now,
        },
        &remote_node.keyring(),
    )
    .unwrap()
    .verify(
        remote_node.authority_id(),
        &remote_node.public_keys(),
        None,
        now,
    )
    .unwrap();
    let remote_handle = SqlitePrincipalStore
        .upsert_remote_descriptor(&remote_descriptor)
        .unwrap();
    let chat_id = e2ee_storage::principal_chat_id(local_handle, remote_handle).unwrap();
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

    let router = Arc::new(AcceptingRouter::default());
    let local_users: Arc<dyn LocalUserStore> = Arc::new(SqliteLocalUserStore);
    let relay = Arc::new(
        RelayService::new(local_users.clone(), router.clone()).with_federation(
            Arc::new(StoreResolver),
            Arc::new(TestNodeIdentity(local_node.clone())),
        ),
    );
    let sessions = Arc::new(SessionManager::default());
    let manager = Arc::new(ClientConnectionManager::new(
        Arc::new(StoreResolver),
        Arc::new(HostedSessionRegistrar::new(sessions.clone())),
        sessions.clone(),
        relay.clone(),
    ));
    let direct_router = Arc::new(other_iota::DirectPeerRouter::default());
    let peers = Arc::new(other_iota::PeerManager::new(
        local_node.clone(),
        Arc::new(iota_storage::node_directory::SqliteNodeDirectory),
        direct_router.clone(),
        relay.clone(),
        manager.clone(),
    ));
    let gateway = Arc::new(ConnectionGateway::new(
        client::tau_gateway::admission_engine(),
        manager.clone(),
        peers,
    ));

    let (certificate, private_key) = certificate();
    let client_public_key = local_key.public_key_bundle();
    let peer_public_key = remote_node.public_keys();
    let host_keyring = Keyring::from_bytes(&local_node.keyring().try_to_bytes().unwrap()).unwrap();
    let host = HostConfig::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        certificate.clone(),
        private_key,
    )
    .with_authentication(
        host_keyring,
        Box::new(move |client_id, _| {
            let key = if client_id & (1_u64 << 63) != 0 {
                Some(peer_public_key.clone())
            } else {
                Some(client_public_key.clone())
            };
            Box::pin(async move { key })
        }),
        Box::new(|_, _| Box::pin(async { 0 })),
    )
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
    let mut server = MTPWebServer::new(host, WebServerConfig::new())
        .await
        .unwrap();
    let address = server.local_addr();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let (accepted, mut admissions) = tokio::sync::mpsc::unbounded_channel();
    let (ended, mut terminations) = tokio::sync::mpsc::unbounded_channel();
    let server_gateway = gateway.clone();
    let server_task = tokio::spawn(async move {
        let mut handlers = tokio::task::JoinSet::new();
        loop {
            let connection = tokio::select! {
                _ = server_shutdown.cancelled() => break,
                connection = server.accept() => connection.unwrap().unwrap(),
            };
            let (resume, ready) = tokio::sync::oneshot::channel();
            accepted.send(resume).unwrap();
            let gateway = server_gateway.clone();
            let shutdown = server_shutdown.clone();
            let ended = ended.clone();
            handlers.spawn(async move {
                ready.await.unwrap();
                web_server::MtpConnectionHandler::accept_until_shutdown(
                    gateway.as_ref(),
                    connection,
                    shutdown,
                )
                .await;
                ended.send(()).unwrap();
            });
        }
        server.shutdown().await;
        while let Some(result) = handlers.join_next().await {
            result.unwrap();
        }
    });
    for (id, description) in [(1, "unsupported"), (1, ""), (2, "client")] {
        let rejected = mtp::client::MTPClient::auth_connect(
            mtp::client::ClientConfig::new(format!("https://{address}/"))
                .with_client_id(id)
                .with_description(description)
                .with_pinned_pem(certificate.clone()),
            &local_key,
            &local_node.public_keys(),
        )
        .await
        .unwrap();
        admissions.recv().await.unwrap().send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), terminations.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!manager.is_connected(local_handle));
        assert!(rejected.receive().await.is_err());
    }
    // A handshake using the old configured key must still fail the current
    // account-to-key binding at the application boundary.
    let obsolete = mtp::client::MTPClient::auth_connect(
        mtp::client::ClientConfig::new(format!("https://{address}/"))
            .with_client_id(1)
            .with_description("client")
            .with_pinned_pem(certificate.clone()),
        &local_key,
        &local_node.public_keys(),
    )
    .await
    .unwrap();
    let resume = admissions.recv().await.unwrap();
    iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "UPDATE users SET public_key = ?1 WHERE user_id = 1",
            [remote_key.public_key_bundle().try_to_base64().unwrap()],
        )?;
        Ok(())
    })
    .unwrap();
    resume.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), terminations.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!manager.is_connected(local_handle));
    assert!(obsolete.receive().await.is_err());
    iota_storage::util::db::with_db(|connection| {
        connection.execute(
            "UPDATE users SET public_key = ?1 WHERE user_id = 1",
            [&local_user.public_key],
        )?;
        Ok(())
    })
    .unwrap();
    let offline = FederatedRelay::sign(
        remote_descriptor.descriptor().principal.clone(),
        PrincipalId {
            authority: local_node.authority_id().clone(),
            user_id: 1,
        },
        local_node.node_id().clone(),
        "offline-delivery".into(),
        iota_storage::util::sync::now_millis() as u64,
        CommunicationValue::new(CommunicationType::MessageSend)
            .add_typed_default(
                DataType::Content,
                DataValue::Str("offline ciphertext".into()),
            )
            .add_typed_default(DataType::SendTime, DataValue::SignedNumber(9))
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1)),
        &remote_key,
        vec![
            local_node.public_keys(),
            remote_node.public_keys(),
            local_key.public_key_bundle(),
            remote_key.public_key_bundle(),
        ],
    )
    .unwrap()
    .into_frame(8)
    .unwrap();
    let outcome = relay
        .accept_relay(
            iota_connection::relay_service::IngressSource::DirectPeer {
                node_id: remote_node.node_id().clone(),
            },
            offline.clone(),
        )
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        iota_connection::relay_service::RelayOutcome::Accepted { .. }
    ));
    let pending_offline = || {
        iota_storage::util::relay_queue::list_active(100)
            .unwrap()
            .into_iter()
            .filter(|pending| pending.relay_message_id.as_deref() == Some("offline-delivery"))
            .count()
    };
    assert_eq!(
        pending_offline(),
        1,
        "offline acceptance must retain durable delivery"
    );
    let client = mtp::client::MTPClient::auth_connect(
        mtp::client::ClientConfig::new(format!("https://{address}/"))
            .with_client_id(1)
            .with_description("client")
            .with_pinned_pem(certificate.clone()),
        &local_key,
        &local_node.public_keys(),
    )
    .await
    .unwrap();
    admissions.recv().await.unwrap().send(()).unwrap();

    let snapshot = client
        .request(
            &CommunicationValue::new(CommunicationType::AccountStateRequest)
                .with_id(3)
                .with_sender(99),
            None,
        )
        .await
        .unwrap();
    assert!(snapshot.is_type(CommunicationType::AccountStateSnapshot));
    assert_eq!(snapshot.receiver(), Some(1));
    let own_principal = iota_connection::federated_relay::protocol_principal(&PrincipalId {
        authority: local_node.authority_id().clone(),
        user_id: 1,
    });
    let peer_principal = iota_connection::federated_relay::protocol_principal(
        &remote_descriptor.descriptor().principal,
    );
    let canonical_chat = iota_connection::federated_relay::protocol::canonical_chat_id(
        &own_principal,
        &peer_principal,
    );
    let secret_response = client
        .request(
            &CommunicationValue::new(CommunicationType::GetChatSecret)
                .with_id(31)
                .with_sender(99)
                .add_typed_default(
                    DataType::UserId,
                    DataValue::Str(serde_json::to_string(&own_principal).unwrap()),
                )
                .add_typed_default(DataType::ChatId, DataValue::Str(canonical_chat.clone()))
                .add_typed_default(
                    DataType::SecretId,
                    DataValue::Str(iota_connection::federated_relay::protocol::chat_secret_id(
                        &canonical_chat,
                    )),
                ),
            None,
        )
        .await
        .unwrap();
    assert!(
        secret_response.is_type(CommunicationType::ChatSecretResponse),
        "unexpected private secret response: {secret_response:?}"
    );
    assert_eq!(secret_response.receiver(), Some(1));
    assert_eq!(
        secret_response.get_data(DataType::EncryptedSecret),
        Some(&DataValue::Bytes(vec![1]))
    );
    iota_storage::util::relay_queue::resume_client_deliveries(1).unwrap();
    LocalDeliverySink::deliver(manager.as_ref(), local_handle, offline.clone()).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), client.receive())
            .await
            .is_err(),
        "ready work must wait until the client durably applies its initial snapshot"
    );
    assert_eq!(pending_offline(), 1);
    assert!(
        client
            .request(
                &CommunicationValue::new(CommunicationType::AccountStateApplied).with_id(32),
                None
            )
            .await
            .unwrap()
            .is_type(CommunicationType::Success)
    );

    let content = CommunicationValue::new(CommunicationType::MessageSend)
        .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into()))
        .add_typed_default(DataType::SendTime, DataValue::SignedNumber(10))
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1));
    let outgoing = FederatedRelay::sign(
        PrincipalId {
            authority: local_node.authority_id().clone(),
            user_id: 1,
        },
        remote_descriptor.descriptor().principal.clone(),
        remote_node.node_id().clone(),
        "client-relay".into(),
        iota_storage::util::sync::now_millis() as u64,
        content,
        &local_key,
        vec![
            local_node.public_keys(),
            remote_node.public_keys(),
            local_key.public_key_bundle(),
            remote_key.public_key_bundle(),
        ],
    )
    .unwrap()
    .into_frame(4)
    .unwrap();
    let response = client.request(&outgoing, None).await.unwrap();
    assert_eq!(
        response.get_comm_type_enum(),
        Some(CommunicationType::Success),
        "unexpected relay response: {response:?}"
    );
    assert_eq!(
        response.get_data(DataType::RelayMessageId).as_str(),
        Some("client-relay")
    );
    iota_connection::relay_service::PendingRelayDispatcher::new(router.clone())
        .dispatch_ready(100)
        .await
        .unwrap();
    assert_eq!(router.frames.lock().unwrap().len(), 1);

    LocalDeliverySink::deliver(manager.as_ref(), local_handle, offline.clone()).await;
    let delivery = tokio::time::timeout(std::time::Duration::from_secs(5), client.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(delivery.is_type(CommunicationType::Relay));
    assert_eq!(
        delivery.get_data(DataType::SecurePayload),
        offline.get_data(DataType::SecurePayload)
    );
    let Some(DataValue::Bytes(payload)) = delivery.get_data(DataType::SecurePayload) else {
        unreachable!()
    };
    let opened = iota_connection::federated_relay::protocol::verify_and_open(
        payload,
        &[remote_key.public_key_bundle()],
        &local_key,
        None,
        Some(local_node.node_id().as_str()),
    )
    .unwrap();
    assert_eq!(opened.wire.message_id, "offline-delivery");
    assert_eq!(
        opened.application.get_data(DataType::Content).as_str(),
        Some("offline ciphertext")
    );
    let acknowledgement = CommunicationValue::new(CommunicationType::Success)
        .with_id(delivery.id().unwrap())
        .add_typed_default(
            DataType::RelayMessageId,
            DataValue::Str("offline-delivery".into()),
        )
        .add_typed_default(
            DataType::Principal,
            DataValue::Str(
                serde_json::to_string(&remote_descriptor.descriptor().principal).unwrap(),
            ),
        );
    for incorrect in [
        acknowledgement
            .clone()
            .with_id(delivery.id().unwrap().wrapping_add(1)),
        acknowledgement.clone().add_typed_default(
            DataType::RelayMessageId,
            DataValue::Str("another-relay".into()),
        ),
        acknowledgement.clone().add_typed_default(
            DataType::Principal,
            DataValue::Str(
                serde_json::to_string(&PrincipalId {
                    authority: local_node.authority_id().clone(),
                    user_id: 1,
                })
                .unwrap(),
            ),
        ),
    ] {
        client.sender.send(&incorrect).await.unwrap();
        client
            .request(
                &CommunicationValue::new(CommunicationType::AccountStateRequest).with_id(50),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            pending_offline(),
            1,
            "only the exact correlated acknowledgement can delete pending delivery"
        );
    }
    client.sender.send(&acknowledgement).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while pending_offline() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let replacement = mtp::client::MTPClient::auth_connect(
        mtp::client::ClientConfig::new(format!("https://{address}/"))
            .with_client_id(1)
            .with_description("client")
            .with_pinned_pem(certificate.clone()),
        &local_key,
        &local_node.public_keys(),
    )
    .await
    .unwrap();
    admissions.recv().await.unwrap().send(()).unwrap();
    replacement
        .request(
            &CommunicationValue::new(CommunicationType::AccountStateRequest).with_id(9),
            None,
        )
        .await
        .unwrap();
    client.sender.close().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), terminations.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        manager.is_connected(local_handle),
        "stale cleanup removed the replacement"
    );
    replacement
        .request(
            &CommunicationValue::new(CommunicationType::AccountStateRequest).with_id(10),
            None,
        )
        .await
        .unwrap();
    for (id, description) in [
        (
            remote_node.node_id().mtp_authentication_hint(),
            "iota-peer:".to_owned(),
        ),
        (
            remote_node.node_id().mtp_authentication_hint(),
            format!("iota-peer:{}", local_node.node_id().as_str()),
        ),
        (
            remote_node.node_id().mtp_authentication_hint() ^ 1,
            format!("iota-peer:{}", remote_node.node_id().as_str()),
        ),
        (
            remote_node.node_id().mtp_authentication_hint(),
            format!("iota-peer:{}", remote_node.node_id().as_str()),
        ),
    ] {
        let peer = mtp::client::MTPClient::auth_connect(
            mtp::client::ClientConfig::new(format!("https://{address}/"))
                .with_client_id(id)
                .with_description(description)
                .with_pinned_pem(certificate.clone()),
            &remote_node.keyring(),
            &local_node.public_keys(),
        )
        .await
        .unwrap();
        admissions.recv().await.unwrap().send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), terminations.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!direct_router.has_connection(remote_node.node_id()));
        assert!(peer.receive().await.is_err());
    }
    let descriptor = iota_identity::SignedNodeDescriptor::sign(
        iota_identity::NodeDescriptor {
            node: remote_node.node_id().clone(),
            public_keys: remote_node.public_keys(),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: None,
        },
        &remote_node,
    )
    .unwrap()
    .verify(None, now)
    .unwrap();
    iota_storage::node_directory::SqliteNodeDirectory
        .upsert_node_descriptor(&descriptor)
        .unwrap();
    let mut peers = Vec::new();
    for _ in 0..2 {
        let peer = mtp::client::MTPClient::auth_connect(
            mtp::client::ClientConfig::new(format!("https://{address}/"))
                .with_client_id(remote_node.node_id().mtp_authentication_hint())
                .with_description(format!("iota-peer:{}", remote_node.node_id().as_str()))
                .with_pinned_pem(certificate.clone()),
            &remote_node.keyring(),
            &local_node.public_keys(),
        )
        .await
        .unwrap();
        admissions.recv().await.unwrap().send(()).unwrap();
        // A relay response proves that initialization and trusted registration
        // finished for this particular connection, even when a route already exists.
        let frame = FederatedRelay::sign(
            remote_descriptor.descriptor().principal.clone(),
            PrincipalId {
                authority: local_node.authority_id().clone(),
                user_id: 1,
            },
            local_node.node_id().clone(),
            format!("inbound-{}", peers.len()),
            iota_storage::util::sync::now_millis() as u64,
            CommunicationValue::new(CommunicationType::MessageSend)
                .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into()))
                .add_typed_default(DataType::SendTime, DataValue::SignedNumber(10))
                .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1)),
            &remote_key,
            vec![
                local_node.public_keys(),
                remote_node.public_keys(),
                local_key.public_key_bundle(),
                remote_key.public_key_bundle(),
            ],
        )
        .unwrap()
        .into_frame(20)
        .unwrap();
        relay
            .prepare_relay(
                &iota_connection::relay_service::IngressSource::DirectPeer {
                    node_id: remote_node.node_id().clone(),
                },
                frame.clone(),
            )
            .await
            .expect("protected peer frame must pass destination preparation");
        let response = peer.request(&frame, None).await.unwrap();
        assert!(response.is_type(CommunicationType::Success), "{response:?}");
        assert!(direct_router.has_connection(remote_node.node_id()));
        peers.push(peer);
    }
    peers[0].sender.close().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), terminations.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        direct_router.has_connection(remote_node.node_id()),
        "stale peer cleanup removed its replacement"
    );
    shutdown.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap();
    assert!(!manager.is_connected(local_handle));
    assert!(!direct_router.has_connection(remote_node.node_id()));

    // Exercise the production supervisor and both externally owned limits.
    let (certificate, private_key) = crate::certificate();
    let certificate_path = storage.path().join("certificate.pem");
    let key_path = storage.path().join("key.pem");
    std::fs::write(&certificate_path, &certificate).unwrap();
    std::fs::write(&key_path, private_key).unwrap();
    let node_descriptor = iota_identity::SignedNodeDescriptor::sign(
        iota_identity::NodeDescriptor {
            node: local_node.node_id().clone(),
            public_keys: local_node.public_keys(),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: None,
        },
        &local_node,
    )
    .unwrap();
    for (max_all, max_user, budget_secs) in [(1, 2, 60), (2, 1, 60), (2, 1, 1)] {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let handle = web_server::start(
            web_server::WebConfig {
                mode: web_server::WebMode::Loopback,
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                asset_dir: storage.path().to_owned(),
                tls: Some(web_server::TlsConfig {
                    certificate: certificate_path.clone(),
                    key: key_path.clone(),
                }),
                required: true,
                max_mtp_sessions: max_all,
                max_mtp_sessions_per_user: max_user,
                shutdown_budget: std::time::Duration::from_secs(budget_secs),
                authority_discovery: iota_identity::AuthorityDiscoveryDocument {
                    version: 1,
                    service: AuthorityKind::Iota,
                    authority_id: local_node.authority_id().clone(),
                    node_id: Some(local_node.node_id().clone()),
                    public_key: local_node.public_keys().try_to_base64().unwrap(),
                    protocols: Vec::new(),
                    node_descriptor: Some("/federation/v1/node".into()),
                    direct_endpoints: Vec::new(),
                    relay_hints: Vec::new(),
                },
                publish_discovery: true,
                local_users: Arc::new(SqliteLocalUserStore),
                descriptor_publisher: Arc::new(
                    iota_storage::identity::SqliteLocalDescriptorPublisher::new(local_node.clone()),
                ),
                node_descriptor: node_descriptor.clone(),
                node_identity: local_node.clone(),
                client_keys: Arc::new(client::HostedAndPeerKeyResolver::new(Arc::new(
                    SqliteLocalUserStore,
                ))),
                mtp_handler: gateway.clone(),
                peer_introduction: None,
                introduction_limits: Default::default(),
            },
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap()
        .unwrap();
        let config = || {
            mtp::client::ClientConfig::new(format!("https://127.0.0.1:{port}/"))
                .with_client_id(1)
                .with_description("client")
                .with_pinned_pem(certificate.clone())
        };
        let waiter = tokio::spawn({
            let handle = handle.clone();
            async move {
                handle.join().await;
            }
        });
        let rejected = mtp::client::MTPClient::auth_connect(
            config().with_description("unsupported"),
            &local_key,
            &local_node.public_keys(),
        )
        .await;
        if let Ok(rejected) = rejected {
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(5), rejected.receive())
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        let first =
            mtp::client::MTPClient::auth_connect(config(), &local_key, &local_node.public_keys())
                .await
                .unwrap();
        first
            .request(
                &CommunicationValue::new(CommunicationType::AccountStateRequest).with_id(1),
                None,
            )
            .await
            .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let supervisor_waiter = tokio::spawn({
            let handle = handle.clone();
            async move {
                handle.join().await;
            }
        });
        let limited =
            mtp::client::MTPClient::auth_connect(config(), &local_key, &local_node.public_keys())
                .await;
        if let Ok(limited) = limited {
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(5), limited.receive())
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        first.sender.close().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while manager.is_connected(local_handle) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let last =
            mtp::client::MTPClient::auth_connect(config(), &local_key, &local_node.public_keys())
                .await
                .unwrap();
        last.request(
            &CommunicationValue::new(CommunicationType::AccountStateRequest).with_id(2),
            None,
        )
        .await
        .unwrap();
        let mut peer = None;
        if max_all == 2 {
            peer = Some(
                mtp::client::MTPClient::auth_connect(
                    mtp::client::ClientConfig::new(format!("https://127.0.0.1:{port}/"))
                        .with_client_id(remote_node.node_id().mtp_authentication_hint())
                        .with_description(format!("iota-peer:{}", remote_node.node_id().as_str()))
                        .with_pinned_pem(certificate.clone()),
                    &remote_node.keyring(),
                    &local_node.public_keys(),
                )
                .await
                .unwrap(),
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !direct_router.has_connection(remote_node.node_id()) {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        if max_all == 2 {
            let (reached, wait) = tokio::sync::oneshot::channel();
            let (resume, continued) = tokio::sync::oneshot::channel();
            *router.pause.lock().unwrap() = Some((reached, continued));
            let frame = FederatedRelay::sign(
                PrincipalId {
                    authority: local_node.authority_id().clone(),
                    user_id: 1,
                },
                remote_descriptor.descriptor().principal.clone(),
                remote_node.node_id().clone(),
                format!("in-flight-shutdown-{budget_secs}"),
                iota_storage::util::sync::now_millis() as u64,
                CommunicationValue::new(CommunicationType::MessageSend)
                    .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into()))
                    .add_typed_default(DataType::SendTime, DataValue::SignedNumber(10))
                    .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1)),
                &local_key,
                vec![
                    local_node.public_keys(),
                    remote_node.public_keys(),
                    local_key.public_key_bundle(),
                    remote_key.public_key_bundle(),
                ],
            )
            .unwrap()
            .into_frame(30)
            .unwrap();
            assert!(
                last.request(&frame, None)
                    .await
                    .unwrap()
                    .is_type(CommunicationType::Success)
            );
            let pending_shutdown = || {
                iota_storage::util::db::with_db(|connection| {
                    Ok(connection.query_row(
                        "SELECT COUNT(*) FROM pending_relays WHERE relay_message_id = ?1",
                        [format!("in-flight-shutdown-{budget_secs}")],
                        |row| row.get::<_, i64>(0),
                    )?)
                })
                .unwrap()
            };
            assert_eq!(pending_shutdown(), 1);
            // Dispatch belongs to the process, independently of the ingress session.
            let dispatch_task = tokio::spawn({
                let router = router.clone();
                async move {
                    iota_connection::relay_service::PendingRelayDispatcher::new(router)
                        .dispatch_ready(100)
                        .await
                        .unwrap()
                }
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), wait)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown())
                    .await
                    .unwrap(),
                web_server::ShutdownReport::Complete
            );
            assert!(!manager.is_connected(local_handle));
            assert!(!dispatch_task.is_finished());
            assert_eq!(
                pending_shutdown(),
                1,
                "cleanup removed committed relay work"
            );
            resume.send(()).unwrap();
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_task)
                    .await
                    .unwrap()
                    .unwrap(),
                1
            );
            assert_eq!(pending_shutdown(), 0);
        } else {
            let report = tokio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown())
                .await
                .unwrap();
            assert_eq!(report, web_server::ShutdownReport::Complete);
        }
        assert!(!manager.is_connected(local_handle));
        assert!(!direct_router.has_connection(remote_node.node_id()));
        tokio::time::timeout(std::time::Duration::from_secs(5), supervisor_waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(last.receive().await.is_err());
        if let Some(peer) = peer {
            assert!(peer.receive().await.is_err());
        }
    }
}
