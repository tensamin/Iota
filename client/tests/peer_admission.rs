use async_trait::async_trait;
use client::{ClientConnectionManager, ConnectionGateway, HostedAndPeerKeyResolver};
use iota_auth::{HostedSessionRegistrar, SessionManager};
use iota_connection::relay_service::{RelayNodeIdentity, RelayService};
use iota_identity::peer_introduction::{
    PeerIntroductionLimits, PeerIntroductionRequest, PeerTrust,
};
use iota_identity::{
    IdentityError, IdentityResolver, IotaNodeId, LocalNodeIdentity, NodeDescriptor, PrincipalId,
    PublicKeyBundle, ResolutionContext, ResolvedPrincipal, SignedNodeDescriptor, UserAddress,
};
use iota_storage::{
    identity::SqliteLocalUserStore, node_directory::SqliteNodeDirectory, peer_admission, util::db,
};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    crypto::Keyring,
    host::{AuthenticationPolicy, HostConfig},
    webserver::{MTPWebServer, WebServerConfig},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use web_server::{ClientPublicKeyResolver, MtpConnectionHandler};

struct ResolvingPeer {
    entered: tokio::sync::Notify,
}

#[async_trait]
impl IdentityResolver for ResolvingPeer {
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }
    async fn resolve_principal(&self, _: &PrincipalId) -> Result<ResolvedPrincipal, IdentityError> {
        self.entered.notify_one();
        std::future::pending().await
    }
    async fn signing_keys(
        &self,
        id: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        self.resolve_principal(id).await.map(|p| p.public_keys)
    }
}

struct NodeIdentity(LocalNodeIdentity);
#[async_trait]
impl RelayNodeIdentity for NodeIdentity {
    async fn keyring(&self) -> Option<Arc<Keyring>> {
        Some(self.0.keyring())
    }
    fn node_id(&self) -> Option<IotaNodeId> {
        Some(self.0.node_id().clone())
    }
}

fn introduce(
    node: &LocalNodeIdentity,
    host: &LocalNodeIdentity,
    limits: &PeerIntroductionLimits,
) -> SignedNodeDescriptor {
    let now = iota_storage::util::sync::now_millis();
    let descriptor = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: node.node_id().clone(),
            public_keys: node.public_keys(),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
            revision: 1,
            valid_until: Some(now + 60_000),
        },
        node,
    )
    .unwrap();
    let challenge = peer_admission::issue_challenge(
        &descriptor,
        host.node_id(),
        "192.0.2.1".parse().unwrap(),
        None,
        limits,
        now,
    )
    .unwrap();
    peer_admission::redeem(
        PeerIntroductionRequest::sign(&challenge, &descriptor, node).unwrap(),
        limits,
        now,
    )
    .unwrap();
    descriptor
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_fences_provisional_roles_expiry_renewal_and_inflight_revocation() {
    let root = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(root.path().to_owned());
    db::initialize_database().unwrap();
    let local = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let remote = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let limits = PeerIntroductionLimits::default();
    let descriptor = introduce(&remote, &local, &limits);
    let resolver = Arc::new(ResolvingPeer {
        entered: tokio::sync::Notify::new(),
    });
    let router = Arc::new(other_iota::DirectPeerRouter::default());
    let local_users = Arc::new(SqliteLocalUserStore);
    let relay = Arc::new(
        RelayService::new(local_users.clone(), router.clone())
            .with_federation(resolver.clone(), Arc::new(NodeIdentity(local.clone()))),
    );
    let sessions = Arc::new(SessionManager::default());
    let clients = Arc::new(ClientConnectionManager::new(
        resolver.clone(),
        Arc::new(HostedSessionRegistrar::new(sessions.clone())),
        sessions,
        relay.clone(),
    ));
    // SQLite supplies admission policy even without an outgoing introducer.
    let peers = Arc::new(other_iota::PeerManager::new(
        local.clone(),
        Arc::new(SqliteNodeDirectory),
        router.clone(),
        relay,
        clients.clone(),
    ));
    let gateway = Arc::new(ConnectionGateway::new(
        client::tau_gateway::admission_engine(),
        clients,
        peers.clone(),
    ));
    let key_resolver = Arc::new(HostedAndPeerKeyResolver::new(local_users));
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&tls_key)
        .unwrap()
        .pem()
        .into_bytes();
    let config = HostConfig::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        certificate.clone(),
        tls_key.serialize_pem().into_bytes(),
    )
    .with_authentication(
        Keyring::from_bytes(&local.keyring().try_to_bytes().unwrap()).unwrap(),
        Box::new({
            let resolver = key_resolver.clone();
            move |id, _| {
                let resolver = resolver.clone();
                Box::pin(async move { resolver.public_key(id).await })
            }
        }),
        Box::new(|_, _| Box::pin(async { 0 })),
    )
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
    let mut server = MTPWebServer::new(config, WebServerConfig::new())
        .await
        .unwrap();
    let address = server.local_addr();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let (accepted, mut admissions) =
        tokio::sync::mpsc::unbounded_channel::<tokio::sync::oneshot::Sender<()>>();
    let (ended, mut completions) = tokio::sync::mpsc::unbounded_channel();
    let server_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _=server_shutdown.cancelled()=>break,
                Some(result)=tasks.join_next(),if !tasks.is_empty()=>{ result.unwrap(); },
                result=server.accept()=>{
                    let connection=result.unwrap().unwrap();
                    let (resume,ready)=tokio::sync::oneshot::channel();
                    accepted.send(resume).unwrap();
                    let gateway=gateway.clone();let token=server_shutdown.clone();let ended=ended.clone();
                    tasks.spawn(async move {
                        tokio::select! { _=token.cancelled()=>return, _=ready=>{} }
                        gateway.accept_until_shutdown(connection,token).await;
                        let _=ended.send(());
                    });
                }
            }
        }
        server.shutdown().await;
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let connect = |description: String| {
        let config = mtp::client::ClientConfig::new(format!("https://{address}/"))
            .with_client_id(remote.node_id().mtp_authentication_hint())
            .with_description(description)
            .with_pinned_pem(certificate.clone());
        let key = remote.keyring();
        let public_key = local.public_keys();
        async move {
            mtp::client::MTPClient::auth_connect(config, &key, &public_key)
                .await
                .unwrap()
        }
    };
    for description in [
        "client".to_owned(),
        format!("iota-peer:{}", local.node_id().as_str()),
    ] {
        let connection = connect(description).await;
        admissions.recv().await.unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), completions.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(connection.receive().await.is_err());
        assert!(matches!(
            peers
                .validate_peer(remote.node_id(), &remote.public_keys())
                .await
                .unwrap()
                .trust(),
            PeerTrust::Provisional { .. }
        ));
        assert!(!router.has_connection(remote.node_id()));
    }
    let candidate = peers
        .validate_peer(remote.node_id(), &remote.public_keys())
        .await
        .unwrap();
    let stale_trust = candidate.trust().clone();
    assert!(
        !candidate
            .trust()
            .is_established_at(iota_storage::util::sync::now_millis())
    );
    assert!(
        peers
            .validate_established_peer(remote.node_id(), &remote.public_keys())
            .await
            .is_err()
    );
    let expired = connect(format!("iota-peer:{}", remote.node_id().as_str())).await;
    let resume = admissions.recv().await.unwrap();
    // Independently learned descriptors must not override the admission's expiry.
    SqliteNodeDirectory
        .upsert(
            &descriptor
                .clone()
                .verify(None, iota_storage::util::sync::now_millis())
                .unwrap(),
        )
        .unwrap();
    let before_wait = iota_storage::util::sync::now_millis();
    db::with_db(|db| {
        db.execute(
            "UPDATE federation_peer_admissions SET expires_at=?1 WHERE node_id=?2",
            (before_wait + 50, remote.node_id().as_str()),
        )?;
        Ok(())
    })
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A timestamp captured before a pool/lock wait cannot bypass commit-time expiry.
    assert!(
        peer_admission::trust_for_peer(remote.node_id(), &remote.public_keys(), before_wait)
            .is_err()
    );
    assert!(
        key_resolver
            .public_key(remote.node_id().mtp_authentication_hint())
            .await
            .is_none()
    );
    resume.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), completions.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(expired.receive().await.is_err());
    assert!(!router.has_connection(remote.node_id()));
    let now = iota_storage::util::sync::now_millis();
    let challenge = peer_admission::issue_challenge(
        &descriptor,
        local.node_id(),
        "192.0.2.1".parse().unwrap(),
        None,
        &limits,
        now,
    )
    .unwrap();
    peer_admission::redeem(
        PeerIntroductionRequest::sign(&challenge, &descriptor, &remote).unwrap(),
        &limits,
        now,
    )
    .unwrap();
    assert!(
        peers
            .establish_peer(candidate, &remote.public_keys())
            .await
            .is_err()
    );
    let connection = connect(format!("iota-peer:{}", remote.node_id().as_str())).await;
    admissions.recv().await.unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !router.has_connection(remote.node_id()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        peers
            .validate_peer(remote.node_id(), &remote.public_keys())
            .await
            .unwrap()
            .trust()
            .is_established_at(iota_storage::util::sync::now_millis())
    );
    assert!(
        peer_admission::promote(
            &stale_trust,
            &remote.public_keys(),
            iota_storage::util::sync::now_millis()
        )
        .is_err()
    );
    for request in [
        CommunicationType::AccountStateRequest,
        CommunicationType::UserResolve,
        CommunicationType::GetChatSecret,
        CommunicationType::MessageSend,
    ] {
        connection
            .sender
            .send(&CommunicationValue::new(request).with_id(77))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.receive())
                .await
                .is_err()
        );
    }
    let sender = Keyring::generate();
    let recipient = Keyring::generate();
    let frame = iota_connection::federated_relay::FederatedRelay::sign(
        PrincipalId {
            authority: remote.authority_id().clone(),
            user_id: 1,
        },
        PrincipalId {
            authority: local.authority_id().clone(),
            user_id: 1,
        },
        local.node_id().clone(),
        "inflight-revocation".into(),
        iota_storage::util::sync::now_millis() as u64,
        CommunicationValue::new(CommunicationType::MessageSend)
            .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into())),
        &sender,
        vec![
            local.public_keys(),
            remote.public_keys(),
            recipient.public_key_bundle(),
        ],
    )
    .unwrap()
    .into_frame(88)
    .unwrap();
    connection.sender.send(&frame).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), resolver.entered.notified())
        .await
        .unwrap();
    peer_admission::revoke(remote.node_id()).unwrap();
    // Notification must close an operation blocked in discovery, not wait for the
    // five-second external-writer poll or for the resolver to return.
    tokio::time::timeout(Duration::from_secs(2), completions.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!router.has_connection(remote.node_id()));
    assert!(connection.receive().await.is_err());
    assert!(
        key_resolver
            .public_key(remote.node_id().mtp_authentication_hint())
            .await
            .is_none()
    );
    assert_eq!(
        db::with_db(
            |db| Ok(db.query_row("SELECT COUNT(*) FROM relay_inbox", [], |r| r
                .get::<_, i64>(0))?)
        )
        .unwrap(),
        0
    );
    shutdown.cancel();
    server_task.await.unwrap();
    assert!(peers.shutdown(Duration::from_secs(2)).await);
}
