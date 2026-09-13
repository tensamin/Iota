use async_trait::async_trait;
use client::ClientConnectionManager;
use iota_auth::{HostedSessionRegistrar, SessionManager};
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::federated_relay::FederatedRelayV2;
use iota_connection::relay_service::{RelayNodeIdentity, RelayService};
use iota_identity::{
    AuthorityKind, IdentityError, IdentityResolver, IotaNodeId, LocalNodeIdentity,
    LocalUserDescriptor, LocalUserId, LocalUserStore, PrincipalDescriptor, PrincipalHome,
    PrincipalId, PrincipalStore, PublicKeyBundle, ResolutionContext, ResolvedPrincipal,
    SignedPrincipalDescriptor, UserAddress,
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
struct AcceptingRouter(Mutex<Vec<CommunicationValue>>);

#[async_trait]
impl PeerRouter for AcceptingRouter {
    async fn route(
        &self,
        _: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        self.0.lock().unwrap().push(frame);
        Ok(RouteOutcome::Accepted {
            relay_message_id: "client-relay".into(),
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
    let remote_node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
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
        RelayService::new(local_users.clone(), router.clone(), None).with_federation(
            Arc::new(StoreResolver),
            Arc::new(TestNodeIdentity(local_node.clone())),
        ),
    );
    let sessions = Arc::new(SessionManager::default());
    let manager = Arc::new(ClientConnectionManager::new(
        local_users,
        Arc::new(SqlitePrincipalStore),
        Arc::new(HostedSessionRegistrar::new(sessions.clone())),
        sessions,
        relay,
    ));

    let (certificate, private_key) = certificate();
    let client_public_key = local_key.public_key_bundle();
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
            let key = (client_id == 1).then(|| client_public_key.clone());
            Box::pin(async move { key })
        }),
        Box::new(|_, _| Box::pin(async { 0 })),
    )
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
    let mut server = MTPWebServer::new(host, WebServerConfig::new())
        .await
        .unwrap();
    let address = server.local_addr();
    let server_manager = manager.clone();
    let server_task = tokio::spawn(async move {
        if let Some(connection) = server.accept().await.unwrap() {
            web_server::MtpConnectionHandler::accept(server_manager.as_ref(), connection).await;
        }
    });
    let client = mtp::client::MTPClient::auth_connect(
        mtp::client::ClientConfig::new(format!("https://{address}/"))
            .with_client_id(1)
            .with_pinned_pem(certificate),
        &local_key,
        &local_node.public_keys(),
    )
    .await
    .unwrap();

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

    let content = CommunicationValue::new(CommunicationType::MessageSend)
        .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into()))
        .add_typed_default(DataType::SendTime, DataValue::SignedNumber(10))
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1));
    let relay = FederatedRelayV2::sign(
        PrincipalId {
            authority: local_node.authority_id().clone(),
            user_id: 1,
        },
        remote_descriptor.descriptor().principal.clone(),
        remote_node.node_id().clone(),
        "client-relay".into(),
        10,
        content,
        &local_key,
    )
    .unwrap()
    .into_frame(4)
    .unwrap();
    let payload = match relay.get_data(DataType::SecurePayload).unwrap() {
        DataValue::Bytes(payload) => payload.clone(),
        _ => panic!("Relay V2 payload has wrong type"),
    };
    let response = client
        .request(
            &CommunicationValue::new(CommunicationType::MessageSend)
                .with_id(4)
                .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
                .add_typed_default(DataType::SecurePayload, DataValue::Bytes(payload)),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        response.get_comm_type_enum(),
        Some(CommunicationType::Success),
        "unexpected relay response: {response:?}"
    );
    assert_eq!(
        response.get_data(DataType::RelayMessageId).as_str(),
        Some("client-relay")
    );
    assert_eq!(router.0.lock().unwrap().len(), 1);

    LocalDeliverySink::deliver(
        manager.as_ref(),
        local_handle,
        CommunicationValue::new(CommunicationType::MessageLive).with_id(8),
    )
    .await;
    let delivery = tokio::time::timeout(std::time::Duration::from_secs(5), client.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(delivery.is_type(CommunicationType::MessageLive));

    server_task.abort();
}
