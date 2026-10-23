use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::federated_relay::FederatedRelay;
use iota_connection::relay_service::{RelayNodeIdentity, RelayService};
use iota_identity::{
    AuthorityLocator, IdentityError, IdentityResolver, IotaNodeId, LocalNodeIdentity,
    LocalUserDescriptor, LocalUserId, LocalUserStore, PrincipalDescriptor, PrincipalHandle,
    PrincipalHome, PrincipalId, PrincipalStore, PublicKeyBundle, ResolutionContext,
    ResolvedPrincipal, SignedPrincipalDescriptor, UserAddress,
};
use iota_storage::identity::SqlitePrincipalStore;
use iota_storage::util::{chat_files, e2ee_storage};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::Keyring;
use mtp::host::{AuthenticationPolicy, HostConfig};
use mtp::webserver::{MTPWebServer, WebServerConfig};
use other_iota::LocalDeliverySink;
use other_iota::relay_router::{RelayRouterClient, RelayRouterService};
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

struct HostedRecipient(PrincipalHandle);

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

    fn is_hosted_here(&self, user: LocalUserId) -> Result<bool, IdentityError> {
        Ok(user == LocalUserId(1))
    }

    fn local_user_for_principal(
        &self,
        principal: PrincipalHandle,
    ) -> Result<Option<LocalUserId>, IdentityError> {
        Ok((principal == self.0).then_some(LocalUserId(1)))
    }

    fn principal_for_local_user(
        &self,
        user: LocalUserId,
    ) -> Result<Option<PrincipalHandle>, IdentityError> {
        Ok((user == LocalUserId(1)).then_some(self.0))
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
) -> iota_identity::VerifiedPrincipalDescriptor {
    let now = iota_storage::util::sync::now_millis();
    SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: authority.authority_id().clone(),
                user_id: 1,
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
async fn authenticated_router_forwards_and_mailboxes_opaque_relays() {
    if std::env::var("TENSAMIN_ROUTER_TEST_MODE").is_err() {
        for mode in ["online", "mailbox"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("authenticated_router_forwards_and_mailboxes_opaque_relays")
                .env("TENSAMIN_ROUTER_TEST_MODE", mode)
                .status()
                .unwrap();
            assert!(status.success(), "router mode {mode}");
        }
        return;
    }
    let mailbox = std::env::var("TENSAMIN_ROUTER_TEST_MODE").unwrap() == "mailbox";
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    iota_storage::util::db::initialize_database().unwrap();

    let iota_a = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let iota_b = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let user_a = Keyring::generate();
    let user_b = Keyring::generate();
    let principal_a = verified_principal(&iota_a, &user_a);
    let principal_b = verified_principal(&iota_b, &user_b);
    let handle_a = SqlitePrincipalStore
        .upsert_remote_descriptor(&principal_a)
        .unwrap();
    let handle_b = SqlitePrincipalStore
        .upsert_remote_descriptor(&principal_b)
        .unwrap();
    iota_storage::util::db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO users(user_id, username, public_key, created_at) VALUES(1, 'recipient', 'test', 1)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id, principal_handle) VALUES(1, ?1)", [handle_b.0])?;
        Ok(())
    }).unwrap();
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

    let relay = Arc::new(
        RelayService::new(Arc::new(HostedRecipient(handle_b)), Arc::new(NoRoute)).with_federation(
            Arc::new(StoreResolver),
            Arc::new(TestNodeIdentity(iota_b.clone())),
        ),
    );
    let deliveries = Arc::new(Deliveries::default());
    let router = Arc::new(if mailbox {
        RelayRouterService::with_mailbox(Default::default())
    } else {
        RelayRouterService::default()
    });
    let router_keyring = Keyring::generate();
    let router_public_key = router_keyring.public_key_bundle();
    let key_a = iota_a.public_keys();
    let key_b = iota_b.public_keys();
    let hint_a = iota_a.node_id().mtp_authentication_hint();
    let hint_b = iota_b.node_id().mtp_authentication_hint();
    let (certificate, private_key) = certificate();
    let host = HostConfig::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        certificate.clone(),
        private_key,
    )
    .with_authentication(
        router_keyring,
        Box::new(move |client_id, _| {
            let key = if client_id == hint_a {
                Some(key_a.clone())
            } else if client_id == hint_b {
                Some(key_b.clone())
            } else {
                None
            };
            Box::pin(async move { key })
        }),
        Box::new(|_, _| Box::pin(async { 0 })),
    )
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
    let mut server = MTPWebServer::new(host, WebServerConfig::new())
        .await
        .unwrap();
    let endpoint = AuthorityLocator::new(server.local_addr().to_string()).unwrap();
    let server_task = {
        let router = router.clone();
        tokio::spawn(async move {
            loop {
                match server.accept().await {
                    Ok(Some(connection)) => {
                        let router = router.clone();
                        tokio::spawn(async move {
                            web_server::MtpConnectionHandler::accept(router.as_ref(), connection)
                                .await;
                        });
                    }
                    Ok(None) => break,
                    Err(_) => continue,
                }
            }
        })
    };

    let iota_a_router = RelayRouterClient::connect(
        iota_a.clone(),
        &endpoint,
        certificate.clone(),
        router_public_key.clone(),
        relay.clone(),
        deliveries.clone(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !router.has_connection(iota_a.node_id()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let frame = FederatedRelay::sign(
        principal_a.descriptor().principal.clone(),
        principal_b.descriptor().principal.clone(),
        iota_b.node_id().clone(),
        "through-router".into(),
        iota_storage::util::sync::now_millis() as u64,
        CommunicationValue::new(CommunicationType::MessageSend)
            .add_typed_default(DataType::Content, DataValue::Str("opaque".into()))
            .add_typed_default(DataType::SendTime, DataValue::SignedNumber(10))
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1)),
        &user_a,
        vec![
            iota_a.public_keys(),
            iota_b.public_keys(),
            user_a.public_key_bundle(),
            user_b.public_key_bundle(),
        ],
    )
    .unwrap()
    .into_frame(7)
    .unwrap();
    assert!(matches!(
        iota_a_router
            .route(
                &RouteDestination::Iota(iota_b.node_id().clone()),
                frame.clone(),
            )
            .await
            .unwrap(),
        RouteOutcome::Retryable { .. }
    ));
    if mailbox {
        assert_eq!(iota_storage::util::db::with_db(|db| Ok(db.query_row("SELECT COUNT(*) FROM relay_mailbox WHERE encrypted_frame IS NOT NULL AND acceptance IS NULL",[],|r|r.get::<_,i64>(0))?)).unwrap(),1);
    }

    let _iota_b_router = RelayRouterClient::connect(
        iota_b.clone(),
        &endpoint,
        certificate,
        router_public_key,
        relay,
        deliveries.clone(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !router.has_connection(iota_b.node_id()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    if mailbox {
        tokio::time::timeout(std::time::Duration::from_secs(10),async {
            loop {
                let count=iota_storage::util::db::with_db(|db| Ok(db.query_row("SELECT COUNT(*) FROM relay_mailbox WHERE acceptance IS NOT NULL AND encrypted_frame IS NULL",[],|r|r.get::<_,i64>(0))?)).unwrap();
                if count==1 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }).await.unwrap();
    }
    let outcome = iota_a_router
        .route(&RouteDestination::Iota(iota_b.node_id().clone()), frame)
        .await
        .unwrap();
    assert!(
        matches!(
        &outcome,
        RouteOutcome::Accepted {
            relay_message_id,
            ..
        } if relay_message_id == "through-router"
        ),
        "unexpected router outcome: {outcome:?}"
    );
    let messages = chat_files::get_messages_for_principal(1, handle_a, 0, 10).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, "opaque");
    let delivered = deliveries.0.lock().unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, handle_b);

    server_task.abort();
}
