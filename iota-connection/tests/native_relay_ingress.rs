use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_auth::{AuthenticatedSession, SessionCapabilities, SessionIdentity};
use iota_connection::{
    connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome},
    relay_service::{IngressSource, RelayNodeIdentity, RelayOutcome, RelayService},
};
use iota_identity::*;
use iota_storage::{identity::SqlitePrincipalStore, util::db};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap},
    crypto::Keyring,
};
use std::sync::Arc;

#[allow(dead_code)]
pub mod relay_support;

fn subprocess_test_name() -> &'static str {
    if env!("CARGO_PKG_NAME") == "other-iota" {
        "pinned::native_client_production_ingress"
    } else {
        "native_client_production_ingress"
    }
}

fn fixture() -> serde_json::Value {
    let bytes = std::fs::read(fixture_path()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

pub fn fixture_path() -> &'static std::path::Path {
    static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        if let Some(path) = std::env::var_os("RELAY_NATIVE_CLIENT_FIXTURE") {
            return path.into();
        }
        use mtp::codec::relay::SealedRelayBuilder;
        let map = TypeMap::new(mtp::type_map::Version(1, 0));
        let nodes = [Keyring::generate(), Keyring::generate()];
        let signer = Keyring::generate();
        let authority = AuthorityId::for_omega(&nodes[0].public_key_bundle()).unwrap();
        let ids = [11, 22].map(|user_id| PrincipalId {
            authority: authority.clone(),
            user_id,
        });
        let principals = ids
            .each_ref()
            .map(|id| iota_identity::relay_protocol::Principal::try_from(id).unwrap());
        let chat = iota_identity::relay_protocol::canonical_chat_id(&principals[0], &principals[1]);
        let secret = iota_identity::relay_protocol::chat_secret_id(&chat);
        let envelopes = [vec![11, 1], vec![22, 2]];
        let kems = [vec![11, 3], vec![22, 4]];
        let recipients = (0..2)
            .map(|index| {
                DataValue::Container(
                    vec![
                        (
                            DataType::UserId,
                            DataValue::Str(serde_json::to_string(&principals[index]).unwrap()),
                        ),
                        (
                            DataType::EncryptedSecret,
                            DataValue::Bytes(envelopes[index].clone()),
                        ),
                        (
                            DataType::KemCiphertext,
                            DataValue::Bytes(kems[index].clone()),
                        ),
                    ]
                    .into_iter()
                    .map(|(kind, value)| (kind.try_to_id(&map).unwrap(), value))
                    .collect(),
                )
            })
            .collect();
        let application =
            CommunicationValue::new_with_type_map(CommunicationType::SetChatSecret, &map)
                .add_typed_default(DataType::ChatId, DataValue::Str(chat))
                .add_typed_default(DataType::SecretId, DataValue::Str(secret))
                .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1))
                .add_typed_default(DataType::WrappingScheme, DataValue::Str("fixture".into()))
                .add_typed_default(DataType::Recipients, DataValue::Array(recipients));
        let destination = IotaNodeId::from_public_keys(&nodes[1].public_key_bundle()).unwrap();
        let route = iota_identity::relay_protocol::NativeRelayRoute {
            signer: principals[0].clone(),
            recipient: principals[1].clone(),
            destination: destination.as_str().into(),
            type_map_version: "1.0".into(),
            type_map_fingerprint: map.fingerprint_hex().unwrap(),
        };
        let signing = mtp::crypto::Ed25519Signer::new(&signer.sig_cl_secret_key).unwrap();
        let keys = nodes.each_ref().map(Keyring::public_key_bundle).to_vec();
        let frame = SealedRelayBuilder::new(
            CommunicationType::SetChatSecret,
            application.payload().clone(),
            11,
            22,
            IotaNodeId::from_public_keys(&nodes[0].public_key_bundle())
                .unwrap()
                .mtp_authentication_hint(),
            &signing,
        )
        .type_map(&map)
        .message_id(1u128)
        .created_at(iota_storage::util::sync::now_millis() as u64)
        .metadata(route.to_metadata(&map).unwrap())
        .metadata_recipients(keys.clone())
        .content_recipients(keys)
        .build()
        .unwrap();
        let fixture = serde_json::json!({
            "nodeKeys": nodes.each_ref().map(|key| STANDARD.encode(key.try_to_bytes().unwrap())),
            "signerPublicKey": signer.public_key_bundle().try_to_base64().unwrap(),
            "frame": STANDARD.encode(frame.to_bytes().unwrap()),
            "encryptedSecrets": envelopes.map(|bytes| STANDARD.encode(bytes)),
            "kemCiphertexts": kems.map(|bytes| STANDARD.encode(bytes)),
        });
        let path = std::path::Path::new("/tmp/opencode")
            .join(format!("native-relay-peer-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
        path
    })
}

// The real-MTP integration harness reuses these pinned Client assertions while
// replacing only the process transport and coordinator wiring.
pub static ROUTER: std::sync::OnceLock<Arc<dyn PeerRouter>> = std::sync::OnceLock::new();
pub type StageFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
type StageHook = fn(Arc<RelayService>, Vec<LocalNodeIdentity>, usize) -> StageFuture;
pub static STAGE_HOOK: std::sync::OnceLock<StageHook> = std::sync::OnceLock::new();

struct Resolver;
#[async_trait]
impl IdentityResolver for Resolver {
    async fn resolve_current_principal(
        &self,
        id: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        self.resolve_principal(id).await
    }
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }
    async fn resolve_principal(
        &self,
        id: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        SqlitePrincipalStore
            .get_by_canonical_id(id)?
            .ok_or(IdentityError::NotFound)
    }
    async fn signing_keys(
        &self,
        id: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        SqlitePrincipalStore.signing_keys(id)
    }
}

struct Node(LocalNodeIdentity);
#[async_trait]
impl RelayNodeIdentity for Node {
    async fn keyring(&self) -> Option<Arc<Keyring>> {
        Some(self.0.keyring())
    }
    fn node_id(&self) -> Option<IotaNodeId> {
        Some(self.0.node_id().clone())
    }
}

struct TestTransport;
#[async_trait]
impl PeerRouter for TestTransport {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        if let Some(router) = ROUTER.get() {
            return router.route(destination, frame).await;
        }
        assert_eq!(std::env::var("NATIVE_RELAY_TEST_STAGE").unwrap(), "origin");
        let response_path = std::path::Path::new("/tmp/opencode").join(format!(
            "native-destination-response-{}",
            uuid::Uuid::new_v4()
        ));
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", subprocess_test_name(), "--nocapture"])
                .env("NATIVE_RELAY_TEST_STAGE", "destination")
                .env("RELAY_NATIVE_CLIENT_FIXTURE", fixture_path())
                .env(
                    "NATIVE_RELAY_TEST_REQUEST",
                    STANDARD.encode(frame.to_bytes().unwrap())
                )
                .env("NATIVE_RELAY_TEST_RESPONSE", &response_path)
                .status()
                .unwrap()
                .success()
        );
        let response = CommunicationValue::try_from_bytes_with(
            &std::fs::read(&response_path).unwrap(),
            frame.type_map().unwrap(),
        )
        .unwrap();
        std::fs::remove_file(response_path).unwrap();
        RouteOutcome::from_relay_response(&frame, response)
    }
}

// Separate processes model independent Iota databases. A shared inbox would
// mistake the origin's accepted row for the destination's own acceptance.
#[tokio::test]
async fn native_client_production_ingress() {
    run_native_stage().await;
}

pub async fn run_native_stage() {
    let Ok(stage) = std::env::var("NATIVE_RELAY_TEST_STAGE") else {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", subprocess_test_name(), "--nocapture"])
                .env("NATIVE_RELAY_TEST_STAGE", "origin")
                .env("RELAY_NATIVE_CLIENT_FIXTURE", fixture_path())
                .status()
                .unwrap()
                .success()
        );
        return;
    };
    let directory = std::env::var_os("RELAY_NATIVE_STORAGE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new("/tmp/opencode")
                .join(format!("native-ingress-{}", uuid::Uuid::new_v4()))
        });
    std::fs::create_dir_all(&directory).unwrap();
    iota_util::file_util::configure_storage_directory(directory.clone());
    db::initialize_database().unwrap();
    let fixture = fixture();
    let nodes: Vec<_> = fixture["nodeKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| {
            LocalNodeIdentity::from_keyring(
                Keyring::from_bytes(&STANDARD.decode(key.as_str().unwrap()).unwrap()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let signer_key =
        PublicKeyBundle::from_base64(fixture["signerPublicKey"].as_str().unwrap()).unwrap();
    let ids = [11, 22].map(|user_id| PrincipalId {
        authority: AuthorityId::for_omega(&nodes[0].public_keys()).unwrap(),
        user_id,
    });
    let now = iota_storage::util::sync::now_millis();
    let mut handles = Vec::new();
    for index in 0..2 {
        let descriptor = SignedPrincipalDescriptor::sign(
            PrincipalDescriptor {
                principal: ids[index].clone(),
                authority_kind: AuthorityKind::Omega,
                username: Some(format!("native{index}")),
                display_name: None,
                public_keys: vec![if index == 0 {
                    signer_key.clone()
                } else {
                    Keyring::generate().public_key_bundle()
                }],
                home: PrincipalHome::Iota(nodes[index].node_id().clone()),
                revision: 1,
                issued_at: now,
                valid_until: Some(now + 600_000),
            },
            &nodes[0].keyring(),
        )
        .unwrap()
        .verify(&ids[index].authority, &nodes[0].public_keys(), None, now)
        .unwrap();
        handles.push(
            SqlitePrincipalStore
                .upsert_remote_descriptor(&descriptor)
                .unwrap(),
        );
    }
    let index = usize::from(stage == "destination");
    let local = ids[index].user_id as i64;
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO users(user_id, username, public_key, created_at) VALUES (?1, ?2, ?3, 1)", rusqlite::params![local, format!("native{index}"), fixture["signerPublicKey"].as_str().unwrap()])?;
        tx.execute("INSERT INTO user_residency(user_id, username, lifecycle_state, data_state, credential_origin, updated_at) VALUES (?1, ?2, 'managed', 'present', 'external', 1)", rusqlite::params![local, format!("native{index}")])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id, principal_handle) VALUES (?1, ?2)", rusqlite::params![local, handles[index].0])?;
        Ok(())
    }).unwrap();
    iota_storage::hosted_auth::maintain_server("native-test", true).unwrap();
    let connection_id = uuid::Uuid::new_v4();
    let lease = HostedAuthorizationLease {
        connection_id: connection_id.to_string(),
        server_instance: "native-test".into(),
        identity: iota_storage::hosted_auth::resolve(LocalUserId(local))
            .unwrap()
            .0,
    };
    iota_storage::hosted_auth::register(&lease).unwrap();
    let source = if index == 0 {
        IngressSource::HostedClient {
            session: AuthenticatedSession {
                connection_id,
                identity: SessionIdentity::Hosted {
                    local_user: LocalUserId(local),
                    principal: handles[0],
                },
                capabilities: SessionCapabilities::hosted(),
                hosted_lease: Some(lease.clone()),
            },
        }
    } else {
        IngressSource::DirectPeer {
            node_id: nodes[0].node_id().clone(),
        }
    };
    let service = Arc::new(
        RelayService::new(
            Arc::new(iota_storage::identity::SqliteLocalUserStore),
            Arc::new(TestTransport),
        )
        .with_federation(Arc::new(Resolver), Arc::new(Node(nodes[index].clone()))),
    );
    relay_support::install_test_recovery(service.clone(), &nodes[index], &nodes);
    if let Some(hook) = STAGE_HOOK.get() {
        hook(service.clone(), nodes.clone(), index).await;
    }
    let encoded = std::env::var("NATIVE_RELAY_TEST_REQUEST")
        .unwrap_or_else(|_| fixture["frame"].as_str().unwrap().to_owned());
    let frame = CommunicationValue::try_from_bytes_with(
        &STANDARD.decode(encoded).unwrap(),
        &TypeMap::new(mtp::type_map::Version::parse("1.0").unwrap()),
    )
    .unwrap();
    let verified = service.prepare_relay(&source, frame.clone()).await.unwrap();
    assert_eq!(verified.signer.principal, ids[0]);
    assert_eq!(verified.recipient.principal, ids[1]);
    assert_eq!(
        verified.frame.to_bytes().unwrap(),
        frame.to_bytes().unwrap()
    );
    let mut tampered = frame.to_bytes().unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    let tampered =
        CommunicationValue::try_from_bytes_with(&tampered, frame.type_map().unwrap()).unwrap();
    assert!(service.prepare_relay(&source, tampered).await.is_err());
    let wrong_node = Arc::new(
        RelayService::new(
            Arc::new(iota_storage::identity::SqliteLocalUserStore),
            Arc::new(TestTransport),
        )
        .with_federation(
            Arc::new(Resolver),
            Arc::new(Node(
                LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap(),
            )),
        ),
    );
    assert!(
        wrong_node
            .prepare_relay(&source, frame.clone())
            .await
            .is_err()
    );
    if let IngressSource::HostedClient { mut session } = source.clone() {
        session.identity = SessionIdentity::Hosted {
            local_user: LocalUserId(local),
            principal: handles[1],
        };
        assert!(
            service
                .accept_verified_relay(IngressSource::HostedClient { session }, verified.clone())
                .await
                .is_err()
        );
    }
    let message_id = verified.message_id.clone();
    let outcome = service
        .accept_verified_relay(source.clone(), verified)
        .await
        .unwrap();
    let RelayOutcome::Accepted {
        ingress_response, ..
    } = outcome
    else {
        panic!("native acceptance failed: {outcome:?}")
    };
    assert!(
        matches!(RouteOutcome::from_relay_response(&frame, ingress_response.clone()).unwrap(), RouteOutcome::Accepted { relay_message_id, .. } if relay_message_id == message_id)
    );
    if index == 0 {
        assert_eq!(service.dispatcher().dispatch_ready(1).await.unwrap(), 1);
        assert_eq!(service.dispatcher().dispatch_ready(1).await.unwrap(), 0);
    } else {
        if let Ok(path) = std::env::var("NATIVE_RELAY_TEST_RESPONSE") {
            std::fs::write(path, ingress_response.to_bytes().unwrap()).unwrap();
        }
    }
    let chat_id =
        iota_storage::util::chat_secret_recovery::canonical_chat_id(&ids[0], &ids[1]).unwrap();
    let secret_id = iota_identity::relay_protocol::chat_secret_id(&chat_id);
    let read = CommunicationValue::new_with_type_map(
        CommunicationType::GetChatSecret,
        frame.type_map().unwrap(),
    )
    .with_id(992)
    .with_sender(local as u64)
    .add_typed_default(
        DataType::UserId,
        DataValue::Str(serde_json::to_string(&ids[index]).unwrap()),
    )
    .add_typed_default(DataType::ChatId, DataValue::Str(chat_id.clone()))
    .add_typed_default(DataType::SecretId, DataValue::Str(secret_id.clone()))
    .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(1));
    let read = iota_connection::message_handlers::handle_get_chat_secret(&read);
    if let Some(directory) = std::env::var_os("RELAY_NATIVE_RESPONSES") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(format!("{local}.json")),
            serde_json::to_vec_pretty(&serde_json::json!({
                "frame": STANDARD.encode(read.to_bytes().unwrap()),
                "typeMapVersion": read.type_map().unwrap().version.to_string(),
            }))
            .unwrap(),
        )
        .unwrap();
    }
    assert!(
        read.is_type(CommunicationType::ChatSecretResponse),
        "native canonical read failed: {read:?}"
    );
    assert_eq!(
        read.get_data(DataType::ChatId).and_then(DataValue::as_str),
        Some(chat_id.as_str())
    );
    assert_eq!(
        read.get_data(DataType::SecretId)
            .and_then(DataValue::as_str),
        Some(secret_id.as_str())
    );
    assert_eq!(
        read.get_data(DataType::EncryptedSecret),
        Some(&DataValue::Bytes(
            STANDARD
                .decode(fixture["encryptedSecrets"][index].as_str().unwrap())
                .unwrap()
        ))
    );
    assert_eq!(
        read.get_data(DataType::KemCiphertext),
        Some(&DataValue::Bytes(
            STANDARD
                .decode(fixture["kemCiphertexts"][index].as_str().unwrap())
                .unwrap()
        ))
    );
    let escrow = iota_storage::util::chat_secret_recovery::escrow_for_recovery(
        &ids[0],
        &ids[1],
        &ids[index],
        Some(1),
    )
    .unwrap()
    .unwrap();
    service
        .verify_recovery_escrow(&escrow, frame.type_map().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        wrong_node
            .verify_recovery_escrow(&escrow, frame.type_map().unwrap())
            .await,
        Err(iota_connection::relay_service::RelayServiceError::Internal(
            _
        ))
    ));
    let mut substituted = escrow.clone();
    substituted.envelopes[0].encrypted_secret[0] ^= 1;
    assert!(
        service
            .verify_recovery_escrow(&substituted, frame.type_map().unwrap())
            .await
            .is_err()
    );
    let mut namespace = escrow.clone();
    namespace.namespace.chat_id = "11:33".into();
    assert!(
        service
            .verify_recovery_escrow(&namespace, frame.type_map().unwrap())
            .await
            .is_err()
    );
    let duplicate = service
        .accept_relay(source.clone(), frame.clone().with_id(991))
        .await
        .unwrap();
    let RelayOutcome::Accepted {
        ingress_response: duplicate,
        local_deliveries,
    } = duplicate
    else {
        panic!("native replay failed: {duplicate:?}")
    };
    assert!(local_deliveries.is_empty());
    assert_eq!(
        duplicate
            .get_data(DataType::Status)
            .and_then(DataValue::as_str),
        Some("already_accepted")
    );
    let mut wrong_ack = ingress_response;
    wrong_ack.set_data(
        DataType::RelayMessageId,
        DataValue::Str("tau-message-id".into()),
    );
    assert!(RouteOutcome::from_relay_response(&frame, wrong_ack).is_err());
    if index == 1 {
        assert!(
            service
                .accept_relay(
                    IngressSource::DirectPeer {
                        node_id: nodes[1].node_id().clone()
                    },
                    frame.clone()
                )
                .await
                .is_err()
        );
    } else {
        iota_storage::hosted_auth::remove(&lease.connection_id).unwrap();
        assert!(!matches!(
            service
                .accept_relay(source.clone(), frame.clone())
                .await
                .unwrap(),
            RelayOutcome::Accepted { .. }
        ));
    }
    // Another authority's numeric ID cannot alter a canonical native replay.
    db::with_db(|connection| {
        connection.execute("INSERT INTO principals(authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) VALUES ('omega', ?1, 11, 1, 0)", [format!("omega-key:{}", "c".repeat(64))])?;
        Ok(())
    }).unwrap();
    let replay = service.prepare_relay(&source, frame).await.unwrap();
    assert_eq!(replay.signer.principal, ids[0]);
    assert_eq!(replay.recipient.principal, ids[1]);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn native_ack_binds_exact_ciphertext_and_dictionary_not_correlation_id() {
    use iota_connection::connection_handler::bind_relay_response_identity;
    let fixture = fixture();
    let bytes = STANDARD.decode(fixture["frame"].as_str().unwrap()).unwrap();
    let map = TypeMap::new(mtp::type_map::Version::parse("1.0").unwrap());
    let frame = CommunicationValue::try_from_bytes_with(&bytes, &map)
        .unwrap()
        .with_id(9);
    let response = CommunicationValue::new_with_type_map(CommunicationType::Success, &map)
        .with_id(9)
        .add_typed_default(
            DataType::RelayMessageId,
            DataValue::Str("mtp-sealed-v1:1".into()),
        )
        .add_typed_default(DataType::Status, DataValue::Str("accepted".into()))
        .add_typed_default(DataType::RelayAcceptedAt, DataValue::SignedNumber(1));
    let response = bind_relay_response_identity(&frame, response).unwrap();
    assert!(matches!(
        RouteOutcome::from_relay_response(&frame, response.clone()).unwrap(),
        RouteOutcome::Accepted { .. }
    ));
    assert!(
        RouteOutcome::from_relay_response(&frame.clone().with_id(10), response.clone()).is_err()
    );
    let mut bytes = frame.to_bytes().unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let changed = CommunicationValue::try_from_bytes_with(&bytes, &map).unwrap();
    assert!(RouteOutcome::from_relay_response(&changed, response).is_err());
}

#[cfg(feature = "relay-fault-injection")]
#[tokio::test]
async fn first_epoch_crash_recovery_rechecks_peer_authority() {
    use iota_connection::chat_secret_recovery::*;
    struct ChangedPeer(Vec<LocalNodeIdentity>);
    #[async_trait]
    impl NodeIdentityResolver for ChangedPeer {
        async fn resolve_node(
            &self,
            id: &IotaNodeId,
        ) -> Result<ResolvedNodeIdentity, IdentityError> {
            let node = self
                .0
                .iter()
                .find(|node| node.node_id() == id)
                .ok_or(IdentityError::NotFound)?;
            Ok(ResolvedNodeIdentity {
                node: id.clone(),
                public_keys: vec![node.public_keys()],
                descriptor_revision: 1,
                valid_until: None,
                direct_endpoints: vec![],
                relay_hints: vec![],
                last_successful_endpoint: None,
                resolved_at: iota_storage::util::sync::now_millis(),
            })
        }
    }
    #[async_trait]
    impl RecoveryTransport for ChangedPeer {
        async fn request(
            &self,
            id: &IotaNodeId,
            request: &RecoveryRequest,
        ) -> Result<AuthenticatedRecoveryReply, RecoveryError> {
            assert!(request.proposal_digest.is_some());
            let node = self
                .0
                .iter()
                .find(|node| node.node_id() == id)
                .ok_or(RecoveryError::Unauthorized)?;
            // The original process observed a virgin peer. After its crash the
            // same authenticated peer reports a conflicting accepted history.
            Ok(AuthenticatedRecoveryReply {
                node: id.clone(),
                key: node.public_keys(),
                reply: RecoveryReply {
                    request: request.clone(),
                    result: Err(RecoveryError::Conflict),
                },
            })
        }
    }
    let directory = std::path::Path::new("/tmp/opencode")
        .join(format!("native-crash-gate-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let fixture = fixture();
    let nodes: Vec<_> = fixture["nodeKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| {
            LocalNodeIdentity::from_keyring(
                Keyring::from_bytes(&STANDARD.decode(key.as_str().unwrap()).unwrap()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let frame = CommunicationValue::try_from_bytes_with(
        &STANDARD.decode(fixture["frame"].as_str().unwrap()).unwrap(),
        &TypeMap::new(mtp::type_map::Version::parse("1.0").unwrap()),
    )
    .unwrap();
    let signer_key =
        PublicKeyBundle::from_base64(fixture["signerPublicKey"].as_str().unwrap()).unwrap();
    let metadata = mtp::codec::relay::open_relay_metadata_with_limits_without_replay(
        &frame,
        &[&nodes[0].keyring()],
        Some(11),
        |_| Some(vec![signer_key]),
        mtp::codec::relay::RelayOpenOptions::new(mtp::codec::ProtectionPolicy::ed25519()),
    )
    .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", subprocess_test_name(), "--nocapture"])
        .env("NATIVE_RELAY_TEST_STAGE", "origin")
        .env("RELAY_NATIVE_STORAGE", &directory)
        .env("IOTA_RELAY_FAULT_POINT", "after_claim_acquisition")
        .env(
            "IOTA_RELAY_FAULT_MESSAGE_ID",
            format!("mtp-sealed-v1:{}", metadata.message_id().get()),
        )
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(86),
        "child must crash after preflight and durable claim, before commit"
    );
    relay_support::initialize(&directory);
    let service = Arc::new(
        RelayService::new(
            Arc::new(iota_storage::identity::SqliteLocalUserStore),
            Arc::new(TestTransport),
        )
        .with_federation(Arc::new(Resolver), Arc::new(Node(nodes[0].clone()))),
    );
    install_recovery(Arc::new(RecoveryCoordinator::new(
        Arc::new(Resolver),
        Arc::new(ChangedPeer(nodes.clone())),
        Arc::new(SqlitePrincipalStore),
        Arc::new(iota_storage::identity::SqliteLocalUserStore),
        nodes[0].node_id().clone(),
        Arc::new(ChangedPeer(nodes)),
        Arc::new(OriginalOperationVerifier {
            relay: service.clone(),
        }),
    )));
    relay_support::execute("UPDATE relay_inbox SET processing_deadline=0,recovery_next_at=0");
    // Legacy synchronous replay must not bypass the newly required async gate.
    assert_eq!(service.recover_incomplete(10).unwrap().completed, 0);
    relay_support::execute("UPDATE relay_inbox SET recovery_next_at=0,recovery_status='ready'");
    let report = service.recover_incomplete_authorized(10).await.unwrap();
    assert_eq!(report.completed, 0);
    assert_eq!(report.blocked, 1);
    assert_eq!(relay_support::count("SELECT count(*) FROM chat_secrets"), 0);
    assert_eq!(
        relay_support::count("SELECT count(*) FROM chat_secret_escrows"),
        0
    );
    assert_eq!(
        relay_support::count("SELECT count(*) FROM pending_relays"),
        0
    );
    assert_eq!(
        relay_support::count(
            "SELECT count(*) FROM relay_inbox WHERE state IN ('applied','queued','delivered')"
        ),
        0
    );
    std::fs::remove_dir_all(directory).unwrap();
}
