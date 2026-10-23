use async_trait::async_trait;
use iota_auth::{AuthenticatedSession, SessionCapabilities, SessionIdentity};
use iota_connection::{
    connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome},
    federated_relay::FederatedRelay,
    relay_service::{IngressSource, RelayNodeIdentity, RelayOutcome, RelayService},
};
use iota_identity::*;
use iota_storage::{
    identity::{SqliteLocalUserStore, SqlitePrincipalStore},
    util::db,
};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    crypto::Keyring,
};
use std::{path::Path, sync::Arc};

pub fn initialize(path: &Path) {
    iota_util::file_util::configure_storage_directory(path.to_owned());
    db::initialize_database().unwrap();
}

pub fn count(sql: &str) -> i64 {
    db::with_db(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
}

pub fn execute(sql: &str) {
    db::with_db(|c| {
        c.execute_batch(sql)?;
        Ok(())
    })
    .unwrap();
}

pub struct Router(pub bool);
#[async_trait]
impl PeerRouter for Router {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let RouteDestination::Iota(node) = destination else {
            panic!("noncanonical route")
        };
        let Some(DataValue::Bytes(payload)) = frame.get_data(DataType::SecurePayload) else {
            panic!("missing protected relay payload")
        };
        let wire: iota_connection::federated_relay::protocol::RelayWire =
            serde_json::from_slice(payload).unwrap();
        let signer = PrincipalId {
            authority: AuthorityId::new(&wire.signer.authority).unwrap(),
            user_id: wire.signer.user_id,
        };
        let keys = SqlitePrincipalStore.signing_keys(&signer).unwrap();
        let verified = iota_connection::federated_relay::protocol::verify_outer(
            payload,
            &keys,
            None,
            Some(node.as_str()),
        )
        .unwrap();
        if self.0 {
            Ok(RouteOutcome::Accepted {
                relay_message_id: verified.wire.message_id,
                destination_accepted_at: 1234,
            })
        } else {
            Ok(RouteOutcome::Rejected {
                response_type: CommunicationType::ErrorInvalidData,
            })
        }
    }
}

pub struct Resolver;
#[async_trait]
impl IdentityResolver for Resolver {
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

pub struct Fixture {
    pub service: Arc<RelayService>,
    pub node: LocalNodeIdentity,
    pub destination: LocalNodeIdentity,
    pub keys: [Keyring; 2],
    pub ids: [PrincipalId; 2],
    pub handles: [PrincipalHandle; 2],
    pub sources: Vec<IngressSource>,
}

impl Fixture {
    pub fn destination_service(&self) -> Arc<RelayService> {
        Arc::new(
            RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true)))
                .with_federation(Arc::new(Resolver), Arc::new(Node(self.destination.clone()))),
        )
    }

    pub fn new(both_local: bool) -> Self {
        let mut node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
        let mut destination = if both_local {
            node.clone()
        } else {
            LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap()
        };
        if node.authority_id().as_str() > destination.authority_id().as_str() {
            std::mem::swap(&mut node, &mut destination);
        }
        let keys = [Keyring::generate(), Keyring::generate()];
        let ids = [
            PrincipalId {
                authority: node.authority_id().clone(),
                user_id: 1,
            },
            PrincipalId {
                authority: destination.authority_id().clone(),
                user_id: 2,
            },
        ];
        let handles = std::array::from_fn(|i| {
            let authority = if i == 0 { &node } else { &destination };
            let now = iota_storage::util::sync::now_millis();
            let descriptor = SignedPrincipalDescriptor::sign(
                PrincipalDescriptor {
                    principal: ids[i].clone(),
                    authority_kind: AuthorityKind::Iota,
                    username: Some(format!("user{i}")),
                    display_name: None,
                    public_keys: vec![keys[i].public_key_bundle()],
                    home: PrincipalHome::Iota(authority.node_id().clone()),
                    revision: 1,
                    valid_until: Some(now + 600_000),
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
            .unwrap();
            SqlitePrincipalStore
                .upsert_remote_descriptor(&descriptor)
                .unwrap()
        });
        let mut sources = Vec::new();
        iota_storage::hosted_auth::maintain_server("test", true).unwrap();
        for (i, handle) in handles
            .iter()
            .enumerate()
            .take(if both_local { 2 } else { 1 })
        {
            db::with_immediate_transaction(|tx| {
                tx.execute("INSERT INTO users(user_id, username, public_key, created_at) VALUES(?1, ?2, 'test', 1)", rusqlite::params![i as i64 + 1, format!("user{i}")])?;
                tx.execute("INSERT INTO user_residency(user_id, username, lifecycle_state, data_state, credential_origin, updated_at) VALUES(?1, ?2, 'managed', 'present', 'external', 1)", rusqlite::params![i as i64 + 1, format!("user{i}")])?;
                tx.execute("INSERT INTO hosted_principals(local_user_id, principal_handle) VALUES(?1, ?2)", rusqlite::params![i as i64 + 1, handle.0])?;
                Ok(())
            }).unwrap();
            let connection_id = uuid::Uuid::new_v4();
            let lease = HostedAuthorizationLease {
                connection_id: connection_id.to_string(),
                server_instance: "test".into(),
                identity: iota_storage::hosted_auth::resolve(LocalUserId(i as i64 + 1))
                    .unwrap()
                    .0,
            };
            iota_storage::hosted_auth::register(&lease).unwrap();
            sources.push(IngressSource::HostedClient {
                session: AuthenticatedSession {
                    connection_id,
                    identity: SessionIdentity::Hosted {
                        local_user: LocalUserId(i as i64 + 1),
                        principal: *handle,
                    },
                    capabilities: SessionCapabilities::hosted(),
                    hosted_lease: Some(lease),
                },
            });
        }
        let service = Arc::new(
            RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true)))
                .with_federation(Arc::new(Resolver), Arc::new(Node(node.clone()))),
        );
        Self {
            service,
            node,
            destination,
            keys,
            ids,
            handles,
            sources,
        }
    }

    pub fn frame(
        &self,
        signer: usize,
        id: &str,
        content: CommunicationValue,
    ) -> CommunicationValue {
        FederatedRelay::sign(
            self.ids[signer].clone(),
            self.ids[1 - signer].clone(),
            if signer == 0 {
                self.destination.node_id().clone()
            } else {
                self.node.node_id().clone()
            },
            id.into(),
            iota_storage::util::sync::now_millis() as u64,
            content,
            &self.keys[signer],
            vec![
                self.node.public_keys(),
                self.destination.public_keys(),
                self.keys[0].public_key_bundle(),
                self.keys[1].public_key_bundle(),
            ],
        )
        .unwrap()
        .into_frame(7)
        .unwrap()
    }

    pub async fn accept(
        &self,
        signer: usize,
        id: &str,
        content: CommunicationValue,
    ) -> RelayOutcome {
        self.service
            .accept_relay(
                self.sources[signer].clone(),
                self.frame(signer, id, content),
            )
            .await
            .unwrap()
    }
}

pub fn accepted(outcome: RelayOutcome) {
    let RelayOutcome::Accepted {
        ingress_response, ..
    } = outcome
    else {
        panic!("{outcome:?}")
    };
    assert!(ingress_response.is_type(CommunicationType::Success));
    assert!(matches!(
        ingress_response
            .get_data(DataType::Status)
            .and_then(DataValue::as_str),
        Some("accepted" | "already_accepted")
    ));
}

pub fn send(time: i64) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::MessageSend)
        .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into()))
        .add_typed_default(DataType::SendTime, DataValue::SignedNumber(time.into()))
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1))
}

pub fn secret(fixture: &Fixture) -> CommunicationValue {
    use iota_connection::federated_relay::{protocol, protocol_principal};
    let principals = fixture.ids.each_ref().map(protocol_principal);
    let chat_id = protocol::canonical_chat_id(&principals[0], &principals[1]);
    let frame = CommunicationValue::new(CommunicationType::SetChatSecret);
    let map = frame.type_map().unwrap();
    let copies = principals
        .iter()
        .enumerate()
        .map(|(index, principal)| {
            let id = index as u8 + 1;
            tau::typed_container(
                map,
                vec![
                    (
                        DataType::UserId,
                        DataValue::Str(serde_json::to_string(principal).unwrap()),
                    ),
                    (DataType::EncryptedSecret, DataValue::Bytes(vec![id])),
                    (DataType::KemCiphertext, DataValue::Bytes(vec![10 + id])),
                ],
            )
            .unwrap()
        })
        .collect();
    frame
        .add_typed_default(
            DataType::SecretId,
            DataValue::Str(protocol::chat_secret_id(&chat_id)),
        )
        .add_typed_default(DataType::ChatId, DataValue::Str(chat_id))
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1))
        .add_typed_default(DataType::WrappingScheme, DataValue::Str("test".into()))
        .add_typed_default(DataType::Recipients, DataValue::Array(copies))
}
