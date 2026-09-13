use async_trait::async_trait;
use dashmap::DashMap;
use iota_auth::{
    AuthenticatedSession, HostedSessionRegistrar, SessionCapability, SessionIdentity,
    SessionManager,
};
use iota_connection::message_common::CommunicationResponseExt;
use iota_connection::message_handlers;
use iota_connection::relay_service::{IngressSource, RelayService};
use iota_identity::{
    LocalUserId, LocalUserStore, PrincipalHandle, PrincipalStore, PublicKeyBundle,
};
use iota_util::crypto_helper::public_key_bundle_from_base64;
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue};
use mtp::codec::{DataType, DataValue};
use other_iota::LocalDeliverySink;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub struct HostedAndPeerKeyResolver {
    local_users: Arc<dyn LocalUserStore>,
}

impl HostedAndPeerKeyResolver {
    pub fn new(local_users: Arc<dyn LocalUserStore>) -> Self {
        Self { local_users }
    }
}

#[async_trait]
impl web_server::ClientPublicKeyResolver for HostedAndPeerKeyResolver {
    async fn public_key(&self, client_id: u64) -> Option<PublicKeyBundle> {
        if client_id & (1_u64 << 63) != 0 {
            return iota_storage::node_directory::SqliteNodeDirectory
                .key_for_authentication_hint(client_id)
                .ok()
                .flatten();
        }
        let local_user = i64::try_from(client_id).ok().map(LocalUserId)?;
        self.local_users
            .get_local_user(local_user)
            .ok()
            .flatten()
            .and_then(|user| public_key_bundle_from_base64(&user.public_key))
    }
}

pub struct ClientConnectionManager {
    local_users: Arc<dyn LocalUserStore>,
    principals: Arc<dyn PrincipalStore>,
    registrar: Arc<HostedSessionRegistrar>,
    sessions: Arc<SessionManager>,
    relay: Arc<RelayService>,
    active: DashMap<PrincipalHandle, HashMap<Uuid, mtp::webserver::WebMtpSender>>,
}

impl ClientConnectionManager {
    pub fn new(
        local_users: Arc<dyn LocalUserStore>,
        principals: Arc<dyn PrincipalStore>,
        registrar: Arc<HostedSessionRegistrar>,
        sessions: Arc<SessionManager>,
        relay: Arc<RelayService>,
    ) -> Self {
        Self {
            local_users,
            principals,
            registrar,
            sessions,
            relay,
            active: DashMap::new(),
        }
    }

    pub fn is_connected(&self, principal: PrincipalHandle) -> bool {
        self.active.contains_key(&principal)
    }

    async fn handle(
        &self,
        session: &AuthenticatedSession,
        frame: CommunicationValue,
    ) -> Vec<CommunicationValue> {
        if let Some(relay) = client_relay_frame(&frame) {
            let request = frame.clone();
            return match self
                .relay
                .accept_relay(
                    IngressSource::HostedClient {
                        session: session.clone(),
                    },
                    relay,
                )
                .await
            {
                Ok(outcome) => {
                    let (response, deliveries) = outcome.into_parts();
                    for delivery in deliveries {
                        self.deliver(delivery.recipient, delivery.frame).await;
                    }
                    response.into_iter().collect()
                }
                Err(_) => vec![
                    CommunicationValue::new(CommunicationType::ErrorInvalidData)
                        .with_request_id(&request),
                ],
            };
        }
        let request = frame.clone();
        let Some(frame) = authorized_hosted_frame(session, frame) else {
            return vec![
                CommunicationValue::new(CommunicationType::ErrorNotAuthenticated)
                    .with_request_id(&request),
            ];
        };
        if frame.is_type(CommunicationType::AccountStateRequest) {
            return vec![message_handlers::handle_account_state_request(&frame)];
        }
        if frame.is_type(CommunicationType::AccountStateApplied) {
            return vec![message_handlers::handle_account_state_applied(&frame)];
        }
        if frame.is_type(CommunicationType::MessagesGet) {
            return vec![message_handlers::handle_messages_get(&frame)];
        }
        if frame.is_type(CommunicationType::MessageGet) {
            return vec![message_handlers::handle_message_get(&frame)];
        }
        vec![CommunicationValue::new(CommunicationType::ErrorInvalidData).with_request_id(&frame)]
    }
}

fn authorized_hosted_frame(
    session: &AuthenticatedSession,
    frame: CommunicationValue,
) -> Option<CommunicationValue> {
    let SessionIdentity::Hosted { local_user, .. } = &session.identity else {
        return None;
    };
    let capability = if frame.is_type(CommunicationType::AccountStateRequest)
        || frame.is_type(CommunicationType::AccountStateApplied)
    {
        SessionCapability::AccountData
    } else if frame.is_type(CommunicationType::MessagesGet)
        || frame.is_type(CommunicationType::MessageGet)
    {
        SessionCapability::Messaging
    } else {
        return None;
    };
    if !session.allows(&capability) {
        return None;
    }
    let sender = u64::try_from(local_user.0).ok()?;
    Some(frame.with_sender(sender))
}

fn client_relay_frame(frame: &CommunicationValue) -> Option<CommunicationValue> {
    if frame.is_type(CommunicationType::Relay) {
        return Some(frame.clone());
    }
    if !frame.is_type(CommunicationType::MessageSend)
        || frame.get_data(DataType::VersionNumber).as_number() != Some(2)
    {
        return None;
    }
    let frame_id = frame.id()?;
    let payload = match frame.get_data(DataType::SecurePayload)? {
        DataValue::Bytes(payload) => payload.clone(),
        _ => return None,
    };
    Some(
        CommunicationValue::new(CommunicationType::Relay)
            .with_id(frame_id)
            .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
            .add_typed_default(DataType::SecurePayload, DataValue::Bytes(payload)),
    )
}

#[async_trait]
impl other_iota::LocalDeliverySink for ClientConnectionManager {
    async fn deliver(&self, recipient: PrincipalHandle, frame: CommunicationValue) {
        let senders = self
            .active
            .get(&recipient)
            .map(|connections| connections.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for sender in senders {
            let _ = sender.send(&frame).await;
        }
    }
}

#[async_trait]
impl web_server::MtpConnectionHandler for ClientConnectionManager {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection) {
        if connection.auth_state != mtp::host::AuthState::Authenticated
            || connection.client_id & (1_u64 << 63) != 0
        {
            return;
        }
        let Ok(local_user_id) = i64::try_from(connection.client_id) else {
            return;
        };
        let local_user = LocalUserId(local_user_id);
        if !self.local_users.is_hosted_here(local_user).unwrap_or(false) {
            return;
        }
        let Ok(Some(principal)) = self.local_users.principal_for_local_user(local_user) else {
            return;
        };
        if self
            .principals
            .get_principal(principal)
            .ok()
            .flatten()
            .is_none()
        {
            return;
        }
        let connection_id = Uuid::new_v4();
        let session = self
            .registrar
            .authenticate(connection_id, local_user, principal);
        self.active
            .entry(principal)
            .or_default()
            .insert(connection_id, connection.sender.clone());
        while let Ok(frame) = connection.receive().await {
            for response in self.handle(&session, frame).await {
                if connection.sender.send(&response).await.is_err() {
                    break;
                }
            }
        }
        if let dashmap::mapref::entry::Entry::Occupied(mut connections) =
            self.active.entry(principal)
        {
            connections.get_mut().remove(&connection_id);
            if connections.get().is_empty() {
                connections.remove();
            }
        }
        self.sessions.remove(connection_id);
    }
}

pub struct ConnectionGateway {
    clients: Arc<ClientConnectionManager>,
    peers: Arc<other_iota::PeerManager>,
}

impl ConnectionGateway {
    pub fn new(clients: Arc<ClientConnectionManager>, peers: Arc<other_iota::PeerManager>) -> Self {
        Self { clients, peers }
    }
}

#[async_trait]
impl web_server::MtpConnectionHandler for ConnectionGateway {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection) {
        if connection.client_id & (1_u64 << 63) != 0 {
            self.peers.accept(connection).await;
        } else {
            self.clients.accept(connection).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_auth::SessionCapabilities;

    #[test]
    fn signed_message_send_enters_relay_v2_path() {
        let message = CommunicationValue::new(CommunicationType::MessageSend)
            .with_id(7)
            .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
            .add_typed_default(DataType::SecurePayload, DataValue::Bytes(vec![1, 2, 3]));

        let relay = client_relay_frame(&message).unwrap();
        assert!(relay.is_type(CommunicationType::Relay));
        assert_eq!(relay.id(), Some(7));
        assert_eq!(
            relay.get_data(DataType::SecurePayload),
            Some(&DataValue::Bytes(vec![1, 2, 3]))
        );
    }

    #[test]
    fn unsigned_message_send_does_not_enter_relay_path() {
        assert!(
            client_relay_frame(&CommunicationValue::new(CommunicationType::MessageSend)).is_none()
        );
    }

    #[test]
    fn hosted_session_replaces_untrusted_request_sender() {
        let session = AuthenticatedSession {
            connection_id: Uuid::new_v4(),
            identity: SessionIdentity::Hosted {
                local_user: LocalUserId(7),
                principal: PrincipalHandle(9),
            },
            capabilities: SessionCapabilities::hosted(),
        };
        let frame = CommunicationValue::new(CommunicationType::AccountStateRequest).with_sender(99);

        assert_eq!(
            authorized_hosted_frame(&session, frame).unwrap().sender(),
            Some(7)
        );
    }
}
