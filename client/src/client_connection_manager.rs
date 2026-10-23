mod delivery;
mod identity;
use delivery::authorized_hosted_frame;
#[cfg(test)]
use delivery::local_delivery_ack_matches;
mod gateway;
use crate::tau_gateway::{GatewayError, IotaConnectionIdentity, IotaConnectionRole};
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
    HostedAuthorizationLease, IdentityResolver, LocalUserId, LocalUserStore, PrincipalHandle,
    PrincipalStore, PublicKeyBundle, ValidatedHostedIdentity,
};
use iota_util::crypto_helper::public_key_bundle_from_base64;
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue};
use mtp::codec::{DataType, DataValue};
use other_iota::LocalDeliverySink;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct HostedAndPeerKeyResolver {
    local_users: Arc<dyn LocalUserStore>,
}

pub struct ClientConnectionManager {
    identities: Arc<dyn IdentityResolver>,
    registrar: Arc<HostedSessionRegistrar>,
    sessions: Arc<SessionManager>,
    relay: Arc<RelayService>,
    active: DashMap<PrincipalHandle, HashMap<Uuid, Arc<HostedConnection>>>,
    publication_epochs: Mutex<HashMap<PrincipalHandle, Arc<()>>>,
    server_instance: Uuid,
    pending_revocations: Mutex<std::collections::HashSet<Uuid>>,
    server_started: Mutex<bool>,
}

struct HostedConnection {
    sender: mtp::webserver::WebMtpSender,
    responses: tau::ResponseCorrelator,
    delivery_ready: tokio::sync::Notify,
    state_applied: std::sync::atomic::AtomicBool,
}

impl HostedConnection {
    fn close(&self) {
        self.responses.close();
        self.sender.close();
    }
}

impl ClientConnectionManager {
    /// Daemon-supervised reconciliation also closes senders while their handlers
    /// finish accepted work. Periodic reads catch commits by external writers.
    pub async fn monitor_authorization(&self, shutdown: CancellationToken) {
        let mut changes = iota_storage::hosted_auth::changes();
        let mut scanner = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = changes.changed() => {},
                _ = scanner.tick() => {},
            }
            let pending = self
                .pending_revocations
                .lock()
                .expect("revocation lock poisoned")
                .clone();
            for id in pending {
                if iota_storage::hosted_auth::remove(&id.to_string()).is_ok() {
                    self.pending_revocations
                        .lock()
                        .expect("revocation lock poisoned")
                        .remove(&id);
                }
            }
            let sessions = self.sessions.snapshot();
            let leases = sessions
                .iter()
                .filter_map(|session| session.hosted_lease.clone())
                .collect::<Vec<_>>();
            let invalid = self
                .ensure_server()
                .and_then(|()| iota_storage::hosted_auth::verify_batch(&leases));
            for session in sessions {
                if session.hosted_lease.is_some()
                    && invalid
                        .as_ref()
                        .map_or(true, |ids| ids.contains(&session.connection_id.to_string()))
                    && let Err(error) =
                        self.revoke_session(session.principal(), session.connection_id)
                {
                    iota_logger::log!("Hosted authorization reconciliation failed: {}", error);
                }
            }
        }
    }

    pub fn new(
        identities: Arc<dyn IdentityResolver>,
        registrar: Arc<HostedSessionRegistrar>,
        sessions: Arc<SessionManager>,
        relay: Arc<RelayService>,
    ) -> Self {
        Self {
            identities,
            registrar,
            sessions,
            relay,
            active: DashMap::new(),
            publication_epochs: Mutex::new(HashMap::new()),
            server_instance: Uuid::new_v4(),
            pending_revocations: Mutex::new(std::collections::HashSet::new()),
            server_started: Mutex::new(false),
        }
    }

    fn ensure_server(&self) -> Result<(), iota_storage::storage_error::StorageError> {
        let mut started = self.server_started.lock().expect("server lock poisoned");
        iota_storage::hosted_auth::maintain_server(&self.server_instance.to_string(), !*started)?;
        *started = true;
        Ok(())
    }

    pub fn is_connected(&self, principal: PrincipalHandle) -> bool {
        self.active.contains_key(&principal)
    }

    /// Revoke only this connection instance. An operation already committed
    /// finishes; pending preparation must recheck the live session before commit.
    pub fn revoke_session(
        &self,
        principal: PrincipalHandle,
        connection_id: Uuid,
    ) -> Result<(), iota_storage::storage_error::StorageError> {
        self.pending_revocations
            .lock()
            .expect("revocation lock poisoned")
            .insert(connection_id);
        let mut epochs = self
            .publication_epochs
            .lock()
            .expect("publication lock poisoned");
        epochs.insert(principal, Arc::new(()));
        self.sessions.remove(connection_id);
        if let dashmap::mapref::entry::Entry::Occupied(mut connections) =
            self.active.entry(principal)
        {
            if let Some(connection) = connections.get_mut().remove(&connection_id) {
                connection.close();
                iota_logger::log!(
                    "Hosted session revoked: connection={} principal={}",
                    connection_id,
                    principal.0
                );
            }
            if connections.get().is_empty() {
                connections.remove();
            }
        }
        drop(epochs);
        let durable = iota_storage::hosted_auth::remove(&connection_id.to_string());
        if durable.is_ok() {
            self.pending_revocations
                .lock()
                .expect("revocation lock poisoned")
                .remove(&connection_id);
        }
        durable
    }

    /// Explicit account-wide revocation commits authority before registry cleanup.
    /// Lifecycle changes notify the monitor after their own transaction commits.
    pub fn revoke_principal(
        &self,
        principal: PrincipalHandle,
    ) -> Result<(), iota_storage::storage_error::StorageError> {
        iota_storage::util::db::with_immediate_transaction(|tx| {
            let user = tx.query_row(
                "SELECT local_user_id FROM hosted_principals WHERE principal_handle = ?1",
                [principal.0],
                |row| row.get::<_, i64>(0),
            )?;
            iota_storage::hosted_auth::revoke_in_tx(tx, LocalUserId(user))?;
            Ok(())
        })?;
        let mut epochs = self
            .publication_epochs
            .lock()
            .expect("publication lock poisoned");
        epochs.insert(principal, Arc::new(()));
        self.sessions.remove_principal(principal);
        if let Some((_, connections)) = self.active.remove(&principal) {
            for (connection_id, connection) in connections {
                self.sessions.remove(connection_id);
                connection.close();
                iota_logger::log!(
                    "Hosted principal revoked: connection={} principal={}",
                    connection_id,
                    principal.0
                );
            }
        }
        Ok(())
    }
}

impl ClientConnectionManager {
    fn session_is_registered(&self, session: &AuthenticatedSession) -> bool {
        self.sessions
            .get(session.connection_id)
            .is_some_and(|current| {
                current.identity == session.identity && current.hosted_lease == session.hosted_lease
            })
    }

    async fn run_hosted(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        connection_id: Uuid,
        identity: ValidatedHostedIdentity,
        shutdown: CancellationToken,
    ) {
        let ValidatedHostedIdentity {
            local_user,
            principal,
            auth_generation,
        } = identity;
        let verified_key = connection
            .client_public_key
            .clone()
            .expect("hosted transport was authenticated");
        struct HostedRegistration<'a> {
            manager: &'a ClientConnectionManager,
            principal: PrincipalHandle,
            connection_id: Uuid,
            sender: mtp::webserver::WebMtpSender,
        }

        impl Drop for HostedRegistration<'_> {
            fn drop(&mut self) {
                if let Err(error) = self
                    .manager
                    .revoke_session(self.principal, self.connection_id)
                {
                    iota_logger::log!("Durable hosted-session cleanup failed: {}", error);
                }
                self.sender.close();
            }
        }

        let epoch = self
            .publication_epochs
            .lock()
            .expect("publication lock poisoned")
            .entry(principal)
            .or_insert_with(|| Arc::new(()))
            .clone();
        let _registration = HostedRegistration {
            manager: self,
            principal,
            connection_id,
            sender: connection.sender.clone(),
        };
        let lease = HostedAuthorizationLease {
            connection_id: connection_id.to_string(),
            server_instance: self.server_instance.to_string(),
            identity: ValidatedHostedIdentity {
                local_user,
                principal,
                auth_generation,
            },
        };
        if self.ensure_server().is_err() || iota_storage::hosted_auth::register(&lease).is_err() {
            return;
        }
        let session = {
            let publication = self
                .publication_epochs
                .lock()
                .expect("publication lock poisoned");
            if !publication
                .get(&principal)
                .is_some_and(|current| Arc::ptr_eq(current, &epoch))
            {
                return;
            }
            let session = self.registrar.authenticate(connection_id, lease);
            let active = Arc::new(HostedConnection {
                sender: connection.sender.clone(),
                responses: tau::ResponseCorrelator::new(),
                delivery_ready: tokio::sync::Notify::new(),
                state_applied: std::sync::atomic::AtomicBool::new(false),
            });
            self.active
                .entry(principal)
                .or_default()
                .insert(connection_id, active.clone());
            (session, active)
        };
        let (session, active) = session;
        let pending_delivery = self.deliver_pending(&session, &active, &shutdown);
        tokio::pin!(pending_delivery);
        // Removing connection-local state on cancellation does not roll back
        // application operations that already committed.
        'receive: loop {
            let frame = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = &mut pending_delivery => break,
                frame = connection.receive() => match frame { Ok(frame) => frame, Err(_) => break },
            };
            let valid = tokio::select! {
                _ = shutdown.cancelled() => false,
                valid = self.hosted_session_is_current(&session, &verified_key) => valid,
            };
            if !valid {
                break;
            }
            if frame
                .id()
                .is_some_and(|id| active.responses.complete(id, frame.clone()))
            {
                continue;
            }
            // Finish an accepted mutation before cleanup. Cancelling its future
            // would not roll back application state already committed.
            let Some(current_session) = self.sessions.get(connection_id) else {
                break;
            };
            let private_read = frame.is_type(CommunicationType::AccountStateRequest)
                || frame.is_type(CommunicationType::RelayReceiptPage)
                || frame.is_type(CommunicationType::MessagesGet)
                || frame.is_type(CommunicationType::MessageGet)
                || frame.is_type(CommunicationType::GetChatSecret)
                || frame.is_type(CommunicationType::GetChats);
            let account_applied = frame.is_type(CommunicationType::AccountStateApplied);
            for response in self
                .handle(&current_session, &verified_key, &shutdown, frame)
                .await
            {
                if private_read
                    && !response
                        .get_comm_type_enum()
                        .is_some_and(tau::is_protocol_error)
                    && !self
                        .hosted_session_is_current(&current_session, &verified_key)
                        .await
                {
                    break 'receive;
                }
                if !matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        connection.sender.send(&response)
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    break 'receive;
                }
                if account_applied && response.is_type(CommunicationType::Success) {
                    active
                        .state_applied
                        .store(true, std::sync::atomic::Ordering::Release);
                    active.delivery_ready.notify_one();
                }
            }
        }
    }

    async fn hosted_session_is_current(
        &self,
        session: &AuthenticatedSession,
        key: &PublicKeyBundle,
    ) -> bool {
        let SessionIdentity::Hosted {
            local_user,
            principal,
        } = session.identity
        else {
            return false;
        };
        let valid = session
            .hosted_lease
            .as_ref()
            .is_some_and(|lease| iota_storage::hosted_auth::verify(lease).is_ok())
            && matches!(self.resolve_hosted_identity(local_user.0 as u64, key).await,
            Ok(IotaConnectionIdentity::HostedClient { local_user: current_user, principal: current_principal, auth_generation })
                if current_user == local_user && current_principal == principal
                    && session.hosted_lease.as_ref().is_some_and(|lease| lease.identity.auth_generation == auth_generation));
        if !valid && let Err(error) = self.revoke_session(principal, session.connection_id) {
            iota_logger::log!("Durable hosted-session revocation failed: {}", error);
        }
        valid
            && self
                .sessions
                .get(session.connection_id)
                .is_some_and(|current| {
                    current.identity == session.identity
                        && current.hosted_lease == session.hosted_lease
                })
    }

    async fn handle(
        &self,
        session: &AuthenticatedSession,
        _verified_key: &PublicKeyBundle,
        shutdown: &CancellationToken,
        frame: CommunicationValue,
    ) -> Vec<CommunicationValue> {
        if frame.type_map().is_none() {
            return Vec::new();
        }
        if frame.is_type(CommunicationType::Relay) {
            let request = frame.clone();
            let relay = frame;
            let source = IngressSource::HostedClient {
                session: session.clone(),
            };
            let prepared = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Vec::new(),
                prepared = self.relay.prepare_relay(&source, relay) => prepared,
            };
            let outcome = match prepared {
                Ok(verified) => self.relay.accept_verified_relay(source, verified).await,
                Err(error) => Err(error),
            };
            return match outcome {
                Ok(outcome) => {
                    let (response, deliveries) = outcome.into_parts();
                    for delivery in deliveries {
                        tokio::select! {
                            _ = shutdown.cancelled() => break,
                            _ = self.deliver(delivery.recipient, delivery.frame) => {},
                        }
                    }
                    response.into_iter().collect()
                }
                Err(error) => vec![iota_connection::relay_service::relay_error_response(
                    &request, &error,
                )],
            };
        }
        let request = frame.clone();
        let Some(frame) = authorized_hosted_frame(session, frame) else {
            return vec![
                CommunicationValue::new(CommunicationType::ErrorNotAuthenticated)
                    .with_request_id(&request),
            ];
        };
        if frame.is_type(CommunicationType::UserResolve) {
            let request = frame.clone();
            let resolver = self.identities.clone();
            let resolve = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                message_handlers::handle_user_resolve(&frame, resolver.as_ref()),
            )
            .await;
            return vec![match resolve {
                Ok(response) => response,
                Err(_) => CommunicationValue::new(CommunicationType::ErrorNoIota)
                    .with_request_id(&request)
                    .add_typed_default(
                        DataType::ErrorType,
                        DataValue::Str("resolve_timeout".into()),
                    ),
            }];
        }
        if frame.is_type(CommunicationType::AccountStateRequest) {
            return vec![message_handlers::handle_account_state_request(&frame)];
        }
        if frame.is_type(CommunicationType::RelayReceiptPage) {
            return vec![message_handlers::handle_relay_receipt_page(&frame)];
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
        if frame.is_type(CommunicationType::GetChatSecret) {
            return vec![message_handlers::handle_get_chat_secret(&frame)];
        }
        if frame.is_type(CommunicationType::GetChats) {
            return vec![message_handlers::handle_get_chats(&frame)];
        }
        vec![CommunicationValue::new(CommunicationType::ErrorInvalidData).with_request_id(&frame)]
    }
}

#[async_trait]
impl other_iota::LocalDeliverySink for ClientConnectionManager {
    async fn deliver(&self, recipient: PrincipalHandle, _frame: CommunicationValue) {
        let connections = self
            .active
            .get(&recipient)
            .map(|connections| {
                connections
                    .iter()
                    .map(|(id, connection)| (*id, connection.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (connection_id, connection) in connections {
            if !self
                .sessions
                .get(connection_id)
                .and_then(|session| session.hosted_lease)
                .is_some_and(|lease| iota_storage::hosted_auth::verify(&lease).is_ok())
            {
                continue;
            }
            connection.delivery_ready.notify_one();
        }
    }
}

#[async_trait]
// Hosted-only centralized compatibility boundary. Decentralized ingress installs
// ConnectionGateway; both paths share key binding and scoped application cleanup.
impl web_server::MtpConnectionHandler for ClientConnectionManager {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection) {
        self.accept_until_shutdown(connection, CancellationToken::new())
            .await;
    }

    async fn accept_until_shutdown(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        shutdown: CancellationToken,
    ) {
        let sender = connection.sender.clone();
        let Ok((description, _)) =
            crate::tau_gateway::parse_description(connection.description.as_deref())
        else {
            sender.close();
            return;
        };
        let mut facts = tau::ConnectionFacts::from_mtp(&connection);
        facts.description = Some(description);
        let engine = crate::tau_gateway::hosted_admission_engine();
        let Ok(admission) = engine.admit(&facts) else {
            sender.close();
            return;
        };
        let tau::TransportAuthentication::TransportAuthenticated {
            mtp_client_id,
            public_key: key,
        } = admission.transport()
        else {
            unreachable!()
        };
        let identity = tokio::select! {
            _ = shutdown.cancelled() => { sender.close(); return; },
            identity = self.resolve_hosted_identity(*mtp_client_id, key) => identity,
        };
        let Ok(IotaConnectionIdentity::HostedClient {
            local_user,
            principal,
            auth_generation,
        }) = identity
        else {
            sender.close();
            return;
        };
        let Ok(mut session) = admission.into_session(|_, _, _| {
            Ok::<_, tau::AdmissionError>(IotaConnectionIdentity::HostedClient {
                local_user,
                principal,
                auth_generation,
            })
        }) else {
            sender.close();
            return;
        };
        if session
            .establish_transport_session()
            .and_then(|()| session.activate())
            .is_err()
        {
            sender.close();
            return;
        }
        let operation = self.run_hosted(
            connection,
            session.connection_id().as_uuid(),
            ValidatedHostedIdentity {
                local_user,
                principal,
                auth_generation,
            },
            shutdown.clone(),
        );
        tokio::pin!(operation);
        tokio::select! {
            _ = &mut operation => {},
            _ = shutdown.cancelled() => { sender.close(); operation.await; },
        }
        session.close();
    }
}

pub struct ConnectionGateway {
    engine: tau::AdmissionEngine<IotaConnectionRole>,
    clients: Arc<ClientConnectionManager>,
    peers: Arc<other_iota::PeerManager>,
}

#[cfg(test)]
mod tests;
