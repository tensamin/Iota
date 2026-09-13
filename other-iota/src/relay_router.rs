use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::relay_service::{IngressSource, RelayService};
use iota_identity::{
    AuthorityLocator, IotaNodeId, LocalNodeIdentity, PublicKeyBundle, RelayRouterId,
};
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::{LocalDeliverySink, route_outcome};

const ROUTER_PROTOCOL: &str = "tensamin-relay-router:v1";
static NEXT_ROUTER_FRAME_ID: AtomicU32 = AtomicU32::new(1);

#[async_trait]
trait RouterPeerConnection: Send + Sync {
    async fn request(&self, frame: CommunicationValue) -> Result<CommunicationValue, RouteError>;
}

type RegisteredRouterPeer = (u64, Arc<dyn RouterPeerConnection>);

#[derive(Default)]
pub struct RelayRouterService {
    peers: RwLock<HashMap<IotaNodeId, RegisteredRouterPeer>>,
    next_registration: AtomicU64,
}

impl RelayRouterService {
    pub fn has_connection(&self, node: &IotaNodeId) -> bool {
        self.peers
            .read()
            .is_ok_and(|peers| peers.contains_key(node))
    }

    fn register(&self, node: IotaNodeId, connection: Arc<dyn RouterPeerConnection>) -> u64 {
        let registration = self.next_registration.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut peers) = self.peers.write() {
            peers.insert(node, (registration, connection));
        }
        registration
    }

    fn unregister(&self, node: &IotaNodeId, registration: u64) {
        if let Ok(mut peers) = self.peers.write()
            && peers
                .get(node)
                .is_some_and(|current| current.0 == registration)
        {
            peers.remove(node);
        }
    }

    async fn forward(
        &self,
        source: &IotaNodeId,
        destination: &IotaNodeId,
        frame: CommunicationValue,
    ) -> Result<CommunicationValue, RouteError> {
        if source == destination {
            return Err(RouteError::Delivery(
                "relay router source and destination are identical".into(),
            ));
        }
        let peer = self
            .peers
            .read()
            .ok()
            .and_then(|peers| peers.get(destination).map(|peer| peer.1.clone()))
            .ok_or_else(|| RouteError::NoRoute(destination.clone()))?;
        peer.request(frame).await
    }
}

#[async_trait]
impl web_server::MtpConnectionHandler for RelayRouterService {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection) {
        if connection.auth_state != mtp::host::AuthState::Authenticated {
            return;
        }
        let Some(public_key) = connection.client_public_key.clone() else {
            return;
        };
        let Ok(node) = IotaNodeId::from_public_keys(&public_key) else {
            return;
        };
        let connection = Arc::new(connection);
        let pending = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let registration = self.register(
            node.clone(),
            Arc::new(IncomingRouterPeer {
                connection: connection.clone(),
                pending: pending.clone(),
            }),
        );
        while let Ok(frame) = connection.receive().await {
            if let Some(frame_id) = frame.id()
                && let Some(response) = pending.lock().await.remove(&frame_id)
            {
                let _ = response.send(frame);
                continue;
            }
            let Some(frame_id) = frame.id() else {
                continue;
            };
            let response = match decode_router_request(&frame) {
                Ok((destination, relay)) => match self.forward(&node, &destination, relay).await {
                    Ok(response) => response.with_id(frame_id),
                    Err(RouteError::NoRoute(_)) => {
                        CommunicationValue::new(CommunicationType::ErrorNoIota).with_id(frame_id)
                    }
                    Err(RouteError::Delivery(message)) => {
                        CommunicationValue::new(CommunicationType::ErrorInternal)
                            .with_id(frame_id)
                            .add_typed_default(DataType::ErrorMessage, DataValue::Str(message))
                    }
                },
                Err(message) => CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(frame_id)
                    .add_typed_default(DataType::ErrorMessage, DataValue::Str(message)),
            };
            let _ = connection.sender.send(&response).await;
        }
        self.unregister(&node, registration);
    }
}

struct IncomingRouterPeer {
    connection: Arc<mtp::webserver::WebMTPConnection>,
    pending:
        Arc<tokio::sync::Mutex<HashMap<u32, tokio::sync::oneshot::Sender<CommunicationValue>>>>,
}

#[async_trait]
impl RouterPeerConnection for IncomingRouterPeer {
    async fn request(
        &self,
        mut frame: CommunicationValue,
    ) -> Result<CommunicationValue, RouteError> {
        let frame_id = next_frame_id();
        frame = frame.with_id(frame_id);
        let (send, receive) = tokio::sync::oneshot::channel();
        if self.pending.lock().await.insert(frame_id, send).is_some() {
            return Err(RouteError::Delivery(
                "relay router request ID is already pending".into(),
            ));
        }
        if let Err(error) = self.connection.sender.send(&frame).await {
            self.pending.lock().await.remove(&frame_id);
            return Err(RouteError::Delivery(error.to_string()));
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), receive)
            .await
            .map_err(|_| RouteError::Delivery("relay router request timed out".into()))?
            .map_err(|_| RouteError::Delivery("relay router connection closed".into()))
    }
}

pub struct RelayRouterClient {
    router_id: RelayRouterId,
    connection: Arc<mtp::client::MTPConnection>,
    connected: AtomicBool,
    disconnected: tokio::sync::Notify,
}

#[derive(Default)]
pub struct RelayRouterSet {
    routers: RwLock<Vec<Arc<RelayRouterClient>>>,
}

impl RelayRouterSet {
    pub fn add(&self, router: Arc<RelayRouterClient>) {
        if let Ok(mut routers) = self.routers.write() {
            routers.retain(|current| current.router_id() != router.router_id());
            routers.push(router);
        }
    }
}

#[async_trait]
impl PeerRouter for RelayRouterSet {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let routers = self
            .routers
            .read()
            .map(|routers| routers.clone())
            .unwrap_or_default();
        if routers.is_empty() {
            return Ok(RouteOutcome::Retryable {
                reason: "no relay router is configured".into(),
            });
        }
        let mut last_reason = "all relay routers are unavailable".to_string();
        for router in routers {
            if !router.is_connected() {
                continue;
            }
            match router.route(destination, frame.clone()).await {
                outcome @ Ok(RouteOutcome::Accepted { .. } | RouteOutcome::Rejected { .. }) => {
                    return outcome;
                }
                Ok(RouteOutcome::Retryable { reason }) => last_reason = reason,
                Err(error) => last_reason = error.to_string(),
            }
        }
        Ok(RouteOutcome::Retryable {
            reason: last_reason,
        })
    }
}

impl RelayRouterClient {
    pub async fn connect(
        identity: LocalNodeIdentity,
        endpoint: &AuthorityLocator,
        pinned_certificate: Vec<u8>,
        router_key: PublicKeyBundle,
        relay: Arc<RelayService>,
        deliveries: Arc<dyn LocalDeliverySink>,
    ) -> Result<Arc<Self>, RouteError> {
        let router_id = RelayRouterId::from_public_keys(&router_key)
            .map_err(|error| RouteError::Delivery(error.to_string()))?;
        let config = mtp::client::ClientConfig::new(format!("https://{}/", endpoint.as_str()))
            .with_pinned_pem(pinned_certificate)
            .with_client_id(identity.node_id().mtp_authentication_hint())
            .with_description(format!("iota-router: {}", identity.node_id().as_str()));
        let connection =
            mtp::client::MTPClient::auth_connect(config, &identity.keyring(), &router_key)
                .await
                .map_err(|error| RouteError::Delivery(error.to_string()))?;
        if connection.auth_state != mtp::client::AuthState::Authenticated {
            return Err(RouteError::Delivery(
                "relay router did not complete authentication".into(),
            ));
        }
        let client = Arc::new(Self {
            router_id,
            connection: Arc::new(connection),
            connected: AtomicBool::new(true),
            disconnected: tokio::sync::Notify::new(),
        });
        let reader = client.clone();
        tokio::spawn(async move {
            while let Ok(frame) = reader.connection.receive().await {
                let outcome = relay
                    .accept_relay(
                        IngressSource::RelayRouter {
                            router_id: reader.router_id.clone(),
                        },
                        frame,
                    )
                    .await;
                let Ok(outcome) = outcome else {
                    continue;
                };
                let (response, local_deliveries) = outcome.into_parts();
                for delivery in local_deliveries {
                    deliveries.deliver(delivery.recipient, delivery.frame).await;
                }
                if let Some(response) = response {
                    let _ = reader.connection.sender.send(&response).await;
                }
            }
            reader.connected.store(false, Ordering::Release);
            reader.disconnected.notify_waiters();
        });
        Ok(client)
    }

    pub fn router_id(&self) -> &RelayRouterId {
        &self.router_id
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    pub async fn wait_disconnected(&self) {
        loop {
            let disconnected = self.disconnected.notified();
            if !self.is_connected() {
                return;
            }
            disconnected.await;
        }
    }
}

#[async_trait]
impl PeerRouter for RelayRouterClient {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let RouteDestination::Iota(destination) = destination else {
            return Ok(RouteOutcome::Retryable {
                reason: "relay router cannot route a legacy Omega destination".into(),
            });
        };
        let request = encode_router_request(destination, &frame)?;
        let response = self
            .connection
            .request(&request, None)
            .await
            .map_err(|error| RouteError::Delivery(error.to_string()))?;
        if response.is_type(CommunicationType::ErrorNoIota)
            || response.is_type(CommunicationType::ErrorInternal)
        {
            return Ok(RouteOutcome::Retryable {
                reason: response
                    .get_data(DataType::ErrorMessage)
                    .as_str()
                    .unwrap_or("relay router destination is unavailable")
                    .to_owned(),
            });
        }
        route_outcome(response)
    }
}

pub struct DirectThenRelayRouter {
    direct: Arc<dyn PeerRouter>,
    relay: Arc<dyn PeerRouter>,
}

impl DirectThenRelayRouter {
    pub fn new(direct: Arc<dyn PeerRouter>, relay: Arc<dyn PeerRouter>) -> Self {
        Self { direct, relay }
    }
}

#[async_trait]
impl PeerRouter for DirectThenRelayRouter {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        match self.direct.route(destination, frame.clone()).await {
            outcome @ Ok(RouteOutcome::Accepted { .. } | RouteOutcome::Rejected { .. }) => outcome,
            Ok(RouteOutcome::Retryable { .. }) | Err(_) => {
                self.relay.route(destination, frame).await
            }
        }
    }
}

fn encode_router_request(
    destination: &IotaNodeId,
    frame: &CommunicationValue,
) -> Result<CommunicationValue, RouteError> {
    let type_map = frame
        .type_map()
        .ok_or_else(|| RouteError::Delivery("relay frame has no type map".into()))?;
    let payload = frame
        .to_bytes()
        .map_err(|error| RouteError::Delivery(error.to_string()))?;
    Ok(CommunicationValue::new(CommunicationType::Relay)
        .with_id(next_frame_id())
        .add_typed_default(DataType::About, DataValue::Str(ROUTER_PROTOCOL.into()))
        .add_typed_default(
            DataType::Description,
            DataValue::Str(destination.as_str().into()),
        )
        .add_typed_default(
            DataType::Version,
            DataValue::Str(type_map.version.to_string()),
        )
        .add_typed_default(DataType::SecurePayload, DataValue::Bytes(payload)))
}

fn decode_router_request(
    frame: &CommunicationValue,
) -> Result<(IotaNodeId, CommunicationValue), String> {
    if !frame.is_type(CommunicationType::Relay)
        || frame.get_data(DataType::About).as_str() != Some(ROUTER_PROTOCOL)
    {
        return Err("frame is not a relay-router request".into());
    }
    let destination = frame
        .get_data(DataType::Description)
        .as_str()
        .ok_or_else(|| "relay-router destination is missing".to_string())
        .and_then(|destination| IotaNodeId::new(destination).map_err(|error| error.to_string()))?;
    let version = frame
        .get_data(DataType::Version)
        .as_str()
        .and_then(mtp::type_map::Version::parse)
        .ok_or_else(|| "relay-router type-map version is invalid".to_string())?;
    let payload = match frame.get_data(DataType::SecurePayload) {
        Some(DataValue::Bytes(payload)) => payload,
        _ => return Err("relay-router payload is missing".into()),
    };
    let relay = CommunicationValue::from_bytes_with(payload, &TypeMap::new(version))
        .map_err(|error| error.to_string())?;
    Ok((destination, relay))
}

fn next_frame_id() -> u32 {
    loop {
        let id = NEXT_ROUTER_FRAME_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}
