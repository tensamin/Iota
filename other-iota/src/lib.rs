mod http_client;
#[cfg(test)]
use http_client::certificate_to_pem;
pub use http_client::publish_omega_node_descriptor;
mod direct_router;
mod iota_resolver;
mod omega_resolver;
mod peer_manager;
mod peer_transport;
use peer_transport::prefers_inbound;
mod peer_admission;
mod relay_adapter;
use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::relay_service::{
    IngressSource, RelayOutcome, RelayService, RelayServiceError, VerifiedRelayEnvelope,
};
use iota_identity::IotaNodeId;
use iota_identity::peer_introduction::PeerTrust;
use iota_identity::{
    AuthorityId, AuthorityKind, AuthorityLocator, DiscoveredAuthority, IdentityError,
    IdentityResolver, NodeDescriptorWireV1, NodeDirectory, PrincipalDescriptorWireV1, PrincipalId,
    PrincipalStore, PublicKeyBundle, ResolutionContext, ResolvedPrincipal, UserAddress,
    UserSelector,
};
use mtp::codec::CommunicationValue;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};

pub mod introduction;
pub mod relay_router;

const FRESH_CACHE_MILLIS: i64 = 15 * 60 * 1_000;

#[async_trait]
pub trait FederationIdentityClient: Send + Sync {
    async fn discover(
        &self,
        locator: &AuthorityLocator,
    ) -> Result<DiscoveredAuthority, IdentityError>;

    async fn node_descriptor(
        &self,
        locator: &AuthorityLocator,
        path: &str,
    ) -> Result<FetchedNodeDescriptor, IdentityError>;

    async fn principal_descriptor(
        &self,
        locator: &AuthorityLocator,
        selector: &UserSelector,
    ) -> Result<PrincipalDescriptorWireV1, IdentityError>;
}

pub struct FetchedNodeDescriptor {
    pub descriptor: NodeDescriptorWireV1,
    pub tls_certificate: Option<Vec<u8>>,
}

pub struct HttpFederationIdentityClient {
    client: reqwest::Client,
    ip_bootstrap_client: Result<reqwest::Client, String>,
    allow_lan: bool,
    allow_raw_ip: bool,
    requests: tokio::sync::Semaphore,
}

pub struct RemoteIotaResolver {
    client: Arc<dyn FederationIdentityClient>,
    principals: Arc<dyn PrincipalStore>,
    nodes: Arc<dyn NodeDirectory>,
    authorities: RwLock<HashMap<AuthorityLocator, CachedIotaAuthority>>,
    discovery_freshness: std::time::Duration,
    authority_directory: Option<Arc<dyn iota_identity::AuthorityDirectory>>,
}

#[derive(Clone)]
struct CachedIotaAuthority {
    authority: DiscoveredAuthority,
    node: IotaNodeId,
    verified_at: i64,
    descriptor_revision: i64,
}

pub struct RemoteOmegaResolver {
    client: Arc<dyn FederationIdentityClient>,
    principals: Arc<dyn PrincipalStore>,
    nodes: Arc<dyn NodeDirectory>,
    authorities: RwLock<HashMap<AuthorityLocator, DiscoveredAuthority>>,
}

fn verify_key_pin(
    pin: Option<&PublicKeyBundle>,
    keys: &[PublicKeyBundle],
) -> Result<(), IdentityError> {
    let Some(pin) = pin else {
        return Ok(());
    };
    let pin = pin
        .try_as_bytes()
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    if keys.iter().any(|key| {
        key.try_as_bytes()
            .map(|candidate| candidate == pin)
            .unwrap_or(false)
    }) {
        Ok(())
    } else {
        Err(IdentityError::KeyPinMismatch)
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[async_trait]
pub trait DirectPeerConnection: Send + Sync {
    async fn send_relay(&self, frame: CommunicationValue) -> Result<RouteOutcome, RouteError>;
    fn authenticated_key(&self) -> Option<PublicKeyBundle> {
        None
    }
    fn close(&self) {}
}

type RegisteredDirectPeer = (u64, Arc<dyn DirectPeerConnection>, bool);

#[derive(Default)]
pub struct DirectPeerRouter {
    peers: RwLock<HashMap<IotaNodeId, RegisteredDirectPeer>>,
    next_registration: AtomicU64,
    manager: RwLock<Option<Weak<PeerManager>>>,
}

#[async_trait]
pub trait LocalDeliverySink: Send + Sync {
    async fn deliver(&self, recipient: iota_identity::PrincipalHandle, frame: CommunicationValue);
}

#[derive(Clone)]
enum DialState {
    Connecting,
    Finished(Result<(), RouteError>),
}

pub struct PeerManager {
    identity: iota_identity::LocalNodeIdentity,
    nodes: Arc<dyn NodeDirectory>,
    router: Arc<DirectPeerRouter>,
    relay: Arc<RelayService>,
    deliveries: Arc<dyn LocalDeliverySink>,
    shutdown: tokio_util::sync::CancellationToken,
    outgoing: std::sync::Mutex<Option<tokio::task::JoinSet<()>>>,
    outgoing_failed: AtomicBool,
    shutdown_join: tokio::sync::Mutex<(Option<tokio::task::JoinHandle<bool>>, Option<bool>)>,
    introducer: Option<Arc<dyn introduction::PeerIntroducer>>,
    authority_resolver: Option<Arc<RemoteIotaResolver>>,
    last_authentication_error: std::sync::Mutex<Option<String>>,
    dials: std::sync::Mutex<HashMap<IotaNodeId, tokio::sync::watch::Receiver<DialState>>>,
}

/// A checked directory/admission snapshot. Provisional trust is not permission
/// to activate a session, and this value alone does not prove key possession.
pub struct ValidatedPeer {
    trust: PeerTrust,
    public_key: Vec<u8>,
}

impl ValidatedPeer {
    pub fn trust(&self) -> &PeerTrust {
        &self.trust
    }
}

struct OutgoingRegistration {
    router: Arc<DirectPeerRouter>,
    node: IotaNodeId,
    generation: Option<u64>,
    connection: Arc<mtp::client::MTPConnection>,
}

struct OutgoingPeer(Arc<mtp::client::MTPConnection>, PublicKeyBundle);

struct IncomingPeer {
    connection: Arc<mtp::webserver::WebMTPConnection>,
    pending: PendingPeerResponses,
}

type PendingPeerResponses = Arc<
    std::sync::Mutex<HashMap<u32, (Arc<()>, tokio::sync::oneshot::Sender<CommunicationValue>)>>,
>;

struct PendingPeerRequest {
    pending: PendingPeerResponses,
    frame_id: u32,
    instance: Arc<()>,
}

pub struct PeerRelayAdapter {
    relay: Arc<RelayService>,
}

#[cfg(test)]
mod tests;
