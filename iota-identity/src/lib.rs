mod addresses;
mod discovery;
mod identifiers;
mod local_node;
mod principal_descriptor;
pub use principal_descriptor::verify_dual_signature;
use principal_descriptor::{push_bytes, push_optional_i64, verify_authority_signature};
mod node_descriptor;
use node_descriptor::node_descriptor_bytes;
mod resolver;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
pub use mtp::crypto::PublicKeyBundle;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub mod node_transition;
pub mod peer_introduction;

pub const FEDERATION_PROTOCOLS: [&str; 3] = ["identity-http-v1", "mtp-relay", "peer-introduction"];

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IotaNodeId(String);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelayRouterId(String);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityId(String);

#[derive(Debug)]
pub enum LocalNodeIdentityError {
    Directory {
        path: String,
        source: std::io::Error,
    },
    Storage {
        path: String,
        source: String,
    },
    Verification(String),
    InvalidIdentity(IdentityError),
}

#[derive(Clone)]
pub struct LocalNodeIdentity {
    keyring: Arc<mtp::crypto::Keyring>,
    node_id: IotaNodeId,
    authority_id: AuthorityId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    Iota,
    Omega,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityDiscoveryDocument {
    pub version: u32,
    pub service: AuthorityKind,
    pub authority_id: AuthorityId,
    pub node_id: Option<IotaNodeId>,
    pub public_key: String,
    pub protocols: Vec<String>,
    #[serde(default)]
    pub node_descriptor: Option<String>,
    #[serde(default)]
    pub direct_endpoints: Vec<AuthorityLocator>,
    #[serde(default)]
    pub relay_hints: Vec<AuthorityLocator>,
}

#[derive(Clone, Debug)]
pub struct DiscoveredAuthority {
    pub service: AuthorityKind,
    pub authority_id: AuthorityId,
    pub node_id: Option<IotaNodeId>,
    pub public_keys: PublicKeyBundle,
    pub protocols: Vec<String>,
    pub node_descriptor: Option<String>,
    pub direct_endpoints: Vec<AuthorityLocator>,
    pub relay_hints: Vec<AuthorityLocator>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId {
    pub authority: AuthorityId,
    pub user_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSelector {
    UserId(u64),
    Username(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityLocator(String);

#[derive(Clone, Debug)]
pub struct UserAddress {
    pub selector: UserSelector,
    pub public_key_pin: Option<PublicKeyBundle>,
    pub authority: Option<AuthorityLocator>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalUserId(pub i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalHandle(pub i64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalHome {
    Iota(IotaNodeId),
    LegacyOmegaIota { omega: AuthorityId, iota_id: u64 },
    Omega(AuthorityLocator),
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OfflineResolutionPolicy {
    #[default]
    RejectStale,
    AllowUnexpired {
        max_staleness: Duration,
    },
}

impl OfflineResolutionPolicy {
    pub fn allows_cached(self, resolved_at: i64, now: i64) -> bool {
        let Self::AllowUnexpired { max_staleness } = self else {
            return false;
        };
        let max_staleness = i64::try_from(max_staleness.as_millis()).unwrap_or(i64::MAX);
        now.saturating_sub(resolved_at) <= max_staleness
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolutionContext {
    pub allow_network: bool,
    pub offline_policy: OfflineResolutionPolicy,
}

#[derive(Clone, Debug)]
pub struct ResolvedPrincipal {
    pub principal: PrincipalId,
    pub handle: PrincipalHandle,
    pub username: Option<String>,
    pub public_keys: Vec<PublicKeyBundle>,
    pub home: PrincipalHome,
    pub descriptor_revision: i64,
    pub valid_until: Option<i64>,
    pub resolved_at: i64,
}

impl ResolvedPrincipal {
    pub fn is_valid_at(&self, timestamp: i64) -> bool {
        self.valid_until
            .is_none_or(|valid_until| valid_until > timestamp)
    }
}

#[derive(Clone, Debug)]
pub struct PrincipalDescriptor {
    pub principal: PrincipalId,
    pub authority_kind: AuthorityKind,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub public_keys: Vec<PublicKeyBundle>,
    pub home: PrincipalHome,
    pub revision: i64,
    pub valid_until: Option<i64>,
    pub issued_at: i64,
}

#[derive(Clone, Debug)]
pub struct SignedPrincipalDescriptor {
    pub descriptor: PrincipalDescriptor,
    pub authority_signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrincipalDescriptorWireV1 {
    pub version: u32,
    pub principal: PrincipalId,
    pub authority_kind: AuthorityKind,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub public_keys: Vec<String>,
    pub home: PrincipalHome,
    pub revision: i64,
    pub valid_until: Option<i64>,
    pub issued_at: i64,
    pub authority_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_node: Option<NodeDescriptorWireV1>,
}

#[derive(Clone, Debug)]
pub struct VerifiedPrincipalDescriptor {
    descriptor: PrincipalDescriptor,
    resolved_at: i64,
}

pub trait LocalDescriptorPublisher: Send + Sync {
    fn principal_descriptor(
        &self,
        user: LocalUserId,
    ) -> Result<SignedPrincipalDescriptor, IdentityError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalUserDescriptor {
    pub id: LocalUserId,
    pub username: String,
    pub display_name: Option<String>,
    pub public_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedHostedIdentity {
    pub local_user: LocalUserId,
    pub principal: PrincipalHandle,
    pub auth_generation: i64,
}

/// Application-issued lease, never a credential supplied by a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedAuthorizationLease {
    pub connection_id: String,
    pub server_instance: String,
    pub identity: ValidatedHostedIdentity,
}

pub trait LocalUserStore: Send + Sync {
    fn get_local_user(&self, id: LocalUserId)
    -> Result<Option<LocalUserDescriptor>, IdentityError>;

    fn get_local_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<LocalUserDescriptor>, IdentityError>;

    fn is_hosted_here(&self, id: LocalUserId) -> Result<bool, IdentityError>;

    fn local_user_for_principal(
        &self,
        principal: PrincipalHandle,
    ) -> Result<Option<LocalUserId>, IdentityError>;

    fn principal_for_local_user(
        &self,
        user: LocalUserId,
    ) -> Result<Option<PrincipalHandle>, IdentityError>;
}

pub trait PrincipalStore: Send + Sync {
    fn get_principal(
        &self,
        handle: PrincipalHandle,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError>;

    fn get_by_canonical_id(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError>;

    fn get_by_username(
        &self,
        authority: &AuthorityId,
        username: &str,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError>;

    fn upsert_remote_descriptor(
        &self,
        descriptor: &VerifiedPrincipalDescriptor,
    ) -> Result<PrincipalHandle, IdentityError>;

    fn signing_keys(&self, principal: &PrincipalId) -> Result<Vec<PublicKeyBundle>, IdentityError>;
}

#[derive(Clone, Debug)]
pub struct ResolvedNodeIdentity {
    pub node: IotaNodeId,
    pub public_keys: Vec<PublicKeyBundle>,
    pub descriptor_revision: i64,
    pub valid_until: Option<i64>,
    pub direct_endpoints: Vec<AuthorityLocator>,
    pub relay_hints: Vec<AuthorityLocator>,
    pub last_successful_endpoint: Option<AuthorityLocator>,
    pub resolved_at: i64,
}

#[derive(Clone, Debug)]
pub struct NodeDescriptor {
    pub node: IotaNodeId,
    pub public_keys: PublicKeyBundle,
    pub direct_endpoints: Vec<AuthorityLocator>,
    pub relay_hints: Vec<AuthorityLocator>,
    pub revision: i64,
    pub valid_until: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SignedNodeDescriptor {
    pub descriptor: NodeDescriptor,
    pub node_signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDescriptorWireV1 {
    pub version: u32,
    pub node: IotaNodeId,
    pub public_key: String,
    pub direct_endpoints: Vec<AuthorityLocator>,
    pub relay_hints: Vec<AuthorityLocator>,
    pub revision: i64,
    pub valid_until: Option<i64>,
    pub node_signature: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedNodeDescriptor {
    descriptor: NodeDescriptor,
    resolved_at: i64,
}

#[async_trait]
pub trait NodeIdentityResolver: Send + Sync {
    async fn resolve_node(&self, node: &IotaNodeId) -> Result<ResolvedNodeIdentity, IdentityError>;
}

/// Verified discovery provenance. A locator cannot silently change authority or node.
pub trait AuthorityDirectory: Send + Sync {
    fn record_verified_iota(
        &self,
        locator: &AuthorityLocator,
        authority: &AuthorityId,
        node: &IotaNodeId,
        verified_at: i64,
    ) -> Result<(), IdentityError>;

    fn locators_for(&self, authority: &AuthorityId)
    -> Result<Vec<AuthorityLocator>, IdentityError>;
}

pub trait NodeDirectory: NodeIdentityResolver {
    /// None selects established-descriptor-only policy. Admission-aware stores
    /// must return an error for expired or revoked candidates, never fall back.
    fn peer_admission(
        &self,
        _node: &IotaNodeId,
        _key: &PublicKeyBundle,
        _now: i64,
    ) -> Result<Option<peer_introduction::PeerTrust>, IdentityError> {
        Ok(None)
    }

    fn promote_peer(
        &self,
        _trust: &peer_introduction::PeerTrust,
        _key: &PublicKeyBundle,
        _now: i64,
    ) -> Result<Option<peer_introduction::PeerTrust>, IdentityError> {
        Ok(None)
    }

    fn revoke_peer_admission(&self, _node: &IotaNodeId) -> Result<(), IdentityError> {
        Ok(())
    }

    fn upsert_node_descriptor(
        &self,
        descriptor: &VerifiedNodeDescriptor,
    ) -> Result<(), IdentityError>;

    fn pin_endpoint(
        &self,
        endpoint: &AuthorityLocator,
        node: &IotaNodeId,
        now: i64,
    ) -> Result<(), IdentityError>;

    fn pinned_node(&self, endpoint: &AuthorityLocator)
    -> Result<Option<IotaNodeId>, IdentityError>;

    fn pin_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
        certificate: &[u8],
    ) -> Result<(), IdentityError>;

    fn pinned_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<Vec<u8>>, IdentityError>;

    fn record_successful_endpoint(
        &self,
        node: &IotaNodeId,
        endpoint: &AuthorityLocator,
    ) -> Result<(), IdentityError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidIdentifier(String),
    NotFound,
    Unavailable(String),
    InvalidDescriptor(String),
    KeyPinMismatch,
    Storage(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(message)
            | Self::Unavailable(message)
            | Self::InvalidDescriptor(message)
            | Self::Storage(message) => formatter.write_str(message),
            Self::NotFound => formatter.write_str("principal was not found"),
            Self::KeyPinMismatch => formatter.write_str("principal key does not match address pin"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[async_trait]
pub trait IdentityResolver: Send + Sync {
    async fn resolve_address(
        &self,
        address: &UserAddress,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError>;

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError>;

    async fn resolve_principal_with_context(
        &self,
        principal: &PrincipalId,
        _context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        self.resolve_principal(principal).await
    }

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError>;
}

pub struct CompositeIdentityResolver {
    resolvers: Vec<Arc<dyn IdentityResolver>>,
}

#[cfg(test)]
mod tests;
