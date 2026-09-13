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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IotaNodeId(String);

impl IotaNodeId {
    const PREFIX: &'static str = "iota:v1:";

    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let Some(fingerprint) = value.strip_prefix(Self::PREFIX) else {
            return Err(IdentityError::InvalidIdentifier(
                "Iota node ID has an unsupported format".into(),
            ));
        };
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IdentityError::InvalidIdentifier(
                "Iota node ID fingerprint must be 32 hexadecimal bytes".into(),
            ));
        }
        Ok(Self(format!(
            "{}{}",
            Self::PREFIX,
            fingerprint.to_ascii_lowercase()
        )))
    }

    pub fn from_public_keys(keys: &PublicKeyBundle) -> Result<Self, IdentityError> {
        let bytes = keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        let fingerprint = mtp::crypto::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::new(format!("{}{fingerprint}", Self::PREFIX))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn mtp_authentication_hint(&self) -> u64 {
        let fingerprint = self.0.strip_prefix(Self::PREFIX).unwrap_or_default();
        u64::from_str_radix(&fingerprint[..fingerprint.len().min(16)], 16).unwrap_or_default()
            | (1_u64 << 63)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelayRouterId(String);

impl RelayRouterId {
    const PREFIX: &'static str = "router:v1:";

    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let Some(fingerprint) = value.strip_prefix(Self::PREFIX) else {
            return Err(IdentityError::InvalidIdentifier(
                "relay router ID has an unsupported format".into(),
            ));
        };
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IdentityError::InvalidIdentifier(
                "relay router ID fingerprint must be 32 hexadecimal bytes".into(),
            ));
        }
        Ok(Self(format!(
            "{}{}",
            Self::PREFIX,
            fingerprint.to_ascii_lowercase()
        )))
    }

    pub fn from_public_keys(keys: &PublicKeyBundle) -> Result<Self, IdentityError> {
        let bytes = keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        let fingerprint = mtp::crypto::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::new(format!("{}{fingerprint}", Self::PREFIX))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityId(String);

impl AuthorityId {
    pub fn new(fingerprint: impl Into<String>) -> Result<Self, IdentityError> {
        let fingerprint = fingerprint.into();
        if fingerprint.trim().is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty authority ID".into(),
            ));
        }
        Ok(Self(fingerprint))
    }

    pub fn omega_legacy(locator: &str) -> Result<Self, IdentityError> {
        let locator = locator.trim().to_ascii_lowercase();
        if locator.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty Omega authority locator".into(),
            ));
        }
        Ok(Self(format!("omega:{locator}")))
    }

    pub fn for_omega(keys: &PublicKeyBundle) -> Result<Self, IdentityError> {
        let bytes = keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        let fingerprint = mtp::crypto::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::new(format!("omega-key:{fingerprint}"))
    }

    pub fn for_iota(node: &IotaNodeId) -> Self {
        Self(format!("authority:{}", node.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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

impl fmt::Display for LocalNodeIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory { path, source } => {
                write!(
                    formatter,
                    "failed to create identity directory {path}: {source}"
                )
            }
            Self::Storage { path, source } => {
                write!(formatter, "failed to access node identity {path}: {source}")
            }
            Self::Verification(error) => formatter.write_str(error),
            Self::InvalidIdentity(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LocalNodeIdentityError {}

#[derive(Clone)]
pub struct LocalNodeIdentity {
    keyring: Arc<mtp::crypto::Keyring>,
    node_id: IotaNodeId,
    authority_id: AuthorityId,
}

impl fmt::Debug for LocalNodeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalNodeIdentity")
            .field("node_id", &self.node_id)
            .field("authority_id", &self.authority_id)
            .finish_non_exhaustive()
    }
}

impl LocalNodeIdentity {
    pub fn load_or_create(
        path: &Path,
        legacy: Option<mtp::crypto::Keyring>,
    ) -> Result<Self, LocalNodeIdentityError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|source| LocalNodeIdentityError::Directory {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let keyring = match mtp::files::load_keyring_raw(path) {
            Ok(keyring) => keyring,
            Err(mtp::files::FileError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                let keyring = legacy.unwrap_or_else(mtp::crypto::Keyring::generate);
                Self::save_keyring_verified(&keyring, path)?;
                keyring
            }
            Err(error) => {
                return Err(LocalNodeIdentityError::Storage {
                    path: path.display().to_string(),
                    source: error.to_string(),
                });
            }
        };
        Self::from_keyring(keyring)
    }

    pub fn from_keyring(keyring: mtp::crypto::Keyring) -> Result<Self, LocalNodeIdentityError> {
        let node_id = IotaNodeId::from_public_keys(&keyring.public_key_bundle())
            .map_err(LocalNodeIdentityError::InvalidIdentity)?;
        let authority_id = AuthorityId::for_iota(&node_id);
        Ok(Self {
            keyring: Arc::new(keyring),
            node_id,
            authority_id,
        })
    }

    pub fn save_keyring_verified(
        keyring: &mtp::crypto::Keyring,
        path: &Path,
    ) -> Result<(), LocalNodeIdentityError> {
        mtp::files::save_keyring_raw(keyring, path).map_err(|error| {
            LocalNodeIdentityError::Storage {
                path: path.display().to_string(),
                source: error.to_string(),
            }
        })?;
        let persisted = mtp::files::load_keyring_raw(path).map_err(|error| {
            LocalNodeIdentityError::Storage {
                path: path.display().to_string(),
                source: error.to_string(),
            }
        })?;
        let expected = keyring
            .try_to_bytes()
            .map_err(|error| LocalNodeIdentityError::Verification(error.to_string()))?;
        let actual = persisted
            .try_to_bytes()
            .map_err(|error| LocalNodeIdentityError::Verification(error.to_string()))?;
        if expected != actual {
            return Err(LocalNodeIdentityError::Verification(
                "persisted keyring differs from requested node identity".into(),
            ));
        }
        Ok(())
    }

    pub fn keyring(&self) -> Arc<mtp::crypto::Keyring> {
        self.keyring.clone()
    }

    pub fn public_keys(&self) -> PublicKeyBundle {
        self.keyring.public_key_bundle()
    }

    pub fn node_id(&self) -> &IotaNodeId {
        &self.node_id
    }

    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }
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

impl AuthorityDiscoveryDocument {
    pub fn verify(self) -> Result<DiscoveredAuthority, IdentityError> {
        if self.version != 1 {
            return Err(IdentityError::InvalidDescriptor(
                "authority discovery version is unsupported".into(),
            ));
        }
        if self.protocols.iter().any(|protocol| protocol.is_empty()) {
            return Err(IdentityError::InvalidDescriptor(
                "authority discovery contains an empty protocol name".into(),
            ));
        }
        let public_keys = PublicKeyBundle::from_base64(&self.public_key)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        match self.service {
            AuthorityKind::Iota => {
                let node = self.node_id.as_ref().ok_or_else(|| {
                    IdentityError::InvalidDescriptor("Iota discovery has no node ID".into())
                })?;
                let derived_node = IotaNodeId::from_public_keys(&public_keys)?;
                if node != &derived_node || self.authority_id != AuthorityId::for_iota(node) {
                    return Err(IdentityError::InvalidDescriptor(
                        "Iota discovery identity does not match its public key".into(),
                    ));
                }
            }
            AuthorityKind::Omega if self.node_id.is_some() => {
                return Err(IdentityError::InvalidDescriptor(
                    "Omega discovery must not claim an Iota node ID".into(),
                ));
            }
            AuthorityKind::Omega => {
                if self.authority_id != AuthorityId::for_omega(&public_keys)? {
                    return Err(IdentityError::InvalidDescriptor(
                        "Omega discovery identity does not match its public key".into(),
                    ));
                }
            }
        }
        Ok(DiscoveredAuthority {
            service: self.service,
            authority_id: self.authority_id,
            node_id: self.node_id,
            public_keys,
            protocols: self.protocols,
            node_descriptor: self.node_descriptor,
            direct_endpoints: self.direct_endpoints,
            relay_hints: self.relay_hints,
        })
    }
}

impl AuthorityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iota => "iota",
            Self::Omega => "omega",
        }
    }
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

impl AuthorityLocator {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty authority locator".into(),
            ));
        }
        if value.contains('@') || value.contains('/') || value.chars().any(char::is_whitespace) {
            return Err(IdentityError::InvalidIdentifier(
                "invalid authority locator".into(),
            ));
        }

        if let Ok(address) = value.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err(IdentityError::InvalidIdentifier(
                    "authority port must not be zero".into(),
                ));
            }
            return Ok(Self(address.to_string()));
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            return Ok(Self(address.to_string()));
        }
        if let Some(address) = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            let address = address
                .parse::<Ipv6Addr>()
                .map_err(|_| IdentityError::InvalidIdentifier("invalid IPv6 authority".into()))?;
            return Ok(Self(format!("[{address}]")));
        }

        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port.parse::<u16>().map_err(|_| {
                    IdentityError::InvalidIdentifier("invalid authority port".into())
                })?;
                if port == 0 {
                    return Err(IdentityError::InvalidIdentifier(
                        "authority port must not be zero".into(),
                    ));
                }
                (host, Some(port))
            }
            Some(_) => {
                return Err(IdentityError::InvalidIdentifier(
                    "IPv6 authorities must use brackets".into(),
                ));
            }
            None => (value, None),
        };
        if !valid_domain(host) {
            return Err(IdentityError::InvalidIdentifier(
                "invalid authority domain".into(),
            ));
        }

        let host = host.to_ascii_lowercase();
        Ok(Self(match port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_ip_literal(&self) -> bool {
        self.0.parse::<SocketAddr>().is_ok()
            || self.0.parse::<IpAddr>().is_ok()
            || self
                .0
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .is_some_and(|value| value.parse::<Ipv6Addr>().is_ok())
    }
}

#[derive(Clone, Debug)]
pub struct UserAddress {
    pub selector: UserSelector,
    pub public_key_pin: Option<PublicKeyBundle>,
    pub authority: Option<AuthorityLocator>,
}

impl UserAddress {
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        value.parse()
    }
}

impl FromStr for UserAddress {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty user address".into(),
            ));
        }
        if value.matches('@').count() > 1 {
            return Err(IdentityError::InvalidIdentifier(
                "user address contains multiple authority delimiters".into(),
            ));
        }

        let (local, authority) = match value.split_once('@') {
            Some((local, authority)) => {
                if authority.is_empty() {
                    return Err(IdentityError::InvalidIdentifier(
                        "empty authority locator".into(),
                    ));
                }
                (local, Some(AuthorityLocator::new(authority)?))
            }
            None => (value, None),
        };
        let (selector, public_key_pin) = match local.split_once("::") {
            Some((selector, pin)) => {
                if pin.is_empty() {
                    return Err(IdentityError::InvalidIdentifier(
                        "empty public-key pin".into(),
                    ));
                }
                let pin = PublicKeyBundle::from_base64(pin).map_err(|_| {
                    IdentityError::InvalidIdentifier("invalid public-key pin".into())
                })?;
                (selector, Some(pin))
            }
            None => (local, None),
        };
        if selector.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty user selector".into(),
            ));
        }
        if selector
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '@' | ':'))
        {
            return Err(IdentityError::InvalidIdentifier(
                "invalid user selector".into(),
            ));
        }

        let selector = if selector.bytes().all(|byte| byte.is_ascii_digit()) {
            UserSelector::UserId(selector.parse::<u64>().map_err(|_| {
                IdentityError::InvalidIdentifier("numeric user ID is out of range".into())
            })?)
        } else {
            UserSelector::Username(selector.into())
        };

        Ok(Self {
            selector,
            public_key_pin,
            authority,
        })
    }
}

fn valid_domain(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
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

impl SignedPrincipalDescriptor {
    pub fn to_wire_v1(&self) -> Result<PrincipalDescriptorWireV1, IdentityError> {
        Ok(PrincipalDescriptorWireV1 {
            version: 1,
            principal: self.descriptor.principal.clone(),
            authority_kind: self.descriptor.authority_kind,
            username: self.descriptor.username.clone(),
            display_name: self.descriptor.display_name.clone(),
            public_keys: self
                .descriptor
                .public_keys
                .iter()
                .map(|key| {
                    key.try_to_base64()
                        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            home: self.descriptor.home.clone(),
            revision: self.descriptor.revision,
            valid_until: self.descriptor.valid_until,
            issued_at: self.descriptor.issued_at,
            authority_signature: STANDARD.encode(&self.authority_signature),
            home_node: None,
        })
    }

    pub fn sign(
        descriptor: PrincipalDescriptor,
        authority: &mtp::crypto::Keyring,
    ) -> Result<Self, IdentityError> {
        use mtp::crypto::SignatureScheme;

        validate_principal_descriptor(&descriptor, descriptor.issued_at)?;
        let signer = mtp::crypto::DualSigner::new(
            &authority.sig_cl_secret_key,
            &authority.sig_pq_secret_key,
            &authority.sig_pq_public_key,
        )
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        let authority_signature = signer
            .sign(&principal_descriptor_bytes(&descriptor)?)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(Self {
            descriptor,
            authority_signature,
        })
    }

    pub fn verify(
        self,
        expected_authority: &AuthorityId,
        authority_keys: &PublicKeyBundle,
        current_revision: Option<i64>,
        now: i64,
    ) -> Result<VerifiedPrincipalDescriptor, IdentityError> {
        if &self.descriptor.principal.authority != expected_authority {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor authority mismatch".into(),
            ));
        }
        validate_principal_descriptor(&self.descriptor, now)?;
        if current_revision.is_some_and(|revision| revision > self.descriptor.revision) {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor revision is stale".into(),
            ));
        }
        verify_authority_signature(
            authority_keys,
            &principal_descriptor_bytes(&self.descriptor)?,
            &self.authority_signature,
        )?;
        if self.descriptor.authority_kind == AuthorityKind::Iota {
            let PrincipalHome::Iota(home) = &self.descriptor.home else {
                return Err(IdentityError::InvalidDescriptor(
                    "Iota principal descriptor has no Iota home".into(),
                ));
            };
            let signer_node = IotaNodeId::from_public_keys(authority_keys)?;
            if home != &signer_node || expected_authority != &AuthorityId::for_iota(&signer_node) {
                return Err(IdentityError::InvalidDescriptor(
                    "Iota principal descriptor signer does not match its authority".into(),
                ));
            }
        }
        Ok(VerifiedPrincipalDescriptor {
            descriptor: self.descriptor,
            resolved_at: now,
        })
    }
}

impl PrincipalDescriptorWireV1 {
    pub fn with_home_node(mut self, home_node: NodeDescriptorWireV1) -> Self {
        self.home_node = Some(home_node);
        self
    }

    pub fn parse(self) -> Result<SignedPrincipalDescriptor, IdentityError> {
        if self.version != 1 {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor wire version is unsupported".into(),
            ));
        }
        let public_keys = self
            .public_keys
            .into_iter()
            .map(|key| {
                PublicKeyBundle::from_base64(&key)
                    .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authority_signature = STANDARD
            .decode(self.authority_signature)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(SignedPrincipalDescriptor {
            descriptor: PrincipalDescriptor {
                principal: self.principal,
                authority_kind: self.authority_kind,
                username: self.username,
                display_name: self.display_name,
                public_keys,
                home: self.home,
                revision: self.revision,
                valid_until: self.valid_until,
                issued_at: self.issued_at,
            },
            authority_signature,
        })
    }
}

pub trait LocalDescriptorPublisher: Send + Sync {
    fn principal_descriptor(
        &self,
        user: LocalUserId,
    ) -> Result<SignedPrincipalDescriptor, IdentityError>;
}

impl VerifiedPrincipalDescriptor {
    pub fn from_trusted_authority(descriptor: PrincipalDescriptor) -> Result<Self, IdentityError> {
        let resolved_at = descriptor.issued_at;
        validate_principal_descriptor(&descriptor, resolved_at)?;
        Ok(Self {
            descriptor,
            resolved_at,
        })
    }

    pub fn descriptor(&self) -> &PrincipalDescriptor {
        &self.descriptor
    }

    pub fn into_descriptor(self) -> PrincipalDescriptor {
        self.descriptor
    }

    pub fn resolved_at(&self) -> i64 {
        self.resolved_at
    }
}

fn validate_principal_descriptor(
    descriptor: &PrincipalDescriptor,
    now: i64,
) -> Result<(), IdentityError> {
    if descriptor.revision < 0 {
        return Err(IdentityError::InvalidDescriptor(
            "principal descriptor revision is negative".into(),
        ));
    }
    if descriptor.public_keys.is_empty() {
        return Err(IdentityError::InvalidDescriptor(
            "principal descriptor contains no signing keys".into(),
        ));
    }
    for key in &descriptor.public_keys {
        key.validate()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    }
    if descriptor
        .valid_until
        .is_some_and(|valid_until| valid_until <= now)
    {
        return Err(IdentityError::InvalidDescriptor(
            "principal descriptor is expired".into(),
        ));
    }
    Ok(())
}

fn verify_authority_signature(
    keys: &PublicKeyBundle,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    const ED25519_SIGNATURE_LENGTH: usize = 64;
    let (classical, post_quantum) = signature
        .split_at_checked(ED25519_SIGNATURE_LENGTH)
        .ok_or_else(|| {
            IdentityError::InvalidDescriptor("authority signature is truncated".into())
        })?;
    mtp::crypto::verify_ed25519(&keys.sig_cl_public_key, payload, classical)
        .and_then(|_| mtp::crypto::verify_ml_dsa(&keys.sig_pq_public_key, payload, post_quantum))
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
}

pub fn verify_dual_signature(
    keys: &PublicKeyBundle,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    verify_authority_signature(keys, payload, signature)
}

fn principal_descriptor_bytes(descriptor: &PrincipalDescriptor) -> Result<Vec<u8>, IdentityError> {
    let mut bytes = b"tensamin-principal-descriptor:v1".to_vec();
    push_bytes(
        &mut bytes,
        descriptor.principal.authority.as_str().as_bytes(),
    )?;
    bytes.extend_from_slice(&descriptor.principal.user_id.to_be_bytes());
    bytes.push(match descriptor.authority_kind {
        AuthorityKind::Iota => 1,
        AuthorityKind::Omega => 2,
    });
    push_optional_string(&mut bytes, descriptor.username.as_deref())?;
    push_optional_string(&mut bytes, descriptor.display_name.as_deref())?;
    bytes.extend_from_slice(&descriptor.revision.to_be_bytes());
    push_optional_i64(&mut bytes, descriptor.valid_until);
    bytes.extend_from_slice(&descriptor.issued_at.to_be_bytes());
    match &descriptor.home {
        PrincipalHome::Iota(node) => {
            bytes.push(1);
            push_bytes(&mut bytes, node.as_str().as_bytes())?;
        }
        PrincipalHome::LegacyOmegaIota { omega, iota_id } => {
            bytes.push(2);
            push_bytes(&mut bytes, omega.as_str().as_bytes())?;
            bytes.extend_from_slice(&iota_id.to_be_bytes());
        }
        PrincipalHome::Omega(locator) => {
            bytes.push(3);
            push_bytes(&mut bytes, locator.as_str().as_bytes())?;
        }
        PrincipalHome::Unknown => bytes.push(4),
    }
    let key_count = u32::try_from(descriptor.public_keys.len()).map_err(|_| {
        IdentityError::InvalidDescriptor("principal descriptor has too many keys".into())
    })?;
    bytes.extend_from_slice(&key_count.to_be_bytes());
    for key in &descriptor.public_keys {
        push_bytes(
            &mut bytes,
            &key.try_as_bytes()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
        )?;
    }
    Ok(bytes)
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), IdentityError> {
    let length = u32::try_from(value.len())
        .map_err(|_| IdentityError::InvalidDescriptor("descriptor field is too large".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), IdentityError> {
    match value {
        Some(value) => {
            output.push(1);
            push_bytes(output, value.as_bytes())
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

fn push_optional_i64(output: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalUserDescriptor {
    pub id: LocalUserId,
    pub username: String,
    pub display_name: Option<String>,
    pub public_key: String,
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

impl SignedNodeDescriptor {
    pub fn to_wire_v1(&self) -> Result<NodeDescriptorWireV1, IdentityError> {
        Ok(NodeDescriptorWireV1 {
            version: 1,
            node: self.descriptor.node.clone(),
            public_key: self
                .descriptor
                .public_keys
                .try_to_base64()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
            direct_endpoints: self.descriptor.direct_endpoints.clone(),
            relay_hints: self.descriptor.relay_hints.clone(),
            revision: self.descriptor.revision,
            valid_until: self.descriptor.valid_until,
            node_signature: STANDARD.encode(&self.node_signature),
        })
    }

    pub fn sign(
        descriptor: NodeDescriptor,
        identity: &LocalNodeIdentity,
    ) -> Result<Self, IdentityError> {
        use mtp::crypto::SignatureScheme;

        validate_node_descriptor(&descriptor, 0)?;
        if descriptor.node != *identity.node_id()
            || descriptor
                .public_keys
                .try_as_bytes()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?
                != identity
                    .public_keys()
                    .try_as_bytes()
                    .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?
        {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor does not match local identity".into(),
            ));
        }
        let keyring = identity.keyring();
        let signer = mtp::crypto::DualSigner::new(
            &keyring.sig_cl_secret_key,
            &keyring.sig_pq_secret_key,
            &keyring.sig_pq_public_key,
        )
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        let node_signature = signer
            .sign(&node_descriptor_bytes(&descriptor)?)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(Self {
            descriptor,
            node_signature,
        })
    }

    pub fn verify(
        self,
        current_revision: Option<i64>,
        now: i64,
    ) -> Result<VerifiedNodeDescriptor, IdentityError> {
        validate_node_descriptor(&self.descriptor, now)?;
        if current_revision.is_some_and(|revision| revision > self.descriptor.revision) {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor revision is stale".into(),
            ));
        }
        if IotaNodeId::from_public_keys(&self.descriptor.public_keys)? != self.descriptor.node {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor key does not match node ID".into(),
            ));
        }
        verify_authority_signature(
            &self.descriptor.public_keys,
            &node_descriptor_bytes(&self.descriptor)?,
            &self.node_signature,
        )?;
        Ok(VerifiedNodeDescriptor {
            descriptor: self.descriptor,
            resolved_at: now,
        })
    }
}

impl NodeDescriptorWireV1 {
    pub fn parse(self) -> Result<SignedNodeDescriptor, IdentityError> {
        if self.version != 1 {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor wire version is unsupported".into(),
            ));
        }
        Ok(SignedNodeDescriptor {
            descriptor: NodeDescriptor {
                node: self.node,
                public_keys: PublicKeyBundle::from_base64(&self.public_key)
                    .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
                direct_endpoints: self.direct_endpoints,
                relay_hints: self.relay_hints,
                revision: self.revision,
                valid_until: self.valid_until,
            },
            node_signature: STANDARD
                .decode(self.node_signature)
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
        })
    }
}

impl VerifiedNodeDescriptor {
    pub fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }

    pub fn into_descriptor(self) -> NodeDescriptor {
        self.descriptor
    }

    pub fn resolved_at(&self) -> i64 {
        self.resolved_at
    }
}

fn validate_node_descriptor(descriptor: &NodeDescriptor, now: i64) -> Result<(), IdentityError> {
    if descriptor.revision < 0 {
        return Err(IdentityError::InvalidDescriptor(
            "node descriptor revision is negative".into(),
        ));
    }
    descriptor
        .public_keys
        .validate()
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    if descriptor
        .valid_until
        .is_some_and(|valid_until| valid_until <= now)
    {
        return Err(IdentityError::InvalidDescriptor(
            "node descriptor is expired".into(),
        ));
    }
    Ok(())
}

fn node_descriptor_bytes(descriptor: &NodeDescriptor) -> Result<Vec<u8>, IdentityError> {
    let mut bytes = b"tensamin-node-descriptor:v1".to_vec();
    push_bytes(&mut bytes, descriptor.node.as_str().as_bytes())?;
    push_bytes(
        &mut bytes,
        &descriptor
            .public_keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
    )?;
    bytes.extend_from_slice(&descriptor.revision.to_be_bytes());
    push_optional_i64(&mut bytes, descriptor.valid_until);
    push_locators(&mut bytes, &descriptor.direct_endpoints)?;
    push_locators(&mut bytes, &descriptor.relay_hints)?;
    Ok(bytes)
}

fn push_locators(output: &mut Vec<u8>, locators: &[AuthorityLocator]) -> Result<(), IdentityError> {
    let count = u32::try_from(locators.len())
        .map_err(|_| IdentityError::InvalidDescriptor("too many node endpoints".into()))?;
    output.extend_from_slice(&count.to_be_bytes());
    for locator in locators {
        push_bytes(output, locator.as_str().as_bytes())?;
    }
    Ok(())
}

#[async_trait]
pub trait NodeIdentityResolver: Send + Sync {
    async fn resolve_node(&self, node: &IotaNodeId) -> Result<ResolvedNodeIdentity, IdentityError>;
}

pub trait NodeDirectory: NodeIdentityResolver {
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

impl CompositeIdentityResolver {
    pub fn new(resolvers: Vec<Arc<dyn IdentityResolver>>) -> Result<Self, IdentityError> {
        if resolvers.is_empty() {
            return Err(IdentityError::Unavailable(
                "identity resolver chain is empty".into(),
            ));
        }
        Ok(Self { resolvers })
    }
}

#[async_trait]
impl IdentityResolver for CompositeIdentityResolver {
    async fn resolve_address(
        &self,
        address: &UserAddress,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        for resolver in &self.resolvers {
            match resolver.resolve_address(address, context).await {
                Ok(resolved) => return Ok(resolved),
                Err(IdentityError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Err(IdentityError::NotFound)
    }

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        for resolver in &self.resolvers {
            match resolver.resolve_principal(principal).await {
                Ok(resolved) => return Ok(resolved),
                Err(IdentityError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Err(IdentityError::NotFound)
    }

    async fn resolve_principal_with_context(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        for resolver in &self.resolvers {
            match resolver
                .resolve_principal_with_context(principal, context)
                .await
            {
                Ok(resolved) => return Ok(resolved),
                Err(IdentityError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Err(IdentityError::NotFound)
    }

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        for resolver in &self.resolvers {
            match resolver.signing_keys(principal, context).await {
                Ok(keys) => return Ok(keys),
                Err(IdentityError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Err(IdentityError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_scopes_equal_numeric_user_ids() {
        let first = PrincipalId {
            authority: AuthorityId::new("omega:first").unwrap(),
            user_id: 7,
        };
        let second = PrincipalId {
            authority: AuthorityId::new("omega:second").unwrap(),
            user_id: 7,
        };
        assert_ne!(first, second);
    }

    #[test]
    fn signed_iota_descriptor_verifies_authority_revision_and_expiry() {
        let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let user = mtp::crypto::Keyring::generate();
        let descriptor = PrincipalDescriptor {
            principal: PrincipalId {
                authority: authority.authority_id().clone(),
                user_id: 7,
            },
            authority_kind: AuthorityKind::Iota,
            username: Some("alice".into()),
            display_name: None,
            public_keys: vec![user.public_key_bundle()],
            home: PrincipalHome::Iota(authority.node_id().clone()),
            revision: 3,
            valid_until: Some(200),
            issued_at: 100,
        };
        let signed = SignedPrincipalDescriptor::sign(descriptor, &authority.keyring()).unwrap();

        let verified = signed
            .clone()
            .verify(
                authority.authority_id(),
                &authority.public_keys(),
                Some(3),
                150,
            )
            .unwrap();
        assert_eq!(verified.descriptor().principal.user_id, 7);
        assert_eq!(verified.resolved_at(), 150);
        assert!(
            signed
                .clone()
                .verify(
                    authority.authority_id(),
                    &authority.public_keys(),
                    Some(4),
                    150,
                )
                .is_err()
        );
        assert!(
            signed
                .verify(
                    authority.authority_id(),
                    &authority.public_keys(),
                    None,
                    200,
                )
                .is_err()
        );
    }

    #[test]
    fn principal_descriptor_wire_round_trip_preserves_signed_binary_meaning() {
        let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let signed = SignedPrincipalDescriptor::sign(
            PrincipalDescriptor {
                principal: PrincipalId {
                    authority: authority.authority_id().clone(),
                    user_id: 7,
                },
                authority_kind: AuthorityKind::Iota,
                username: Some("alice".into()),
                display_name: Some("Alice".into()),
                public_keys: vec![mtp::crypto::Keyring::generate().public_key_bundle()],
                home: PrincipalHome::Iota(authority.node_id().clone()),
                revision: 4,
                valid_until: Some(500),
                issued_at: 100,
            },
            &authority.keyring(),
        )
        .unwrap();
        let wire = signed.to_wire_v1().unwrap();
        let json = serde_json::to_vec(&wire).unwrap();
        let parsed: PrincipalDescriptorWireV1 = serde_json::from_slice(&json).unwrap();
        let verified = parsed
            .parse()
            .unwrap()
            .verify(
                authority.authority_id(),
                &authority.public_keys(),
                None,
                200,
            )
            .unwrap();
        assert_eq!(verified.descriptor().revision, 4);
        assert_eq!(verified.descriptor().display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn descriptor_signature_rejects_modified_identity() {
        let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let mut signed = SignedPrincipalDescriptor::sign(
            PrincipalDescriptor {
                principal: PrincipalId {
                    authority: authority.authority_id().clone(),
                    user_id: 7,
                },
                authority_kind: AuthorityKind::Iota,
                username: Some("alice".into()),
                display_name: None,
                public_keys: vec![mtp::crypto::Keyring::generate().public_key_bundle()],
                home: PrincipalHome::Iota(authority.node_id().clone()),
                revision: 1,
                valid_until: None,
                issued_at: 100,
            },
            &authority.keyring(),
        )
        .unwrap();
        signed.descriptor.principal.user_id = 8;

        assert!(
            signed
                .verify(
                    authority.authority_id(),
                    &authority.public_keys(),
                    None,
                    101,
                )
                .is_err()
        );
    }

    #[test]
    fn signed_node_descriptor_binds_node_id_and_endpoints() {
        let identity = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let signed = SignedNodeDescriptor::sign(
            NodeDescriptor {
                node: identity.node_id().clone(),
                public_keys: identity.public_keys(),
                direct_endpoints: vec![AuthorityLocator::new("iota.example.org:8443").unwrap()],
                relay_hints: vec![AuthorityLocator::new("relay.example.org:9443").unwrap()],
                revision: 2,
                valid_until: Some(200),
            },
            &identity,
        )
        .unwrap();
        let verified = signed.clone().verify(Some(2), 150).unwrap();
        assert_eq!(
            verified.descriptor().direct_endpoints[0].as_str(),
            "iota.example.org:8443"
        );

        let mut modified = signed;
        modified.descriptor.direct_endpoints =
            vec![AuthorityLocator::new("attacker.example.org:8443").unwrap()];
        assert!(modified.verify(None, 150).is_err());
    }

    #[test]
    fn node_descriptor_wire_round_trip_keeps_endpoint_signature_valid() {
        let identity = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let signed = SignedNodeDescriptor::sign(
            NodeDescriptor {
                node: identity.node_id().clone(),
                public_keys: identity.public_keys(),
                direct_endpoints: vec![AuthorityLocator::new("iota.example.org:1984").unwrap()],
                relay_hints: Vec::new(),
                revision: 1,
                valid_until: Some(500),
            },
            &identity,
        )
        .unwrap();
        let wire = signed.to_wire_v1().unwrap();
        let json = serde_json::to_vec(&wire).unwrap();
        let parsed: NodeDescriptorWireV1 = serde_json::from_slice(&json).unwrap();
        let verified = parsed.parse().unwrap().verify(None, 200).unwrap();
        assert_eq!(verified.descriptor().revision, 1);
    }

    #[test]
    fn discovery_document_binds_iota_id_to_public_key() {
        let identity = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let document = AuthorityDiscoveryDocument {
            version: 1,
            service: AuthorityKind::Iota,
            authority_id: identity.authority_id().clone(),
            node_id: Some(identity.node_id().clone()),
            public_key: identity.public_keys().try_to_base64().unwrap(),
            protocols: vec!["mtp-relay-v2".into()],
            node_descriptor: Some("/federation/v1/node".into()),
            direct_endpoints: vec![AuthorityLocator::new("iota.example.org:8443").unwrap()],
            relay_hints: Vec::new(),
        };
        assert_eq!(
            document.verify().unwrap().node_id,
            Some(identity.node_id().clone())
        );

        let mut mismatched = AuthorityDiscoveryDocument {
            version: 1,
            service: AuthorityKind::Iota,
            authority_id: identity.authority_id().clone(),
            node_id: Some(identity.node_id().clone()),
            public_key: mtp::crypto::Keyring::generate()
                .public_key_bundle()
                .try_to_base64()
                .unwrap(),
            protocols: vec!["mtp-relay-v2".into()],
            node_descriptor: Some("/federation/v1/node".into()),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
        };
        assert!(mismatched.clone().verify().is_err());
        mismatched.protocols.clear();
        assert!(mismatched.verify().is_err());
    }

    #[test]
    fn discovery_document_binds_omega_id_to_public_key() {
        let keyring = mtp::crypto::Keyring::generate();
        let public_keys = keyring.public_key_bundle();
        let document = AuthorityDiscoveryDocument {
            version: 1,
            service: AuthorityKind::Omega,
            authority_id: AuthorityId::for_omega(&public_keys).unwrap(),
            node_id: None,
            public_key: public_keys.try_to_base64().unwrap(),
            protocols: vec!["identity-http-v1".into()],
            node_descriptor: None,
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
        };
        assert!(document.verify().is_ok());
    }

    #[test]
    fn identifiers_reject_empty_values() {
        assert!(AuthorityId::new("  ").is_err());
        assert!(IotaNodeId::new(String::new()).is_err());
        assert!(IotaNodeId::new("node-a").is_err());
        assert!(AuthorityLocator::new(" ").is_err());
    }

    #[test]
    fn parses_user_addresses() {
        let key = mtp::crypto::Keyring::generate().public_key_bundle();
        let encoded_key = key.try_to_base64().unwrap();
        let username = UserAddress::parse("alice@IOTA.Example.Org:443").unwrap();
        let numeric = UserAddress::parse("51@192.0.2.20").unwrap();
        let numeric_domain = UserAddress::parse("51@iota.example.org").unwrap();
        let omega = UserAddress::parse("alice@omega.example.org").unwrap();
        let numeric_pinned =
            UserAddress::parse(&format!("51::{encoded_key}@omega.example.org")).unwrap();
        let pinned =
            UserAddress::parse(&format!("alice::{encoded_key}@[2001:DB8::1]:8443")).unwrap();

        assert_eq!(username.selector, UserSelector::Username("alice".into()));
        assert_eq!(username.authority.unwrap().as_str(), "iota.example.org:443");
        assert_eq!(numeric.selector, UserSelector::UserId(51));
        assert_eq!(numeric.authority.unwrap().as_str(), "192.0.2.20");
        assert_eq!(numeric_domain.selector, UserSelector::UserId(51));
        assert_eq!(
            numeric_domain.authority.unwrap().as_str(),
            "iota.example.org"
        );
        assert_eq!(omega.authority.unwrap().as_str(), "omega.example.org");
        assert_eq!(numeric_pinned.selector, UserSelector::UserId(51));
        assert!(numeric_pinned.public_key_pin.is_some());
        assert_eq!(pinned.authority.unwrap().as_str(), "[2001:db8::1]:8443");
        assert_eq!(
            pinned.public_key_pin.unwrap().try_as_bytes().unwrap(),
            key.try_as_bytes().unwrap()
        );
    }

    #[test]
    fn numeric_only_selectors_are_user_ids() {
        assert_eq!(
            UserAddress::parse("00051").unwrap().selector,
            UserSelector::UserId(51)
        );
        assert_eq!(
            UserAddress::parse("51alice").unwrap().selector,
            UserSelector::Username("51alice".into())
        );
    }

    #[test]
    fn parses_local_and_bracketed_ipv6_addresses() {
        let local = UserAddress::parse("alice").unwrap();
        let ipv6 = UserAddress::parse("alice@[2001:DB8::1]").unwrap();
        let ipv4 = AuthorityLocator::new("192.0.2.10:443").unwrap();
        let domain = AuthorityLocator::new("iota.example:443").unwrap();

        assert!(local.authority.is_none());
        let ipv6 = ipv6.authority.unwrap();
        assert_eq!(ipv6.as_str(), "[2001:db8::1]");
        assert!(ipv6.is_ip_literal());
        assert!(ipv4.is_ip_literal());
        assert!(!domain.is_ip_literal());
    }

    #[test]
    fn rejects_malformed_user_addresses() {
        for address in [
            "",
            "@example.org",
            "alice@",
            "alice@@example.org",
            "alice::not-a-key@example.org",
            "alice::@example.org",
        ] {
            assert!(UserAddress::parse(address).is_err(), "accepted {address}");
        }
    }

    #[test]
    fn node_identity_is_stable_across_reload() {
        let path = std::env::temp_dir().join(format!(
            "iota-node-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = LocalNodeIdentity::load_or_create(&path, None).unwrap();
        let second = LocalNodeIdentity::load_or_create(&path, None).unwrap();

        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(first.authority_id(), second.authority_id());
        assert_eq!(
            IotaNodeId::from_public_keys(&first.public_keys()).unwrap(),
            *first.node_id()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_omega_route_is_not_a_cryptographic_iota_identity() {
        let authority = AuthorityId::omega_legacy("omega-a.example").unwrap();
        let home = PrincipalHome::LegacyOmegaIota {
            omega: authority,
            iota_id: 42,
        };
        assert!(matches!(
            home,
            PrincipalHome::LegacyOmegaIota { iota_id: 42, .. }
        ));
    }

    #[test]
    fn descriptor_expiry_is_exclusive() {
        let resolved = ResolvedPrincipal {
            principal: PrincipalId {
                authority: AuthorityId::new("omega:example").unwrap(),
                user_id: 1,
            },
            handle: PrincipalHandle(1),
            username: None,
            public_keys: Vec::new(),
            home: PrincipalHome::Unknown,
            descriptor_revision: 1,
            valid_until: Some(100),
            resolved_at: 1,
        };
        assert!(resolved.is_valid_at(99));
        assert!(!resolved.is_valid_at(100));
    }

    #[test]
    fn offline_cache_policy_enforces_its_staleness_limit() {
        let policy = OfflineResolutionPolicy::AllowUnexpired {
            max_staleness: Duration::from_secs(1),
        };

        assert!(policy.allows_cached(1_000, 2_000));
        assert!(!policy.allows_cached(1_000, 2_001));
        assert!(!OfflineResolutionPolicy::RejectStale.allows_cached(1_000, 1_000));
    }
}
