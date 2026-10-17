use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::relay_service::{
    IngressSource, RelayOutcome, RelayService, RelayServiceError, VerifiedRelayEnvelope,
};
use iota_identity::IotaNodeId;
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
}

impl Default for HttpFederationIdentityClient {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
            ip_bootstrap_client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .tls_info(true)
                .build()
                .map_err(|error| error.to_string()),
        }
    }
}

pub async fn publish_omega_node_descriptor(
    locator: &AuthorityLocator,
    iota_id: u64,
    descriptor: &NodeDescriptorWireV1,
) -> Result<(), IdentityError> {
    let response = reqwest::Client::new()
        .post(format!(
            "https://{}/federation/v1/iotas/{iota_id}/node",
            locator.as_str()
        ))
        .json(descriptor)
        .send()
        .await
        .map_err(|error| IdentityError::Unavailable(error.to_string()))?;
    if !response.status().is_success() {
        return Err(IdentityError::Unavailable(format!(
            "Omega rejected node descriptor publication with HTTP {}",
            response.status()
        )));
    }
    Ok(())
}

#[async_trait]
impl FederationIdentityClient for HttpFederationIdentityClient {
    async fn discover(
        &self,
        locator: &AuthorityLocator,
    ) -> Result<DiscoveredAuthority, IdentityError> {
        iota_util::authority_discovery::discover_authority(self.client(locator)?, locator).await
    }

    async fn node_descriptor(
        &self,
        locator: &AuthorityLocator,
        path: &str,
    ) -> Result<FetchedNodeDescriptor, IdentityError> {
        let (descriptor, certificate) = self.get_json_with_certificate(locator, path).await?;
        Ok(FetchedNodeDescriptor {
            descriptor,
            tls_certificate: certificate.map(certificate_to_pem).transpose()?,
        })
    }

    async fn principal_descriptor(
        &self,
        locator: &AuthorityLocator,
        selector: &UserSelector,
    ) -> Result<PrincipalDescriptorWireV1, IdentityError> {
        let path = match selector {
            UserSelector::UserId(user) => format!("/federation/v1/users/id/{user}"),
            UserSelector::Username(username) => {
                let mut url = reqwest::Url::parse("https://placeholder.invalid/")
                    .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
                url.path_segments_mut()
                    .map_err(|_| {
                        IdentityError::InvalidIdentifier(
                            "username cannot be encoded in a federation URL".into(),
                        )
                    })?
                    .extend(["federation", "v1", "users", "name", username]);
                url.path().to_owned()
            }
        };
        self.get_json(locator, &path).await
    }
}

impl HttpFederationIdentityClient {
    fn client(&self, locator: &AuthorityLocator) -> Result<&reqwest::Client, IdentityError> {
        if !locator.is_ip_literal() {
            return Ok(&self.client);
        }
        self.ip_bootstrap_client.as_ref().map_err(|error| {
            IdentityError::Unavailable(format!("raw-IP bootstrap client is unavailable: {error}"))
        })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        locator: &AuthorityLocator,
        path: &str,
    ) -> Result<T, IdentityError> {
        let url = format!("https://{}{}", locator.as_str(), path);
        self.client(locator)?
            .get(&url)
            .send()
            .await
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request failed for {url}: {error}"))
            })?
            .error_for_status()
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request rejected {url}: {error}"))
            })?
            .json()
            .await
            .map_err(|error| {
                IdentityError::InvalidDescriptor(format!(
                    "invalid federation response from {url}: {error}"
                ))
            })
    }

    async fn get_json_with_certificate<T: serde::de::DeserializeOwned>(
        &self,
        locator: &AuthorityLocator,
        path: &str,
    ) -> Result<(T, Option<Vec<u8>>), IdentityError> {
        let url = format!("https://{}{}", locator.as_str(), path);
        let response = self
            .client(locator)?
            .get(&url)
            .send()
            .await
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request failed for {url}: {error}"))
            })?
            .error_for_status()
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request rejected {url}: {error}"))
            })?;
        let certificate = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(reqwest::tls::TlsInfo::peer_certificate)
            .map(Vec::from);
        let descriptor = response.json().await.map_err(|error| {
            IdentityError::InvalidDescriptor(format!(
                "invalid federation response from {url}: {error}"
            ))
        })?;
        Ok((descriptor, certificate))
    }
}

fn certificate_to_pem(certificate: Vec<u8>) -> Result<Vec<u8>, IdentityError> {
    if certificate.is_empty() {
        return Err(IdentityError::InvalidDescriptor(
            "raw-IP bootstrap response contains an empty TLS certificate".into(),
        ));
    }
    let encoded =
        iota_util::crypto_util::export(&certificate, iota_util::crypto_util::DataFormat::Base64)
            .map_err(IdentityError::InvalidDescriptor)?;
    Ok(format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n").into_bytes())
}

pub struct RemoteIotaResolver {
    client: Arc<dyn FederationIdentityClient>,
    principals: Arc<dyn PrincipalStore>,
    nodes: Arc<dyn NodeDirectory>,
    authorities: RwLock<HashMap<AuthorityLocator, CachedIotaAuthority>>,
    discovery_freshness: std::time::Duration,
}

#[derive(Clone)]
struct CachedIotaAuthority {
    authority: DiscoveredAuthority,
    node: IotaNodeId,
    verified_at: i64,
    descriptor_revision: i64,
}

impl RemoteIotaResolver {
    pub fn new(
        client: Arc<dyn FederationIdentityClient>,
        principals: Arc<dyn PrincipalStore>,
        nodes: Arc<dyn NodeDirectory>,
    ) -> Self {
        Self {
            client,
            principals,
            nodes,
            authorities: RwLock::new(HashMap::new()),
            discovery_freshness: std::time::Duration::from_secs(60),
        }
    }

    pub fn with_discovery_freshness(mut self, freshness: std::time::Duration) -> Self {
        self.discovery_freshness = freshness;
        self
    }

    pub fn pin_node(
        &self,
        locator: &AuthorityLocator,
        node: &IotaNodeId,
    ) -> Result<(), IdentityError> {
        self.nodes.pin_endpoint(locator, node, now_millis())
    }

    pub fn pin_public_key(
        &self,
        locator: &AuthorityLocator,
        key: &PublicKeyBundle,
    ) -> Result<IotaNodeId, IdentityError> {
        let node = IotaNodeId::from_public_keys(key)?;
        self.pin_node(locator, &node)?;
        Ok(node)
    }

    async fn authority(
        &self,
        locator: &AuthorityLocator,
        allow_network: bool,
    ) -> Result<DiscoveredAuthority, IdentityError> {
        let cached = self
            .authorities
            .read()
            .ok()
            .and_then(|authorities| authorities.get(locator).cloned());
        if let Some(cached) = &cached {
            if self.nodes.pinned_node(locator)?.as_ref() != Some(&cached.node) {
                return Err(IdentityError::KeyPinMismatch);
            }
            if let Ok(node) = self.nodes.resolve_node(&cached.node).await
                && node.descriptor_revision == cached.descriptor_revision
                && node.resolved_at == cached.verified_at
                && now_millis().saturating_sub(cached.verified_at)
                    < i64::try_from(self.discovery_freshness.as_millis()).unwrap_or(i64::MAX)
            {
                return Ok(cached.authority.clone());
            }
            // Keep the expected identity even if refresh fails. This entry is
            // unusable until its verified descriptor generation matches again.
        }
        if !allow_network {
            let node = self.nodes.pinned_node(locator)?.ok_or_else(|| {
                IdentityError::Unavailable("authority discovery is not cached".into())
            })?;
            let resolved = self.nodes.resolve_node(&node).await?;
            let public_keys = resolved.public_keys.first().cloned().ok_or_else(|| {
                IdentityError::InvalidDescriptor("cached node has no trusted key".into())
            })?;
            return Ok(DiscoveredAuthority {
                service: AuthorityKind::Iota,
                authority_id: AuthorityId::for_iota(&node),
                node_id: Some(node),
                public_keys,
                protocols: vec!["identity-http-v1".into(), "mtp-relay-v2".into()],
                node_descriptor: Some("/federation/v1/node".into()),
                direct_endpoints: resolved.direct_endpoints,
                relay_hints: resolved.relay_hints,
            });
        }
        let authority = self.client.discover(locator).await?;
        if authority.service != AuthorityKind::Iota {
            return Err(IdentityError::NotFound);
        }
        let node = authority.node_id.as_ref().ok_or_else(|| {
            IdentityError::InvalidDescriptor("Iota discovery contains no node ID".into())
        })?;
        if authority.authority_id != AuthorityId::for_iota(node)
            || IotaNodeId::from_public_keys(&authority.public_keys)? != *node
        {
            return Err(IdentityError::InvalidDescriptor(
                "discovery authority, node identity and public key disagree".into(),
            ));
        }
        let expected = self
            .nodes
            .pinned_node(locator)?
            .or_else(|| cached.map(|entry| entry.node));
        if expected.is_some() && authority.node_id != expected {
            return Err(IdentityError::InvalidDescriptor(
                "authority locator node identity changed from its pin".into(),
            ));
        }
        Ok(authority)
    }

    async fn refresh(
        &self,
        locator: &AuthorityLocator,
        authority: &DiscoveredAuthority,
        selector: &UserSelector,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        let expected_node = authority.node_id.as_ref().ok_or_else(|| {
            IdentityError::InvalidDescriptor("Iota discovery contains no node ID".into())
        })?;
        if self
            .nodes
            .pinned_node(locator)?
            .is_some_and(|pinned| &pinned != expected_node)
        {
            return Err(IdentityError::InvalidDescriptor(
                "authority locator node identity changed from its pin".into(),
            ));
        }
        let node_path = authority.node_descriptor.as_deref().ok_or_else(|| {
            IdentityError::InvalidDescriptor(
                "Iota discovery contains no node descriptor endpoint".into(),
            )
        })?;
        let fetched_node = self.client.node_descriptor(locator, node_path).await?;
        let raw_ip_certificate = if locator.is_ip_literal() {
            let certificate = fetched_node.tls_certificate.as_ref().ok_or_else(|| {
                IdentityError::InvalidDescriptor(
                    "raw-IP bootstrap response contains no TLS certificate".into(),
                )
            })?;
            if self
                .nodes
                .pinned_endpoint_certificate(locator)?
                .as_deref()
                .is_some_and(|pinned| pinned != certificate)
            {
                return Err(IdentityError::InvalidDescriptor(
                    "raw-IP TLS certificate changed from its TOFU pin".into(),
                ));
            }
            Some(certificate)
        } else {
            None
        };
        let signed_node = fetched_node.descriptor.parse()?;
        if &signed_node.descriptor.node != expected_node {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor does not match discovery node ID".into(),
            ));
        }
        let discovered_key = authority
            .public_keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        let descriptor_key = signed_node
            .descriptor
            .public_keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        if discovered_key != descriptor_key {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor key does not match discovery".into(),
            ));
        }
        let current_node_revision = self
            .nodes
            .resolve_node(expected_node)
            .await
            .ok()
            .map(|node| node.descriptor_revision);
        let verified_node = signed_node.verify(current_node_revision, now_millis())?;
        self.nodes.upsert_node_descriptor(&verified_node)?;
        self.nodes
            .pin_endpoint(locator, expected_node, now_millis())?;
        if let Some(certificate) = raw_ip_certificate {
            self.nodes.pin_endpoint_certificate(locator, certificate)?;
        }
        let node = self.nodes.resolve_node(expected_node).await?;
        if let Ok(mut authorities) = self.authorities.write() {
            authorities.insert(
                locator.clone(),
                CachedIotaAuthority {
                    authority: authority.clone(),
                    node: expected_node.clone(),
                    verified_at: node.resolved_at,
                    descriptor_revision: node.descriptor_revision,
                },
            );
        }

        let signed = self
            .client
            .principal_descriptor(locator, selector)
            .await?
            .parse()?;
        match selector {
            UserSelector::UserId(user_id) if signed.descriptor.principal.user_id != *user_id => {
                return Err(IdentityError::InvalidDescriptor(
                    "principal descriptor user ID does not match lookup".into(),
                ));
            }
            UserSelector::Username(username)
                if signed.descriptor.username.as_deref() != Some(username.as_str()) =>
            {
                return Err(IdentityError::InvalidDescriptor(
                    "principal descriptor username does not match lookup".into(),
                ));
            }
            _ => {}
        }
        let current_revision = self
            .principals
            .get_by_canonical_id(&signed.descriptor.principal)?
            .map(|principal| principal.descriptor_revision);
        let verified = signed.verify(
            &authority.authority_id,
            &verified_node.descriptor().public_keys,
            current_revision,
            now_millis(),
        )?;
        let handle = self.principals.upsert_remote_descriptor(&verified)?;
        self.principals
            .get_principal(handle)?
            .ok_or(IdentityError::NotFound)
    }

    fn cached(
        &self,
        authority: &AuthorityId,
        selector: &UserSelector,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        match selector {
            UserSelector::UserId(user_id) => self.principals.get_by_canonical_id(&PrincipalId {
                authority: authority.clone(),
                user_id: *user_id,
            }),
            UserSelector::Username(username) => {
                self.principals.get_by_username(authority, username)
            }
        }
    }
}

#[async_trait]
impl IdentityResolver for RemoteIotaResolver {
    async fn resolve_address(
        &self,
        address: &UserAddress,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        let locator = address.authority.as_ref().ok_or(IdentityError::NotFound)?;
        let authority = self.authority(locator, context.allow_network).await?;
        let cached = self.cached(&authority.authority_id, &address.selector)?;
        let now = now_millis();
        let resolved = if let Some(cached) = cached.as_ref()
            && cached.is_valid_at(now)
            && !cached.public_keys.is_empty()
            && now.saturating_sub(cached.resolved_at) < FRESH_CACHE_MILLIS
        {
            cached.clone()
        } else if context.allow_network {
            self.refresh(locator, &authority, &address.selector).await?
        } else if let Some(cached) = cached
            && cached.is_valid_at(now)
            && !cached.public_keys.is_empty()
            && context
                .offline_policy
                .allows_cached(cached.resolved_at, now)
        {
            cached
        } else {
            return Err(IdentityError::Unavailable(
                "cached principal descriptor is stale".into(),
            ));
        };
        verify_key_pin(address.public_key_pin.as_ref(), &resolved.public_keys)?;
        Ok(resolved)
    }

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        self.resolve_principal_with_context(
            principal,
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
    }

    async fn resolve_principal_with_context(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        let cached = self.principals.get_by_canonical_id(principal)?;
        let now = now_millis();
        if let Some(cached) = cached.as_ref()
            && cached.is_valid_at(now)
            && !cached.public_keys.is_empty()
            && (now.saturating_sub(cached.resolved_at) < FRESH_CACHE_MILLIS
                || context
                    .offline_policy
                    .allows_cached(cached.resolved_at, now))
        {
            return Ok(cached.clone());
        }
        let locator = self.authorities.read().ok().and_then(|authorities| {
            authorities
                .iter()
                .find(|(_, entry)| entry.authority.authority_id == principal.authority)
                .map(|(locator, _)| locator.clone())
        });
        if context.allow_network
            && let Some(locator) = locator
        {
            let authority = self.authority(&locator, true).await?;
            return self
                .refresh(
                    &locator,
                    &authority,
                    &UserSelector::UserId(principal.user_id),
                )
                .await;
        }
        match cached {
            Some(_) => Err(IdentityError::Unavailable(
                "cached principal descriptor is stale".into(),
            )),
            None => Err(IdentityError::NotFound),
        }
    }

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        self.resolve_principal_with_context(principal, context)
            .await
            .map(|principal| principal.public_keys)
    }
}

pub struct RemoteOmegaResolver {
    client: Arc<dyn FederationIdentityClient>,
    principals: Arc<dyn PrincipalStore>,
    nodes: Arc<dyn NodeDirectory>,
    authorities: RwLock<HashMap<AuthorityLocator, DiscoveredAuthority>>,
}

impl RemoteOmegaResolver {
    pub fn new(
        client: Arc<dyn FederationIdentityClient>,
        principals: Arc<dyn PrincipalStore>,
        nodes: Arc<dyn NodeDirectory>,
    ) -> Self {
        Self {
            client,
            principals,
            nodes,
            authorities: RwLock::new(HashMap::new()),
        }
    }

    async fn authority(
        &self,
        locator: &AuthorityLocator,
        allow_network: bool,
    ) -> Result<DiscoveredAuthority, IdentityError> {
        if let Some(authority) = self
            .authorities
            .read()
            .ok()
            .and_then(|authorities| authorities.get(locator).cloned())
        {
            return Ok(authority);
        }
        if !allow_network {
            return Err(IdentityError::Unavailable(
                "Omega authority discovery is not cached".into(),
            ));
        }
        let authority = self.client.discover(locator).await?;
        if authority.service != AuthorityKind::Omega {
            return Err(IdentityError::NotFound);
        }
        if let Ok(mut authorities) = self.authorities.write() {
            authorities.insert(locator.clone(), authority.clone());
        }
        Ok(authority)
    }

    async fn refresh(
        &self,
        locator: &AuthorityLocator,
        authority: &DiscoveredAuthority,
        selector: &UserSelector,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        let wire = self.client.principal_descriptor(locator, selector).await?;
        let home_node = wire.home_node.clone();
        let signed = wire.parse()?;
        match selector {
            UserSelector::UserId(user_id) if signed.descriptor.principal.user_id != *user_id => {
                return Err(IdentityError::InvalidDescriptor(
                    "principal descriptor user ID does not match lookup".into(),
                ));
            }
            UserSelector::Username(username)
                if signed.descriptor.username.as_deref() != Some(username.as_str()) =>
            {
                return Err(IdentityError::InvalidDescriptor(
                    "principal descriptor username does not match lookup".into(),
                ));
            }
            _ => {}
        }
        let current_revision = self
            .principals
            .get_by_canonical_id(&signed.descriptor.principal)?
            .map(|principal| principal.descriptor_revision);
        let verified = signed.verify(
            &authority.authority_id,
            &authority.public_keys,
            current_revision,
            now_millis(),
        )?;
        if verified.descriptor().authority_kind != AuthorityKind::Omega {
            return Err(IdentityError::InvalidDescriptor(
                "remote Omega returned a non-Omega principal".into(),
            ));
        }
        if let iota_identity::PrincipalHome::Iota(home) = &verified.descriptor().home {
            let signed_node = home_node
                .ok_or_else(|| {
                    IdentityError::InvalidDescriptor(
                        "Omega principal response contains no hosting Iota descriptor".into(),
                    )
                })?
                .parse()?;
            if &signed_node.descriptor.node != home {
                return Err(IdentityError::InvalidDescriptor(
                    "hosting Iota descriptor does not match principal home".into(),
                ));
            }
            let current_node_revision = self
                .nodes
                .resolve_node(home)
                .await
                .ok()
                .map(|node| node.descriptor_revision);
            let verified_node = signed_node.verify(current_node_revision, now_millis())?;
            self.nodes.upsert_node_descriptor(&verified_node)?;
        }
        let handle = self.principals.upsert_remote_descriptor(&verified)?;
        self.principals
            .get_principal(handle)?
            .ok_or(IdentityError::NotFound)
    }

    fn cached(
        &self,
        authority: &AuthorityId,
        selector: &UserSelector,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        match selector {
            UserSelector::UserId(user_id) => self.principals.get_by_canonical_id(&PrincipalId {
                authority: authority.clone(),
                user_id: *user_id,
            }),
            UserSelector::Username(username) => {
                self.principals.get_by_username(authority, username)
            }
        }
    }
}

#[async_trait]
impl IdentityResolver for RemoteOmegaResolver {
    async fn resolve_address(
        &self,
        address: &UserAddress,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        let locator = address.authority.as_ref().ok_or(IdentityError::NotFound)?;
        let authority = self.authority(locator, context.allow_network).await?;
        let cached = self.cached(&authority.authority_id, &address.selector)?;
        let now = now_millis();
        let resolved = if let Some(cached) = cached.as_ref()
            && cached.is_valid_at(now)
            && !cached.public_keys.is_empty()
            && now.saturating_sub(cached.resolved_at) < FRESH_CACHE_MILLIS
        {
            cached.clone()
        } else if context.allow_network {
            self.refresh(locator, &authority, &address.selector).await?
        } else if let Some(cached) = cached
            && cached.is_valid_at(now)
            && !cached.public_keys.is_empty()
            && context
                .offline_policy
                .allows_cached(cached.resolved_at, now)
        {
            cached
        } else {
            return Err(IdentityError::Unavailable(
                "cached Omega principal descriptor is stale".into(),
            ));
        };
        verify_key_pin(address.public_key_pin.as_ref(), &resolved.public_keys)?;
        Ok(resolved)
    }

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        self.resolve_principal_with_context(
            principal,
            &ResolutionContext {
                allow_network: true,
                ..ResolutionContext::default()
            },
        )
        .await
    }

    async fn resolve_principal_with_context(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        let cached = self.principals.get_by_canonical_id(principal)?;
        let now = now_millis();
        if let Some(cached) = cached.as_ref()
            && cached.is_valid_at(now)
            && !cached.public_keys.is_empty()
            && (now.saturating_sub(cached.resolved_at) < FRESH_CACHE_MILLIS
                || context
                    .offline_policy
                    .allows_cached(cached.resolved_at, now))
        {
            return Ok(cached.clone());
        }
        let locator = self.authorities.read().ok().and_then(|authorities| {
            authorities
                .iter()
                .find(|(_, authority)| authority.authority_id == principal.authority)
                .map(|(locator, authority)| (locator.clone(), authority.clone()))
        });
        if context.allow_network
            && let Some((locator, authority)) = locator
        {
            return self
                .refresh(
                    &locator,
                    &authority,
                    &UserSelector::UserId(principal.user_id),
                )
                .await;
        }
        match cached {
            Some(_) => Err(IdentityError::Unavailable(
                "cached Omega principal descriptor is stale".into(),
            )),
            None => Err(IdentityError::NotFound),
        }
    }

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        self.resolve_principal_with_context(principal, context)
            .await
            .map(|principal| principal.public_keys)
    }
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

impl DirectPeerRouter {
    pub fn register(
        &self,
        node: IotaNodeId,
        connection: Arc<dyn DirectPeerConnection>,
    ) -> Result<u64, RouteError> {
        Ok(self
            .register_selected(node, connection, true)?
            .expect("preferred route is published"))
    }

    fn register_selected(
        &self,
        node: IotaNodeId,
        connection: Arc<dyn DirectPeerConnection>,
        preferred: bool,
    ) -> Result<Option<u64>, RouteError> {
        let mut peers = self
            .peers
            .write()
            .map_err(|_| RouteError::Delivery("peer route registry lock poisoned".into()))?;
        if !preferred && peers.get(&node).is_some_and(|current| current.2) {
            return Ok(None);
        }
        let registration = self.next_registration.fetch_add(1, Ordering::Relaxed) + 1;
        let replaced = peers
            .insert(node.clone(), (registration, connection, preferred))
            .is_some();
        iota_logger::log!(
            "Peer route publication: node={} generation={} replaced={}",
            node.as_str(),
            registration,
            replaced
        );
        Ok(Some(registration))
    }

    pub fn unregister(&self, node: &IotaNodeId, registration: u64) {
        if let Ok(mut peers) = self.peers.write()
            && peers
                .get(node)
                .is_some_and(|current| current.0 == registration)
        {
            peers.remove(node);
            iota_logger::log!(
                "Peer route removal: node={} generation={}",
                node.as_str(),
                registration
            );
        }
    }

    pub fn attach_manager(&self, manager: &Arc<PeerManager>) {
        if let Ok(mut current) = self.manager.write() {
            *current = Some(Arc::downgrade(manager));
        }
    }

    pub fn has_connection(&self, node: &IotaNodeId) -> bool {
        self.peers
            .read()
            .is_ok_and(|peers| peers.contains_key(node))
    }
}

#[async_trait]
impl PeerRouter for DirectPeerRouter {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let RouteDestination::Iota(node) = destination else {
            return Ok(RouteOutcome::Retryable {
                reason: "direct Iota router cannot route a legacy Omega destination".into(),
            });
        };
        let manager = self
            .manager
            .read()
            .ok()
            .and_then(|manager| manager.as_ref().and_then(Weak::upgrade));
        let mut connection = self
            .peers
            .read()
            .ok()
            .and_then(|peers| peers.get(node).map(|peer| (peer.0, peer.1.clone())));
        if connection.is_none()
            && let Some(manager) = manager.as_ref()
        {
            manager.connect_best(node).await?;
            connection = self
                .peers
                .read()
                .ok()
                .and_then(|peers| peers.get(node).map(|peer| (peer.0, peer.1.clone())));
        }
        let (generation, connection) =
            connection.ok_or_else(|| RouteError::NoRoute(node.clone()))?;
        if let Some(manager) = manager {
            if manager.shutdown.is_cancelled() {
                return Err(RouteError::Delivery("peer manager is shutting down".into()));
            }
            let key = connection.authenticated_key().ok_or_else(|| {
                RouteError::Delivery("peer route has no authenticated key".into())
            })?;
            if let Err(error) = manager.validate_peer(node, &key).await {
                self.unregister(node, generation);
                connection.close();
                return Err(RouteError::Delivery(error.to_string()));
            }
            if manager.shutdown.is_cancelled() {
                return Err(RouteError::Delivery("peer manager is shutting down".into()));
            }
        }
        connection.send_relay(frame).await
    }
}

#[async_trait]
pub trait LocalDeliverySink: Send + Sync {
    async fn deliver(&self, recipient: iota_identity::PrincipalHandle, frame: CommunicationValue);
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
}

/// Produced only by PeerManager's trusted node-directory validation.
pub struct ValidatedPeer {
    node: IotaNodeId,
    public_key: Vec<u8>,
}

struct OutgoingRegistration {
    router: Arc<DirectPeerRouter>,
    node: IotaNodeId,
    generation: Option<u64>,
    connection: Arc<mtp::client::MTPConnection>,
}

impl Drop for OutgoingRegistration {
    fn drop(&mut self) {
        if let Some(generation) = self.generation {
            self.router.unregister(&self.node, generation);
        }
        self.connection.sender.close_immediate();
    }
}

impl PeerManager {
    pub fn new(
        identity: iota_identity::LocalNodeIdentity,
        nodes: Arc<dyn NodeDirectory>,
        router: Arc<DirectPeerRouter>,
        relay: Arc<RelayService>,
        deliveries: Arc<dyn LocalDeliverySink>,
    ) -> Self {
        Self {
            identity,
            nodes,
            router,
            relay,
            deliveries,
            shutdown: tokio_util::sync::CancellationToken::new(),
            outgoing: std::sync::Mutex::new(Some(tokio::task::JoinSet::new())),
            outgoing_failed: AtomicBool::new(false),
            shutdown_join: tokio::sync::Mutex::new((None, None)),
        }
    }

    pub async fn connect(
        self: &Arc<Self>,
        node: IotaNodeId,
        endpoint: &AuthorityLocator,
        pinned_certificate: Option<Vec<u8>>,
    ) -> Result<(), RouteError> {
        if self.shutdown.is_cancelled() {
            return Err(RouteError::Delivery("peer manager is shutting down".into()));
        }
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.nodes.resolve_node(&node),
        )
        .await
        .map_err(|_| RouteError::Delivery("peer directory lookup timed out".into()))?
        .map_err(|error| RouteError::Delivery(error.to_string()))?;
        let host_key = resolved
            .public_keys
            .first()
            .ok_or_else(|| RouteError::Delivery("remote node has no trusted key".into()))?
            .clone();
        let mut config = mtp::client::ClientConfig::new(format!("https://{}/", endpoint.as_str()))
            .with_client_id(self.identity.node_id().mtp_authentication_hint())
            .with_description(format!("iota-peer:{}", self.identity.node_id().as_str()));
        if let Some(certificate) = pinned_certificate {
            config = config.with_pinned_pem(certificate);
        }
        let keyring = self.identity.keyring();
        let connection = tokio::select! {
            _ = self.shutdown.cancelled() => return Err(RouteError::Delivery("peer manager is shutting down".into())),
            connection = tokio::time::timeout(std::time::Duration::from_secs(15), mtp::client::MTPClient::auth_connect(config, &keyring, &host_key)) =>
                connection.map_err(|_| RouteError::Delivery("peer handshake timed out".into()))?
                    .map_err(|error| RouteError::Delivery(error.to_string()))?,
        };
        if connection.auth_state != mtp::client::AuthState::Authenticated {
            connection.sender.close_immediate();
            return Err(RouteError::Delivery(
                "remote peer did not complete node authentication".into(),
            ));
        }
        let connection = Arc::new(connection);
        let mut registration = OutgoingRegistration {
            router: self.router.clone(),
            node: node.clone(),
            generation: None,
            connection: connection.clone(),
        };
        if let Err(error) = self.validate_peer(&node, &host_key).await {
            connection.sender.close_immediate();
            return Err(RouteError::Delivery(error.to_string()));
        }
        self.nodes
            .pin_endpoint(endpoint, &node, now_millis())
            .map_err(|error| RouteError::Delivery(error.to_string()))?;
        let mut outgoing = self.outgoing.lock().expect("peer supervisor lock poisoned");
        let Some(tasks) = outgoing.as_mut().filter(|_| !self.shutdown.is_cancelled()) else {
            connection.sender.close_immediate();
            return Err(RouteError::Delivery("peer manager is shutting down".into()));
        };
        registration.generation = self.router.register_selected(
            node.clone(),
            Arc::new(OutgoingPeer(connection.clone(), host_key.clone())),
            !self.prefers_inbound(&node),
        )?;
        let manager = self.clone();
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                self.outgoing_failed.store(true, Ordering::Release);
                iota_logger::log!("Outbound peer task failed: {}", error);
            }
        }
        tasks.spawn(async move {
            manager.outgoing_read_loop(host_key, registration).await;
        });
        Ok(())
    }

    /// Stop dials and signal both inbound and outbound peer handlers.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    /// Called after authoritative directory revocation. Remove the selected
    /// route and close its transport without affecting another node.
    pub fn revoke_peer(&self, node: &IotaNodeId) -> Result<(), RouteError> {
        let removed = self
            .router
            .peers
            .write()
            .map_err(|_| RouteError::Delivery("peer route registry lock poisoned".into()))?
            .remove(node);
        if let Some((generation, connection, _)) = removed {
            connection.close();
            iota_logger::log!(
                "Peer revoked: node={} generation={}",
                node.as_str(),
                generation
            );
        }
        Ok(())
    }

    /// Retain the drain task across concurrent callers and cancelled waiters.
    /// Incomplete shutdown never treats an aborted mutation as successful cleanup.
    pub async fn shutdown(&self, budget: std::time::Duration) -> bool {
        self.stop();
        let mut join = self.shutdown_join.lock().await;
        if join.0.is_none() && join.1.is_none() {
            let tasks = self
                .outgoing
                .lock()
                .expect("peer supervisor lock poisoned")
                .take();
            let mut clean = !self.outgoing_failed.load(Ordering::Acquire);
            join.0 = Some(tokio::spawn(async move {
                let Some(mut tasks) = tasks else {
                    return clean;
                };
                if tokio::time::timeout(budget, async {
                    while let Some(result) = tasks.join_next().await {
                        if let Err(error) = result {
                            clean = false;
                            iota_logger::log!(
                                "Outbound peer task failed during shutdown: {}",
                                error
                            );
                        }
                    }
                })
                .await
                .is_err()
                {
                    iota_logger::log!(
                        "Outbound peer shutdown incomplete: remaining={} budget={:?}",
                        tasks.len(),
                        budget
                    );
                    tasks.detach_all();
                    return false;
                }
                clean
            }));
        }
        if let Some(task) = join.0.as_mut() {
            let result = task.await.unwrap_or(false);
            join.0.take();
            join.1 = Some(result);
        }
        join.1.expect("peer shutdown result retained")
    }

    pub async fn connect_best(self: &Arc<Self>, node: &IotaNodeId) -> Result<(), RouteError> {
        let resolved = self
            .nodes
            .resolve_node(node)
            .await
            .map_err(|error| RouteError::Delivery(error.to_string()))?;
        let mut endpoints = resolved.direct_endpoints;
        if let Some(last) = resolved.last_successful_endpoint {
            endpoints.retain(|endpoint| endpoint != &last);
            endpoints.insert(0, last);
        }
        let mut last_error = None;
        for endpoint in endpoints {
            let certificate = self
                .nodes
                .pinned_endpoint_certificate(&endpoint)
                .map_err(|error| RouteError::Delivery(error.to_string()))?;
            match self.connect(node.clone(), &endpoint, certificate).await {
                Ok(()) => {
                    let _ = self.nodes.record_successful_endpoint(node, &endpoint);
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| RouteError::NoRoute(node.clone())))
    }

    fn prefers_inbound(&self, remote: &IotaNodeId) -> bool {
        prefers_inbound(self.identity.node_id(), remote)
    }

    async fn outgoing_read_loop(
        self: Arc<Self>,
        key: PublicKeyBundle,
        registration: OutgoingRegistration,
    ) {
        let node = &registration.node;
        let connection = &registration.connection;
        let mut trust_check = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            let frame = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                _ = trust_check.tick() => {
                    let trusted = tokio::select! {
                        _ = self.shutdown.cancelled() => break,
                        peer = self.validate_peer(node, &key) => peer,
                    };
                    if let Err(error) = trusted {
                        iota_logger::log!("Peer trust invalidated: node={} reason={}", node.as_str(), error);
                        break;
                    }
                    continue;
                },
                frame = connection.receive() => match frame { Ok(frame) => frame, Err(_) => break },
            };
            let operation = self.process_incoming(node, &key, &self.shutdown, frame, |response| {
                let sender = connection.sender.clone();
                async move {
                    sender
                        .send(&response)
                        .await
                        .map_err(|error| error.to_string())
                }
            });
            tokio::pin!(operation);
            tokio::select! {
                _ = &mut operation => {},
                _ = self.shutdown.cancelled() => {
                    connection.sender.close_immediate();
                    operation.await;
                },
            }
        }
    }

    async fn process_incoming<F, Fut>(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
        shutdown: &tokio_util::sync::CancellationToken,
        frame: CommunicationValue,
        send: F,
    ) where
        F: FnOnce(CommunicationValue) -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        if !frame.is_type(mtp::codec::CommunicationType::Relay)
            || iota_connection::relay::message_security_class(&frame)
                != iota_connection::relay::MessageSecurityClass::AuthenticatedPeerControl
        {
            return;
        }
        let source = IngressSource::DirectPeer {
            node_id: node.clone(),
        };
        let request = frame.clone();
        let prepared = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = self.shutdown.cancelled() => return,
            verified = self.relay.prepare_relay(&source, frame) => verified,
        };
        let verified = match prepared {
            Ok(verified) => verified,
            Err(error) => {
                let response =
                    iota_connection::relay_service::relay_error_response(&request, &error);
                tokio::select! {
                    _ = shutdown.cancelled() => {},
                    _ = tokio::time::timeout(std::time::Duration::from_secs(5), send(response)) => {},
                }
                return;
            }
        };
        let trusted = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = self.shutdown.cancelled() => return,
            peer = self.validate_peer(node, key) => peer,
        };
        if trusted.is_err() {
            return;
        }
        let outcome = self.relay.accept_verified_relay(source, verified).await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let response =
                    iota_connection::relay_service::relay_error_response(&request, &error);
                tokio::select! {
                    _ = shutdown.cancelled() => {},
                    _ = tokio::time::timeout(std::time::Duration::from_secs(5), send(response)) => {},
                }
                return;
            }
        };
        let (response, deliveries) = outcome.into_parts();
        for delivery in deliveries {
            tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.deliveries.deliver(delivery.recipient, delivery.frame),
            ) => {},
            }
        }
        if let Some(response) = response {
            tokio::select! {
                _ = shutdown.cancelled() => {},
                _ = tokio::time::timeout(std::time::Duration::from_secs(5), send(response)) => {},
            }
        }
    }
}

fn prefers_inbound(local: &IotaNodeId, remote: &IotaNodeId) -> bool {
    // The smaller node selects outbound; the larger selects inbound. Both ends
    // select the same transport when they dial simultaneously.
    local.as_str() > remote.as_str()
}

struct OutgoingPeer(Arc<mtp::client::MTPConnection>, PublicKeyBundle);

#[async_trait]
impl DirectPeerConnection for OutgoingPeer {
    fn authenticated_key(&self) -> Option<PublicKeyBundle> {
        Some(self.1.clone())
    }
    fn close(&self) {
        self.0.sender.close_immediate();
    }
    async fn send_relay(&self, frame: CommunicationValue) -> Result<RouteOutcome, RouteError> {
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.0.request(&frame, None),
        )
        .await
        .map_err(|_| RouteError::Delivery("peer relay request timed out".into()))?
        .map_err(|error| RouteError::Delivery(error.to_string()))?;
        RouteOutcome::from_relay_response(&frame, response)
    }
}

impl PeerManager {
    pub async fn validate_peer(
        &self,
        node: &IotaNodeId,
        public_key: &PublicKeyBundle,
    ) -> Result<ValidatedPeer, IdentityError> {
        if &IotaNodeId::from_public_keys(public_key)? != node {
            return Err(IdentityError::KeyPinMismatch);
        }
        let expected = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.nodes.resolve_node(node),
        )
        .await
        .map_err(|_| IdentityError::Unavailable("peer directory lookup timed out".into()))??;
        if &expected.node != node {
            return Err(IdentityError::KeyPinMismatch);
        }
        let actual = public_key
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        if !expected.public_keys.iter().any(|key| {
            key.try_as_bytes()
                .map(|trusted| trusted == actual)
                .unwrap_or(false)
        }) {
            return Err(IdentityError::KeyPinMismatch);
        }
        if expected
            .valid_until
            .is_some_and(|until| until <= now_millis())
        {
            return Err(IdentityError::Unavailable(
                "trusted peer descriptor expired".into(),
            ));
        }
        Ok(ValidatedPeer {
            node: node.clone(),
            public_key: actual,
        })
    }

    pub async fn accept_validated(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        peer: ValidatedPeer,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<(), IdentityError> {
        let node = peer.node;
        if shutdown.is_cancelled() || self.shutdown.is_cancelled() {
            return Ok(());
        }
        // The handoff cannot be reused with a transport authenticated by another key.
        if connection.auth_state != mtp::host::AuthState::Authenticated
            || connection.client_id != node.mtp_authentication_hint()
            || connection
                .description
                .as_deref()
                .and_then(|description| description.strip_prefix("iota-peer:"))
                .and_then(|description| IotaNodeId::new(description).ok())
                .as_ref()
                != Some(&node)
            || connection
                .client_public_key
                .as_ref()
                .and_then(|key| key.try_as_bytes().ok())
                .as_ref()
                != Some(&peer.public_key)
        {
            return Err(IdentityError::KeyPinMismatch);
        }
        let connection = Arc::new(connection);
        let key = connection
            .client_public_key
            .as_ref()
            .expect("validated transport has a key")
            .clone();
        let pending: PendingPeerResponses = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registration = self
            .router
            .register_selected(
                node.clone(),
                Arc::new(IncomingPeer {
                    connection: connection.clone(),
                    pending: pending.clone(),
                }),
                self.prefers_inbound(&node),
            )
            .map_err(|error| IdentityError::Unavailable(error.to_string()))?;
        struct IncomingRegistration<'a> {
            router: &'a DirectPeerRouter,
            node: &'a IotaNodeId,
            registration: Option<u64>,
            pending: PendingPeerResponses,
            sender: mtp::webserver::WebMtpSender,
        }

        impl Drop for IncomingRegistration<'_> {
            fn drop(&mut self) {
                if let Some(registration) = self.registration {
                    self.router.unregister(self.node, registration);
                }
                self.pending
                    .lock()
                    .expect("peer response lock poisoned")
                    .clear();
                self.sender.close();
            }
        }

        let _registration = IncomingRegistration {
            router: &self.router,
            node: &node,
            registration,
            pending: pending.clone(),
            sender: connection.sender.clone(),
        };
        let mut trust_check = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            let frame = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = self.shutdown.cancelled() => break,
                _ = trust_check.tick() => {
                    let trusted = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = self.shutdown.cancelled() => break,
                        peer = self.validate_peer(&node, &key) => peer,
                    };
                    if let Err(error) = trusted {
                        iota_logger::log!("Peer trust invalidated: node={} reason={}", node.as_str(), error);
                        break;
                    }
                    continue;
                },
                frame = connection.receive() => match frame { Ok(frame) => frame, Err(_) => break },
            };
            if let Some(frame_id) = frame.id()
                && let Some((_, response)) = pending
                    .lock()
                    .expect("peer response lock poisoned")
                    .remove(&frame_id)
            {
                let _ = response.send(frame);
                continue;
            }
            let operation = self.process_incoming(&node, &key, &shutdown, frame, |response| {
                let sender = connection.sender.clone();
                async move {
                    sender
                        .send(&response)
                        .await
                        .map_err(|error| error.to_string())
                }
            });
            tokio::pin!(operation);
            tokio::select! {
                _ = &mut operation => {},
                _ = shutdown.cancelled() => {
                    pending.lock().expect("peer response lock poisoned").clear();
                    connection.sender.close(); operation.await;
                },
                _ = self.shutdown.cancelled() => {
                    pending.lock().expect("peer response lock poisoned").clear();
                    connection.sender.close(); operation.await;
                },
            }
        }
        Ok(())
    }
}

#[async_trait]
impl web_server::MtpConnectionHandler for PeerManager {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection) {
        self.accept_until_shutdown(connection, tokio_util::sync::CancellationToken::new())
            .await;
    }

    async fn accept_until_shutdown(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        let sender = connection.sender.clone();
        let result = async {
            if connection.auth_state != mtp::host::AuthState::Authenticated {
                return Err(IdentityError::KeyPinMismatch);
            }
            let key = connection
                .client_public_key
                .as_ref()
                .ok_or(IdentityError::KeyPinMismatch)?;
            let node = IotaNodeId::from_public_keys(key)?;
            let validated = tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                peer = self.validate_peer(&node, key) => peer?,
            };
            self.accept_validated(connection, validated, shutdown).await
        }
        .await;
        if let Err(error) = result {
            iota_logger::log!("Peer compatibility handler rejected connection: {}", error);
        }
        sender.close();
    }
}

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

impl Drop for PendingPeerRequest {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().expect("peer response lock poisoned");
        if pending
            .get(&self.frame_id)
            .is_some_and(|(instance, _)| Arc::ptr_eq(instance, &self.instance))
        {
            pending.remove(&self.frame_id);
        }
    }
}

#[async_trait]
impl DirectPeerConnection for IncomingPeer {
    fn authenticated_key(&self) -> Option<PublicKeyBundle> {
        self.connection.client_public_key.clone()
    }
    fn close(&self) {
        self.pending
            .lock()
            .expect("peer response lock poisoned")
            .clear();
        self.connection.sender.close();
    }
    async fn send_relay(&self, frame: CommunicationValue) -> Result<RouteOutcome, RouteError> {
        let frame_id = frame
            .id()
            .filter(|frame_id| *frame_id != 0)
            .ok_or_else(|| RouteError::Delivery("relay request has no frame ID".into()))?;
        let (send, receive) = tokio::sync::oneshot::channel();
        let instance = Arc::new(());
        {
            let mut pending = self.pending.lock().expect("peer response lock poisoned");
            match pending.entry(frame_id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((instance.clone(), send));
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(RouteError::Delivery(
                        "relay request ID is already pending".into(),
                    ));
                }
            }
        }
        let _request = PendingPeerRequest {
            pending: self.pending.clone(),
            frame_id,
            instance,
        };
        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.connection.sender.send(&frame),
        )
        .await
        .map_err(|_| RouteError::Delivery("peer relay send timed out".into()))?;
        if let Err(error) = sent {
            return Err(RouteError::Delivery(error.to_string()));
        }
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), receive)
            .await
            .map_err(|_| RouteError::Delivery("peer relay request timed out".into()))?
            .map_err(|_| RouteError::Delivery("peer relay connection closed".into()))?;
        RouteOutcome::from_relay_response(&frame, response)
    }
}

pub struct PeerRelayAdapter {
    relay: Arc<RelayService>,
}

impl PeerRelayAdapter {
    pub fn new(relay: Arc<RelayService>) -> Self {
        Self { relay }
    }

    pub async fn accept_verified_relay(
        &self,
        authenticated_peer: IotaNodeId,
        relay: VerifiedRelayEnvelope,
    ) -> Result<RelayOutcome, RelayServiceError> {
        self.relay
            .accept_verified_relay(
                IngressSource::DirectPeer {
                    node_id: authenticated_peer,
                },
                relay,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_identity::{
        LocalNodeIdentity, NodeDescriptor, NodeIdentityResolver, PrincipalDescriptor,
        PrincipalHandle, PrincipalHome, SignedNodeDescriptor, SignedPrincipalDescriptor,
        VerifiedNodeDescriptor, VerifiedPrincipalDescriptor,
    };
    use mtp::codec::CommunicationType;
    use std::sync::Mutex;

    fn node() -> IotaNodeId {
        iota_identity::LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate())
            .expect("generated identity is valid")
            .node_id()
            .clone()
    }

    #[test]
    fn route_publication_fails_when_the_registry_is_poisoned() {
        let router = Arc::new(DirectPeerRouter::default());
        let poisoning = router.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoning.peers.write().unwrap();
            panic!("poison route registry");
        })
        .join();
        assert!(router.register(node(), Arc::new(AcceptingPeer)).is_err());
    }

    #[test]
    fn nonpreferred_and_stale_connections_cannot_remove_the_selected_route() {
        let router = DirectPeerRouter::default();
        let node = node();
        let old = router
            .register_selected(node.clone(), Arc::new(AcceptingPeer), false)
            .unwrap()
            .unwrap();
        let selected = router
            .register_selected(node.clone(), Arc::new(AcceptingPeer), true)
            .unwrap()
            .unwrap();
        assert!(
            router
                .register_selected(node.clone(), Arc::new(AcceptingPeer), false)
                .unwrap()
                .is_none()
        );
        router.unregister(&node, old);
        assert!(router.has_connection(&node));
        router.unregister(&node, selected);
        assert!(!router.has_connection(&node));
    }

    #[test]
    fn captured_der_certificate_is_stored_as_valid_pem() {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let pem = certificate_to_pem(certificate.der().to_vec()).unwrap();
        reqwest::Certificate::from_pem(&pem).unwrap();
    }

    struct AcceptingPeer;

    #[async_trait]
    impl DirectPeerConnection for AcceptingPeer {
        async fn send_relay(&self, _: CommunicationValue) -> Result<RouteOutcome, RouteError> {
            Ok(RouteOutcome::Accepted {
                relay_message_id: "relay-a".into(),
                destination_accepted_at: 42,
            })
        }
    }

    #[tokio::test]
    async fn direct_router_uses_the_connection_registered_for_the_node() {
        let router = DirectPeerRouter::default();
        let node = node();
        router
            .register(node.clone(), Arc::new(AcceptingPeer))
            .unwrap();

        let outcome = router
            .route(
                &RouteDestination::Iota(node),
                CommunicationValue::new(CommunicationType::Relay),
            )
            .await
            .expect("registered peer is routable");
        assert!(matches!(outcome, RouteOutcome::Accepted { .. }));
    }

    #[tokio::test]
    async fn direct_router_reports_an_unknown_node_as_no_route() {
        let router = DirectPeerRouter::default();
        let node = node();
        let error = router
            .route(
                &RouteDestination::Iota(node.clone()),
                CommunicationValue::new(CommunicationType::Relay),
            )
            .await
            .expect_err("unregistered peer has no route");
        assert!(matches!(error, RouteError::NoRoute(found) if found == node));
    }

    #[test]
    fn simultaneous_dials_choose_one_connection_direction() {
        let first = node();
        let second = node();
        assert_ne!(first, second);
        assert_ne!(
            prefers_inbound(&first, &second),
            prefers_inbound(&second, &first)
        );
    }

    struct MemoryPrincipals {
        values: Mutex<HashMap<PrincipalId, ResolvedPrincipal>>,
    }

    impl PrincipalStore for MemoryPrincipals {
        fn get_principal(
            &self,
            handle: PrincipalHandle,
        ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?
                .values()
                .find(|principal| principal.handle == handle)
                .cloned())
        }

        fn get_by_canonical_id(
            &self,
            principal: &PrincipalId,
        ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?
                .get(principal)
                .cloned())
        }

        fn get_by_username(
            &self,
            authority: &AuthorityId,
            username: &str,
        ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?
                .values()
                .find(|principal| {
                    &principal.principal.authority == authority
                        && principal.username.as_deref() == Some(username)
                })
                .cloned())
        }

        fn upsert_remote_descriptor(
            &self,
            descriptor: &VerifiedPrincipalDescriptor,
        ) -> Result<PrincipalHandle, IdentityError> {
            let descriptor_value = descriptor.descriptor();
            let mut values = self
                .values
                .lock()
                .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))?;
            if values
                .get(&descriptor_value.principal)
                .is_some_and(|current| current.descriptor_revision > descriptor_value.revision)
            {
                return Err(IdentityError::Storage("stale descriptor".into()));
            }
            let handle = values
                .get(&descriptor_value.principal)
                .map(|principal| principal.handle)
                .unwrap_or(PrincipalHandle(values.len() as i64 + 1));
            values.insert(
                descriptor_value.principal.clone(),
                ResolvedPrincipal {
                    principal: descriptor_value.principal.clone(),
                    handle,
                    username: descriptor_value.username.clone(),
                    public_keys: descriptor_value.public_keys.clone(),
                    home: descriptor_value.home.clone(),
                    descriptor_revision: descriptor_value.revision,
                    valid_until: descriptor_value.valid_until,
                    resolved_at: descriptor.resolved_at(),
                },
            );
            Ok(handle)
        }

        fn signing_keys(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
            self.get_by_canonical_id(principal)?
                .map(|principal| principal.public_keys)
                .ok_or(IdentityError::NotFound)
        }
    }

    struct MemoryNodes {
        values: Mutex<HashMap<IotaNodeId, iota_identity::ResolvedNodeIdentity>>,
        pins: Mutex<HashMap<AuthorityLocator, IotaNodeId>>,
        certificates: Mutex<HashMap<AuthorityLocator, Vec<u8>>>,
    }

    #[async_trait]
    impl iota_identity::NodeIdentityResolver for MemoryNodes {
        async fn resolve_node(
            &self,
            node: &IotaNodeId,
        ) -> Result<iota_identity::ResolvedNodeIdentity, IdentityError> {
            self.values
                .lock()
                .map_err(|_| IdentityError::Storage("node lock is poisoned".into()))?
                .get(node)
                .cloned()
                .ok_or(IdentityError::NotFound)
        }
    }

    impl NodeDirectory for MemoryNodes {
        fn upsert_node_descriptor(
            &self,
            descriptor: &VerifiedNodeDescriptor,
        ) -> Result<(), IdentityError> {
            let value = descriptor.descriptor();
            self.values
                .lock()
                .map_err(|_| IdentityError::Storage("node lock is poisoned".into()))?
                .insert(
                    value.node.clone(),
                    iota_identity::ResolvedNodeIdentity {
                        node: value.node.clone(),
                        public_keys: vec![value.public_keys.clone()],
                        descriptor_revision: value.revision,
                        valid_until: value.valid_until,
                        direct_endpoints: value.direct_endpoints.clone(),
                        relay_hints: value.relay_hints.clone(),
                        last_successful_endpoint: None,
                        resolved_at: descriptor.resolved_at(),
                    },
                );
            Ok(())
        }

        fn pin_endpoint(
            &self,
            endpoint: &AuthorityLocator,
            node: &IotaNodeId,
            _: i64,
        ) -> Result<(), IdentityError> {
            let mut pins = self
                .pins
                .lock()
                .map_err(|_| IdentityError::Storage("pin lock is poisoned".into()))?;
            if pins.get(endpoint).is_some_and(|pinned| pinned != node) {
                return Err(IdentityError::InvalidDescriptor(
                    "endpoint node identity changed from its TOFU pin".into(),
                ));
            }
            pins.insert(endpoint.clone(), node.clone());
            Ok(())
        }

        fn pinned_node(
            &self,
            endpoint: &AuthorityLocator,
        ) -> Result<Option<IotaNodeId>, IdentityError> {
            Ok(self
                .pins
                .lock()
                .map_err(|_| IdentityError::Storage("pin lock is poisoned".into()))?
                .get(endpoint)
                .cloned())
        }

        fn pin_endpoint_certificate(
            &self,
            endpoint: &AuthorityLocator,
            certificate: &[u8],
        ) -> Result<(), IdentityError> {
            let mut certificates = self
                .certificates
                .lock()
                .map_err(|_| IdentityError::Storage("certificate lock is poisoned".into()))?;
            if certificates
                .get(endpoint)
                .is_some_and(|pinned| pinned != certificate)
            {
                return Err(IdentityError::InvalidDescriptor(
                    "endpoint TLS certificate changed from its TOFU pin".into(),
                ));
            }
            certificates.insert(endpoint.clone(), certificate.to_vec());
            Ok(())
        }

        fn pinned_endpoint_certificate(
            &self,
            endpoint: &AuthorityLocator,
        ) -> Result<Option<Vec<u8>>, IdentityError> {
            Ok(self
                .certificates
                .lock()
                .map_err(|_| IdentityError::Storage("certificate lock is poisoned".into()))?
                .get(endpoint)
                .cloned())
        }

        fn record_successful_endpoint(
            &self,
            _: &IotaNodeId,
            _: &AuthorityLocator,
        ) -> Result<(), IdentityError> {
            Ok(())
        }
    }

    struct FakeFederationClient {
        authority: Mutex<DiscoveredAuthority>,
        node: Mutex<NodeDescriptorWireV1>,
        principal: Mutex<PrincipalDescriptorWireV1>,
        certificate: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl FederationIdentityClient for FakeFederationClient {
        async fn discover(
            &self,
            _: &AuthorityLocator,
        ) -> Result<DiscoveredAuthority, IdentityError> {
            self.authority
                .lock()
                .map(|authority| authority.clone())
                .map_err(|_| IdentityError::Storage("authority lock is poisoned".into()))
        }

        async fn node_descriptor(
            &self,
            _: &AuthorityLocator,
            _: &str,
        ) -> Result<FetchedNodeDescriptor, IdentityError> {
            let descriptor = self
                .node
                .lock()
                .map_err(|_| IdentityError::Storage("node lock is poisoned".into()))?
                .clone();
            let certificate = self
                .certificate
                .lock()
                .map_err(|_| IdentityError::Storage("certificate lock is poisoned".into()))?
                .clone();
            Ok(FetchedNodeDescriptor {
                descriptor,
                tls_certificate: Some(certificate),
            })
        }

        async fn principal_descriptor(
            &self,
            _: &AuthorityLocator,
            _: &UserSelector,
        ) -> Result<PrincipalDescriptorWireV1, IdentityError> {
            self.principal
                .lock()
                .map(|principal| principal.clone())
                .map_err(|_| IdentityError::Storage("principal lock is poisoned".into()))
        }
    }

    type RemoteFixture = (
        Arc<RemoteIotaResolver>,
        Arc<FakeFederationClient>,
        Arc<MemoryPrincipals>,
        Arc<MemoryNodes>,
        AuthorityLocator,
        PrincipalId,
        PublicKeyBundle,
    );

    fn remote_fixture(principal_revision: i64) -> RemoteFixture {
        let authority = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let user = mtp::crypto::Keyring::generate();
        let locator = AuthorityLocator::new("192.0.2.10").unwrap();
        let node = SignedNodeDescriptor::sign(
            NodeDescriptor {
                node: authority.node_id().clone(),
                public_keys: authority.public_keys(),
                direct_endpoints: vec![locator.clone()],
                relay_hints: Vec::new(),
                revision: 1,
                valid_until: Some(now_millis() + 60_000),
            },
            &authority,
        )
        .unwrap()
        .to_wire_v1()
        .unwrap();
        let principal_id = PrincipalId {
            authority: authority.authority_id().clone(),
            user_id: 7,
        };
        let principal = SignedPrincipalDescriptor::sign(
            PrincipalDescriptor {
                principal: principal_id.clone(),
                authority_kind: AuthorityKind::Iota,
                username: Some("alice".into()),
                display_name: None,
                public_keys: vec![user.public_key_bundle()],
                home: PrincipalHome::Iota(authority.node_id().clone()),
                revision: principal_revision,
                valid_until: Some(now_millis() + 60_000),
                issued_at: now_millis(),
            },
            &authority.keyring(),
        )
        .unwrap()
        .to_wire_v1()
        .unwrap();
        let client = Arc::new(FakeFederationClient {
            authority: Mutex::new(DiscoveredAuthority {
                service: AuthorityKind::Iota,
                authority_id: authority.authority_id().clone(),
                node_id: Some(authority.node_id().clone()),
                public_keys: authority.public_keys(),
                protocols: vec!["identity-http-v1".into()],
                node_descriptor: Some("/federation/v1/node".into()),
                direct_endpoints: Vec::new(),
                relay_hints: Vec::new(),
            }),
            node: Mutex::new(node),
            principal: Mutex::new(principal),
            certificate: Mutex::new(b"test certificate".to_vec()),
        });
        let principals = Arc::new(MemoryPrincipals {
            values: Mutex::new(HashMap::new()),
        });
        let nodes = Arc::new(MemoryNodes {
            values: Mutex::new(HashMap::new()),
            pins: Mutex::new(HashMap::new()),
            certificates: Mutex::new(HashMap::new()),
        });
        let resolver = Arc::new(RemoteIotaResolver::new(
            client.clone(),
            principals.clone(),
            nodes.clone(),
        ));
        (
            resolver,
            client,
            principals,
            nodes,
            locator,
            principal_id,
            user.public_key_bundle(),
        )
    }

    #[tokio::test]
    async fn discovery_cache_tracks_verified_generation_and_deadline() {
        let (resolver, client, _, nodes, locator, _, _) = remote_fixture(1);
        let authority = resolver.authority(&locator, true).await.unwrap();
        // Discovery alone never creates a verified cache entry.
        assert!(resolver.authorities.read().unwrap().is_empty());
        resolver
            .refresh(&locator, &authority, &UserSelector::UserId(7))
            .await
            .unwrap();
        client.authority.lock().unwrap().protocols = vec!["changed".into()];
        assert_eq!(
            resolver.authority(&locator, true).await.unwrap().protocols,
            authority.protocols
        );
        let fresh =
            RemoteIotaResolver::new(client.clone(), resolver.principals.clone(), nodes.clone())
                .with_discovery_freshness(std::time::Duration::ZERO);
        fresh
            .refresh(&locator, &authority, &UserSelector::UserId(7))
            .await
            .unwrap();
        assert_eq!(
            fresh.authority(&locator, true).await.unwrap().protocols,
            vec!["changed"]
        );
        let node = authority.node_id.as_ref().unwrap();
        nodes
            .values
            .lock()
            .unwrap()
            .get_mut(node)
            .unwrap()
            .descriptor_revision += 1;
        assert_eq!(
            resolver.authority(&locator, true).await.unwrap().protocols,
            vec!["changed"]
        );
        assert_ne!(
            resolver
                .authorities
                .read()
                .unwrap()
                .get(&locator)
                .unwrap()
                .descriptor_revision,
            nodes
                .values
                .lock()
                .unwrap()
                .get(node)
                .unwrap()
                .descriptor_revision
        );
    }

    #[tokio::test]
    async fn discovery_refresh_rejects_identity_change_and_removed_trust() {
        let (resolver, client, _, nodes, locator, _, _) = remote_fixture(1);
        let authority = resolver.authority(&locator, true).await.unwrap();
        resolver
            .refresh(&locator, &authority, &UserSelector::UserId(7))
            .await
            .unwrap();
        nodes.pins.lock().unwrap().remove(&locator);
        assert_eq!(
            resolver.authority(&locator, true).await.unwrap_err(),
            IdentityError::KeyPinMismatch
        );
        nodes
            .pins
            .lock()
            .unwrap()
            .insert(locator.clone(), authority.node_id.clone().unwrap());
        resolver
            .authorities
            .write()
            .unwrap()
            .get_mut(&locator)
            .unwrap()
            .verified_at = 0;
        client.authority.lock().unwrap().node_id = Some(
            IotaNodeId::from_public_keys(&mtp::crypto::Keyring::generate().public_key_bundle())
                .unwrap(),
        );
        assert!(matches!(
            resolver.authority(&locator, true).await.unwrap_err(),
            IdentityError::InvalidDescriptor(_)
        ));
    }

    #[tokio::test]
    async fn remote_iota_resolves_username_id_and_key_pin() {
        let (resolver, _, _, _, locator, principal, key) = remote_fixture(1);
        for selector in [
            UserSelector::Username("alice".into()),
            UserSelector::UserId(7),
        ] {
            let resolved = resolver
                .resolve_address(
                    &UserAddress {
                        selector,
                        public_key_pin: Some(key.clone()),
                        authority: Some(locator.clone()),
                    },
                    &ResolutionContext {
                        allow_network: true,
                        ..ResolutionContext::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(resolved.principal, principal);
        }
    }

    #[tokio::test]
    async fn remote_iota_rejects_wrong_key_pin() {
        let (resolver, _, _, _, locator, _, _) = remote_fixture(1);
        let error = resolver
            .resolve_address(
                &UserAddress {
                    selector: UserSelector::UserId(7),
                    public_key_pin: Some(mtp::crypto::Keyring::generate().public_key_bundle()),
                    authority: Some(locator.clone()),
                },
                &ResolutionContext {
                    allow_network: true,
                    ..ResolutionContext::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error, IdentityError::KeyPinMismatch);
    }

    #[tokio::test]
    async fn remote_iota_rejects_wrong_authority_signature() {
        let (resolver, client, _, _, locator, _, _) = remote_fixture(1);
        let descriptor = client
            .principal
            .lock()
            .unwrap()
            .clone()
            .parse()
            .unwrap()
            .descriptor;
        *client.principal.lock().unwrap() =
            SignedPrincipalDescriptor::sign(descriptor, &mtp::crypto::Keyring::generate())
                .unwrap()
                .to_wire_v1()
                .unwrap();

        let authority = client.discover(&locator).await.unwrap();
        let error = resolver
            .refresh(&locator, &authority, &UserSelector::UserId(7))
            .await
            .unwrap_err();
        assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
    }

    #[tokio::test]
    async fn remote_iota_rejects_stale_principal_revision() {
        let (resolver, client, principals, _, locator, _, _) = remote_fixture(1);
        let mut current = client
            .principal
            .lock()
            .unwrap()
            .clone()
            .parse()
            .unwrap()
            .descriptor;
        current.revision = 2;
        principals
            .upsert_remote_descriptor(
                &VerifiedPrincipalDescriptor::from_trusted_authority(current).unwrap(),
            )
            .unwrap();

        let authority = client.discover(&locator).await.unwrap();
        let error = resolver
            .refresh(&locator, &authority, &UserSelector::UserId(7))
            .await
            .unwrap_err();
        assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
    }

    #[tokio::test]
    async fn remote_iota_uses_valid_cached_descriptor_offline() {
        let (resolver, client, principals, nodes, locator, principal, _) = remote_fixture(1);
        let address = UserAddress {
            selector: UserSelector::UserId(7),
            public_key_pin: None,
            authority: Some(locator),
        };
        resolver
            .resolve_address(
                &address,
                &ResolutionContext {
                    allow_network: true,
                    ..ResolutionContext::default()
                },
            )
            .await
            .unwrap();

        let restarted = RemoteIotaResolver::new(client, principals, nodes);
        let cached = restarted
            .resolve_address(&address, &ResolutionContext::default())
            .await
            .unwrap();
        assert_eq!(cached.principal, principal);
    }

    #[tokio::test]
    async fn remote_iota_rejects_discovery_node_mismatch() {
        let (resolver, client, _, _, locator, _, _) = remote_fixture(1);
        client.authority.lock().unwrap().node_id = Some(node());

        let error = resolver
            .resolve_address(
                &UserAddress {
                    selector: UserSelector::UserId(7),
                    public_key_pin: None,
                    authority: Some(locator),
                },
                &ResolutionContext {
                    allow_network: true,
                    ..ResolutionContext::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
    }

    #[tokio::test]
    async fn raw_ip_bootstrap_rejects_changed_tofu_node() {
        let (resolver, _, _, nodes, locator, _, _) = remote_fixture(1);
        nodes.pins.lock().unwrap().insert(locator.clone(), node());

        let error = resolver
            .resolve_address(
                &UserAddress {
                    selector: UserSelector::UserId(7),
                    public_key_pin: None,
                    authority: Some(locator),
                },
                &ResolutionContext {
                    allow_network: true,
                    ..ResolutionContext::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, IdentityError::InvalidDescriptor(_)));
    }

    #[tokio::test]
    async fn raw_ip_bootstrap_accepts_explicit_node_key_pin() {
        let (resolver, client, _, nodes, locator, principal, _) = remote_fixture(1);
        let key = client
            .node
            .lock()
            .unwrap()
            .clone()
            .parse()
            .unwrap()
            .descriptor
            .public_keys;
        let pinned = resolver.pin_public_key(&locator, &key).unwrap();

        let resolved = resolver
            .resolve_address(
                &UserAddress {
                    selector: UserSelector::UserId(7),
                    public_key_pin: None,
                    authority: Some(locator.clone()),
                },
                &ResolutionContext {
                    allow_network: true,
                    ..ResolutionContext::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(resolved.principal, principal);
        assert!(matches!(resolved.home, PrincipalHome::Iota(home) if home == pinned));
        assert_eq!(
            nodes.pinned_endpoint_certificate(&locator).unwrap(),
            Some(b"test certificate".to_vec())
        );
        let resolved_at = nodes.resolve_node(&pinned).await.unwrap().resolved_at;

        *client.certificate.lock().unwrap() = b"changed certificate".to_vec();
        let authority = client.discover(&locator).await.unwrap();
        assert!(
            resolver
                .refresh(&locator, &authority, &UserSelector::UserId(7))
                .await
                .is_err()
        );
        assert_eq!(
            nodes.resolve_node(&pinned).await.unwrap().resolved_at,
            resolved_at
        );
    }

    #[tokio::test]
    async fn remote_omega_resolves_principal_and_hosting_iota() {
        let omega = mtp::crypto::Keyring::generate();
        let omega_authority = AuthorityId::for_omega(&omega.public_key_bundle()).unwrap();
        let hosting_iota =
            LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();
        let user = mtp::crypto::Keyring::generate();
        let locator = AuthorityLocator::new("omega.example.org").unwrap();
        let node = SignedNodeDescriptor::sign(
            NodeDescriptor {
                node: hosting_iota.node_id().clone(),
                public_keys: hosting_iota.public_keys(),
                direct_endpoints: vec![AuthorityLocator::new("iota.example.org").unwrap()],
                relay_hints: Vec::new(),
                revision: 1,
                valid_until: Some(now_millis() + 60_000),
            },
            &hosting_iota,
        )
        .unwrap()
        .to_wire_v1()
        .unwrap();
        let principal_id = PrincipalId {
            authority: omega_authority.clone(),
            user_id: 7,
        };
        let principal = SignedPrincipalDescriptor::sign(
            PrincipalDescriptor {
                principal: principal_id.clone(),
                authority_kind: AuthorityKind::Omega,
                username: Some("alice".into()),
                display_name: None,
                public_keys: vec![user.public_key_bundle()],
                home: PrincipalHome::Iota(hosting_iota.node_id().clone()),
                revision: 1,
                valid_until: Some(now_millis() + 60_000),
                issued_at: now_millis(),
            },
            &omega,
        )
        .unwrap()
        .to_wire_v1()
        .unwrap()
        .with_home_node(node);
        let client = Arc::new(FakeFederationClient {
            authority: Mutex::new(DiscoveredAuthority {
                service: AuthorityKind::Omega,
                authority_id: omega_authority,
                node_id: None,
                public_keys: omega.public_key_bundle(),
                protocols: vec!["identity-http-v1".into()],
                node_descriptor: None,
                direct_endpoints: Vec::new(),
                relay_hints: Vec::new(),
            }),
            node: Mutex::new(
                SignedNodeDescriptor::sign(
                    NodeDescriptor {
                        node: hosting_iota.node_id().clone(),
                        public_keys: hosting_iota.public_keys(),
                        direct_endpoints: Vec::new(),
                        relay_hints: Vec::new(),
                        revision: 1,
                        valid_until: Some(now_millis() + 60_000),
                    },
                    &hosting_iota,
                )
                .unwrap()
                .to_wire_v1()
                .unwrap(),
            ),
            principal: Mutex::new(principal),
            certificate: Mutex::new(b"test certificate".to_vec()),
        });
        let principals = Arc::new(MemoryPrincipals {
            values: Mutex::new(HashMap::new()),
        });
        let nodes = Arc::new(MemoryNodes {
            values: Mutex::new(HashMap::new()),
            pins: Mutex::new(HashMap::new()),
            certificates: Mutex::new(HashMap::new()),
        });
        let resolver = RemoteOmegaResolver::new(client, principals, nodes.clone());

        let resolved = resolver
            .resolve_address(
                &UserAddress {
                    selector: UserSelector::Username("alice".into()),
                    public_key_pin: Some(user.public_key_bundle()),
                    authority: Some(locator),
                },
                &ResolutionContext {
                    allow_network: true,
                    ..ResolutionContext::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(resolved.principal, principal_id);
        assert!(nodes.resolve_node(hosting_iota.node_id()).await.is_ok());
    }
}
