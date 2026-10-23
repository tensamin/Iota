use super::*;

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
            authority_directory: None,
        }
    }

    pub fn with_discovery_freshness(mut self, freshness: std::time::Duration) -> Self {
        self.discovery_freshness = freshness;
        self
    }

    pub fn with_authority_directory(
        mut self,
        directory: Arc<dyn iota_identity::AuthorityDirectory>,
    ) -> Self {
        self.authority_directory = Some(directory);
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

    pub(super) async fn authority(
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
                protocols: iota_identity::FEDERATION_PROTOCOLS
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
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

    pub async fn verify_authority_locator(
        &self,
        locator: &AuthorityLocator,
    ) -> Result<IotaNodeId, IdentityError> {
        let authority = self.authority(locator, true).await?;
        let verified = self.refresh_node(locator, &authority).await?;
        Ok(verified.descriptor().node.clone())
    }

    pub async fn refresh_node_identity(&self, node: &IotaNodeId) -> Result<(), IdentityError> {
        let directory = self
            .authority_directory
            .as_ref()
            .ok_or(IdentityError::NotFound)?;
        let mut unavailable = None;
        for locator in directory.locators_for(&AuthorityId::for_iota(node))? {
            match self.verify_authority_locator(&locator).await {
                Ok(found) if &found == node => return Ok(()),
                Ok(_) => return Err(IdentityError::KeyPinMismatch),
                Err(e @ IdentityError::Unavailable(_)) => unavailable = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(unavailable.unwrap_or(IdentityError::NotFound))
    }

    pub(super) async fn refresh_node(
        &self,
        locator: &AuthorityLocator,
        authority: &DiscoveredAuthority,
    ) -> Result<iota_identity::VerifiedNodeDescriptor, IdentityError> {
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
        if node_path != "/federation/v1/node" {
            return Err(IdentityError::InvalidDescriptor(
                "unexpected node descriptor path".into(),
            ));
        }
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
        let verified_node = iota_storage::blocking::identity_lookup(move || {
            signed_node.verify(current_node_revision, now_millis())
        })
        .await?;
        self.nodes.upsert_node_descriptor(&verified_node)?;
        self.nodes
            .pin_endpoint(locator, expected_node, now_millis())?;
        if let Some(certificate) = raw_ip_certificate {
            self.nodes.pin_endpoint_certificate(locator, certificate)?;
        }
        let node = self.nodes.resolve_node(expected_node).await?;
        if let Some(directory) = &self.authority_directory {
            directory.record_verified_iota(
                locator,
                &authority.authority_id,
                expected_node,
                node.resolved_at,
            )?;
        }
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

        Ok(verified_node)
    }

    pub(super) async fn refresh(
        &self,
        locator: &AuthorityLocator,
        authority: &DiscoveredAuthority,
        selector: &UserSelector,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        let verified_node = self.refresh_node(locator, authority).await?;
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

    pub(super) fn cached(
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
        if context.allow_network {
            let mut locators = match &self.authority_directory {
                Some(directory) => directory.locators_for(&principal.authority)?,
                None => Vec::new(),
            };
            if let Some(locator) = locator
                && !locators.contains(&locator)
            {
                locators.push(locator);
            }
            let mut unavailable = None;
            for locator in locators {
                let result = async {
                    let authority = self.authority(&locator, true).await?;
                    if authority.authority_id != principal.authority {
                        return Err(IdentityError::KeyPinMismatch);
                    }
                    self.refresh(
                        &locator,
                        &authority,
                        &UserSelector::UserId(principal.user_id),
                    )
                    .await
                }
                .await;
                match result {
                    Ok(found) => return Ok(found),
                    Err(error @ IdentityError::Unavailable(_)) => unavailable = Some(error),
                    Err(error) => return Err(error),
                }
            }
            if let Some(error) = unavailable {
                return Err(error);
            }
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
