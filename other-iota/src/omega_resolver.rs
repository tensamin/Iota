use super::*;

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

    pub(super) async fn authority(
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

    pub(super) async fn refresh(
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
