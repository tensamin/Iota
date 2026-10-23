use super::*;

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
