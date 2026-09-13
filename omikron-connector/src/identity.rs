use async_trait::async_trait;
use iota_identity::{
    AuthorityId, AuthorityKind, AuthorityLocator, IdentityError, IdentityResolver,
    PrincipalDescriptor, PrincipalHome, PrincipalId, PrincipalStore, ResolutionContext,
    ResolvedPrincipal, UserAddress, UserSelector,
};
use iota_util::crypto_helper::public_key_bundle_from_base64;
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::OmikronClient;

pub struct OmegaIdentityResolver {
    client: Arc<dyn OmikronClient>,
    authority: AuthorityId,
    locator: AuthorityLocator,
    principals: Arc<dyn PrincipalStore>,
}

impl OmegaIdentityResolver {
    pub fn new(
        client: Arc<dyn OmikronClient>,
        authority: AuthorityId,
        locator: AuthorityLocator,
        principals: Arc<dyn PrincipalStore>,
    ) -> Self {
        Self {
            client,
            authority,
            locator,
            principals,
        }
    }

    pub fn authority(&self) -> &AuthorityId {
        &self.authority
    }

    async fn resolve_remote(
        &self,
        selector: &UserSelector,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        resolve_omega_principal(
            self.client.as_ref(),
            self.principals.as_ref(),
            &self.authority,
            &self.locator,
            selector,
        )
        .await
    }

    async fn resolve_cached_or_remote(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        if principal.authority != self.authority {
            return Err(IdentityError::NotFound);
        }
        let cached = self.principals.get_by_canonical_id(principal)?;
        let now = now_millis();
        if let Some(resolved) = &cached
            && resolved.is_valid_at(now)
            && !resolved.public_keys.is_empty()
            && now.saturating_sub(resolved.resolved_at) < 900_000
        {
            return Ok(resolved.clone());
        }
        if context.allow_network {
            match self
                .resolve_remote(&UserSelector::UserId(principal.user_id))
                .await
            {
                Ok(resolved) => return Ok(resolved),
                Err(IdentityError::Unavailable(_)) => {}
                Err(error) => return Err(error),
            }
        }
        match cached {
            Some(resolved)
                if resolved.is_valid_at(now)
                    && !resolved.public_keys.is_empty()
                    && context
                        .offline_policy
                        .allows_cached(resolved.resolved_at, now) =>
            {
                Ok(resolved)
            }
            Some(_) => Err(IdentityError::Unavailable(
                "cached principal descriptor is stale".into(),
            )),
            None => Err(IdentityError::NotFound),
        }
    }
}

pub async fn resolve_omega_principal(
    client: &dyn OmikronClient,
    principals: &dyn PrincipalStore,
    authority: &AuthorityId,
    locator: &AuthorityLocator,
    selector: &UserSelector,
) -> Result<ResolvedPrincipal, IdentityError> {
    let request = match selector {
        UserSelector::UserId(user_id) => CommunicationValue::new(CommunicationType::GetUserData)
            .add_typed_default(
                DataType::UserId,
                DataValue::UnsignedNumber(u128::from(*user_id)),
            ),
        UserSelector::Username(username) => CommunicationValue::new(CommunicationType::GetUserData)
            .add_typed_default(DataType::Username, DataValue::Str(username.clone())),
    };
    let response = client
        .await_response(&request, Duration::from_secs(10))
        .await
        .map_err(|error| IdentityError::Unavailable(error.to_string()))?;
    if !response.is_type(CommunicationType::GetUserData) {
        return Err(IdentityError::InvalidDescriptor(
            "Omega returned an unexpected identity response".into(),
        ));
    }
    let user_id = response
        .get_data(DataType::UserId)
        .as_number()
        .and_then(|value| u64::try_from(value).ok())
        .or(match selector {
            UserSelector::UserId(user_id) => Some(*user_id),
            UserSelector::Username(_) => None,
        })
        .ok_or_else(|| IdentityError::InvalidDescriptor("Omega returned no user ID".into()))?;
    let public_key = response
        .get_data(DataType::PublicKey)
        .as_str()
        .and_then(public_key_bundle_from_base64)
        .ok_or_else(|| {
            IdentityError::InvalidDescriptor("Omega returned no valid user key".into())
        })?;
    let username = response
        .get_data(DataType::Username)
        .as_str()
        .map(str::to_owned);
    let home = response
        .get_data(DataType::IotaId)
        .as_number()
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .map(|iota_id| PrincipalHome::LegacyOmegaIota {
            omega: authority.clone(),
            iota_id,
        })
        .unwrap_or_else(|| PrincipalHome::Omega(locator.clone()));
    let principal = PrincipalId {
        authority: authority.clone(),
        user_id,
    };
    let descriptor =
        iota_identity::VerifiedPrincipalDescriptor::from_trusted_authority(PrincipalDescriptor {
            principal: principal.clone(),
            authority_kind: AuthorityKind::Omega,
            username: username.clone(),
            display_name: None,
            public_keys: vec![public_key],
            home,
            revision: 0,
            valid_until: None,
            issued_at: now_millis(),
        })?;
    let handle = principals.upsert_remote_descriptor(&descriptor)?;
    principals
        .get_principal(handle)?
        .ok_or(IdentityError::NotFound)
}

#[async_trait]
impl IdentityResolver for OmegaIdentityResolver {
    async fn resolve_address(
        &self,
        address: &UserAddress,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        if let Some(locator) = &address.authority
            && locator != &self.locator
            && locator.as_str() != self.authority.as_str()
        {
            return Err(IdentityError::NotFound);
        }
        let cached = match &address.selector {
            UserSelector::UserId(user_id) => self.principals.get_by_canonical_id(&PrincipalId {
                authority: self.authority.clone(),
                user_id: *user_id,
            })?,
            UserSelector::Username(_) => None,
        };
        let now = now_millis();
        let resolved = match cached {
            Some(resolved)
                if resolved.is_valid_at(now)
                    && !resolved.public_keys.is_empty()
                    && now.saturating_sub(resolved.resolved_at) < 900_000 =>
            {
                resolved
            }
            None if context.allow_network => self.resolve_remote(&address.selector).await?,
            Some(_) if context.allow_network => self.resolve_remote(&address.selector).await?,
            Some(resolved)
                if resolved.is_valid_at(now)
                    && !resolved.public_keys.is_empty()
                    && context
                        .offline_policy
                        .allows_cached(resolved.resolved_at, now) =>
            {
                resolved
            }
            None => return Err(IdentityError::NotFound),
            Some(_) => {
                return Err(IdentityError::Unavailable(
                    "cached principal descriptor is stale".into(),
                ));
            }
        };
        verify_pin(address, &resolved)?;
        Ok(resolved)
    }

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        if principal.authority != self.authority {
            return Err(IdentityError::NotFound);
        }
        if let Some(cached) = self.principals.get_by_canonical_id(principal)?
            && cached.is_valid_at(now_millis())
            && !cached.public_keys.is_empty()
            && now_millis().saturating_sub(cached.resolved_at) < 900_000
        {
            return Ok(cached);
        }
        self.resolve_remote(&UserSelector::UserId(principal.user_id))
            .await
    }

    async fn resolve_principal_with_context(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        self.resolve_cached_or_remote(principal, context).await
    }

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
        context: &ResolutionContext,
    ) -> Result<Vec<mtp::crypto::PublicKeyBundle>, IdentityError> {
        self.resolve_cached_or_remote(principal, context)
            .await
            .map(|resolved| resolved.public_keys)
    }
}

fn verify_pin(address: &UserAddress, resolved: &ResolvedPrincipal) -> Result<(), IdentityError> {
    let Some(pin) = &address.public_key_pin else {
        return Ok(());
    };
    let pin = pin
        .try_as_bytes()
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    if resolved.public_keys.iter().any(|key| {
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_identity::{OfflineResolutionPolicy, PrincipalHandle};
    use mtp::crypto::Keyring;

    struct CachedStore {
        resolved: ResolvedPrincipal,
    }

    impl PrincipalStore for CachedStore {
        fn get_principal(
            &self,
            handle: PrincipalHandle,
        ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
            Ok((handle == self.resolved.handle).then(|| self.resolved.clone()))
        }

        fn get_by_canonical_id(
            &self,
            principal: &PrincipalId,
        ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
            Ok((principal == &self.resolved.principal).then(|| self.resolved.clone()))
        }

        fn get_by_username(
            &self,
            authority: &AuthorityId,
            username: &str,
        ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
            Ok((authority == &self.resolved.principal.authority
                && self.resolved.username.as_deref() == Some(username))
            .then(|| self.resolved.clone()))
        }

        fn upsert_remote_descriptor(
            &self,
            _: &iota_identity::VerifiedPrincipalDescriptor,
        ) -> Result<PrincipalHandle, IdentityError> {
            Err(IdentityError::Storage(
                "unexpected descriptor update".into(),
            ))
        }

        fn signing_keys(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<mtp::crypto::PublicKeyBundle>, IdentityError> {
            self.get_by_canonical_id(principal)?
                .map(|resolved| resolved.public_keys)
                .ok_or(IdentityError::NotFound)
        }
    }

    struct OfflineClient;

    #[async_trait]
    impl OmikronClient for OfflineClient {
        async fn send_message(&self, _: &CommunicationValue) -> Result<(), crate::OmikronError> {
            Err(crate::OmikronError::Disconnected("offline".into()))
        }

        async fn await_response(
            &self,
            _: &CommunicationValue,
            _: Duration,
        ) -> Result<CommunicationValue, crate::OmikronError> {
            Err(crate::OmikronError::Disconnected("offline".into()))
        }

        async fn reconnect(&self) -> Result<(), crate::OmikronError> {
            Err(crate::OmikronError::Disconnected("offline".into()))
        }

        async fn rotate_identity(&self) -> Result<(), crate::OmikronError> {
            Err(crate::OmikronError::Disconnected("offline".into()))
        }

        async fn is_connected(&self) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn network_preferred_resolution_falls_back_to_unexpired_cache() {
        let authority = AuthorityId::new("omega:remote.example").unwrap();
        let principal = PrincipalId {
            authority: authority.clone(),
            user_id: 7,
        };
        let resolved = ResolvedPrincipal {
            principal: principal.clone(),
            handle: PrincipalHandle(9),
            username: Some("cached-user".into()),
            public_keys: vec![Keyring::generate().public_key_bundle()],
            home: PrincipalHome::Omega(AuthorityLocator::new("remote.example").unwrap()),
            descriptor_revision: 0,
            valid_until: None,
            resolved_at: now_millis().saturating_sub(16 * 60 * 1000),
        };
        let resolver = OmegaIdentityResolver::new(
            Arc::new(OfflineClient),
            authority,
            AuthorityLocator::new("remote.example").unwrap(),
            Arc::new(CachedStore { resolved }),
        );

        let cached = resolver
            .resolve_principal_with_context(
                &principal,
                &ResolutionContext {
                    allow_network: true,
                    offline_policy: OfflineResolutionPolicy::AllowUnexpired {
                        max_staleness: Duration::from_secs(24 * 60 * 60),
                    },
                },
            )
            .await
            .unwrap();

        assert_eq!(cached.handle, PrincipalHandle(9));
    }
}
