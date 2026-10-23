use async_trait::async_trait;
use iota_auth::{
    ForeignPrincipalAuthenticator, HostedSessionRegistrar, IotaPeerAuthenticator, SessionManager,
};
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_connection::relay_service::{RelayNodeIdentity, RelayService};
use iota_identity::{
    AuthorityId, AuthorityKind, AuthorityLocator, CompositeIdentityResolver, IdentityError,
    IdentityResolver, IotaNodeId, LocalUserStore, NodeDirectory, NodeIdentityResolver,
    PrincipalHome, PrincipalId, PrincipalStore, ResolutionContext, ResolvedNodeIdentity,
    ResolvedPrincipal, UserAddress,
};
use mtp::codec::CommunicationValue;
use omikron_connector::{OmikronClient, OmikronConnection};
use std::sync::Arc;

use crate::accounts::{
    AccountAuthority, AccountError, CreateUserRequest, CredentialPreview, LocalAccount,
    LocalIotaAccountAuthority, OmegaAccountAuthority, ReconcileResult,
};

#[derive(Default)]
pub struct UserService;
#[derive(Default)]
pub struct ConfigService;

pub struct CentralizedServices {
    pub omikron: Arc<dyn OmikronClient>,
}

pub struct AuthService {
    pub hosted_accounts: Arc<HostedSessionRegistrar>,
    pub foreign_principals: Arc<ForeignPrincipalAuthenticator>,
    pub iota_peers: Arc<IotaPeerAuthenticator>,
}

pub struct DaemonServiceComponents {
    pub accounts: Arc<dyn AccountAuthority>,
    pub identities: Arc<dyn IdentityResolver>,
    pub principals: Arc<dyn PrincipalStore>,
    pub local_users: Arc<dyn LocalUserStore>,
    pub node_identities: Arc<dyn NodeIdentityResolver>,
    pub relay: Arc<RelayService>,
    pub router: Arc<dyn PeerRouter>,
    pub direct_router: Option<Arc<other_iota::DirectPeerRouter>>,
    pub relay_routers: Option<Arc<other_iota::relay_router::RelayRouterSet>>,
    pub centralized: Option<Arc<CentralizedServices>>,
}

pub struct DaemonServices {
    pub accounts: Arc<dyn AccountAuthority>,
    pub identities: Arc<dyn IdentityResolver>,
    pub principals: Arc<dyn PrincipalStore>,
    pub local_users: Arc<dyn LocalUserStore>,
    pub relay: Arc<RelayService>,
    pub router: Arc<dyn PeerRouter>,
    pub direct_router: Option<Arc<other_iota::DirectPeerRouter>>,
    pub relay_routers: Option<Arc<other_iota::relay_router::RelayRouterSet>>,
    pub sessions: Arc<SessionManager>,
    pub auth: Arc<AuthService>,
    pub centralized: Option<Arc<CentralizedServices>>,
    pub users: Arc<UserService>,
    pub config: Arc<ConfigService>,
    pub active: bool,
}

impl DaemonServices {
    pub fn standalone(
        identity: iota_identity::LocalNodeIdentity,
    ) -> Result<Arc<Self>, IdentityError> {
        let principals = Arc::new(iota_storage::identity::SqlitePrincipalStore);
        let local_users: Arc<dyn LocalUserStore> =
            Arc::new(iota_storage::identity::SqliteLocalUserStore);
        let local_identity: Arc<dyn IdentityResolver> =
            Arc::new(iota_storage::identity::LocalIdentityResolver::new(
                identity.authority_id().clone(),
                AuthorityKind::Iota,
                PrincipalHome::Iota(identity.node_id().clone()),
                local_users.clone(),
                principals.clone(),
            ));
        let nodes = Arc::new(iota_storage::node_directory::SqliteNodeDirectory);
        let node_directory: Arc<dyn NodeDirectory> = nodes.clone();
        let web = &iota_storage::util::config_util::CONFIG.load().web;
        let federation_client: Arc<dyn other_iota::FederationIdentityClient> =
            Arc::new(other_iota::HttpFederationIdentityClient::new(
                web.allow_lan_federation,
                web.allow_raw_ip_federation,
            ));
        let remote_iota: Arc<dyn IdentityResolver> = Arc::new(
            other_iota::RemoteIotaResolver::new(
                federation_client.clone(),
                principals.clone(),
                node_directory.clone(),
            )
            .with_authority_directory(Arc::new(
                iota_storage::authority_directory::SqliteAuthorityDirectory,
            )),
        );
        let remote_omega: Arc<dyn IdentityResolver> =
            Arc::new(other_iota::RemoteOmegaResolver::new(
                federation_client,
                principals.clone(),
                node_directory,
            ));
        let identities: Arc<dyn IdentityResolver> =
            Arc::new(CompositeIdentityResolver::new(vec![
                local_identity,
                remote_iota,
                remote_omega,
            ])?);
        let direct_router = Arc::new(other_iota::DirectPeerRouter::default());
        let relay_routers = Arc::new(other_iota::relay_router::RelayRouterSet::default());
        let router: Arc<dyn PeerRouter> =
            Arc::new(other_iota::relay_router::DirectThenRelayRouter::new(
                direct_router.clone(),
                relay_routers.clone(),
            ));
        let relay_identity: Arc<dyn RelayNodeIdentity> =
            Arc::new(StandaloneRelayIdentity(identity.clone()));
        let relay = Arc::new(
            RelayService::new(local_users.clone(), router.clone())
                .with_federation(identities.clone(), relay_identity),
        );
        Ok(Self::compose(DaemonServiceComponents {
            accounts: Arc::new(LocalIotaAccountAuthority::new(identity.clone())),
            identities,
            principals,
            local_users,
            node_identities: nodes,
            relay,
            router,
            direct_router: Some(direct_router),
            relay_routers: Some(relay_routers),
            centralized: None,
        }))
    }

    pub fn new(
        omikron: Arc<OmikronConnection>,
        identity: iota_identity::LocalNodeIdentity,
    ) -> Result<Arc<Self>, IdentityError> {
        let client: Arc<dyn OmikronClient> = omikron.clone();
        let authority =
            AuthorityId::omega_legacy(&omikron_connector::omega_discovery::omega_host())
                .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        iota_storage::identity::SqlitePrincipalStore.migrate_legacy_omega_authority(&authority)?;
        let router: Arc<dyn PeerRouter> = Arc::new(
            omikron_connector::router::OmikronPeerRouter::new(client.clone()),
        );
        let services = Self::centralized(
            client,
            Some(router),
            Some(omikron.session_manager()),
            Some(Arc::new(StandaloneRelayIdentity(identity))),
        );
        let _ = omikron.install_relay_service(services.relay.clone());
        Ok(services)
    }

    pub fn with_centralized_client(client: Arc<dyn OmikronClient>) -> Arc<Self> {
        let inactive = Arc::new(InactiveServices);
        Self::centralized(client, None, None, Some(inactive))
    }

    fn centralized(
        client: Arc<dyn OmikronClient>,
        router: Option<Arc<dyn PeerRouter>>,
        sessions: Option<Arc<SessionManager>>,
        node_identity: Option<Arc<dyn RelayNodeIdentity>>,
    ) -> Arc<Self> {
        let principals: Arc<dyn PrincipalStore> =
            Arc::new(iota_storage::identity::SqlitePrincipalStore);
        let local_users: Arc<dyn LocalUserStore> =
            Arc::new(iota_storage::identity::SqliteLocalUserStore);
        let omega_host = omikron_connector::omega_discovery::omega_host();
        let authority = AuthorityId::omega_legacy(&omega_host)
            .expect("the configured Omega authority ID is valid");
        let locator = AuthorityLocator::new(omega_host)
            .expect("the configured Omega host is a valid authority locator");
        let local_identity: Arc<dyn IdentityResolver> =
            Arc::new(iota_storage::identity::LocalIdentityResolver::new(
                authority.clone(),
                AuthorityKind::Omega,
                node_identity
                    .as_ref()
                    .and_then(|identity| identity.node_id())
                    .map(PrincipalHome::Iota)
                    .unwrap_or_else(|| PrincipalHome::Omega(locator.clone())),
                local_users.clone(),
                Arc::new(iota_storage::identity::SqlitePrincipalStore),
            ));
        let omega_identity: Arc<dyn IdentityResolver> =
            Arc::new(omikron_connector::identity::OmegaIdentityResolver::new(
                client.clone(),
                authority.clone(),
                locator,
                principals.clone(),
            ));
        let identities: Arc<dyn IdentityResolver> = Arc::new(
            CompositeIdentityResolver::new(vec![local_identity, omega_identity])
                .expect("the identity resolver chain is not empty"),
        );
        let router: Arc<dyn PeerRouter> = router.unwrap_or_else(|| {
            Arc::new(omikron_connector::router::OmikronPeerRouter::new(
                client.clone(),
            ))
        });
        let mut relay = RelayService::new(local_users.clone(), router.clone());
        if let Some(node_identity) = node_identity {
            relay = relay.with_federation(identities.clone(), node_identity);
        }
        let relay = Arc::new(relay);
        Self::compose_with_sessions(
            DaemonServiceComponents {
                accounts: Arc::new(OmegaAccountAuthority::new(client.clone())),
                identities,
                principals,
                local_users,
                node_identities: Arc::new(InactiveNodeIdentityResolver),
                relay,
                router,
                direct_router: None,
                relay_routers: None,
                centralized: Some(Arc::new(CentralizedServices { omikron: client })),
            },
            sessions.unwrap_or_else(|| Arc::new(SessionManager::default())),
        )
    }

    pub fn compose(components: DaemonServiceComponents) -> Arc<Self> {
        Self::compose_with_sessions(components, Arc::new(SessionManager::default()))
    }

    fn compose_with_sessions(
        components: DaemonServiceComponents,
        sessions: Arc<SessionManager>,
    ) -> Arc<Self> {
        let auth = Arc::new(AuthService {
            hosted_accounts: Arc::new(HostedSessionRegistrar::new(sessions.clone())),
            foreign_principals: Arc::new(ForeignPrincipalAuthenticator::new(
                components.identities.clone(),
                sessions.clone(),
            )),
            iota_peers: Arc::new(IotaPeerAuthenticator::new(
                components.node_identities.clone(),
            )),
        });
        Arc::new(Self {
            accounts: components.accounts,
            identities: components.identities,
            principals: components.principals,
            local_users: components.local_users,
            relay: components.relay,
            router: components.router,
            direct_router: components.direct_router,
            relay_routers: components.relay_routers,
            sessions,
            auth,
            centralized: components.centralized,
            users: Arc::new(UserService),
            config: Arc::new(ConfigService),
            active: true,
        })
    }

    pub fn inactive() -> Arc<Self> {
        let identities: Arc<dyn IdentityResolver> = Arc::new(InactiveIdentityResolver);
        let sessions = Arc::new(SessionManager::default());
        let auth = Arc::new(AuthService {
            hosted_accounts: Arc::new(HostedSessionRegistrar::new(sessions.clone())),
            foreign_principals: Arc::new(ForeignPrincipalAuthenticator::new(
                identities.clone(),
                sessions.clone(),
            )),
            iota_peers: Arc::new(IotaPeerAuthenticator::new(Arc::new(
                InactiveNodeIdentityResolver,
            ))),
        });
        let inactive = Arc::new(InactiveServices);
        Arc::new(Self {
            accounts: inactive.clone(),
            identities: identities.clone(),
            principals: inactive.clone(),
            local_users: inactive.clone(),
            relay: Arc::new(RelayService::new(inactive.clone(), inactive.clone())),
            router: inactive,
            direct_router: None,
            relay_routers: None,
            sessions,
            auth,
            centralized: None,
            users: Arc::new(UserService),
            config: Arc::new(ConfigService),
            active: false,
        })
    }

    pub fn omikron(&self) -> Option<&Arc<dyn OmikronClient>> {
        self.centralized.as_ref().map(|services| &services.omikron)
    }
}

struct InactiveIdentityResolver;

struct InactiveNodeIdentityResolver;

struct StandaloneRelayIdentity(iota_identity::LocalNodeIdentity);

#[async_trait]
impl RelayNodeIdentity for StandaloneRelayIdentity {
    async fn keyring(&self) -> Option<Arc<mtp::crypto::Keyring>> {
        Some(self.0.keyring())
    }

    fn node_id(&self) -> Option<IotaNodeId> {
        Some(self.0.node_id().clone())
    }
}

#[async_trait]
impl NodeIdentityResolver for InactiveNodeIdentityResolver {
    async fn resolve_node(&self, _: &IotaNodeId) -> Result<ResolvedNodeIdentity, IdentityError> {
        Err(IdentityError::Unavailable(
            "node identity resolution is unavailable".into(),
        ))
    }
}

#[async_trait]
impl IdentityResolver for InactiveIdentityResolver {
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::Unavailable("daemon is inactive".into()))
    }

    async fn resolve_principal(&self, _: &PrincipalId) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::Unavailable("daemon is inactive".into()))
    }

    async fn signing_keys(
        &self,
        _: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<iota_identity::PublicKeyBundle>, IdentityError> {
        Err(IdentityError::Unavailable("daemon is inactive".into()))
    }
}

struct InactiveServices;

#[async_trait]
impl AccountAuthority for InactiveServices {
    async fn is_available(&self) -> bool {
        false
    }

    async fn create_user(&self, _: CreateUserRequest) -> Result<LocalAccount, AccountError> {
        Err(inactive_account())
    }

    async fn inspect_credential(&self, _: &[u8]) -> Result<CredentialPreview, AccountError> {
        Err(inactive_account())
    }

    async fn attach_user(&self, _: &[u8]) -> Result<LocalAccount, AccountError> {
        Err(inactive_account())
    }

    async fn reconcile_user(
        &self,
        _: iota_identity::LocalUserId,
    ) -> Result<ReconcileResult, AccountError> {
        Err(inactive_account())
    }

    async fn release_user(&self, _: iota_identity::LocalUserId) -> Result<(), AccountError> {
        Err(inactive_account())
    }

    async fn delete_user(
        &self,
        _: iota_identity::LocalUserId,
        _: &[u8],
    ) -> Result<(), AccountError> {
        Err(inactive_account())
    }

    async fn reconcile_managed_users(&self) -> Result<(), AccountError> {
        Err(inactive_account())
    }
}

fn inactive_account() -> AccountError {
    AccountError::Unavailable("daemon is inactive".into())
}

impl LocalUserStore for InactiveServices {
    fn get_local_user(
        &self,
        _: iota_identity::LocalUserId,
    ) -> Result<Option<iota_identity::LocalUserDescriptor>, IdentityError> {
        Ok(None)
    }

    fn get_local_user_by_username(
        &self,
        _: &str,
    ) -> Result<Option<iota_identity::LocalUserDescriptor>, IdentityError> {
        Ok(None)
    }

    fn is_hosted_here(&self, _: iota_identity::LocalUserId) -> Result<bool, IdentityError> {
        Ok(false)
    }

    fn local_user_for_principal(
        &self,
        _: iota_identity::PrincipalHandle,
    ) -> Result<Option<iota_identity::LocalUserId>, IdentityError> {
        Ok(None)
    }

    fn principal_for_local_user(
        &self,
        _: iota_identity::LocalUserId,
    ) -> Result<Option<iota_identity::PrincipalHandle>, IdentityError> {
        Ok(None)
    }
}

impl PrincipalStore for InactiveServices {
    fn get_principal(
        &self,
        _: iota_identity::PrincipalHandle,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(None)
    }

    fn get_by_canonical_id(
        &self,
        _: &PrincipalId,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(None)
    }

    fn get_by_username(
        &self,
        _: &AuthorityId,
        _: &str,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        Ok(None)
    }

    fn upsert_remote_descriptor(
        &self,
        _: &iota_identity::VerifiedPrincipalDescriptor,
    ) -> Result<iota_identity::PrincipalHandle, IdentityError> {
        Err(IdentityError::Unavailable("daemon is inactive".into()))
    }

    fn signing_keys(
        &self,
        _: &PrincipalId,
    ) -> Result<Vec<iota_identity::PublicKeyBundle>, IdentityError> {
        Err(IdentityError::NotFound)
    }
}

#[async_trait]
impl PeerRouter for InactiveServices {
    async fn route(
        &self,
        destination: &RouteDestination,
        _: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        match destination {
            RouteDestination::Iota(node) => Err(RouteError::NoRoute(node.clone())),
            RouteDestination::LegacyOmegaIota { .. } => Ok(RouteOutcome::Retryable {
                reason: "daemon is inactive".into(),
            }),
        }
    }
}

#[async_trait]
impl RelayNodeIdentity for InactiveServices {
    async fn keyring(&self) -> Option<Arc<mtp::crypto::Keyring>> {
        None
    }

    fn node_id(&self) -> Option<IotaNodeId> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_services_can_be_composed_without_omikron() {
        let adapters = Arc::new(InactiveServices);
        let identities: Arc<dyn IdentityResolver> = Arc::new(InactiveIdentityResolver);
        let services = DaemonServices::compose(DaemonServiceComponents {
            accounts: adapters.clone(),
            identities,
            principals: adapters.clone(),
            local_users: adapters.clone(),
            node_identities: Arc::new(InactiveNodeIdentityResolver),
            relay: Arc::new(RelayService::new(adapters.clone(), adapters.clone())),
            router: adapters,
            direct_router: None,
            relay_routers: None,
            centralized: None,
        });

        assert!(services.active);
        assert!(services.centralized.is_none());
    }
}
