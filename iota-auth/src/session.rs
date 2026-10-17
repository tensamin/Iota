use dashmap::DashMap;
use iota_identity::{LocalUserId, PrincipalHandle};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CommunityId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionCapability {
    AccountData,
    Messaging,
    Settings,
    LocalStorage,
    Communities,
    Community(CommunityId),
    RelayOrigination,
    Federation,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionCapabilities(HashSet<SessionCapability>);

impl SessionCapabilities {
    pub fn hosted() -> Self {
        Self(HashSet::from([
            SessionCapability::AccountData,
            SessionCapability::Messaging,
            SessionCapability::Settings,
            SessionCapability::LocalStorage,
            SessionCapability::Communities,
            SessionCapability::RelayOrigination,
            SessionCapability::Federation,
        ]))
    }

    pub fn for_community(community: CommunityId) -> Self {
        Self(HashSet::from([SessionCapability::Community(community)]))
    }

    pub fn foreign_authenticated() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, capability: SessionCapability) {
        self.0.insert(capability);
    }

    pub fn allows(&self, capability: &SessionCapability) -> bool {
        self.0.contains(capability)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionIdentity {
    Hosted {
        local_user: LocalUserId,
        principal: PrincipalHandle,
    },
    Foreign {
        principal: PrincipalHandle,
    },
}

impl SessionIdentity {
    pub fn principal(&self) -> PrincipalHandle {
        match self {
            Self::Hosted { principal, .. } | Self::Foreign { principal } => *principal,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedSession {
    pub connection_id: Uuid,
    pub identity: SessionIdentity,
    pub capabilities: SessionCapabilities,
    pub hosted_lease: Option<iota_identity::HostedAuthorizationLease>,
}

impl AuthenticatedSession {
    pub fn principal(&self) -> PrincipalHandle {
        self.identity.principal()
    }

    pub fn allows(&self, capability: &SessionCapability) -> bool {
        self.capabilities.allows(capability)
    }
}

#[derive(Default)]
pub struct SessionManager {
    sessions: DashMap<Uuid, AuthenticatedSession>,
}

impl SessionManager {
    pub fn insert(&self, session: AuthenticatedSession) {
        self.sessions.insert(session.connection_id, session);
    }

    pub fn get(&self, connection_id: Uuid) -> Option<AuthenticatedSession> {
        self.sessions
            .get(&connection_id)
            .map(|session| session.clone())
    }

    pub fn snapshot(&self) -> Vec<AuthenticatedSession> {
        self.sessions
            .iter()
            .map(|session| session.value().clone())
            .collect()
    }

    pub fn remove(&self, connection_id: Uuid) -> Option<AuthenticatedSession> {
        self.sessions
            .remove(&connection_id)
            .map(|(_, session)| session)
    }

    pub fn remove_principal(&self, principal: PrincipalHandle) {
        self.sessions
            .retain(|_, session| session.principal() != principal);
    }

    pub fn grant_community(
        &self,
        connection_id: Uuid,
        community: CommunityId,
    ) -> Result<AuthenticatedSession, SessionAuthorizationError> {
        let mut session = self
            .sessions
            .get_mut(&connection_id)
            .ok_or(SessionAuthorizationError::UnknownSession)?;
        session
            .capabilities
            .grant(SessionCapability::Community(community));
        Ok(session.clone())
    }

    pub fn authorize(
        &self,
        connection_id: Uuid,
        capability: &SessionCapability,
    ) -> Result<AuthenticatedSession, SessionAuthorizationError> {
        let session = self
            .get(connection_id)
            .ok_or(SessionAuthorizationError::UnknownSession)?;
        if !session.allows(capability) {
            return Err(SessionAuthorizationError::CapabilityDenied);
        }
        Ok(session)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionAuthorizationError {
    UnknownSession,
    CapabilityDenied,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_community_session_cannot_access_hosted_data() {
        let manager = SessionManager::default();
        let connection_id = Uuid::new_v4();
        manager.insert(AuthenticatedSession {
            connection_id,
            identity: SessionIdentity::Foreign {
                principal: PrincipalHandle(12),
            },
            capabilities: SessionCapabilities::for_community(CommunityId("community-a".into())),
            hosted_lease: None,
        });

        assert!(
            manager
                .authorize(connection_id, &SessionCapability::AccountData)
                .is_err()
        );
        assert!(
            manager
                .authorize(
                    connection_id,
                    &SessionCapability::Community(CommunityId("community-a".into()))
                )
                .is_ok()
        );
    }

    #[test]
    fn hosted_session_exposes_its_principal() {
        let session = AuthenticatedSession {
            connection_id: Uuid::new_v4(),
            identity: SessionIdentity::Hosted {
                local_user: LocalUserId(4),
                principal: PrincipalHandle(9),
            },
            capabilities: SessionCapabilities::hosted(),
            hosted_lease: None,
        };
        assert_eq!(session.principal(), PrincipalHandle(9));
    }
}
