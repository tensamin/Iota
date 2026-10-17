use dashmap::DashMap;
use iota_identity::{
    IdentityError, IdentityResolver, IotaNodeId, NodeIdentityResolver, PrincipalHandle, PrincipalId,
};
use mtp::crypto::{PublicKeyBundle, SigAlgorithm, verify_ed25519, verify_ml_dsa};
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{AuthenticatedSession, SessionCapabilities, SessionIdentity, SessionManager};

const CHALLENGE_LIFETIME: Duration = Duration::from_secs(60);
const OFFLINE_IDENTITY_TRUST: Duration = Duration::from_secs(24 * 60 * 60);
const CHALLENGE_DOMAIN: &[u8] = b"tensamin.foreign-principal-auth.v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthChallenge {
    pub id: Uuid,
    pub signed_payload: Vec<u8>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    Identity(IdentityError),
    ChallengeNotFound,
    ChallengeExpired,
    ChallengeConnectionMismatch,
    InvalidProof,
}

impl From<IdentityError> for AuthError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

struct PendingChallenge {
    principal: PrincipalHandle,
    keys: Vec<PublicKeyBundle>,
    connection_id: Uuid,
    signed_payload: Vec<u8>,
    expires_at: u64,
}

pub struct ForeignPrincipalAuthenticator {
    identities: Arc<dyn IdentityResolver>,
    sessions: Arc<SessionManager>,
    pending: DashMap<Uuid, PendingChallenge>,
}

impl ForeignPrincipalAuthenticator {
    pub fn new(identities: Arc<dyn IdentityResolver>, sessions: Arc<SessionManager>) -> Self {
        Self {
            identities,
            sessions,
            pending: DashMap::new(),
        }
    }

    pub async fn issue_challenge(
        &self,
        connection_id: Uuid,
        server: &IotaNodeId,
        principal: PrincipalId,
    ) -> Result<AuthChallenge, AuthError> {
        let resolution_context = iota_identity::ResolutionContext {
            allow_network: true,
            offline_policy: iota_identity::OfflineResolutionPolicy::AllowUnexpired {
                max_staleness: OFFLINE_IDENTITY_TRUST,
            },
        };
        let resolved = self
            .identities
            .resolve_principal_with_context(&principal, &resolution_context)
            .await?;
        if resolved.public_keys.is_empty() {
            return Err(AuthError::Identity(IdentityError::InvalidDescriptor(
                "principal has no current signing keys".into(),
            )));
        }
        let now = now_seconds();
        self.pending
            .retain(|_, challenge| challenge.expires_at > now);
        let mut nonce = vec![0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let id = Uuid::new_v4();
        let expires_at = now.saturating_add(CHALLENGE_LIFETIME.as_secs());
        let signed_payload =
            challenge_payload(id, connection_id, server, &principal, &nonce, expires_at);
        let challenge = AuthChallenge {
            id,
            signed_payload: signed_payload.clone(),
            expires_at,
        };
        self.pending.insert(
            challenge.id,
            PendingChallenge {
                principal: resolved.handle,
                keys: resolved.public_keys,
                connection_id,
                signed_payload,
                expires_at,
            },
        );
        Ok(challenge)
    }

    pub async fn authenticate(
        &self,
        connection_id: Uuid,
        challenge_id: Uuid,
        signature: &[u8],
    ) -> Result<AuthenticatedSession, AuthError> {
        let (_, pending) = self
            .pending
            .remove(&challenge_id)
            .ok_or(AuthError::ChallengeNotFound)?;
        if pending.connection_id != connection_id {
            return Err(AuthError::ChallengeConnectionMismatch);
        }
        if pending.expires_at <= now_seconds() {
            return Err(AuthError::ChallengeExpired);
        }
        if !pending
            .keys
            .iter()
            .any(|key| verify_dual(key, &pending.signed_payload, signature))
        {
            return Err(AuthError::InvalidProof);
        }
        let session = AuthenticatedSession {
            connection_id,
            identity: SessionIdentity::Foreign {
                principal: pending.principal,
            },
            capabilities: SessionCapabilities::foreign_authenticated(),
            hosted_lease: None,
        };
        self.sessions.insert(session.clone());
        Ok(session)
    }
}

pub struct HostedSessionRegistrar {
    sessions: Arc<SessionManager>,
}

impl HostedSessionRegistrar {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        Self { sessions }
    }

    pub fn authenticate(
        &self,
        connection_id: Uuid,
        lease: iota_identity::HostedAuthorizationLease,
    ) -> AuthenticatedSession {
        let session = AuthenticatedSession {
            connection_id,
            identity: SessionIdentity::Hosted {
                local_user: lease.identity.local_user,
                principal: lease.identity.principal,
            },
            capabilities: SessionCapabilities::hosted(),
            hosted_lease: Some(lease),
        };
        self.sessions.insert(session.clone());
        session
    }
}

pub struct IotaPeerAuthenticator {
    identities: Arc<dyn NodeIdentityResolver>,
}

impl IotaPeerAuthenticator {
    pub fn new(identities: Arc<dyn NodeIdentityResolver>) -> Self {
        Self { identities }
    }

    pub async fn trusted_keys(
        &self,
        identity: &IotaNodeId,
    ) -> Result<Vec<PublicKeyBundle>, AuthError> {
        self.identities
            .resolve_node(identity)
            .await
            .map(|resolved| resolved.public_keys)
            .map_err(Into::into)
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn challenge_payload(
    challenge_id: Uuid,
    connection_id: Uuid,
    server: &IotaNodeId,
    principal: &PrincipalId,
    nonce: &[u8],
    expires_at: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        CHALLENGE_DOMAIN.len()
            + 16
            + 16
            + server.as_str().len()
            + principal.authority.as_str().len()
            + nonce.len()
            + 32,
    );
    payload.extend_from_slice(CHALLENGE_DOMAIN);
    payload.extend_from_slice(challenge_id.as_bytes());
    payload.extend_from_slice(connection_id.as_bytes());
    append_field(&mut payload, server.as_str().as_bytes());
    append_field(&mut payload, principal.authority.as_str().as_bytes());
    payload.extend_from_slice(&principal.user_id.to_be_bytes());
    append_field(&mut payload, nonce);
    payload.extend_from_slice(&expires_at.to_be_bytes());
    payload
}

fn append_field(target: &mut Vec<u8>, field: &[u8]) {
    target.extend_from_slice(&(field.len() as u64).to_be_bytes());
    target.extend_from_slice(field);
}

fn verify_dual(key: &PublicKeyBundle, message: &[u8], signature: &[u8]) -> bool {
    let Some(classical_length) = SigAlgorithm::length(SigAlgorithm::ED25519) else {
        return false;
    };
    let Some(post_quantum_length) = SigAlgorithm::length(SigAlgorithm::ML_DSA_65) else {
        return false;
    };
    if signature.len() != classical_length + post_quantum_length {
        return false;
    }
    verify_ed25519(
        &key.sig_cl_public_key,
        message,
        &signature[..classical_length],
    )
    .and_then(|_| {
        verify_ml_dsa(
            &key.sig_pq_public_key,
            message,
            &signature[classical_length..],
        )
    })
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use iota_identity::LocalNodeIdentity;
    use iota_identity::{
        AuthorityId, IdentityResolver, PrincipalHome, ResolutionContext, ResolvedPrincipal,
        UserAddress,
    };
    use mtp::crypto::{DualSigner, Keyring, SignatureScheme};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CachedIdentity {
        principal: PrincipalId,
        key: PublicKeyBundle,
    }

    struct OneShotIdentity {
        resolved: ResolvedPrincipal,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl IdentityResolver for OneShotIdentity {
        async fn resolve_address(
            &self,
            _: &UserAddress,
            _: &ResolutionContext,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            Err(IdentityError::NotFound)
        }

        async fn resolve_principal(
            &self,
            _: &PrincipalId,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            Err(IdentityError::Unavailable("authority is offline".into()))
        }

        async fn resolve_principal_with_context(
            &self,
            _: &PrincipalId,
            _: &ResolutionContext,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(self.resolved.clone())
            } else {
                Err(IdentityError::Unavailable("authority is offline".into()))
            }
        }

        async fn signing_keys(
            &self,
            _: &PrincipalId,
            _: &ResolutionContext,
        ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
            Err(IdentityError::Unavailable("authority is offline".into()))
        }
    }

    #[async_trait]
    impl IdentityResolver for CachedIdentity {
        async fn resolve_address(
            &self,
            _: &UserAddress,
            _: &ResolutionContext,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            self.resolve_principal(&self.principal).await
        }

        async fn resolve_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            if principal != &self.principal {
                return Err(IdentityError::NotFound);
            }
            Ok(ResolvedPrincipal {
                principal: principal.clone(),
                handle: PrincipalHandle(44),
                username: Some("foreign-user".into()),
                public_keys: vec![self.key.clone()],
                home: PrincipalHome::Unknown,
                descriptor_revision: 1,
                valid_until: None,
                resolved_at: i64::MAX,
            })
        }

        async fn signing_keys(
            &self,
            principal: &PrincipalId,
            _: &ResolutionContext,
        ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
            self.resolve_principal(principal)
                .await
                .map(|resolved| resolved.public_keys)
        }
    }

    #[tokio::test]
    async fn cached_foreign_principal_authenticates_without_a_hosted_account() {
        let keyring = Keyring::generate();
        let principal = PrincipalId {
            authority: AuthorityId::new("omega:remote").unwrap(),
            user_id: 17,
        };
        let identities = Arc::new(CachedIdentity {
            principal: principal.clone(),
            key: keyring.public_key_bundle(),
        });
        let sessions = Arc::new(SessionManager::default());
        let authenticator = ForeignPrincipalAuthenticator::new(identities, sessions);
        let connection_id = Uuid::new_v4();
        let server = LocalNodeIdentity::from_keyring(Keyring::generate())
            .unwrap()
            .node_id()
            .clone();
        let challenge = authenticator
            .issue_challenge(connection_id, &server, principal.clone())
            .await
            .unwrap();
        let signer = DualSigner::new(
            &keyring.sig_cl_secret_key,
            &keyring.sig_pq_secret_key,
            &keyring.sig_pq_public_key,
        )
        .unwrap();
        let signature = signer.sign(&challenge.signed_payload).unwrap();
        let session = authenticator
            .authenticate(connection_id, challenge.id, &signature)
            .await
            .unwrap();

        assert_eq!(
            session.identity,
            SessionIdentity::Foreign {
                principal: PrincipalHandle(44)
            }
        );
        assert!(!session.allows(&crate::SessionCapability::LocalStorage));
        assert!(
            !session.allows(&crate::SessionCapability::Community(crate::CommunityId(
                "remote-community".into()
            )))
        );

        let other_challenge = authenticator
            .issue_challenge(connection_id, &server, principal)
            .await
            .unwrap();
        assert_eq!(
            authenticator
                .authenticate(Uuid::new_v4(), other_challenge.id, &[])
                .await,
            Err(AuthError::ChallengeConnectionMismatch)
        );
    }

    #[tokio::test]
    async fn challenge_uses_the_key_set_resolved_when_it_was_issued() {
        let keyring = Keyring::generate();
        let principal = PrincipalId {
            authority: AuthorityId::new("omega:remote").unwrap(),
            user_id: 18,
        };
        let identities = Arc::new(OneShotIdentity {
            resolved: ResolvedPrincipal {
                principal: principal.clone(),
                handle: PrincipalHandle(45),
                username: None,
                public_keys: vec![keyring.public_key_bundle()],
                home: PrincipalHome::Unknown,
                descriptor_revision: 1,
                valid_until: None,
                resolved_at: i64::MAX,
            },
            calls: AtomicUsize::new(0),
        });
        let sessions = Arc::new(SessionManager::default());
        let authenticator = ForeignPrincipalAuthenticator::new(identities.clone(), sessions);
        let connection_id = Uuid::new_v4();
        let server = LocalNodeIdentity::from_keyring(Keyring::generate())
            .unwrap()
            .node_id()
            .clone();
        let challenge = authenticator
            .issue_challenge(connection_id, &server, principal)
            .await
            .unwrap();
        let signer = DualSigner::new(
            &keyring.sig_cl_secret_key,
            &keyring.sig_pq_secret_key,
            &keyring.sig_pq_public_key,
        )
        .unwrap();
        let signature = signer.sign(&challenge.signed_payload).unwrap();

        authenticator
            .authenticate(connection_id, challenge.id, &signature)
            .await
            .unwrap();

        assert_eq!(identities.calls.load(Ordering::SeqCst), 1);
    }
}
