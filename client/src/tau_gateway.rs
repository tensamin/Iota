use iota_identity::{IotaNodeId, LocalUserId, PrincipalHandle};
use tau::{AdmissionEngine, AuthenticationRequirement, RoleRule, RoleRules};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IotaConnectionRole {
    HostedClient,
    DirectPeer,
}

#[derive(Debug)]
pub enum IotaConnectionIdentity {
    HostedClient {
        local_user: LocalUserId,
        principal: PrincipalHandle,
        auth_generation: i64,
    },
    DirectPeer(IotaNodeId),
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("invalid connection description")]
    InvalidDescription,
    #[error("unsupported connection role")]
    UnsupportedRole,
    #[error("Tau admission rejected: {0}")]
    Admission(#[from] tau::AdmissionError),
    #[error("invalid hosted-user identity or key association")]
    InvalidHostedIdentity,
    #[error("hosted authentication storage lookup failed")]
    StorageLookup,
    #[error("authenticated key does not match hosted account")]
    InvalidHostedKeyBinding,
    #[error("missing hosted principal")]
    MissingHostedPrincipal,
    #[error("peer key, description, and authentication hint disagree")]
    InvalidPeerBinding,
    #[error("untrusted peer key")]
    UntrustedPeerKey,
    #[error("peer directory lookup failed or trusted descriptor unavailable")]
    PeerDirectoryLookup,
    #[error("application session creation failed: {0}")]
    SessionCreation(#[source] tau::AdmissionError),
    #[error("application session activation failed: {0}")]
    SessionActivation(#[source] tau::AdmissionError),
    #[error("connection handler execution failed")]
    HandlerExecution,
}

pub fn admission_engine() -> AdmissionEngine<IotaConnectionRole> {
    engine(true)
}

pub fn hosted_admission_engine() -> AdmissionEngine<IotaConnectionRole> {
    engine(false)
}

fn engine(peers: bool) -> AdmissionEngine<IotaConnectionRole> {
    let mut rules = RoleRules::new();
    for (description, role) in [
        ("client", IotaConnectionRole::HostedClient),
        ("iota-peer", IotaConnectionRole::DirectPeer),
    ] {
        if role == IotaConnectionRole::DirectPeer && !peers {
            continue;
        }
        rules
            .register(RoleRule {
                description: description.into(),
                authentication: AuthenticationRequirement::Authenticated,
                role,
            })
            .expect("Iota descriptions are unique");
    }
    AdmissionEngine::new(rules)
}

/// Normalize only the policy description. The original authentication facts
/// remain untouched; the peer declaration must still match the verified key.
pub(crate) fn parse_description(
    raw: Option<&str>,
) -> Result<(&'static str, Option<IotaNodeId>), GatewayError> {
    match raw {
        Some("client") => Ok(("client", None)),
        Some(raw) if raw.starts_with("iota-peer:") => {
            let node = IotaNodeId::new(&raw["iota-peer:".len()..])
                .map_err(|_| GatewayError::InvalidDescription)?;
            Ok(("iota-peer", Some(node)))
        }
        None => Err(GatewayError::InvalidDescription),
        _ => Err(GatewayError::UnsupportedRole),
    }
}

pub(crate) fn peer_identity(
    id: u64,
    key: &mtp::crypto::PublicKeyBundle,
    declared: Option<&IotaNodeId>,
) -> Result<IotaConnectionIdentity, GatewayError> {
    let node = IotaNodeId::from_public_keys(key).map_err(|_| GatewayError::InvalidPeerBinding)?;
    if declared != Some(&node) || id != node.mtp_authentication_hint() {
        return Err(GatewayError::InvalidPeerBinding);
    }
    Ok(IotaConnectionIdentity::DirectPeer(node))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_descriptions_and_key_binding_fail_closed() {
        let key = mtp::crypto::Keyring::generate().public_key_bundle();
        let node = IotaNodeId::from_public_keys(&key).unwrap();
        assert_eq!(parse_description(Some("client")).unwrap(), ("client", None));
        assert_eq!(
            parse_description(Some(&format!("iota-peer:{}", node.as_str()))).unwrap(),
            ("iota-peer", Some(node.clone()))
        );
        for raw in [
            None,
            Some(""),
            Some("CLIENT"),
            Some("client:1"),
            Some("iota-peer"),
            Some("iota-peer:"),
            Some("iota-peer:iota:v1:xyz"),
        ] {
            assert!(parse_description(raw).is_err());
        }
        assert!(peer_identity(node.mtp_authentication_hint(), &key, Some(&node)).is_ok());
        assert!(peer_identity(node.mtp_authentication_hint() ^ 1, &key, Some(&node)).is_err());
        assert!(peer_identity(node.mtp_authentication_hint(), &key, None).is_err());
        let other =
            IotaNodeId::from_public_keys(&mtp::crypto::Keyring::generate().public_key_bundle())
                .unwrap();
        assert!(peer_identity(node.mtp_authentication_hint(), &key, Some(&other)).is_err());
        let facts = tau::ConnectionFacts {
            mtp_client_id: 1,
            description: Some("client"),
            auth_state: mtp::host::AuthState::Unauthenticated,
            public_key: None,
            version: mtp::codec::Version(0, 3),
            path: "/",
            remote_addr: None,
        };
        assert!(admission_engine().admit(&facts).is_err());
        let authenticated = tau::ConnectionFacts {
            mtp_client_id: node.mtp_authentication_hint(),
            description: Some("iota-peer"),
            auth_state: mtp::host::AuthState::Authenticated,
            public_key: Some(&key),
            ..facts
        };
        assert!(admission_engine().admit(&authenticated).is_ok());
        assert!(hosted_admission_engine().admit(&authenticated).is_err());
    }
}
