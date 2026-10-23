use super::*;

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
