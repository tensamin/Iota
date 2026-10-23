use super::*;

impl SignedNodeDescriptor {
    pub fn to_wire_v1(&self) -> Result<NodeDescriptorWireV1, IdentityError> {
        Ok(NodeDescriptorWireV1 {
            version: 1,
            node: self.descriptor.node.clone(),
            public_key: self
                .descriptor
                .public_keys
                .try_to_base64()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
            direct_endpoints: self.descriptor.direct_endpoints.clone(),
            relay_hints: self.descriptor.relay_hints.clone(),
            revision: self.descriptor.revision,
            valid_until: self.descriptor.valid_until,
            node_signature: STANDARD.encode(&self.node_signature),
        })
    }

    pub fn sign(
        descriptor: NodeDescriptor,
        identity: &LocalNodeIdentity,
    ) -> Result<Self, IdentityError> {
        use mtp::crypto::SignatureScheme;

        validate_node_descriptor(&descriptor, 0)?;
        if descriptor.node != *identity.node_id()
            || descriptor
                .public_keys
                .try_as_bytes()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?
                != identity
                    .public_keys()
                    .try_as_bytes()
                    .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?
        {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor does not match local identity".into(),
            ));
        }
        let keyring = identity.keyring();
        let signer = mtp::crypto::DualSigner::new(
            &keyring.sig_cl_secret_key,
            &keyring.sig_pq_secret_key,
            &keyring.sig_pq_public_key,
        )
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        let node_signature = signer
            .sign(&node_descriptor_bytes(&descriptor)?)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(Self {
            descriptor,
            node_signature,
        })
    }

    pub fn verify(
        self,
        current_revision: Option<i64>,
        now: i64,
    ) -> Result<VerifiedNodeDescriptor, IdentityError> {
        validate_node_descriptor(&self.descriptor, now)?;
        if current_revision.is_some_and(|revision| revision > self.descriptor.revision) {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor revision is stale".into(),
            ));
        }
        if IotaNodeId::from_public_keys(&self.descriptor.public_keys)? != self.descriptor.node {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor key does not match node ID".into(),
            ));
        }
        verify_authority_signature(
            &self.descriptor.public_keys,
            &node_descriptor_bytes(&self.descriptor)?,
            &self.node_signature,
        )?;
        Ok(VerifiedNodeDescriptor {
            descriptor: self.descriptor,
            resolved_at: now,
        })
    }
}

impl NodeDescriptorWireV1 {
    pub fn parse(self) -> Result<SignedNodeDescriptor, IdentityError> {
        if self.version != 1 {
            return Err(IdentityError::InvalidDescriptor(
                "node descriptor wire version is unsupported".into(),
            ));
        }
        Ok(SignedNodeDescriptor {
            descriptor: NodeDescriptor {
                node: self.node,
                public_keys: PublicKeyBundle::from_base64(&self.public_key)
                    .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
                direct_endpoints: self.direct_endpoints,
                relay_hints: self.relay_hints,
                revision: self.revision,
                valid_until: self.valid_until,
            },
            node_signature: STANDARD
                .decode(self.node_signature)
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
        })
    }
}

impl VerifiedNodeDescriptor {
    pub fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }

    pub fn into_descriptor(self) -> NodeDescriptor {
        self.descriptor
    }

    pub fn resolved_at(&self) -> i64 {
        self.resolved_at
    }
}

pub(super) fn validate_node_descriptor(
    descriptor: &NodeDescriptor,
    now: i64,
) -> Result<(), IdentityError> {
    if descriptor.revision < 0 {
        return Err(IdentityError::InvalidDescriptor(
            "node descriptor revision is negative".into(),
        ));
    }
    descriptor
        .public_keys
        .validate()
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    if descriptor
        .valid_until
        .is_some_and(|valid_until| valid_until <= now)
    {
        return Err(IdentityError::InvalidDescriptor(
            "node descriptor is expired".into(),
        ));
    }
    Ok(())
}

pub(super) fn node_descriptor_bytes(descriptor: &NodeDescriptor) -> Result<Vec<u8>, IdentityError> {
    let mut bytes = b"tensamin-node-descriptor:v1".to_vec();
    push_bytes(&mut bytes, descriptor.node.as_str().as_bytes())?;
    push_bytes(
        &mut bytes,
        &descriptor
            .public_keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
    )?;
    bytes.extend_from_slice(&descriptor.revision.to_be_bytes());
    push_optional_i64(&mut bytes, descriptor.valid_until);
    push_locators(&mut bytes, &descriptor.direct_endpoints)?;
    push_locators(&mut bytes, &descriptor.relay_hints)?;
    Ok(bytes)
}

pub(super) fn push_locators(
    output: &mut Vec<u8>,
    locators: &[AuthorityLocator],
) -> Result<(), IdentityError> {
    let count = u32::try_from(locators.len())
        .map_err(|_| IdentityError::InvalidDescriptor("too many node endpoints".into()))?;
    output.extend_from_slice(&count.to_be_bytes());
    for locator in locators {
        push_bytes(output, locator.as_str().as_bytes())?;
    }
    Ok(())
}
