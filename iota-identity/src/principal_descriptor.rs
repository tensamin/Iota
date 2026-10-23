use super::*;

impl SignedPrincipalDescriptor {
    pub fn to_wire_v1(&self) -> Result<PrincipalDescriptorWireV1, IdentityError> {
        Ok(PrincipalDescriptorWireV1 {
            version: 1,
            principal: self.descriptor.principal.clone(),
            authority_kind: self.descriptor.authority_kind,
            username: self.descriptor.username.clone(),
            display_name: self.descriptor.display_name.clone(),
            public_keys: self
                .descriptor
                .public_keys
                .iter()
                .map(|key| {
                    key.try_to_base64()
                        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            home: self.descriptor.home.clone(),
            revision: self.descriptor.revision,
            valid_until: self.descriptor.valid_until,
            issued_at: self.descriptor.issued_at,
            authority_signature: STANDARD.encode(&self.authority_signature),
            home_node: None,
        })
    }

    pub fn sign(
        descriptor: PrincipalDescriptor,
        authority: &mtp::crypto::Keyring,
    ) -> Result<Self, IdentityError> {
        use mtp::crypto::SignatureScheme;

        validate_principal_descriptor(&descriptor, descriptor.issued_at)?;
        let signer = mtp::crypto::DualSigner::new(
            &authority.sig_cl_secret_key,
            &authority.sig_pq_secret_key,
            &authority.sig_pq_public_key,
        )
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        let authority_signature = signer
            .sign(&principal_descriptor_bytes(&descriptor)?)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(Self {
            descriptor,
            authority_signature,
        })
    }

    pub fn verify(
        self,
        expected_authority: &AuthorityId,
        authority_keys: &PublicKeyBundle,
        current_revision: Option<i64>,
        now: i64,
    ) -> Result<VerifiedPrincipalDescriptor, IdentityError> {
        if &self.descriptor.principal.authority != expected_authority {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor authority mismatch".into(),
            ));
        }
        validate_principal_descriptor(&self.descriptor, now)?;
        if current_revision.is_some_and(|revision| revision > self.descriptor.revision) {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor revision is stale".into(),
            ));
        }
        verify_authority_signature(
            authority_keys,
            &principal_descriptor_bytes(&self.descriptor)?,
            &self.authority_signature,
        )?;
        if self.descriptor.authority_kind == AuthorityKind::Iota {
            let PrincipalHome::Iota(home) = &self.descriptor.home else {
                return Err(IdentityError::InvalidDescriptor(
                    "Iota principal descriptor has no Iota home".into(),
                ));
            };
            let signer_node = IotaNodeId::from_public_keys(authority_keys)?;
            if home != &signer_node || expected_authority != &AuthorityId::for_iota(&signer_node) {
                return Err(IdentityError::InvalidDescriptor(
                    "Iota principal descriptor signer does not match its authority".into(),
                ));
            }
        }
        Ok(VerifiedPrincipalDescriptor {
            descriptor: self.descriptor,
            resolved_at: now,
        })
    }
}

impl PrincipalDescriptorWireV1 {
    pub fn with_home_node(mut self, home_node: NodeDescriptorWireV1) -> Self {
        self.home_node = Some(home_node);
        self
    }

    pub fn parse(self) -> Result<SignedPrincipalDescriptor, IdentityError> {
        if self.version != 1 {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor wire version is unsupported".into(),
            ));
        }
        let public_keys = self
            .public_keys
            .into_iter()
            .map(|key| {
                PublicKeyBundle::from_base64(&key)
                    .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authority_signature = STANDARD
            .decode(self.authority_signature)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(SignedPrincipalDescriptor {
            descriptor: PrincipalDescriptor {
                principal: self.principal,
                authority_kind: self.authority_kind,
                username: self.username,
                display_name: self.display_name,
                public_keys,
                home: self.home,
                revision: self.revision,
                valid_until: self.valid_until,
                issued_at: self.issued_at,
            },
            authority_signature,
        })
    }
}

impl VerifiedPrincipalDescriptor {
    pub fn from_trusted_authority(descriptor: PrincipalDescriptor) -> Result<Self, IdentityError> {
        let resolved_at = descriptor.issued_at;
        validate_principal_descriptor(&descriptor, resolved_at)?;
        Ok(Self {
            descriptor,
            resolved_at,
        })
    }

    pub fn descriptor(&self) -> &PrincipalDescriptor {
        &self.descriptor
    }

    pub fn into_descriptor(self) -> PrincipalDescriptor {
        self.descriptor
    }

    pub fn resolved_at(&self) -> i64 {
        self.resolved_at
    }
}

pub(super) fn validate_principal_descriptor(
    descriptor: &PrincipalDescriptor,
    now: i64,
) -> Result<(), IdentityError> {
    if descriptor.revision < 0 {
        return Err(IdentityError::InvalidDescriptor(
            "principal descriptor revision is negative".into(),
        ));
    }
    if descriptor.public_keys.is_empty() {
        return Err(IdentityError::InvalidDescriptor(
            "principal descriptor contains no signing keys".into(),
        ));
    }
    for key in &descriptor.public_keys {
        key.validate()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    }
    if descriptor
        .valid_until
        .is_some_and(|valid_until| valid_until <= now)
    {
        return Err(IdentityError::InvalidDescriptor(
            "principal descriptor is expired".into(),
        ));
    }
    Ok(())
}

pub(super) fn verify_authority_signature(
    keys: &PublicKeyBundle,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    const ED25519_SIGNATURE_LENGTH: usize = 64;
    let (classical, post_quantum) = signature
        .split_at_checked(ED25519_SIGNATURE_LENGTH)
        .ok_or_else(|| {
            IdentityError::InvalidDescriptor("authority signature is truncated".into())
        })?;
    mtp::crypto::verify_ed25519(&keys.sig_cl_public_key, payload, classical)
        .and_then(|_| mtp::crypto::verify_ml_dsa(&keys.sig_pq_public_key, payload, post_quantum))
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
}

pub fn verify_dual_signature(
    keys: &PublicKeyBundle,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    verify_authority_signature(keys, payload, signature)
}

pub(super) fn principal_descriptor_bytes(
    descriptor: &PrincipalDescriptor,
) -> Result<Vec<u8>, IdentityError> {
    let mut bytes = b"tensamin-principal-descriptor:v1".to_vec();
    push_bytes(
        &mut bytes,
        descriptor.principal.authority.as_str().as_bytes(),
    )?;
    bytes.extend_from_slice(&descriptor.principal.user_id.to_be_bytes());
    bytes.push(match descriptor.authority_kind {
        AuthorityKind::Iota => 1,
        AuthorityKind::Omega => 2,
    });
    push_optional_string(&mut bytes, descriptor.username.as_deref())?;
    push_optional_string(&mut bytes, descriptor.display_name.as_deref())?;
    bytes.extend_from_slice(&descriptor.revision.to_be_bytes());
    push_optional_i64(&mut bytes, descriptor.valid_until);
    bytes.extend_from_slice(&descriptor.issued_at.to_be_bytes());
    match &descriptor.home {
        PrincipalHome::Iota(node) => {
            bytes.push(1);
            push_bytes(&mut bytes, node.as_str().as_bytes())?;
        }
        PrincipalHome::LegacyOmegaIota { omega, iota_id } => {
            bytes.push(2);
            push_bytes(&mut bytes, omega.as_str().as_bytes())?;
            bytes.extend_from_slice(&iota_id.to_be_bytes());
        }
        PrincipalHome::Omega(locator) => {
            bytes.push(3);
            push_bytes(&mut bytes, locator.as_str().as_bytes())?;
        }
        PrincipalHome::Unknown => bytes.push(4),
    }
    let key_count = u32::try_from(descriptor.public_keys.len()).map_err(|_| {
        IdentityError::InvalidDescriptor("principal descriptor has too many keys".into())
    })?;
    bytes.extend_from_slice(&key_count.to_be_bytes());
    for key in &descriptor.public_keys {
        push_bytes(
            &mut bytes,
            &key.try_as_bytes()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
        )?;
    }
    Ok(bytes)
}

pub(super) fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), IdentityError> {
    let length = u32::try_from(value.len())
        .map_err(|_| IdentityError::InvalidDescriptor("descriptor field is too large".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub(super) fn push_optional_string(
    output: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), IdentityError> {
    match value {
        Some(value) => {
            output.push(1);
            push_bytes(output, value.as_bytes())
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

pub(super) fn push_optional_i64(output: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}
