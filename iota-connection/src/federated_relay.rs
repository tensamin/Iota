use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_identity::{
    IdentityError, IdentityResolver, IotaNodeId, PrincipalId, ResolutionContext, ResolvedPrincipal,
    verify_dual_signature,
};
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp::crypto::{Keyring, SignatureScheme};
use serde::{Deserialize, Serialize};

const SIGNING_DOMAIN: &[u8] = b"tensamin-federated-relay:v2";

#[derive(Clone, Debug)]
pub struct FederatedRelayV2 {
    pub signer: PrincipalId,
    pub recipient: PrincipalId,
    pub destination: IotaNodeId,
    pub message_id: String,
    pub created_at: u64,
    pub content: CommunicationValue,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct VerifiedFederatedRelayV2 {
    pub signer: ResolvedPrincipal,
    pub recipient: ResolvedPrincipal,
    pub destination: IotaNodeId,
    pub message_id: String,
    pub created_at: u64,
    pub content: CommunicationValue,
    pub frame: CommunicationValue,
}

#[derive(Serialize, Deserialize)]
struct FederatedRelayWireV2 {
    version: u32,
    signer: PrincipalId,
    recipient: PrincipalId,
    destination: IotaNodeId,
    message_id: String,
    created_at: u64,
    type_map_version: String,
    content: String,
    signature: String,
}

impl FederatedRelayV2 {
    pub fn sign(
        signer: PrincipalId,
        recipient: PrincipalId,
        destination: IotaNodeId,
        message_id: String,
        created_at: u64,
        content: CommunicationValue,
        keyring: &Keyring,
    ) -> Result<Self, IdentityError> {
        validate_fields(&signer, &recipient, &message_id, &content)?;
        let signer_impl = mtp::crypto::DualSigner::new(
            &keyring.sig_cl_secret_key,
            &keyring.sig_pq_secret_key,
            &keyring.sig_pq_public_key,
        )
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        let signature = signer_impl
            .sign(&canonical_bytes(
                &signer,
                &recipient,
                &destination,
                &message_id,
                created_at,
                &content,
            )?)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(Self {
            signer,
            recipient,
            destination,
            message_id,
            created_at,
            content,
            signature,
        })
    }

    pub fn into_frame(self, frame_id: u32) -> Result<CommunicationValue, IdentityError> {
        let type_map = self.content.type_map().ok_or_else(|| {
            IdentityError::InvalidDescriptor("federated relay content has no type map".into())
        })?;
        let content = self
            .content
            .to_bytes()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        let wire = FederatedRelayWireV2 {
            version: 2,
            signer: self.signer,
            recipient: self.recipient,
            destination: self.destination,
            message_id: self.message_id,
            created_at: self.created_at,
            type_map_version: type_map.version.to_string(),
            content: STANDARD.encode(content),
            signature: STANDARD.encode(self.signature),
        };
        let payload = serde_json::to_vec(&wire)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        Ok(CommunicationValue::new(CommunicationType::Relay)
            .with_id(frame_id)
            .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
            .add_typed_default(DataType::SecurePayload, DataValue::Bytes(payload)))
    }
}

pub async fn decode_and_verify(
    frame: CommunicationValue,
    identities: &dyn IdentityResolver,
    local_node: &IotaNodeId,
) -> Result<VerifiedFederatedRelayV2, IdentityError> {
    decode_and_verify_for_ingress(frame, identities, Some(local_node)).await
}

pub async fn decode_and_verify_for_ingress(
    frame: CommunicationValue,
    identities: &dyn IdentityResolver,
    expected_destination: Option<&IotaNodeId>,
) -> Result<VerifiedFederatedRelayV2, IdentityError> {
    if !frame.is_type(CommunicationType::Relay)
        || frame.get_data(DataType::VersionNumber).as_number() != Some(2)
    {
        return Err(IdentityError::InvalidDescriptor(
            "frame is not Federated Relay V2".into(),
        ));
    }
    let payload = frame
        .get_data(DataType::SecurePayload)
        .and_then(|value| match value {
            DataValue::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| IdentityError::InvalidDescriptor("Relay V2 payload is missing".into()))?;
    let wire: FederatedRelayWireV2 = serde_json::from_slice(payload)
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    if wire.version != 2
        || expected_destination.is_some_and(|expected| &wire.destination != expected)
    {
        return Err(IdentityError::InvalidDescriptor(
            "Relay V2 destination does not match this Iota".into(),
        ));
    }
    let type_map_version =
        mtp::type_map::Version::parse(&wire.type_map_version).ok_or_else(|| {
            IdentityError::InvalidDescriptor("Relay V2 type-map version is invalid".into())
        })?;
    let content_bytes = STANDARD
        .decode(&wire.content)
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    let content =
        CommunicationValue::from_bytes_with(&content_bytes, &TypeMap::new(type_map_version))
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    validate_fields(&wire.signer, &wire.recipient, &wire.message_id, &content)?;
    let signature = STANDARD
        .decode(&wire.signature)
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    let context = ResolutionContext {
        allow_network: true,
        ..ResolutionContext::default()
    };
    let signer = identities
        .resolve_principal_with_context(&wire.signer, &context)
        .await?;
    let recipient = identities
        .resolve_principal_with_context(&wire.recipient, &context)
        .await?;
    if !matches!(
        &recipient.home,
        iota_identity::PrincipalHome::Iota(home) if home == &wire.destination
    ) {
        return Err(IdentityError::InvalidDescriptor(
            "Relay V2 destination does not match recipient home".into(),
        ));
    }
    let bytes = canonical_bytes(
        &wire.signer,
        &wire.recipient,
        &wire.destination,
        &wire.message_id,
        wire.created_at,
        &content,
    )?;
    if !signer
        .public_keys
        .iter()
        .any(|key| verify_dual_signature(key, &bytes, &signature).is_ok())
    {
        return Err(IdentityError::InvalidDescriptor(
            "Relay V2 user signature is invalid".into(),
        ));
    }
    Ok(VerifiedFederatedRelayV2 {
        signer,
        recipient,
        destination: wire.destination,
        message_id: wire.message_id,
        created_at: wire.created_at,
        content,
        frame,
    })
}

fn validate_fields(
    signer: &PrincipalId,
    recipient: &PrincipalId,
    message_id: &str,
    content: &CommunicationValue,
) -> Result<(), IdentityError> {
    if signer == recipient {
        return Err(IdentityError::InvalidDescriptor(
            "Relay V2 signer and recipient are identical".into(),
        ));
    }
    if message_id.is_empty() || message_id.len() > 256 {
        return Err(IdentityError::InvalidDescriptor(
            "Relay V2 message ID is invalid".into(),
        ));
    }
    if content.type_map().is_none() || content.is_type(CommunicationType::Relay) {
        return Err(IdentityError::InvalidDescriptor(
            "Relay V2 content is invalid".into(),
        ));
    }
    Ok(())
}

fn canonical_bytes(
    signer: &PrincipalId,
    recipient: &PrincipalId,
    destination: &IotaNodeId,
    message_id: &str,
    created_at: u64,
    content: &CommunicationValue,
) -> Result<Vec<u8>, IdentityError> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    push(&mut bytes, signer.authority.as_str().as_bytes())?;
    bytes.extend_from_slice(&signer.user_id.to_be_bytes());
    push(&mut bytes, recipient.authority.as_str().as_bytes())?;
    bytes.extend_from_slice(&recipient.user_id.to_be_bytes());
    push(&mut bytes, destination.as_str().as_bytes())?;
    push(&mut bytes, message_id.as_bytes())?;
    bytes.extend_from_slice(&created_at.to_be_bytes());
    push(
        &mut bytes,
        &content
            .to_bytes()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
    )?;
    Ok(bytes)
}

fn push(output: &mut Vec<u8>, value: &[u8]) -> Result<(), IdentityError> {
    let length = u32::try_from(value.len())
        .map_err(|_| IdentityError::InvalidDescriptor("Relay V2 field is too large".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use iota_identity::{
        AuthorityId, PrincipalHandle, PrincipalHome, PublicKeyBundle, ResolvedPrincipal,
        UserAddress,
    };

    struct Resolver {
        principals: Vec<ResolvedPrincipal>,
    }

    #[async_trait]
    impl IdentityResolver for Resolver {
        async fn resolve_address(
            &self,
            _: &UserAddress,
            _: &ResolutionContext,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            Err(IdentityError::NotFound)
        }

        async fn resolve_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            self.principals
                .iter()
                .find(|candidate| &candidate.principal == principal)
                .cloned()
                .ok_or(IdentityError::NotFound)
        }

        async fn signing_keys(
            &self,
            principal: &PrincipalId,
            _: &ResolutionContext,
        ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
            self.resolve_principal(principal)
                .await
                .map(|principal| principal.public_keys)
        }
    }

    fn resolved(
        authority: &AuthorityId,
        user_id: u64,
        handle: i64,
        key: PublicKeyBundle,
        home: IotaNodeId,
    ) -> ResolvedPrincipal {
        ResolvedPrincipal {
            principal: PrincipalId {
                authority: authority.clone(),
                user_id,
            },
            handle: PrincipalHandle(handle),
            username: None,
            public_keys: vec![key],
            home: PrincipalHome::Iota(home),
            descriptor_revision: 1,
            valid_until: None,
            resolved_at: 1,
        }
    }

    fn relay() -> (
        CommunicationValue,
        Resolver,
        IotaNodeId,
        AuthorityId,
        AuthorityId,
    ) {
        let signer_node =
            iota_identity::LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
        let recipient_node =
            iota_identity::LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
        let signer = Keyring::generate();
        let recipient = Keyring::generate();
        let signer_principal = PrincipalId {
            authority: signer_node.authority_id().clone(),
            user_id: 7,
        };
        let recipient_principal = PrincipalId {
            authority: recipient_node.authority_id().clone(),
            user_id: 7,
        };
        let content = CommunicationValue::new(CommunicationType::MessageSend)
            .add_typed_default(DataType::Content, DataValue::Str("ciphertext".into()))
            .add_typed_default(DataType::SendTime, DataValue::SignedNumber(10))
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1));
        let frame = FederatedRelayV2::sign(
            signer_principal.clone(),
            recipient_principal.clone(),
            recipient_node.node_id().clone(),
            "same-id".into(),
            10,
            content,
            &signer,
        )
        .unwrap()
        .into_frame(5)
        .unwrap();
        let resolver = Resolver {
            principals: vec![
                resolved(
                    signer_node.authority_id(),
                    7,
                    1,
                    signer.public_key_bundle(),
                    signer_node.node_id().clone(),
                ),
                resolved(
                    recipient_node.authority_id(),
                    7,
                    2,
                    recipient.public_key_bundle(),
                    recipient_node.node_id().clone(),
                ),
            ],
        };
        (
            frame,
            resolver,
            recipient_node.node_id().clone(),
            signer_node.authority_id().clone(),
            recipient_node.authority_id().clone(),
        )
    }

    #[tokio::test]
    async fn equal_user_ids_from_different_iotas_verify_as_distinct_principals() {
        let (frame, resolver, node, signer_authority, recipient_authority) = relay();
        let verified = decode_and_verify(frame, &resolver, &node).await.unwrap();
        assert_eq!(verified.signer.principal.user_id, 7);
        assert_eq!(verified.recipient.principal.user_id, 7);
        assert_eq!(verified.signer.principal.authority, signer_authority);
        assert_eq!(verified.recipient.principal.authority, recipient_authority);
    }

    #[tokio::test]
    async fn changing_either_authority_invalidates_relay_signature() {
        for field in ["signer", "recipient"] {
            let (mut frame, mut resolver, node, _, _) = relay();
            let payload = frame
                .get_data(DataType::SecurePayload)
                .and_then(|value| match value {
                    DataValue::Bytes(bytes) => Some(bytes.clone()),
                    _ => None,
                })
                .unwrap();
            let mut wire: FederatedRelayWireV2 = serde_json::from_slice(&payload).unwrap();
            let changed = AuthorityId::new("authority:iota:v1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
            if field == "signer" {
                resolver.principals[0].principal.authority = changed.clone();
                wire.signer.authority = changed;
            } else {
                resolver.principals[1].principal.authority = changed.clone();
                wire.recipient.authority = changed;
            }
            frame = CommunicationValue::new(CommunicationType::Relay)
                .with_id(5)
                .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
                .add_typed_default(
                    DataType::SecurePayload,
                    DataValue::Bytes(serde_json::to_vec(&wire).unwrap()),
                );
            assert!(decode_and_verify(frame, &resolver, &node).await.is_err());
        }
    }
}
