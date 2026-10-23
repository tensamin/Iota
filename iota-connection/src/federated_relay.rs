use iota_identity::{
    AuthorityId, IdentityError, IdentityResolver, IotaNodeId, PrincipalId, ResolutionContext,
    ResolvedPrincipal,
};
use mtp::codec::{CommunicationValue, DataType, DataValue};
use mtp::crypto::{Keyring, PublicKeyBundle};
pub use tau_relay_protocol as protocol;

/// Application identity resolution stays in Iota. The shared protocol owns the wire and crypto.
#[derive(Clone, Debug)]
pub struct FederatedRelay {
    wire: tau_relay_protocol::RelayWire,
}

#[derive(Clone, Debug)]
pub struct VerifiedFederatedRelay {
    pub signer: ResolvedPrincipal,
    pub recipient: ResolvedPrincipal,
    pub destination: IotaNodeId,
    pub message_id: String,
    pub created_at: u64,
    pub content: Option<CommunicationValue>,
    pub frame: CommunicationValue,
    pub(crate) durable_outcome: Option<crate::relay_service::DurableOutcome>,
}

pub fn protocol_principal(principal: &PrincipalId) -> tau_relay_protocol::Principal {
    tau_relay_protocol::Principal {
        authority: principal.authority.as_str().into(),
        user_id: principal.user_id,
    }
}

pub(crate) fn canonical_principal(
    principal: &tau_relay_protocol::Principal,
) -> Result<PrincipalId, IdentityError> {
    if principal.user_id == 0 {
        return Err(IdentityError::InvalidIdentifier(
            "zero principal user ID".into(),
        ));
    }
    Ok(PrincipalId {
        authority: AuthorityId::new(&principal.authority)?,
        user_id: principal.user_id,
    })
}

fn protocol_error(error: tau_relay_protocol::Error) -> IdentityError {
    IdentityError::InvalidDescriptor(error.to_string())
}

impl FederatedRelay {
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit immutable signed relay and encryption recipients"
    )]
    pub fn sign(
        signer: PrincipalId,
        recipient: PrincipalId,
        destination: IotaNodeId,
        message_id: String,
        created_at: u64,
        content: CommunicationValue,
        keyring: &Keyring,
        encryption_recipients: Vec<PublicKeyBundle>,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            wire: tau_relay_protocol::sign_protected(
                protocol_principal(&signer),
                protocol_principal(&recipient),
                destination.as_str().into(),
                message_id,
                created_at,
                content,
                keyring,
                encryption_recipients,
            )
            .map_err(protocol_error)?,
        })
    }

    pub fn into_frame(self, frame_id: u32) -> Result<CommunicationValue, IdentityError> {
        self.wire.into_frame(frame_id).map_err(protocol_error)
    }
}

pub async fn decode_and_verify_for_ingress(
    frame: CommunicationValue,
    identities: &dyn IdentityResolver,
    expected_destination: Option<&IotaNodeId>,
    keyring: &Keyring,
) -> Result<VerifiedFederatedRelay, IdentityError> {
    let wire = parse_wire(&frame)?;
    let payload = match frame.get_data(DataType::SecurePayload) {
        Some(DataValue::Bytes(bytes)) => bytes,
        _ => unreachable!("parsed relay payload"),
    };
    let signer_id = canonical_principal(&wire.signer)?;
    let recipient_id = canonical_principal(&wire.recipient)?;
    let context = ResolutionContext {
        allow_network: true,
        ..ResolutionContext::default()
    };
    let signer = identities
        .resolve_principal_with_context(&signer_id, &context)
        .await?;
    let recipient = identities
        .resolve_principal_with_context(&recipient_id, &context)
        .await?;
    if signer.principal != signer_id
        || recipient.principal != recipient_id
        || signer.handle == recipient.handle
    {
        return Err(IdentityError::InvalidDescriptor(
            "resolved identities do not match the signed principals".into(),
        ));
    }
    let destination = IotaNodeId::new(&wire.destination)?;
    if !matches!(&recipient.home, iota_identity::PrincipalHome::Iota(home) if home == &destination)
    {
        return Err(IdentityError::InvalidDescriptor(
            "relay destination does not match recipient home".into(),
        ));
    }
    let opened = tau_relay_protocol::verify_and_open(
        payload,
        &signer.public_keys,
        keyring,
        Some(&protocol_principal(&recipient_id)),
        expected_destination.map(IotaNodeId::as_str),
    )
    .map_err(protocol_error)?;
    Ok(VerifiedFederatedRelay {
        signer,
        recipient,
        destination,
        message_id: opened.wire.message_id,
        created_at: opened.wire.created_at,
        content: Some(opened.application),
        frame,
        durable_outcome: None,
    })
}

pub fn parse_wire(
    frame: &CommunicationValue,
) -> Result<tau_relay_protocol::RelayWire, IdentityError> {
    tau_relay_protocol::RelayWire::from_frame(frame)
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
}
