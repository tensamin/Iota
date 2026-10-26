use iota_identity::{
    AuthorityId, IdentityError, IdentityResolver, IotaNodeId, PrincipalId, ResolutionContext,
    ResolvedPrincipal,
};
use mtp::codec::{CommunicationValue, DataType, DataValue};
use mtp::crypto::{Keyring, PublicKeyBundle};
pub use tau_relay_protocol as protocol;

pub const NATIVE_PEER_FRAME: &str = "tensamin-native-peer-v1";

/// Peer channels negotiate their own dictionary. Preserve the original native
/// dictionary and sealed bytes rather than reinterpreting them on the next hop.
pub fn native_peer_frame(frame: CommunicationValue) -> Result<CommunicationValue, IdentityError> {
    if !frame.is_type(mtp::codec::CommunicationType::Relay)
        || frame.payload().as_encrypted().is_none()
    {
        return Err(IdentityError::InvalidDescriptor(
            "expected native sealed relay".into(),
        ));
    }
    let map = frame.type_map().ok_or_else(|| {
        IdentityError::InvalidDescriptor("missing native relay dictionary".into())
    })?;
    let original = frame
        .clone()
        .without_id()
        .to_bytes()
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    let mut wrapper = CommunicationValue::new(mtp::codec::CommunicationType::Relay)
        .add_typed_default(DataType::Status, DataValue::Str(NATIVE_PEER_FRAME.into()))
        .add_typed_default(DataType::Version, DataValue::Str(map.version.to_string()))
        .add_typed_default(DataType::SecurePayload, DataValue::Bytes(original));
    if let Some(id) = frame.id() {
        wrapper = wrapper.with_id(id);
    }
    Ok(wrapper)
}

pub fn open_native_peer_frame(
    frame: &CommunicationValue,
) -> Result<CommunicationValue, IdentityError> {
    let invalid = || IdentityError::InvalidDescriptor("invalid native peer frame".into());
    if !frame.is_type(mtp::codec::CommunicationType::Relay)
        || frame.sender().is_some()
        || frame.receiver().is_some()
        || frame.data_len() != 3
    {
        return Err(invalid());
    }
    if frame.get_data(DataType::Status).and_then(DataValue::as_str) != Some(NATIVE_PEER_FRAME) {
        return Err(invalid());
    }
    let version = frame
        .get_data(DataType::Version)
        .and_then(DataValue::as_str)
        .and_then(mtp::type_map::Version::parse)
        .ok_or_else(invalid)?;
    let Some(DataValue::Bytes(bytes)) = frame.get_data(DataType::SecurePayload) else {
        return Err(invalid());
    };
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    let original =
        CommunicationValue::try_from_bytes_with(bytes, &mtp::codec::TypeMap::new(version))
            .map_err(|_| invalid())?;
    if !original.is_type(mtp::codec::CommunicationType::Relay)
        || original.payload().as_encrypted().is_none()
        || original.id().is_some()
    {
        return Err(invalid());
    }
    Ok(original.with_id(frame.id().ok_or_else(invalid)?))
}

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
    if matches!(&error, tau_relay_protocol::Error::Mtp(message) if message == "no matching recipient" || message == "protection error: no matching recipient")
    {
        return IdentityError::Unavailable(
            "original relay decryption material is unavailable".into(),
        );
    }
    IdentityError::InvalidDescriptor(error.to_string())
}

fn native_error(error: mtp::codec::relay::RelayError) -> IdentityError {
    if matches!(
        error,
        mtp::codec::relay::RelayError::Protection(mtp::codec::ProtectionError::NoMatchingRecipient)
    ) {
        IdentityError::Unavailable(
            "original native relay decryption material is unavailable".into(),
        )
    } else {
        IdentityError::InvalidDescriptor(error.to_string())
    }
}

/// Native frames contain numeric principals only. Never guess an authority or
/// reinterpret a numeric principal as an application-local database handle.
pub(crate) fn unique_numeric_principal(id: u64) -> Result<ResolvedPrincipal, IdentityError> {
    use iota_identity::PrincipalStore;
    let id = i64::try_from(id)
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| IdentityError::InvalidIdentifier("invalid native principal".into()))?;
    let handles = iota_storage::util::db::with_db(|connection| {
        let mut statement = connection
            .prepare("SELECT principal_pk FROM principals WHERE remote_user_id = ?1 LIMIT 2")?;
        Ok(statement
            .query_map([id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?)
    })
    .map_err(|error| IdentityError::Storage(error.to_string()))?;
    if handles.len() != 1 {
        return Err(IdentityError::InvalidDescriptor(
            "native numeric principal is unknown or ambiguous".into(),
        ));
    }
    iota_storage::identity::SqlitePrincipalStore
        .get_principal(iota_identity::PrincipalHandle(handles[0]))?
        .ok_or(IdentityError::NotFound)
}

pub(crate) async fn resolve_and_verify_native_for_ingress(
    frame: CommunicationValue,
    identities: &dyn IdentityResolver,
    expected_destination: Option<&IotaNodeId>,
    keyring: &Keyring,
) -> Result<VerifiedFederatedRelay, IdentityError> {
    use mtp::codec::{ProtectionPolicy, relay::*};
    let options = RelayOpenOptions::new(ProtectionPolicy::ed25519());
    let invalid = native_error;
    let claimed = relay_metadata_claimed_signer_id_with_options(
        &frame,
        &[keyring],
        options.decode_limits,
        options.protected_limits,
    )
    .map_err(invalid)?;
    let context = ResolutionContext {
        allow_network: true,
        ..ResolutionContext::default()
    };
    let candidate = unique_numeric_principal(claimed)?;
    let signer = identities
        .resolve_principal_with_context(&candidate.principal, &context)
        .await?;
    if signer.principal != candidate.principal || signer.handle != candidate.handle {
        return Err(IdentityError::InvalidDescriptor(
            "native signer resolution changed identity".into(),
        ));
    }
    let metadata = open_relay_metadata_with_limits_without_replay(
        &frame,
        &[keyring],
        Some(claimed),
        |id| (id == claimed).then(|| signer.public_keys.clone()),
        options,
    )
    .map_err(invalid)?;
    let candidate = unique_numeric_principal(metadata.final_recipient_id())?;
    let recipient = identities
        .resolve_principal_with_context(&candidate.principal, &context)
        .await?;
    if recipient.principal != candidate.principal || recipient.handle != candidate.handle {
        return Err(IdentityError::InvalidDescriptor(
            "native recipient resolution changed identity".into(),
        ));
    }
    let iota_identity::PrincipalHome::Iota(destination) = &recipient.home else {
        return Err(IdentityError::InvalidDescriptor(
            "native recipient has no Iota home".into(),
        ));
    };
    if expected_destination.is_some_and(|expected| expected != destination) {
        return Err(IdentityError::InvalidDescriptor(
            "native destination is not this node".into(),
        ));
    }
    let destination = destination.clone();
    decode_and_verify_native_for_ingress(frame, signer, recipient, &destination, keyring, options)
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

/// Open the native sealed format without translating its signature into Tau JSON.
/// The caller must select both principals from authenticated, unambiguous identity
/// resolution and bind the signer to the ingress session or authenticated peer.
/// Durable replay must use the returned message ID and original frame together.
pub fn decode_and_verify_native_for_ingress(
    frame: CommunicationValue,
    signer: ResolvedPrincipal,
    recipient: ResolvedPrincipal,
    expected_destination: &IotaNodeId,
    keyring: &Keyring,
    options: mtp::codec::relay::RelayOpenOptions,
) -> Result<VerifiedFederatedRelay, IdentityError> {
    use mtp::codec::relay::{
        open_relay_content_with_limits_without_replay,
        open_relay_metadata_with_limits_without_replay,
    };

    if signer.principal == recipient.principal
        || signer.handle == recipient.handle
        || signer.principal.user_id == 0
        || recipient.principal.user_id == 0
        || signer.principal.user_id == recipient.principal.user_id
        || !matches!(&recipient.home, iota_identity::PrincipalHome::Iota(home) if home == expected_destination)
    {
        return Err(IdentityError::InvalidDescriptor(
            "native relay principals or destination are ambiguous".into(),
        ));
    }
    let relay_error = native_error;
    let metadata = open_relay_metadata_with_limits_without_replay(
        &frame,
        &[keyring],
        Some(signer.principal.user_id),
        |id| (id == signer.principal.user_id).then(|| signer.public_keys.clone()),
        options,
    )
    .map_err(relay_error)?;
    let content = open_relay_content_with_limits_without_replay(
        &metadata,
        &[keyring],
        &signer.public_keys,
        Some(recipient.principal.user_id),
        options,
    )
    .map_err(relay_error)?;
    let map = frame.type_map().ok_or_else(|| {
        IdentityError::InvalidDescriptor("native relay type map is missing".into())
    })?;
    let application = CommunicationValue::new_with_type_map(content.message_type, map)
        .with_payload(content.content);
    Ok(VerifiedFederatedRelay {
        signer,
        recipient,
        destination: expected_destination.clone(),
        // Native MTP uses a u128 ID, unlike Tau's string namespace.
        message_id: format!("mtp-sealed-v1:{}", metadata.message_id().get()),
        created_at: metadata.created_at(),
        content: Some(application),
        frame,
        durable_outcome: None,
    })
}

pub fn parse_wire(
    frame: &CommunicationValue,
) -> Result<tau_relay_protocol::RelayWire, IdentityError> {
    let wire = tau_relay_protocol::RelayWire::from_frame(frame)
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    if wire.message_id.starts_with("mtp-sealed-v1:") {
        return Err(IdentityError::InvalidDescriptor(
            "reserved native message ID namespace".into(),
        ));
    }
    Ok(wire)
}
