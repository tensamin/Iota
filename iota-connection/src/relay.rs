use iota_util::route_target::RouteTarget;
use mtp::codec::{
    CommunicationValue, ProtectionPolicy, RelayError, RelayOpenOptions, SignaturePolicy, TypeMap,
    VerifiedRelayContent, VerifiedRelayMetadata, forward_relay_frame,
    open_relay_content_with_limits_without_replay, open_relay_metadata_with_without_replay,
    relay_metadata_claimed_signer_id_with_options,
};
use mtp::crypto::{Keyring, PublicKeyBundle};
use std::fmt;

pub const RELAY_PROTECTION_POLICY: ProtectionPolicy = ProtectionPolicy {
    signature: SignaturePolicy::Dual,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSecurityClass {
    RelayOnly,
    AuthenticatedPeerControl,
    AuthenticatedLocalRequest,
}

pub fn message_security_class(frame: &CommunicationValue) -> MessageSecurityClass {
    const RELAY_ONLY_TYPES: &[mtp::codec::CommunicationType] = &[
        mtp::codec::CommunicationType::MessageSend,
        mtp::codec::CommunicationType::MessageLive,
        mtp::codec::CommunicationType::MessageState,
        mtp::codec::CommunicationType::MessageEdit,
        mtp::codec::CommunicationType::MessageEditLive,
        mtp::codec::CommunicationType::MessageReactionAdd,
        mtp::codec::CommunicationType::MessageReactionRemove,
        mtp::codec::CommunicationType::MessageReactionLive,
        mtp::codec::CommunicationType::MessageDelete,
        mtp::codec::CommunicationType::MessageDeleteLive,
        mtp::codec::CommunicationType::MessageOtherIota,
        mtp::codec::CommunicationType::SetChatSecret,
        mtp::codec::CommunicationType::SendChat,
        mtp::codec::CommunicationType::SettingsSave,
        mtp::codec::CommunicationType::GlobalSettingsSave,
        mtp::codec::CommunicationType::AddConversation,
        mtp::codec::CommunicationType::AddCommunity,
        mtp::codec::CommunicationType::RemoveCommunity,
    ];

    if RELAY_ONLY_TYPES.iter().any(|kind| frame.is_type(*kind)) {
        MessageSecurityClass::RelayOnly
    } else if frame.is_type(mtp::codec::CommunicationType::GetChatSecret)
        || frame.is_type(mtp::codec::CommunicationType::MessageGet)
        || frame.is_type(mtp::codec::CommunicationType::MessagesGet)
    {
        MessageSecurityClass::AuthenticatedPeerControl
    } else {
        MessageSecurityClass::AuthenticatedLocalRequest
    }
}

#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub user_id: u64,
    pub iota_id: u64,
    pub signing_keys: Vec<PublicKeyBundle>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelayContext {
    pub signer_id: u64,
    pub final_recipient_id: u64,
    pub message_id: String,
    pub created_at: u64,
    pub type_map: TypeMap,
}

#[derive(Debug, Clone)]
pub struct VerifiedRelay {
    pub metadata: VerifiedRelayMetadata,
    pub context: VerifiedRelayContext,
    pub signing_keys: Vec<PublicKeyBundle>,
}

#[derive(Debug)]
pub enum RelayValidationError {
    WrongNextHop { expected: u64, actual: Option<u64> },
    OuterSenderNotAllowed,
    MissingSigningKeys(u64),
    MissingTypeMap,
    InvalidRouteTarget(u64),
    KeyLookup(String),
    Relay(RelayError),
}

impl fmt::Display for RelayValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongNextHop { expected, actual } => {
                write!(
                    formatter,
                    "relay next hop {:?} does not match Iota {expected}",
                    actual
                )
            }
            Self::OuterSenderNotAllowed => formatter.write_str("relay has an outer sender"),
            Self::MissingSigningKeys(signer_id) => {
                write!(formatter, "no trusted signing keys for user {signer_id}")
            }
            Self::MissingTypeMap => formatter.write_str("relay has no negotiated type map"),
            Self::InvalidRouteTarget(target) => {
                write!(formatter, "relay has invalid route target {target}")
            }
            Self::KeyLookup(error) => write!(formatter, "trusted signer lookup failed: {error}"),
            Self::Relay(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RelayValidationError {}

impl From<RelayError> for RelayValidationError {
    fn from(error: RelayError) -> Self {
        Self::Relay(error)
    }
}

/*
 * Relay metadata is opened only after the claimed signer selects trusted key
 * history. Replay reservation happens after verification and durable
 * acceptance, so a failed delivery can be retried without losing the frame.
 */
pub async fn verify_relay_metadata<F, Fut>(
    frame: &CommunicationValue,
    local_iota_id: u64,
    keyring: &Keyring,
    resolve_signing_keys: F,
) -> Result<VerifiedRelay, RelayValidationError>
where
    F: FnOnce(u64) -> Fut,
    Fut: Future<Output = Result<Vec<PublicKeyBundle>, RelayValidationError>>,
{
    let expected_next_hop = RouteTarget::Iota(local_iota_id)
        .wire_id()
        .ok_or(RelayValidationError::InvalidRouteTarget(local_iota_id))?;
    if frame.receiver() != Some(expected_next_hop) {
        return Err(RelayValidationError::WrongNextHop {
            expected: expected_next_hop,
            actual: frame.receiver(),
        });
    }
    if frame.sender().is_some() {
        return Err(RelayValidationError::OuterSenderNotAllowed);
    }

    let open_options = RelayOpenOptions::new(RELAY_PROTECTION_POLICY);
    let claimed_signer = relay_metadata_claimed_signer_id_with_options(
        frame,
        &[keyring],
        open_options.decode_limits,
        open_options.protected_limits,
    )?;
    let signing_keys = resolve_signing_keys(claimed_signer).await?;
    if signing_keys.is_empty() {
        return Err(RelayValidationError::MissingSigningKeys(claimed_signer));
    }

    let resolver_keys = signing_keys.clone();
    let type_map = frame
        .type_map()
        .cloned()
        .ok_or(RelayValidationError::MissingTypeMap)?;
    let metadata = open_relay_metadata_with_without_replay(
        frame,
        &[keyring],
        Some(claimed_signer),
        move |signer_id| (signer_id == claimed_signer).then(|| resolver_keys.clone()),
        open_options,
    )?;

    let context = VerifiedRelayContext {
        signer_id: metadata.signer_id(),
        final_recipient_id: metadata.final_recipient_id(),
        message_id: metadata.message_id().to_owned(),
        created_at: metadata.created_at(),
        type_map,
    };

    Ok(VerifiedRelay {
        metadata,
        context,
        signing_keys,
    })
}

pub fn open_verified_relay_content(
    relay: &VerifiedRelay,
    keyrings: &[&Keyring],
    expected_recipient_id: u64,
) -> Result<VerifiedRelayContent, RelayValidationError> {
    Ok(open_relay_content_with_limits_without_replay(
        &relay.metadata,
        keyrings,
        &relay.signing_keys,
        Some(expected_recipient_id),
        RelayOpenOptions {
            policy: RELAY_PROTECTION_POLICY,
            decode_limits: relay.metadata.decode_limits(),
            encode_limits: relay.metadata.encode_limits(),
            protected_limits: relay.metadata.protected_limits(),
        },
    )?)
}

pub fn forward_verified_relay(
    frame: &CommunicationValue,
    target: RouteTarget,
) -> Result<CommunicationValue, RelayValidationError> {
    let next_hop_id = target
        .wire_id()
        .ok_or(RelayValidationError::InvalidRouteTarget(target.id()))?;
    Ok(forward_relay_frame(frame, next_hop_id)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp::codec::SealedRelayBuilder;
    use mtp::crypto::{DualSigner, Ed25519Signer, Keyring};

    fn relay(message_id: &str) -> Result<(Keyring, Keyring, CommunicationValue), String> {
        let signer_keyring = Keyring::generate();
        let recipient_keyring = Keyring::generate();
        let signer = DualSigner::new(
            &signer_keyring.sig_cl_secret_key,
            &signer_keyring.sig_pq_secret_key,
            &signer_keyring.sig_pq_public_key,
        )
        .map_err(|error| error.to_string())?;
        let frame = SealedRelayBuilder::new(
            "MessageSend",
            mtp::codec::DataValue::Str("payload".into()),
            7,
            42,
            RouteTarget::Iota(99)
                .wire_id()
                .ok_or("invalid test target")?,
            &signer,
        )
        .message_id(message_id)
        .created_at(123)
        .metadata_recipients(vec![recipient_keyring.public_key_bundle()])
        .content_recipients(vec![recipient_keyring.public_key_bundle()])
        .build()
        .map_err(|error| error.to_string())?;
        Ok((signer_keyring, recipient_keyring, frame))
    }

    #[tokio::test]
    async fn verifies_metadata_with_trusted_signing_key() -> Result<(), String> {
        let (signer, recipient, frame) = relay("accepted")?;
        let trusted_key = signer.public_key_bundle();
        let verified = verify_relay_metadata(&frame, 99, &recipient, move |signer_id| async move {
            (signer_id == 7)
                .then_some(vec![trusted_key])
                .ok_or(RelayValidationError::MissingSigningKeys(signer_id))
        })
        .await
        .map_err(|error| error.to_string())?;

        assert_eq!(verified.context.signer_id, 7);
        assert_eq!(verified.context.final_recipient_id, 42);
        assert_eq!(verified.context.message_id, "accepted");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_metadata_signed_by_untrusted_key() -> Result<(), String> {
        let (_signer, recipient, frame) = relay("wrong-key")?;
        let wrong_signer = Keyring::generate();
        let trusted_key = wrong_signer.public_key_bundle();
        let result = verify_relay_metadata(&frame, 99, &recipient, move |_| async move {
            Ok(vec![trusted_key])
        })
        .await;

        assert!(matches!(result, Err(RelayValidationError::Relay(_))));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_classical_only_relay_under_dual_policy() -> Result<(), String> {
        let signer_keyring = Keyring::generate();
        let recipient_keyring = Keyring::generate();
        let signer = Ed25519Signer::new(&signer_keyring.sig_cl_secret_key)
            .map_err(|error| error.to_string())?;
        let frame = SealedRelayBuilder::new(
            "MessageSend",
            mtp::codec::DataValue::Str("payload".into()),
            7,
            42,
            RouteTarget::Iota(99)
                .wire_id()
                .ok_or("invalid test target")?,
            &signer,
        )
        .message_id("classical-only")
        .created_at(123)
        .metadata_recipients(vec![recipient_keyring.public_key_bundle()])
        .content_recipients(vec![recipient_keyring.public_key_bundle()])
        .build()
        .map_err(|error| error.to_string())?;
        let trusted_key = signer_keyring.public_key_bundle();
        let result = verify_relay_metadata(&frame, 99, &recipient_keyring, move |_| async move {
            Ok(vec![trusted_key])
        })
        .await;

        assert!(matches!(result, Err(RelayValidationError::Relay(_))));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_outer_sender_before_key_lookup() -> Result<(), String> {
        let (_signer, recipient, frame) = relay("outer-sender")?;
        let frame = frame.with_sender(501);
        let result = verify_relay_metadata(&frame, 99, &recipient, |_| async {
            Err(RelayValidationError::MissingSigningKeys(7))
        })
        .await;

        assert!(matches!(
            result,
            Err(RelayValidationError::OuterSenderNotAllowed)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn verification_does_not_commit_replay_state() -> Result<(), String> {
        let (signer, recipient, frame) = relay("duplicate")?;
        let trusted_key = signer.public_key_bundle();

        for _ in 0..2 {
            let trusted_key = trusted_key.clone();
            let result = verify_relay_metadata(&frame, 99, &recipient, move |_| async move {
                Ok(vec![trusted_key])
            })
            .await;
            let _ = result.map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    #[test]
    fn forwarding_preserves_sealed_payload() -> Result<(), String> {
        let (_signer, _recipient, frame) = relay("forwarding")?;
        let forwarded = forward_verified_relay(&frame, RouteTarget::User(100))
            .map_err(|error| error.to_string())?;

        assert_eq!(frame.sender(), None);
        assert_eq!(forwarded.sender(), None);
        assert_eq!(forwarded.receiver(), RouteTarget::User(100).wire_id());
        assert_eq!(frame.payload(), forwarded.payload());
        Ok(())
    }
}
