use crate::message_common::{OptionalDataValueExt, now_millis_i64};
use chat_files::MessageState;
use iota_identity::{LocalUserId, PrincipalHandle, PrincipalHome};
use iota_storage::storage_error::StorageError;
use iota_storage::util::{
    chat_files, chat_secret_recovery, chats_util, db, e2ee_storage, outgoing_relay, receipt_policy,
    relay_queue, relay_replay, relay_work,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

pub(crate) use tau_relay_protocol::application::{ApplicationOperation, SecretCopy};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalEffect {
    pub(crate) owner: LocalUserId,
    pub(crate) principal: PrincipalHandle,
    pub(crate) sent_by_self: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum DeliveryTarget {
    Local(LocalUserId),
    Remote(iota_identity::IotaNodeId),
}

/// Explicit durable lease fields. The identity crate's runtime authorization
/// object intentionally has no serde implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OriginLease {
    connection_id: String,
    server_instance: String,
    owner: LocalUserId,
    principal: PrincipalHandle,
    auth_generation: i64,
}

impl OriginLease {
    fn authorization(&self) -> iota_identity::HostedAuthorizationLease {
        iota_identity::HostedAuthorizationLease {
            connection_id: self.connection_id.clone(),
            server_instance: self.server_instance.clone(),
            identity: iota_identity::ValidatedHostedIdentity {
                local_user: self.owner,
                principal: self.principal,
                auth_generation: self.auth_generation,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PreparedRelayOperation {
    pub(crate) principal_fences: [iota_storage::identity::PrincipalCommitFence; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) origin_lease: Option<OriginLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret_escrow: Option<chat_secret_recovery::Escrow>,
    pub signer: PrincipalHandle,
    pub recipient: PrincipalHandle,
    pub message_id: String,
    pub signer_id: u64,
    pub recipient_id: u64,
    pub(crate) signer_identity: tau_relay_protocol::Principal,
    pub(crate) recipient_identity: tau_relay_protocol::Principal,
    pub created_at: u64,
    pub accepted_at: i64,
    pub frame: Vec<u8>,
    pub frame_id: u32,
    pub type_map_version: String,
    pub type_map_fingerprint: String,
    pub(crate) operation: ApplicationOperation,
    pub(crate) effects: Vec<LocalEffect>,
    pub(crate) delivery: DeliveryTarget,
}

fn invalid(field: &'static str) -> StorageError {
    StorageError::InvalidRelayPayload(field)
}

/// A consistent account snapshot already contains these mutations. Clients may
/// acknowledge their queued notifications without replaying an older edit over
/// the newer snapshot. Secret/bootstrap notifications still require application.
pub(crate) fn snapshot_receipts(
    owner: i64,
    after: i64,
    upper: Option<i64>,
    limit: usize,
) -> Result<iota_storage::util::relay_acceptance_receipts::ReceiptPage, StorageError> {
    iota_storage::util::relay_acceptance_receipts::receipt_page(owner, after, upper, limit)
}

fn number(frame: &CommunicationValue, field: DataType) -> Result<i64, StorageError> {
    let value = frame
        .get_data(field)
        .as_number()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| invalid("required integer"))?;
    if (matches!(
        field,
        DataType::SendTime
            | DataType::EventAt
            | DataType::ChatPartnerId
            | DataType::VersionNumber
            | DataType::ReplyId
    ) && value <= 0)
        || (field == DataType::Height && value < 0)
    {
        return Err(invalid("integer outside application range"));
    }
    Ok(value)
}

fn optional_number(
    frame: &CommunicationValue,
    field: DataType,
) -> Result<Option<i64>, StorageError> {
    frame
        .get_data(field)
        .map(|_| number(frame, field))
        .transpose()
}

fn text(frame: &CommunicationValue, field: DataType) -> Result<String, StorageError> {
    let value = frame
        .get_data(field)
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("required string"))?;
    if field == DataType::RelayMessageId && (value.is_empty() || value.len() > 256) {
        return Err(invalid("referenced relay message ID"));
    }
    Ok(value)
}

pub(crate) fn prepare_application(
    verified: &crate::federated_relay::VerifiedFederatedRelay,
    sender: Option<LocalUserId>,
    recipient: Option<LocalUserId>,
) -> Result<PreparedRelayOperation, StorageError> {
    prepare_application_inner(verified, sender, recipient, false)
}

/// For re-verifying an already accepted epoch, never for fresh relay ingress.
/// Historical proof is independent of replay retention and current co-hosting.
pub(crate) fn prepare_recovery_application(
    verified: &crate::federated_relay::VerifiedFederatedRelay,
    sender: Option<LocalUserId>,
    recipient: Option<LocalUserId>,
) -> Result<PreparedRelayOperation, StorageError> {
    if !verified
        .content
        .as_ref()
        .is_some_and(|frame| frame.is_type(CommunicationType::SetChatSecret))
    {
        return Err(StorageError::UnsupportedRelayOperation);
    }
    prepare_application_inner(verified, sender, recipient, true)
}

fn prepare_application_inner(
    verified: &crate::federated_relay::VerifiedFederatedRelay,
    sender: Option<LocalUserId>,
    recipient: Option<LocalUserId>,
    historical: bool,
) -> Result<PreparedRelayOperation, StorageError> {
    let frame = verified
        .content
        .as_ref()
        .ok_or_else(|| invalid("durable replay has no fresh application"))?;
    ApplicationOperation::validate_frame_shape(frame)
        .map_err(|_| invalid("application field schema"))?;
    let signer_id = verified.signer.principal.user_id;
    let recipient_id = verified.recipient.principal.user_id;
    let signer_identity = crate::federated_relay::protocol_principal(&verified.signer.principal);
    let recipient_identity =
        crate::federated_relay::protocol_principal(&verified.recipient.principal);
    if frame.get_comm_type_enum() != Some(CommunicationType::SetChatSecret)
        && let Some(value) = frame.get_data(DataType::ChatId)
        && value.as_str()
            != Some(
                tau_relay_protocol::canonical_chat_id(&signer_identity, &recipient_identity)
                    .as_str(),
            )
    {
        return Err(StorageError::MessageUnauthorized);
    }
    if signer_id == 0 || recipient_id == 0 {
        return Err(invalid("zero principal user ID"));
    }
    i64::try_from(signer_id).map_err(|_| invalid("signer ID range"))?;
    i64::try_from(recipient_id).map_err(|_| invalid("recipient ID range"))?;
    let created_at =
        i64::try_from(verified.created_at).map_err(|_| invalid("creation time range"))?;
    let accepted_at = now_millis_i64();
    if !historical
        && (created_at < accepted_at.saturating_sub(relay_replay::RELAY_RETENTION_MILLIS)
            || created_at
                > accepted_at.saturating_add(relay_replay::MAX_RELAY_FUTURE_SKEW_MILLIS as i64))
    {
        return Err(invalid("creation time outside retention window"));
    }
    if frame.sender().is_some_and(|v| v != signer_id)
        || frame.receiver().is_some_and(|v| v != recipient_id)
    {
        return Err(StorageError::MessageUnauthorized);
    }
    for (field, expected) in [
        (DataType::SenderId, signer_id),
        (DataType::ReceiverId, recipient_id),
    ] {
        if let Some(value) = frame.get_data(field) {
            let actual = value
                .as_number()
                .and_then(|v| u64::try_from(v).ok())
                .ok_or_else(|| invalid("inner identity"))?;
            if actual != expected {
                return Err(StorageError::MessageUnauthorized);
            }
        }
    }
    let positive_version = || {
        number(frame, DataType::VersionNumber).and_then(|v| {
            if v > 0 {
                Ok(v)
            } else {
                Err(invalid("secret version"))
            }
        })
    };
    let mut secret_recipient_ids = None;
    let operation = match frame
        .get_comm_type_enum()
        .ok_or(StorageError::UnsupportedRelayOperation)?
    {
        CommunicationType::MessageSend => {
            if frame.get_data(DataType::RelayMessageId).is_some()
                && text(frame, DataType::RelayMessageId)? != verified.message_id
            {
                return Err(invalid("message ID mismatch"));
            }
            ApplicationOperation::MessageSend {
                content: text(frame, DataType::Content)?,
                send_time: optional_number(frame, DataType::SendTime)?.unwrap_or(created_at),
                height: optional_number(frame, DataType::Height)?.unwrap_or(0),
                version: positive_version()?,
                reply_to: optional_number(frame, DataType::ReplyId)?,
            }
        }
        CommunicationType::MessageEdit => ApplicationOperation::MessageEdit {
            content: text(frame, DataType::Content)?,
            send_time: number(frame, DataType::SendTime)?,
            version: positive_version()?,
        },
        kind @ (CommunicationType::MessageReactionAdd
        | CommunicationType::MessageReactionRemove) => {
            let reaction = text(frame, DataType::Reaction)?;
            if reaction.is_empty() || reaction.len() > 64 {
                return Err(invalid("reaction length"));
            }
            let send_time = number(frame, DataType::SendTime)?;
            if kind == CommunicationType::MessageReactionAdd {
                ApplicationOperation::MessageReactionAdd {
                    reaction,
                    send_time,
                }
            } else {
                ApplicationOperation::MessageReactionRemove {
                    reaction,
                    send_time,
                }
            }
        }
        CommunicationType::MessageDelete => ApplicationOperation::MessageDelete {
            send_time: number(frame, DataType::SendTime)?,
        },
        CommunicationType::MessageDeleteLive => ApplicationOperation::MessageDeleteLive {
            send_time: number(frame, DataType::SendTime)?,
        },
        CommunicationType::MessageState => {
            if number(frame, DataType::ChatPartnerId)? != recipient_id as i64 {
                return Err(StorageError::MessageUnauthorized);
            }
            let state = match text(frame, DataType::MessageState)?.as_str() {
                "read" => MessageState::Read,
                "received" => MessageState::Received,
                _ => return Err(invalid("receipt state")),
            };
            if state == MessageState::Received {
                ApplicationOperation::MessageReceived {
                    message_id: text(frame, DataType::RelayMessageId)?,
                    event_at: number(frame, DataType::EventAt)?,
                }
            } else {
                ApplicationOperation::MessageState {
                    message_id: text(frame, DataType::RelayMessageId)?,
                    state,
                    event_at: number(frame, DataType::EventAt)?,
                }
            }
        }
        CommunicationType::AddConversation => {
            let partner = number(frame, DataType::ChatPartnerId)?;
            if partner != signer_id as i64 && partner != recipient_id as i64 {
                return Err(StorageError::MessageUnauthorized);
            }
            ApplicationOperation::AddConversation {
                name: frame
                    .get_data(DataType::ChatPartnerName)
                    .map(|_| text(frame, DataType::ChatPartnerName))
                    .transpose()?,
            }
        }
        CommunicationType::SetChatSecret => {
            let mut seen = std::collections::HashSet::new();
            for (field, _) in frame.iter_typed_data() {
                if !matches!(
                    field,
                    Some(
                        DataType::ChatId
                            | DataType::SecretId
                            | DataType::VersionNumber
                            | DataType::WrappingScheme
                            | DataType::Recipients
                            | DataType::CreatedAt
                            | DataType::SenderId
                            | DataType::ReceiverId
                    )
                ) || !seen.insert(field)
                {
                    return Err(invalid("secret operation fields"));
                }
            }
            let version = positive_version()?;
            // A shared Iota commits both initial envelopes in the same transaction.
            let shared_initializer =
                (historical || (sender.is_some() && recipient.is_some())) && version == 1;
            if signer_identity == recipient_identity
                || (signer_identity > recipient_identity && !shared_initializer)
            {
                return Err(StorageError::MessageUnauthorized);
            }
            let chat_id = text(frame, DataType::ChatId)?;
            let pair = tau_relay_protocol::ConversationPair::from_chat_id(&chat_id)
                .map_err(|_| invalid("secret namespace"))?;
            if pair
                != tau_relay_protocol::ConversationPair::new(
                    signer_identity.clone(),
                    recipient_identity.clone(),
                )
                .map_err(|_| invalid("secret principals"))?
                || text(frame, DataType::SecretId)? != tau_relay_protocol::chat_secret_id(&chat_id)
            {
                return Err(invalid("secret namespace"));
            }
            let values = frame
                .get_data(DataType::Recipients)
                .and_then(DataValue::as_array)
                .ok_or_else(|| invalid("secret recipients"))?;
            if values.len() != 2 {
                return Err(invalid("secret recipient count"));
            }
            let map = frame.type_map().ok_or_else(|| invalid("type map"))?;
            let mut copies = Vec::new();
            for value in values {
                let DataValue::Container(ref fields) = value else {
                    return Err(invalid("secret recipient fields"));
                };
                let expected = [
                    DataType::UserId,
                    DataType::EncryptedSecret,
                    DataType::KemCiphertext,
                ]
                .map(|kind| kind.try_to_id(map));
                if fields.len() != 3
                    || fields
                        .iter()
                        .any(|(key, _)| !expected.contains(&Some(*key)))
                    || fields.iter().enumerate().any(|(index, (key, _))| {
                        fields[..index].iter().any(|(other, _)| key == other)
                    })
                {
                    return Err(invalid("secret recipient fields"));
                }
                let field = |key: DataType| value.get_field(key.try_to_id(map)?);
                let value =
                    field(DataType::UserId).ok_or_else(|| invalid("secret recipient identity"))?;
                let id = {
                    let encoded = value
                        .as_str()
                        .ok_or_else(|| invalid("secret recipient identity"))?;
                    let id: tau_relay_protocol::Principal = serde_json::from_str(encoded)
                        .map_err(|_| invalid("secret recipient identity"))?;
                    if serde_json::to_string(&id)
                        .map_err(|_| invalid("secret recipient identity"))?
                        != encoded
                    {
                        return Err(invalid("noncanonical secret recipient identity"));
                    }
                    id
                };
                let copy = SecretCopy {
                    encrypted_secret: field(DataType::EncryptedSecret)
                        .and_then(DataValue::as_bytes)
                        .ok_or_else(|| invalid("encrypted secret"))?,
                    kem_ciphertext: field(DataType::KemCiphertext)
                        .and_then(DataValue::as_bytes)
                        .ok_or_else(|| invalid("secret KEM"))?,
                };
                let original_id = chat_secret_recovery::OriginalRecipientId::Principal(
                    serde_json::to_string(&id).map_err(|_| invalid("secret recipient identity"))?,
                );
                if copies.iter().any(|(existing, _, _)| *existing == id) {
                    return Err(StorageError::MessageUnauthorized);
                }
                copies.push((id, copy, original_id));
            }
            let sender_index = copies
                .iter()
                .position(|(identity, _, _)| *identity == signer_identity)
                .ok_or(StorageError::MessageUnauthorized)?;
            let (_, sender_copy, sender_original_id) = copies.remove(sender_index);
            let (identity, recipient_copy, recipient_original_id) = copies.remove(0);
            if identity != recipient_identity {
                return Err(StorageError::MessageUnauthorized);
            }
            secret_recipient_ids = Some([sender_original_id, recipient_original_id]);
            ApplicationOperation::SetChatSecret {
                chat_id,
                version,
                wrapping_scheme: text(frame, DataType::WrappingScheme)?,
                sender: sender_copy,
                recipient: recipient_copy,
            }
        }
        _ => return Err(StorageError::UnsupportedRelayOperation),
    };
    let mut effects = Vec::new();
    if let Some(owner) = sender {
        effects.push(LocalEffect {
            owner,
            principal: verified.signer.handle,
            sent_by_self: true,
        });
    }
    if let Some(owner) = recipient {
        effects.push(LocalEffect {
            owner,
            principal: verified.recipient.handle,
            sent_by_self: false,
        });
    }
    if effects.is_empty() {
        return Err(StorageError::RelayOwnerUnavailable);
    }
    let delivery = match recipient {
        Some(owner) => DeliveryTarget::Local(owner),
        None => match &verified.recipient.home {
            PrincipalHome::Iota(node) if node == &verified.destination => {
                DeliveryTarget::Remote(node.clone())
            }
            _ => return Err(invalid("recipient has no canonical Iota route")),
        },
    };
    let secret_escrow = if let ApplicationOperation::SetChatSecret {
        chat_id,
        version,
        wrapping_scheme,
        sender,
        recipient,
        ..
    } = &operation
    {
        let first = verified.signer.principal.clone();
        let second = verified.recipient.principal.clone();
        let pair = chat_secret_recovery::sorted_pair(&first, &second)?;
        let [sender_original_id, recipient_original_id] =
            secret_recipient_ids.ok_or_else(|| invalid("original secret recipient identities"))?;
        let copy = |owner: &iota_identity::PrincipalId, secret: &SecretCopy, recipient_id| {
            chat_secret_recovery::RecipientEnvelope {
                owner: owner.clone(),
                recipient_id,
                encrypted_secret: secret.encrypted_secret.clone(),
                kem_ciphertext: secret.kem_ciphertext.clone(),
            }
        };
        let sender_copy = copy(&first, sender, sender_original_id);
        let recipient_copy = copy(&second, recipient, recipient_original_id);
        let envelopes = if pair[0] == first {
            [sender_copy, recipient_copy]
        } else {
            [recipient_copy, sender_copy]
        };
        let original_frame = verified
            .frame
            .clone()
            .without_id()
            .to_bytes()
            .map_err(|_| invalid("original verified frame"))?;
        let format = if crate::federated_relay::parse_wire(&verified.frame).is_ok() {
            chat_secret_recovery::RelayFormat::TauSignedRelayV1
        } else {
            chat_secret_recovery::RelayFormat::NativeMtpSealedV1
        };
        Some(chat_secret_recovery::Escrow {
            first: pair[0].clone(),
            second: pair[1].clone(),
            version: *version,
            namespace: chat_secret_recovery::WrappingNamespace {
                chat_id: chat_id.clone(),
                secret_id: text(frame, DataType::SecretId)?,
            },
            wrapping_scheme: wrapping_scheme.clone(),
            signer: first,
            message_id: verified.message_id.clone(),
            operation_digest: chat_secret_recovery::operation_digest(format, &original_frame),
            original_frame,
            original_type_map_fingerprint: verified
                .frame
                .type_map()
                .and_then(|map| map.fingerprint_hex())
                .ok_or_else(|| invalid("original verified dictionary"))?,
            original_type_map_version: verified
                .frame
                .type_map()
                .ok_or_else(|| invalid("original verified type map"))?
                .version
                .to_string(),
            format,
            envelopes,
            created_at,
        })
    } else {
        None
    };
    Ok(PreparedRelayOperation {
        principal_fences: [
            iota_storage::identity::PrincipalCommitFence::capture(&verified.signer)
                .map_err(|_| StorageError::MessageUnauthorized)?,
            iota_storage::identity::PrincipalCommitFence::capture(&verified.recipient)
                .map_err(|_| StorageError::MessageUnauthorized)?,
        ],
        type_map_fingerprint: verified
            .frame
            .type_map()
            .and_then(|map| map.fingerprint_hex())
            .ok_or_else(|| invalid("verified dictionary identity"))?,
        origin_lease: None,
        secret_escrow,
        signer: verified.signer.handle,
        recipient: verified.recipient.handle,
        signer_id,
        recipient_id,
        signer_identity,
        recipient_identity,
        message_id: verified.message_id.clone(),
        created_at: verified.created_at,
        accepted_at,
        frame: verified
            .frame
            .clone()
            .without_id()
            .to_bytes()
            .map_err(|_| invalid("frame serialization"))?,
        frame_id: verified
            .frame
            .id()
            .ok_or_else(|| invalid("transport correlation ID"))?,
        type_map_version: verified
            .frame
            .type_map()
            .ok_or_else(|| invalid("envelope type map"))?
            .version
            .to_string(),
        operation,
        effects,
        delivery,
    })
}

impl PreparedRelayOperation {
    pub(crate) fn validate_origin_lease(&self) -> Result<(), StorageError> {
        if let Some(lease) = &self.origin_lease
            && (lease.connection_id.is_empty()
                || lease.server_instance.is_empty()
                || lease.auth_generation < 0
                || lease.principal != self.signer
                || !self.effects.iter().any(|effect| {
                    effect.sent_by_self
                        && effect.owner == lease.owner
                        && effect.principal == lease.principal
                }))
        {
            return Err(StorageError::HostedAuthorizationDenied);
        }
        Ok(())
    }
    pub fn bind_origin_lease(
        &mut self,
        lease: &iota_identity::HostedAuthorizationLease,
    ) -> Result<(), StorageError> {
        if !self.effects.iter().any(|effect| {
            effect.sent_by_self
                && effect.owner == lease.identity.local_user
                && effect.principal == lease.identity.principal
        }) || lease.identity.principal != self.signer
            || lease.connection_id.is_empty()
            || lease.server_instance.is_empty()
        {
            return Err(StorageError::HostedAuthorizationDenied);
        }
        let origin = OriginLease {
            connection_id: lease.connection_id.clone(),
            server_instance: lease.server_instance.clone(),
            owner: lease.identity.local_user,
            principal: lease.identity.principal,
            auth_generation: lease.identity.auth_generation,
        };
        if self
            .origin_lease
            .as_ref()
            .is_some_and(|current| *current != origin)
        {
            return Err(StorageError::HostedAuthorizationDenied);
        }
        self.origin_lease = Some(origin);
        Ok(())
    }
    pub fn request(&self) -> relay_replay::RelayReservationRequest<'_> {
        relay_replay::RelayReservationRequest {
            signer_principal: self.signer,
            signer_id: self.signer_id,
            message_id: &self.message_id,
            created_at: self.created_at,
            accepted_at: self.accepted_at,
            destination_id: self.recipient_id,
            frame: &self.frame,
            frame_id: self.frame_id,
            type_map_version: &self.type_map_version,
        }
    }

    fn apply_in_tx(&self, tx: &Transaction<'_>, effect: &LocalEffect) -> Result<(), StorageError> {
        relay_work::verify_owner_in_tx(tx, effect.owner.0, effect.principal)?;
        let owner = effect.owner.0;
        let sender = self.signer_id as i64;
        let recipient = self.recipient_id as i64;
        let external = if effect.sent_by_self {
            recipient
        } else {
            sender
        };
        let external_principal = if effect.sent_by_self {
            self.recipient
        } else {
            self.signer
        };
        let chat_id = chat_secret_recovery::canonical_chat_id(
            &crate::federated_relay::canonical_principal(&self.signer_identity)
                .map_err(|_| invalid("signer principal"))?,
            &crate::federated_relay::canonical_principal(&self.recipient_identity)
                .map_err(|_| invalid("recipient principal"))?,
        )?;
        match &self.operation {
            ApplicationOperation::MessageSend {
                content,
                send_time,
                height,
                version,
                reply_to,
            } => {
                let secret = e2ee_storage::get_chat_secret_on(
                    tx,
                    &e2ee_storage::ChatSecretQuery {
                        user_id: owner.to_string(),
                        chat_id: chat_id.clone(),
                        secret_id: Some(e2ee_storage::principal_secret_id(&chat_id)),
                        version: None,
                    },
                )?
                .ok_or(StorageError::MissingRelayDependency)?;
                if secret.version != *version {
                    return Err(StorageError::ChatSecretSequence);
                }
                chat_files::add_message_in_tx(
                    tx,
                    chat_files::NewMessage {
                        relay_signer_id: sender,
                        relay_signer_principal: self.signer,
                        relay_message_id: &self.message_id,
                        authored_at: self.created_at as i64,
                        send_time: *send_time,
                        storage_owner: owner,
                        external_user: external,
                        external_principal,
                        sent_by_self: effect.sent_by_self,
                        content,
                        height: *height,
                        key_version: *version,
                        reply_to: *reply_to,
                        origin_iota_received_at: effect.sent_by_self.then_some(self.accepted_at),
                        destination_iota_received_at: ((!effect.sent_by_self)
                            || matches!(self.delivery, DeliveryTarget::Local(_)))
                        .then_some(self.accepted_at),
                        initial_state: if effect.sent_by_self
                            && matches!(self.delivery, DeliveryTarget::Remote(_))
                        {
                            MessageState::Sending
                        } else {
                            MessageState::Sent
                        },
                    },
                )?;
            }
            ApplicationOperation::MessageEdit {
                content,
                send_time,
                version,
            } => {
                // Edits carry the replacement ciphertext's epoch, including
                // historical epochs. Do not require the latest/original key.
                chat_files::require_edit_key_in_tx(tx, owner, &chat_id, *version)?;
                if effect.sent_by_self {
                    chat_files::edit_message_for_principal_versioned_in_tx(
                        tx,
                        owner,
                        external,
                        external_principal,
                        *send_time,
                        sender,
                        content,
                        *version,
                    )?;
                } else {
                    chat_files::apply_remote_edit_for_principal_versioned_in_tx(
                        tx,
                        owner,
                        external,
                        external_principal,
                        *send_time,
                        sender,
                        content,
                        *version,
                    )?;
                }
            }
            ApplicationOperation::MessageReactionAdd {
                reaction,
                send_time,
            } => chat_files::add_reaction_for_principal_in_tx(
                tx,
                owner,
                external,
                external_principal,
                *send_time,
                sender,
                self.signer,
                reaction,
            )?,
            ApplicationOperation::MessageReactionRemove {
                reaction,
                send_time,
            } => chat_files::remove_reaction_for_principal_in_tx(
                tx,
                owner,
                external,
                external_principal,
                *send_time,
                sender,
                self.signer,
                reaction,
            )?,
            ApplicationOperation::MessageDelete { send_time }
            | ApplicationOperation::MessageDeleteLive { send_time } => {
                if effect.sent_by_self {
                    chat_files::delete_message_for_principal_in_tx(
                        tx,
                        owner,
                        external,
                        external_principal,
                        *send_time,
                    )?;
                } else {
                    chat_files::apply_remote_delete_for_principal_in_tx(
                        tx,
                        owner,
                        external,
                        external_principal,
                        *send_time,
                        sender,
                    )?;
                }
            }
            ApplicationOperation::MessageState {
                message_id,
                state,
                event_at,
            } => self.receipt_in_tx(tx, effect, message_id, state.clone(), *event_at)?,
            ApplicationOperation::MessageReceived {
                message_id,
                event_at,
            } => self.receipt_in_tx(tx, effect, message_id, MessageState::Received, *event_at)?,
            ApplicationOperation::AddConversation { name } => chats_util::add_conversation_in_tx(
                tx,
                owner,
                external,
                external_principal,
                name.as_deref(),
            )?,
            ApplicationOperation::SetChatSecret { .. } => {
                let escrow = self
                    .secret_escrow
                    .as_ref()
                    .ok_or(StorageError::MissingRelayDependency)?;
                chat_secret_recovery::commit_escrow_in_tx(tx, escrow)?;
                let secret = self.secret_for(effect)?;
                e2ee_storage::put_chat_secret_in_tx(tx, &secret)?;
                chat_secret_recovery::enqueue_secret_available_in_tx(tx, effect.owner, escrow)?;
            }
        }
        Ok(())
    }

    fn receipt_in_tx(
        &self,
        tx: &Transaction<'_>,
        effect: &LocalEffect,
        message_id: &str,
        state: MessageState,
        event_at: i64,
    ) -> Result<(), StorageError> {
        if effect.sent_by_self {
            let policy = receipt_policy::get_on(tx, effect.owner.0)?;
            if (state == MessageState::Read && !policy.send_read_receipts)
                || (state == MessageState::Received && !policy.send_received_receipts)
            {
                return Err(StorageError::MessageUnauthorized);
            }
            chat_files::change_message_state_by_relay_id_in_tx(
                tx,
                effect.owner.0,
                self.recipient,
                message_id,
                state,
            )?
            .ok_or(StorageError::MissingRelayDependency)?;
        } else {
            chat_files::record_message_receipt_in_tx(
                tx,
                effect.owner.0,
                self.recipient_id as i64,
                self.recipient,
                message_id,
                self.signer_id as i64,
                self.signer,
                &self.message_id,
                state,
                event_at,
                self.accepted_at,
            )?;
        }
        Ok(())
    }

    fn secret_for(
        &self,
        effect: &LocalEffect,
    ) -> Result<e2ee_storage::StoredChatSecret, StorageError> {
        let ApplicationOperation::SetChatSecret {
            version,
            wrapping_scheme,
            sender,
            recipient,
            ..
        } = &self.operation
        else {
            return Err(invalid("secret operation"));
        };
        let chat_id = chat_secret_recovery::canonical_chat_id(
            &crate::federated_relay::canonical_principal(&self.signer_identity)
                .map_err(|_| invalid("signer principal"))?,
            &crate::federated_relay::canonical_principal(&self.recipient_identity)
                .map_err(|_| invalid("recipient principal"))?,
        )?;
        let copy = if effect.sent_by_self {
            sender
        } else {
            recipient
        };
        Ok(e2ee_storage::StoredChatSecret {
            user_id: effect.owner.0.to_string(),
            secret_id: e2ee_storage::principal_secret_id(&chat_id),
            chat_id,
            version: *version,
            wrapping_scheme: wrapping_scheme.clone(),
            encrypted_secret: copy.encrypted_secret.clone(),
            kem_ciphertext: copy.kem_ciphertext.clone(),
            created_at: self.created_at as i64,
            updated_at: self.accepted_at,
        })
    }

    pub fn commit_checked(
        &self,
        claim: &relay_replay::ProcessingClaim,
        check: impl FnOnce(&Transaction<'_>) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        db::with_immediate_transaction(|tx| self.commit_in_tx(tx, claim, false, check))
    }

    pub(crate) fn commit_in_tx(
        &self,
        tx: &Transaction<'_>,
        claim: &relay_replay::ProcessingClaim,
        durable_origin: bool,
        check: impl FnOnce(&Transaction<'_>) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        if claim.signer != self.signer || claim.message_id != self.message_id {
            return Err(StorageError::StaleRelayClaim);
        }
        relay_replay::verify_claim_in_tx(tx, claim)?;
        self.verify_principal_fences_on(tx)?;
        self.validate_origin_lease()?;
        if let Some(lease) = &self.origin_lease {
            if durable_origin {
                // Proposal persistence already verified the live session.
                // Restart may retire that session, but not account authority.
                let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM hosted_auth_state a JOIN hosted_principals h ON h.local_user_id=a.local_user_id JOIN principals p ON p.principal_pk=h.principal_handle WHERE a.local_user_id=?1 AND a.generation=?2 AND a.enabled=1 AND h.principal_handle=?3 AND p.retired_at IS NULL)",
                        params![lease.owner.0,lease.auth_generation,lease.principal.0], |row| row.get(0))?;
                if !valid {
                    return Err(StorageError::HostedAuthorizationDenied);
                }
                relay_work::verify_owner_in_tx(tx, lease.owner.0, lease.principal)?;
            } else {
                iota_storage::hosted_auth::verify_in_tx(tx, &lease.authorization())?;
            }
        }
        check(tx)?;
        for (handle, identity) in [
            (self.signer, &self.signer_identity),
            (self.recipient, &self.recipient_identity),
        ] {
            let matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_pk = ?1 AND authority_id = ?2 AND remote_user_id = ?3)",
                    params![handle.0, identity.authority, identity.user_id as i64], |row| row.get(0))?;
            if !matches {
                return Err(StorageError::PendingRelayConflict);
            }
        }
        for effect in &self.effects {
            if !effect.sent_by_self {
                let blocked: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM blocked_users WHERE user_id = ?1 AND blocked_principal = ?2)", params![effect.owner.0, self.signer.0], |r| r.get(0))?;
                if blocked {
                    return Err(StorageError::MessageUnauthorized);
                }
            }
            if let ApplicationOperation::SetChatSecret { .. } = &self.operation
                && effect.sent_by_self
                && matches!(self.delivery, DeliveryTarget::Remote(_))
            {
                chat_secret_recovery::stage_escrow_in_tx(
                    tx,
                    self.secret_escrow
                        .as_ref()
                        .ok_or(StorageError::MissingRelayDependency)?,
                )?;
                relay_work::defer_secret_in_tx(
                    tx,
                    claim,
                    &relay_work::DeferredSecret {
                        owner: effect.owner.0,
                        principal: effect.principal,
                        secret: self.secret_for(effect)?,
                    },
                )?;
                continue;
            }
            self.apply_in_tx(tx, effect)?;
            if !matches!(
                self.operation,
                ApplicationOperation::SetChatSecret { .. }
                    | ApplicationOperation::AddConversation { .. }
            ) {
                iota_storage::util::relay_acceptance_receipts::insert_in_tx(
                    tx,
                    effect.owner.0,
                    self.signer.0,
                    &self.message_id,
                    self.accepted_at,
                )?;
            }
            relay_work::fault_point("after_local_mutation", &self.message_id);
        }
        self.publish_delivery_in_tx(tx)?;
        relay_work::fault_point("after_queue_publication", &self.message_id);
        for effect in self.effects.iter().filter(|effect| effect.sent_by_self) {
            outgoing_relay::apply_outgoing_history_policy_in_tx(
                tx,
                effect.owner.0,
                self.signer,
                &self.message_id,
            )?;
        }
        relay_replay::complete_application_in_tx(tx, claim)?;
        relay_replay::mark_queued_in_tx(tx, self.signer, &self.message_id)
    }

    fn publish_delivery_in_tx(&self, tx: &Transaction<'_>) -> Result<(), StorageError> {
        if matches!(self.operation, ApplicationOperation::SetChatSecret { .. })
            && matches!(self.delivery, DeliveryTarget::Local(_))
        {
            // The unchanged Client consumes metadata-only availability hints.
            // It cannot acknowledge this server-to-server sealed operation.
            return Ok(());
        }
        let identity = relay_queue::RelayIdentity {
            signer: self.signer,
            recipient: self.recipient,
            message_id: self.message_id.clone(),
            legacy_signer_id: self
                .effects
                .iter()
                .find(|e| e.sent_by_self)
                .map(|e| e.owner.0)
                .or(Some(self.signer_id as i64)),
            legacy_recipient_id: match self.delivery {
                DeliveryTarget::Local(owner) => Some(owner.0),
                _ => Some(self.recipient_id as i64),
            },
        };
        let target = match &self.delivery {
            DeliveryTarget::Local(owner) => relay_queue::RelayTarget::User(owner.0 as u64),
            DeliveryTarget::Remote(node) => relay_queue::RelayTarget::Iota(node.clone()),
        };
        relay_queue::enqueue_in_tx(
            tx,
            target,
            &identity,
            &self.frame,
            self.accepted_at,
            self.frame_id,
            &self.type_map_version,
        )?;
        Ok(())
    }

    pub(crate) fn verify_principal_fences_on(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), StorageError> {
        for (fence, handle, identity) in [
            (
                &self.principal_fences[0],
                self.signer,
                &self.signer_identity,
            ),
            (
                &self.principal_fences[1],
                self.recipient,
                &self.recipient_identity,
            ),
        ] {
            if fence.handle != handle
                || crate::federated_relay::protocol_principal(&fence.principal) != *identity
            {
                return Err(StorageError::MessageUnauthorized);
            }
            fence.verify_on(connection)?;
        }
        Ok(())
    }

    pub fn resume_applied(&self, work: &relay_work::AcceptedWork) -> Result<(), StorageError> {
        db::with_immediate_transaction(|tx| {
            let matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2 AND state = 'applied' AND frame = ?3
                AND processing_generation = ?4 AND processing_owner IS ?5 AND recovery_attempts = ?6
                AND recovery_status IN ('ready','retry') AND recovery_next_at <= ?7)", params![self.signer.0, self.message_id, self.frame, work.generation, work.owner, work.attempts, now_millis_i64()], |r| r.get(0))?;
            if !matches {
                return Err(StorageError::StaleRelayClaim);
            }
            for effect in &self.effects {
                relay_work::verify_owner_in_tx(tx, effect.owner.0, effect.principal)?;
            }
            self.publish_delivery_in_tx(tx)?;
            relay_replay::mark_queued_in_tx(tx, self.signer, &self.message_id)
        })
    }
}
