use crate::message_common::{OptionalDataValueExt, now_millis_i64};
use chat_files::MessageState;
use iota_identity::{LocalUserId, PrincipalHandle, PrincipalHome};
use iota_storage::storage_error::StorageError;
use iota_storage::util::{
    chat_files, chats_util, db, e2ee_storage, outgoing_relay, receipt_policy, relay_queue,
    relay_replay, relay_work,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum ApplicationOperation {
    MessageSend {
        content: String,
        send_time: i64,
        height: i64,
        version: i64,
        reply_to: Option<i64>,
    },
    MessageEdit {
        content: String,
        send_time: i64,
        version: i64,
    },
    MessageReactionAdd {
        reaction: String,
        send_time: i64,
    },
    MessageReactionRemove {
        reaction: String,
        send_time: i64,
    },
    MessageDelete {
        send_time: i64,
    },
    MessageDeleteLive {
        send_time: i64,
    },
    MessageState {
        message_id: String,
        state: MessageState,
        event_at: i64,
    },
    MessageReceived {
        message_id: String,
        event_at: i64,
    },
    SetChatSecret {
        chat_id: String,
        legacy_chat_id: Option<String>,
        version: i64,
        wrapping_scheme: String,
        sender: SecretCopy,
        recipient: SecretCopy,
    },
    AddConversation {
        name: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SecretCopy {
    pub(crate) encrypted_secret: Vec<u8>,
    pub(crate) kem_ciphertext: Vec<u8>,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PreparedRelayOperation {
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
    let frame = verified
        .content
        .as_ref()
        .ok_or_else(|| invalid("durable replay has no fresh application"))?;
    let signer_id = verified.signer.principal.user_id;
    let recipient_id = verified.recipient.principal.user_id;
    let signer_identity = crate::federated_relay::protocol_principal(&verified.signer.principal);
    let recipient_identity =
        crate::federated_relay::protocol_principal(&verified.recipient.principal);
    if let Some(value) = frame.get_data(DataType::ChatId)
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
    if created_at < accepted_at.saturating_sub(relay_replay::RELAY_RETENTION_MILLIS)
        || created_at
            > accepted_at.saturating_add(relay_replay::MAX_RELAY_FUTURE_SKEW_MILLIS as i64)
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
                .or_else(|| value.as_str().and_then(|v| v.parse::<u64>().ok()))
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
            let version = positive_version()?;
            // A shared Iota commits both initial envelopes in the same transaction.
            let shared_initializer = sender.is_some() && recipient.is_some() && version == 1;
            if signer_identity == recipient_identity
                || (signer_identity > recipient_identity && !shared_initializer)
            {
                return Err(StorageError::MessageUnauthorized);
            }
            let chat_id = text(frame, DataType::ChatId)?;
            if chat_id
                != tau_relay_protocol::canonical_chat_id(&signer_identity, &recipient_identity)
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
                let field = |key: DataType| value.get_field(key.try_to_id(map)?);
                let encoded_identity = field(DataType::UserId)
                    .and_then(DataValue::as_str)
                    .ok_or_else(|| invalid("secret recipient identity"))?;
                let id: tau_relay_protocol::Principal = serde_json::from_str(encoded_identity)
                    .map_err(|_| invalid("secret recipient identity"))?;
                if serde_json::to_string(&id).map_err(|_| invalid("secret recipient identity"))?
                    != encoded_identity
                {
                    return Err(invalid("noncanonical secret recipient identity"));
                }
                let copy = SecretCopy {
                    encrypted_secret: field(DataType::EncryptedSecret)
                        .and_then(DataValue::as_bytes)
                        .ok_or_else(|| invalid("encrypted secret"))?,
                    kem_ciphertext: field(DataType::KemCiphertext)
                        .and_then(DataValue::as_bytes)
                        .ok_or_else(|| invalid("secret KEM"))?,
                };
                copies.push((id, copy));
            }
            let sender_index = copies
                .iter()
                .position(|(identity, _)| *identity == signer_identity)
                .ok_or(StorageError::MessageUnauthorized)?;
            let sender_copy = copies.remove(sender_index).1;
            let (identity, recipient_copy) = copies.remove(0);
            if identity != recipient_identity {
                return Err(StorageError::MessageUnauthorized);
            }
            ApplicationOperation::SetChatSecret {
                chat_id,
                legacy_chat_id: (signer_identity.authority == recipient_identity.authority).then(
                    || {
                        format!(
                            "{}:{}",
                            signer_id.min(recipient_id),
                            signer_id.max(recipient_id)
                        )
                    },
                ),
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
    Ok(PreparedRelayOperation {
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
        let chat_id = e2ee_storage::principal_chat_id(self.signer, self.recipient)
            .ok_or_else(|| invalid("principal pair"))?;
        match &self.operation {
            ApplicationOperation::MessageSend {
                content,
                send_time,
                height,
                version,
                reply_to,
            } => {
                let legacy = if sender < recipient {
                    format!("{sender}:{recipient}")
                } else {
                    format!("{recipient}:{sender}")
                };
                if self.signer_identity.authority == self.recipient_identity.authority {
                    e2ee_storage::migrate_chat_secret_namespace_in_tx(
                        tx,
                        &owner.to_string(),
                        &legacy,
                        &format!("chat:{legacy}:main"),
                        &chat_id,
                        &e2ee_storage::principal_secret_id(&chat_id),
                    )?;
                }
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
                let legacy = format!("{}:{}", sender.min(recipient), sender.max(recipient));
                if self.signer_identity.authority == self.recipient_identity.authority {
                    e2ee_storage::migrate_chat_secret_namespace_in_tx(
                        tx,
                        &owner.to_string(),
                        &legacy,
                        &format!("chat:{legacy}:main"),
                        &chat_id,
                        &e2ee_storage::principal_secret_id(&chat_id),
                    )?;
                }
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
            ApplicationOperation::SetChatSecret { legacy_chat_id, .. } => {
                let secret = self.secret_for(effect)?;
                if let Some(legacy_chat_id) = legacy_chat_id {
                    e2ee_storage::migrate_chat_secret_namespace_in_tx(
                        tx,
                        &owner.to_string(),
                        legacy_chat_id,
                        &format!("chat:{legacy_chat_id}:main"),
                        &secret.chat_id,
                        &secret.secret_id,
                    )?;
                }
                e2ee_storage::put_chat_secret_in_tx(tx, &secret)?;
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
        let chat_id = e2ee_storage::principal_chat_id(self.signer, self.recipient)
            .ok_or_else(|| invalid("principal pair"))?;
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

    pub fn commit(&self, claim: &relay_replay::ProcessingClaim) -> Result<(), StorageError> {
        if claim.signer != self.signer || claim.message_id != self.message_id {
            return Err(StorageError::StaleRelayClaim);
        }
        db::with_immediate_transaction(|tx| {
            relay_replay::verify_claim_in_tx(tx, claim)?;
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
                if let ApplicationOperation::SetChatSecret { legacy_chat_id, .. } = &self.operation
                    && effect.sent_by_self
                    && matches!(self.delivery, DeliveryTarget::Remote(_))
                {
                    relay_work::defer_secret_in_tx(
                        tx,
                        claim,
                        &relay_work::DeferredSecret {
                            owner: effect.owner.0,
                            principal: effect.principal,
                            legacy_chat_id: legacy_chat_id.clone(),
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
        })
    }

    fn publish_delivery_in_tx(&self, tx: &Transaction<'_>) -> Result<(), StorageError> {
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
