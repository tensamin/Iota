use crate::message_common::*;
use iota_storage::util::chat_files::{self, MessageState};
use iota_storage::util::chats_util::{self, get_user, has_user, mod_user};
use iota_storage::util::communities_util::CommunitiesUtil;
use iota_storage::util::e2ee_storage::{self, ChatSecretQuery};
use iota_storage::util::settings;
use iota_storage::util::synced_settings::{self, SettingScope, SyncedSetting};
use iota_storage::util::user_blobs::{self, UserBlob};
use iota_storage::util::{blocked_users, message_storage_policy, receipt_policy};
use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, TypeMap, VerifiedRelayContent,
};

use crate::relay::VerifiedRelayContext;
use iota_storage::storage_error::StorageError;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_NOTIFICATION_ID: AtomicU32 = AtomicU32::new(1);

fn next_notification_id() -> u32 {
    NEXT_NOTIFICATION_ID.fetch_add(1, Ordering::Relaxed).max(1)
}

#[derive(Debug)]
pub struct MessageMutation {
    pub sender_id: i64,
    pub partner_id: i64,
    pub send_time: i64,
}

#[derive(Debug)]
pub struct SettingMutation {
    pub response: CommunicationValue,
    pub changed: Option<CommunicationValue>,
}

#[derive(Debug)]
pub struct BlobMutation {
    pub response: CommunicationValue,
    pub changed: Option<CommunicationValue>,
}

#[derive(Debug)]
pub struct PolicyMutation {
    pub response: CommunicationValue,
    pub changed: Option<CommunicationValue>,
}

struct SettingLocator {
    scope: SettingScope,
    scope_key: String,
    name: String,
}

fn required_sender_id(cv: &CommunicationValue) -> Result<i64, CommunicationValue> {
    let sender = cv
        .require_sender()
        .map_err(|_| error_response(cv, CommunicationType::ErrorInvalidData))?;
    i64::try_from(sender).map_err(|_| error_response(cv, CommunicationType::ErrorInvalidData))
}

fn sender_wire_id(sender_id: i64) -> u64 {
    u64::try_from(sender_id).expect("validated authenticated sender is non-negative")
}

pub fn message_mutation(cv: &CommunicationValue) -> Result<MessageMutation, CommunicationValue> {
    let sender_id = required_sender_id(cv)?;
    let partner_id = data_i64(cv, DataType::ChatPartnerId)
        .filter(|id| *id > 0)
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorInvalidData))?;
    let send_time = data_i64(cv, DataType::SendTime)
        .filter(|time| *time > 0)
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorInvalidData))?;

    Ok(MessageMutation {
        sender_id,
        partner_id,
        send_time,
    })
}

pub fn success_response(cv: &CommunicationValue) -> CommunicationValue {
    error_response(cv, CommunicationType::Success)
}

fn add_conversation_for_user(
    user_id: i64,
    other_id: i64,
    name: Option<&str>,
) -> Result<(), StorageError> {
    let mut contact = get_user(user_id, other_id)?
        .unwrap_or_else(|| iota_storage::users::contact::Contact::new(other_id));
    if let Some(name) = name {
        contact.user_name = Some(name.to_string());
    }
    mod_user(user_id, &contact)
}

fn relay_field<'a>(
    payload: &'a DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Option<&'a DataValue> {
    payload.get_field(data_type.try_to_id(type_map)?)
}

fn relay_string<'a>(
    payload: &'a DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Option<&'a str> {
    relay_field(payload, data_type, type_map)?.as_str()
}

fn relay_number(payload: &DataValue, data_type: DataType, type_map: &TypeMap) -> Option<i128> {
    relay_field(payload, data_type, type_map)?.as_number()
}

fn relay_identity(
    payload: &DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<Option<u64>, String> {
    let Some(value) = relay_field(payload, data_type, type_map) else {
        return Ok(None);
    };
    if let Some(number) = value.as_number() {
        return u64::try_from(number)
            .map(Some)
            .map_err(|_| format!("Relay {data_type:?} is outside the user ID range"));
    }
    if let Some(text) = value.as_str() {
        return text
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("Relay {data_type:?} is not a user ID"));
    }
    Err(format!("Relay {data_type:?} has an invalid user ID value"))
}

fn validate_relay_identity(
    context: &VerifiedRelayContext,
    payload: &DataValue,
) -> Result<(), String> {
    if relay_identity(payload, DataType::SenderId, &context.type_map)?
        .is_some_and(|sender_id| sender_id != context.signer_id)
    {
        return Err("Relay SenderId does not match the authenticated signer".into());
    }
    if relay_identity(payload, DataType::ReceiverId, &context.type_map)?
        .is_some_and(|receiver_id| receiver_id != context.final_recipient_id)
    {
        return Err("Relay ReceiverId does not match the authenticated recipient".into());
    }
    Ok(())
}

/*
 * Apply only operations whose actor and recipient can be taken from verified
 * Relay metadata. The raw Relay frame never enters these handlers, so outer
 * routing fields cannot become application identity.
 */
pub fn apply_verified_relay_content(
    context: &VerifiedRelayContext,
    content: &VerifiedRelayContent,
    accepted_at: i64,
    storage_owner: i64,
    sent_by_self: bool,
) -> Result<(), String> {
    validate_relay_identity(context, &content.content)?;
    let sender_id = i64::try_from(context.signer_id)
        .map_err(|_| "Relay signer ID exceeds the local storage range".to_string())?;
    let recipient_id = i64::try_from(context.final_recipient_id)
        .map_err(|_| "Relay recipient ID exceeds the local storage range".to_string())?;
    let created_at = i64::try_from(context.created_at)
        .map_err(|_| "Relay creation time exceeds the local storage range".to_string())?;

    match content.message_type.as_str() {
        "MessageState" => {
            let partner_id =
                relay_number(&content.content, DataType::ChatPartnerId, &context.type_map)
                    .and_then(|value| i64::try_from(value).ok())
                    .filter(|id| *id == recipient_id)
                    .ok_or_else(|| "Relay MessageState has an invalid ChatPartnerId".to_string())?;
            let relay_message_id = relay_string(
                &content.content,
                DataType::RelayMessageId,
                &context.type_map,
            )
            .ok_or_else(|| "Relay MessageState is missing RelayMessageId".to_string())?;
            let event_at = relay_number(&content.content, DataType::EventAt, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay MessageState is missing EventAt".to_string())?;
            let state = relay_string(&content.content, DataType::MessageState, &context.type_map)
                .map(MessageState::from_str)
                .filter(|state| matches!(state, MessageState::Received | MessageState::Read))
                .ok_or_else(|| "Relay MessageState has an invalid state".to_string())?;
            if sent_by_self {
                return chat_files::change_message_state_by_relay_id(
                    storage_owner,
                    recipient_id,
                    relay_message_id,
                    state,
                )
                .map_err(|error| error.to_string());
            }
            chat_files::record_message_receipt(
                storage_owner,
                recipient_id,
                relay_message_id,
                sender_id,
                &context.message_id,
                state,
                event_at,
                now_millis_i64(),
            )
            .map_err(|error| error.to_string())?;
            let _ = partner_id;
            Ok(())
        }
        "MessageSend" => {
            let message = relay_string(&content.content, DataType::Content, &context.type_map)
                .ok_or_else(|| "Relay MessageSend is missing Content".to_string())?;
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .unwrap_or(created_at);
            let height = relay_number(&content.content, DataType::Height, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .unwrap_or_default();
            let key_version =
                relay_number(&content.content, DataType::VersionNumber, &context.type_map)
                    .and_then(|value| i64::try_from(value).ok())
                    .filter(|value| *value > 0)
                    .ok_or_else(|| "Relay MessageSend has an invalid VersionNumber".to_string())?;
            let reply_to = relay_number(&content.content, DataType::ReplyId, &context.type_map)
                .and_then(|value| i64::try_from(value).ok());
            if relay_string(
                &content.content,
                DataType::RelayMessageId,
                &context.type_map,
            )
            .is_some_and(|relay_message_id| relay_message_id != context.message_id)
            {
                return Err(
                    "Relay MessageSend identity does not match its protected message ID".into(),
                );
            }
            let chat_id = if sender_id < recipient_id {
                format!("{sender_id}:{recipient_id}")
            } else {
                format!("{recipient_id}:{sender_id}")
            };
            let latest_secret = e2ee_storage::get_chat_secret(ChatSecretQuery {
                user_id: storage_owner.to_string(),
                chat_id: chat_id.clone(),
                secret_id: Some(format!("chat:{chat_id}:main")),
                version: None,
            })
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Relay MessageSend has no committed chat secret".to_string())?;
            if latest_secret.version != key_version {
                return Err("Relay MessageSend uses a stale chat secret version".into());
            }
            chat_files::add_message(chat_files::NewMessage {
                relay_signer_id: sender_id,
                relay_message_id: &context.message_id,
                authored_at: created_at,
                send_time,
                storage_owner,
                external_user: if sent_by_self {
                    recipient_id
                } else {
                    sender_id
                },
                sent_by_self,
                content: message,
                height,
                key_version,
                reply_to,
                origin_iota_received_at: sent_by_self.then_some(accepted_at),
                destination_iota_received_at: (!sent_by_self).then_some(accepted_at),
                initial_state: if sent_by_self {
                    MessageState::Sending
                } else {
                    MessageState::Sent
                },
            })
            .map_err(|error| error.to_string())?;
            Ok(())
        }
        "MessageEdit" => {
            let message = relay_string(&content.content, DataType::Content, &context.type_map)
                .ok_or_else(|| "Relay MessageEdit is missing Content".to_string())?;
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay MessageEdit is missing SendTime".to_string())?;
            let external_user = if sent_by_self {
                recipient_id
            } else {
                sender_id
            };
            let result = if sent_by_self {
                chat_files::edit_message(
                    storage_owner,
                    external_user,
                    send_time,
                    sender_id,
                    message,
                )
            } else {
                chat_files::apply_remote_edit(
                    storage_owner,
                    external_user,
                    send_time,
                    sender_id,
                    message,
                )
            };
            result.map_err(|error| error.to_string())
        }
        "MessageReactionAdd" | "MessageReactionRemove" => {
            let reaction = relay_string(&content.content, DataType::Reaction, &context.type_map)
                .filter(|value| !value.is_empty() && value.len() <= 64)
                .ok_or_else(|| "Relay reaction is invalid".to_string())?;
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay reaction is missing SendTime".to_string())?;
            let external_user = if sent_by_self {
                recipient_id
            } else {
                sender_id
            };
            let result = if content.message_type == "MessageReactionAdd" {
                chat_files::add_reaction(
                    storage_owner,
                    external_user,
                    send_time,
                    sender_id,
                    reaction,
                )
            } else {
                chat_files::remove_reaction(
                    storage_owner,
                    external_user,
                    send_time,
                    sender_id,
                    reaction,
                )
            };
            result.map_err(|error| error.to_string())
        }
        "MessageDelete" | "MessageDeleteLive" => {
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay MessageDeleteLive is missing SendTime".to_string())?;
            let external_user = if sent_by_self {
                recipient_id
            } else {
                sender_id
            };
            let result = if sent_by_self {
                chat_files::delete_message(storage_owner, external_user, send_time)
            } else {
                chat_files::apply_remote_delete(storage_owner, external_user, send_time, sender_id)
            };
            result.map_err(|error| error.to_string())
        }
        "SetChatSecret" => {
            let frame = CommunicationValue::new(CommunicationType::SetChatSecret)
                .with_payload(content.content.clone());
            let recipients = chat_secret_recipients(&frame)
                .ok_or_else(|| "Relay SetChatSecret has no recipients".to_string())?;
            let recipient = recipients
                .iter()
                .find(|value| value.user_id == storage_owner.to_string())
                .ok_or_else(|| "Relay SetChatSecret recipient mismatch".to_string())?;
            let chat_id = data_string(&frame, DataType::ChatId)
                .ok_or_else(|| "Relay SetChatSecret is missing ChatId".to_string())?;
            let secret_id = data_string(&frame, DataType::SecretId)
                .ok_or_else(|| "Relay SetChatSecret is missing SecretId".to_string())?;
            let version = data_i64(&frame, DataType::VersionNumber)
                .filter(|value| *value > 0)
                .ok_or_else(|| "Relay SetChatSecret is missing VersionNumber".to_string())?;
            let wrapping_scheme = data_string(&frame, DataType::WrappingScheme)
                .ok_or_else(|| "Relay SetChatSecret is missing WrappingScheme".to_string())?;
            let mut participants = chat_id
                .split(':')
                .map(|value| value.parse::<u64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Relay SetChatSecret ChatId is not a user pair".to_string())?;
            if participants.len() != 2
                || participants.contains(&0)
                || participants[0] == participants[1]
            {
                return Err("Relay SetChatSecret ChatId is not a user pair".into());
            }
            participants.sort_unstable();
            if chat_id != format!("{}:{}", participants[0], participants[1]) {
                return Err("Relay SetChatSecret ChatId is not canonical".into());
            }
            if !participants.contains(&context.signer_id) {
                return Err("Relay SetChatSecret signer is not in ChatId".into());
            }
            if !participants.contains(&context.final_recipient_id) {
                return Err("Relay SetChatSecret recipient is not in ChatId".into());
            }
            if secret_id != format!("chat:{chat_id}:main") {
                return Err("Relay SetChatSecret has an invalid secret namespace".into());
            }
            if context.signer_id != participants[0] {
                return Err(
                    "Relay SetChatSecret was signed by a non-authoritative participant".into(),
                );
            }
            if context.final_recipient_id != participants[1] {
                return Err("Relay SetChatSecret recipient is not the peer participant".into());
            }
            if recipients.len() != 2 {
                return Err("Relay SetChatSecret must contain exactly two recipients".into());
            }
            let mut recipient_ids = recipients
                .iter()
                .map(|value| value.user_id.parse::<u64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Relay SetChatSecret has invalid recipient IDs".to_string())?;
            recipient_ids.sort_unstable();
            let expected_recipient_ids = participants.clone();
            if recipient_ids != expected_recipient_ids {
                return Err("Relay SetChatSecret recipients do not match relay identities".into());
            }
            e2ee_storage::put_chat_secret(e2ee_storage::StoredChatSecret {
                user_id: storage_owner.to_string(),
                chat_id,
                secret_id,
                version,
                encrypted_secret: recipient.encrypted_secret.clone(),
                kem_ciphertext: recipient.kem_ciphertext.clone(),
                wrapping_scheme,
                created_at,
                updated_at: now_millis_i64(),
            })
            .map_err(|error| error.to_string())
        }
        "AddConversation" => {
            let other_id =
                relay_number(&content.content, DataType::ChatPartnerId, &context.type_map)
                    .and_then(|value| i64::try_from(value).ok())
                    .filter(|id| *id > 0)
                    .ok_or_else(|| {
                        "Relay AddConversation has an invalid ChatPartnerId".to_string()
                    })?;
            let user_id = storage_owner;
            if user_id <= 0 {
                return Err("Relay AddConversation has an invalid storage owner".into());
            }
            if sender_id == recipient_id {
                return Err("Relay AddConversation does not support self conversations".into());
            }
            if other_id != sender_id && other_id != recipient_id {
                return Err("Relay AddConversation does not match relay identities".into());
            }
            let expected_partner = if sent_by_self {
                recipient_id
            } else {
                sender_id
            };
            add_conversation_for_user(
                user_id,
                expected_partner,
                relay_string(
                    &content.content,
                    DataType::ChatPartnerName,
                    &context.type_map,
                ),
            )
            .map_err(|error| format!("AddConversation persistence failed: {error}"))
        }
        _ => Ok(()),
    }
}

/* Local receipt disclosure is checked before the relay enters durable state. */
pub fn validate_outgoing_receipt_policy(
    sender_id: i64,
    context: &VerifiedRelayContext,
    content: &VerifiedRelayContent,
) -> Result<(), String> {
    if content.message_type != "MessageState" {
        return Ok(());
    }
    let state = relay_string(&content.content, DataType::MessageState, &context.type_map)
        .map(MessageState::from_str)
        .filter(|state| matches!(state, MessageState::Received | MessageState::Read))
        .ok_or_else(|| "local MessageState has an invalid state".to_string())?;
    let policy = receipt_policy::get(sender_id).map_err(|error| error.to_string())?;
    let allowed = match state {
        MessageState::Read => policy.send_read_receipts,
        MessageState::Received => policy.send_received_receipts,
        MessageState::Sent | MessageState::Sending => false,
    };
    if allowed {
        Ok(())
    } else {
        Err("local receipt disclosure is disabled by policy".into())
    }
}

pub fn handle_message_edit(cv: &CommunicationValue) -> CommunicationValue {
    let mutation = match message_mutation(cv) {
        Ok(mutation) => mutation,
        Err(response) => return response,
    };
    let Some(content) = cv.get_data(DataType::Content).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    match chat_files::edit_message(
        mutation.sender_id,
        mutation.partner_id,
        mutation.send_time,
        mutation.sender_id,
        content,
    ) {
        Ok(()) => success_response(cv),
        Err(_) => error_response(cv, CommunicationType::ErrorNotFound),
    }
}

pub fn handle_message_reaction(cv: &CommunicationValue, add: bool) -> CommunicationValue {
    let mutation = match message_mutation(cv) {
        Ok(mutation) => mutation,
        Err(response) => return response,
    };
    let Some(reaction) = cv.get_data(DataType::Reaction).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if reaction.is_empty() || reaction.len() > 64 {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }

    let result = if add {
        chat_files::add_reaction(
            mutation.sender_id,
            mutation.partner_id,
            mutation.send_time,
            mutation.sender_id,
            reaction,
        )
    } else {
        chat_files::remove_reaction(
            mutation.sender_id,
            mutation.partner_id,
            mutation.send_time,
            mutation.sender_id,
            reaction,
        )
    };

    match result {
        Ok(()) => success_response(cv),
        Err(iota_storage::storage_error::StorageError::ReactionLimitReached) => {
            error_response(cv, CommunicationType::ErrorInvalidData)
        }
        Err(_) => error_response(cv, CommunicationType::ErrorNotFound),
    }
}

pub fn handle_message_delete(cv: &CommunicationValue) -> CommunicationValue {
    let mutation = match message_mutation(cv) {
        Ok(mutation) => mutation,
        Err(response) => return response,
    };

    match chat_files::delete_message(mutation.sender_id, mutation.partner_id, mutation.send_time) {
        Ok(()) => success_response(cv),
        Err(_) => error_response(cv, CommunicationType::ErrorNotFound),
    }
}

fn stored_message_fields(
    message: &chat_files::StoredMessage,
    storage_owner: i64,
    partner_id: i64,
) -> Vec<(DataType, DataValue)> {
    let mut fields = vec![
        (
            DataType::MessageId,
            DataValue::SignedNumber(message.id as i128),
        ),
        (
            DataType::SendTime,
            DataValue::SignedNumber(message.message_time as i128),
        ),
        (DataType::Content, DataValue::Str(message.content.clone())),
        (
            DataType::MessageState,
            DataValue::Str(message.message_state.clone()),
        ),
        (
            DataType::Height,
            DataValue::SignedNumber(message.height as i128),
        ),
        (
            DataType::VersionNumber,
            DataValue::SignedNumber(message.key_version as i128),
        ),
    ];
    let sender_id = if message.sent_by_self {
        storage_owner
    } else {
        partner_id
    };
    if let Some(relay_signer_id) = message.relay_signer_id {
        fields.push((
            DataType::SenderId,
            DataValue::SignedNumber(relay_signer_id.into()),
        ));
    } else if let Ok(sender_id) = u128::try_from(sender_id) {
        fields.push((DataType::SenderId, DataValue::UnsignedNumber(sender_id)));
    }
    if let Some(relay_message_id) = &message.relay_message_id {
        fields.push((
            DataType::RelayMessageId,
            DataValue::Str(relay_message_id.clone()),
        ));
    }
    for (data_type, timestamp) in [
        (DataType::AuthoredAt, message.authored_at),
        (
            DataType::OriginIotaReceivedAt,
            message.origin_iota_received_at,
        ),
        (
            DataType::DestinationIotaReceivedAt,
            message.destination_iota_received_at,
        ),
        (DataType::ClientReceivedAt, message.client_received_at),
        (
            DataType::ClientReceivedRecordedAt,
            message.client_received_recorded_at,
        ),
        (DataType::ReadAt, message.read_at),
        (DataType::ReadRecordedAt, message.read_recorded_at),
    ] {
        if let Some(timestamp) = timestamp {
            fields.push((data_type, DataValue::SignedNumber(timestamp.into())));
        }
    }
    if let Some(failed_at) = message.delivery_failed_at {
        fields.push((
            DataType::UpdatedAt,
            DataValue::SignedNumber(failed_at.into()),
        ));
    }
    if let Some(failure) = &message.delivery_failure {
        fields.push((DataType::ErrorType, DataValue::Str(failure.clone())));
    }
    if message.edited {
        fields.push((DataType::Edited, DataValue::Bool(true)));
    }
    if let Some(reply_to) = message.reply_to.and_then(|id| u64::try_from(id).ok()) {
        fields.push((
            DataType::ReplyId,
            DataValue::UnsignedNumber(u128::from(reply_to)),
        ));
    }
    if !message.reactions.is_empty() {
        let reactions = message
            .reactions
            .iter()
            .map(|reaction| {
                typed_container(vec![
                    (
                        DataType::Reaction,
                        DataValue::Str(reaction.reaction.clone()),
                    ),
                    (
                        DataType::SenderId,
                        DataValue::SignedNumber(reaction.user_id as i128),
                    ),
                ])
            })
            .collect();
        fields.push((DataType::Reactions, DataValue::Array(reactions)));
    }
    fields
}

fn stored_message_value(
    message: &chat_files::StoredMessage,
    storage_owner: i64,
    partner_id: i64,
) -> DataValue {
    typed_container(stored_message_fields(message, storage_owner, partner_id))
}

fn synced_setting_value(setting: &SyncedSetting) -> DataValue {
    typed_container(vec![
        (
            DataType::SettingId,
            DataValue::SignedNumber(setting.id.into()),
        ),
        (
            DataType::SettingScope,
            DataValue::Str(setting.scope.as_str().to_string()),
        ),
        (
            DataType::SettingTarget,
            DataValue::Str(setting.scope_key.clone()),
        ),
        (DataType::SettingsName, DataValue::Str(setting.name.clone())),
        (DataType::Payload, DataValue::Str(setting.payload.clone())),
        (
            DataType::VersionNumber,
            DataValue::SignedNumber(setting.revision.into()),
        ),
    ])
}

pub fn handle_get_chat_secret(cv: &CommunicationValue) -> CommunicationValue {
    let Some(user_id) = data_string(cv, DataType::UserId) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    if user_id != sender_id.to_string() {
        return error_response(cv, CommunicationType::ErrorNotFound);
    }
    let Some(chat_id) = data_string(cv, DataType::ChatId) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    match e2ee_storage::get_chat_secret(ChatSecretQuery {
        user_id,
        chat_id,
        secret_id: data_string(cv, DataType::SecretId),
        version: data_i64(cv, DataType::VersionNumber),
    }) {
        Ok(Some(record)) => CommunicationValue::new(CommunicationType::ChatSecretResponse)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(sender_id))
            .add_typed_default(DataType::UserId, DataValue::Str(record.user_id))
            .add_typed_default(DataType::ChatId, DataValue::Str(record.chat_id))
            .add_typed_default(DataType::SecretId, DataValue::Str(record.secret_id))
            .add_typed_default(
                DataType::VersionNumber,
                DataValue::SignedNumber(record.version as i128),
            )
            .add_typed_default(
                DataType::EncryptedSecret,
                DataValue::Bytes(record.encrypted_secret),
            )
            .add_typed_default(
                DataType::KemCiphertext,
                DataValue::Bytes(record.kem_ciphertext),
            )
            .add_typed_default(
                DataType::WrappingScheme,
                DataValue::Str(record.wrapping_scheme),
            )
            .add_typed_default(
                DataType::CreatedAt,
                DataValue::SignedNumber(record.created_at as i128),
            )
            .add_typed_default(
                DataType::UpdatedAt,
                DataValue::SignedNumber(record.updated_at as i128),
            ),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotSet),
        Err(_) => error_response(cv, CommunicationType::ErrorInvalidData),
    }
}

pub fn handle_create_app(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let app_identifier = cv
        .get_data(DataType::AppIdentifier)
        .as_str()
        .unwrap_or("")
        .to_string();
    let app_public_key = cv
        .get_data(DataType::AppPublicKey)
        .as_str()
        .unwrap_or("")
        .to_string();

    if !app_identifier.is_empty() && !app_public_key.is_empty() {
        let user = match iota_storage::users::user_manager::get_user(sender_id) {
            Ok(user) => user,
            Err(_) => return error_response(cv, CommunicationType::ErrorInternal),
        };
        if let Some(mut user) = user {
            if !user.trusted_apps.contains_key(&app_identifier) {
                user.trusted_apps.insert(app_identifier, app_public_key);
                iota_storage::users::user_manager::update_user(user);
            }
        }
    }

    CommunicationValue::new(CommunicationType::CreateApp)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
}

pub fn handle_delete_app(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let app_identifier = cv
        .get_data(DataType::AppIdentifier)
        .as_str()
        .unwrap_or("")
        .to_string();

    if !app_identifier.is_empty() {
        let user = match iota_storage::users::user_manager::get_user(sender_id) {
            Ok(user) => user,
            Err(_) => return error_response(cv, CommunicationType::ErrorInternal),
        };
        if let Some(mut user) = user {
            if user.trusted_apps.contains_key(&app_identifier) {
                user.trusted_apps.remove(&app_identifier);
                iota_storage::users::user_manager::update_user(user);
            }
        }
    }

    CommunicationValue::new(CommunicationType::DeleteApp)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
}

fn contact_value(
    contact: &iota_storage::users::contact::Contact,
    messages: &[chat_files::StoredMessage],
    storage_owner: i64,
) -> DataValue {
    let mut fields = vec![(
        DataType::UserId,
        DataValue::SignedNumber(contact.user_id as i128),
    )];
    if let Some(name) = &contact.user_name {
        fields.push((DataType::Username, DataValue::Str(name.clone())));
    }
    if contact.created_at > 0 {
        fields.push((
            DataType::CreatedAt,
            DataValue::SignedNumber(contact.created_at.into()),
        ));
    }
    if let Some(last_message_at) = contact.last_message_at {
        fields.push((
            DataType::LastMessageAt,
            DataValue::SignedNumber(last_message_at as i128),
        ));
    }
    fields.push((
        DataType::Messages,
        DataValue::Array(
            messages
                .iter()
                .filter(|message| message.external_user == contact.user_id)
                .map(|message| stored_message_value(message, storage_owner, contact.user_id))
                .collect(),
        ),
    ));
    typed_container(fields)
}

fn current_contact_ids(user_id: i64) -> Result<DataValue, StorageError> {
    Ok(contact_ids_value(
        chats_util::get_users(user_id)?
            .into_iter()
            .map(|contact| contact.user_id),
    ))
}

fn contact_ids_value(ids: impl IntoIterator<Item = i64>) -> DataValue {
    let mut contact_ids = ids.into_iter().collect::<Vec<_>>();
    contact_ids.sort_unstable();
    contact_ids.dedup();

    DataValue::Array(
        contact_ids
            .into_iter()
            .map(|user_id| DataValue::SignedNumber(user_id as i128))
            .collect(),
    )
}

#[cfg(test)]
mod presence_tests {
    use super::{contact_ids_value, handle_get_chats, message_mutation};
    use mtp::codec::{CommunicationType, CommunicationValue, DataValue};

    #[test]
    fn contact_snapshot_is_sorted_and_deduplicated() {
        assert_eq!(
            contact_ids_value([9, 3, 9, 4, 3]),
            DataValue::Array(vec![
                DataValue::SignedNumber(3),
                DataValue::SignedNumber(4),
                DataValue::SignedNumber(9),
            ])
        );
    }

    #[test]
    fn message_mutation_rejects_a_missing_authenticated_sender() {
        let request = CommunicationValue::new(CommunicationType::MessageEdit).with_id(11);
        let response = message_mutation(&request).expect_err("missing sender must be rejected");

        assert!(response.is_type(CommunicationType::ErrorInvalidData));
        assert_eq!(response.id(), Some(11));
        assert_eq!(response.receiver(), None);
    }

    #[test]
    fn read_handler_rejects_a_missing_authenticated_sender() {
        let request = CommunicationValue::new(CommunicationType::GetChats).with_id(12);
        let response = handle_get_chats(&request);

        assert!(response.is_type(CommunicationType::ErrorInvalidData));
        assert_eq!(response.id(), Some(12));
        assert_eq!(response.receiver(), None);
    }
}

fn sync_error(cv: &CommunicationValue) -> CommunicationValue {
    error_response(cv, CommunicationType::ErrorInvalidData).add_typed_default(
        DataType::SessionId,
        cv.get_data(DataType::SessionId)
            .cloned()
            .unwrap_or(DataValue::Null),
    )
}

/// The sender is authenticated by MTP; a UserId embedded by a client is never trusted here.
pub fn handle_client_connected(cv: &CommunicationValue) -> CommunicationValue {
    use iota_storage::util::sync::{self, CACHE_SCHEMA_VERSION};
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return sync_error(cv),
    };
    let session_id = match data_i64(cv, DataType::SessionId) {
        Some(id) if id > 0 => id,
        _ => return sync_error(cv),
    };
    let reported_version = match data_i64(cv, DataType::VersionNumber) {
        Some(version) if version >= 0 => version,
        _ => return sync_error(cv),
    };
    let cache_valid = cv.get_data(DataType::CacheValid).as_bool().unwrap_or(false);
    let schema = data_i64(cv, DataType::CacheSchemaVersion).unwrap_or(0);
    let head = match sync::head(user_id) {
        Ok(version) => version,
        Err(_) => return sync_error(cv),
    };
    let known_session = sync::has_session(user_id, session_id).unwrap_or(false);
    let acknowledged_version = sync::acknowledged_version(user_id, session_id).unwrap_or(None);
    let full = !cache_valid
        || reported_version == 0
        || !known_session
        || acknowledged_version.is_some_and(|version| reported_version < version)
        || reported_version > head
        || schema != CACHE_SCHEMA_VERSION;
    let (contacts, messages, settings, deleted_messages, deleted_contacts, deleted_settings, mode) =
        if full {
            let settings = match synced_settings::list(user_id) {
                Ok(settings) => settings,
                Err(_) => return sync_error(cv),
            };
            (
                match chats_util::get_users(user_id) {
                    Ok(contacts) => contacts,
                    Err(_) => return sync_error(cv),
                },
                chat_files::get_all_messages(user_id),
                settings,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                "full",
            )
        } else {
            match sync::delta(user_id, reported_version, head) {
                Ok(delta) => {
                    let settings =
                        match synced_settings::list_by_ids(user_id, &delta.setting_upserts) {
                            Ok(settings) => settings,
                            Err(_) => return sync_error(cv),
                        };
                    (
                        match chats_util::get_users_by_ids(user_id, &delta.contact_upserts) {
                            Ok(contacts) => contacts,
                            Err(_) => return sync_error(cv),
                        },
                        chat_files::get_messages_by_ids(user_id, &delta.message_upserts),
                        settings,
                        delta.deleted_message_ids,
                        delta.deleted_contact_ids,
                        delta.deleted_setting_ids,
                        "delta",
                    )
                }
                Err(_) => {
                    let settings = match synced_settings::list(user_id) {
                        Ok(settings) => settings,
                        Err(_) => return sync_error(cv),
                    };
                    (
                        match chats_util::get_users(user_id) {
                            Ok(contacts) => contacts,
                            Err(_) => return sync_error(cv),
                        },
                        chat_files::get_all_messages(user_id),
                        settings,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        "full",
                    )
                }
            }
        };
    let message_values = messages
        .iter()
        .map(|message| stored_message_value(message, user_id, message.external_user))
        .collect();
    if iota_storage::util::client_message_delivery::record_sync_delivery(
        user_id,
        session_id,
        head,
        messages.iter().map(|message| message.id),
    )
    .is_err()
    {
        return sync_error(cv);
    }
    let (blobs, deleted_blobs) = if mode == "delta" {
        match sync::delta(user_id, reported_version, head) {
            Ok(delta) => {
                let blobs = match user_blobs::list_by_ids(user_id, &delta.blob_upserts) {
                    Ok(blobs) => blobs,
                    Err(_) => return sync_error(cv),
                };
                let deleted =
                    match user_blobs::list_deleted_by_ids(user_id, &delta.deleted_blob_ids) {
                        Ok(blobs) => blobs,
                        Err(_) => return sync_error(cv),
                    };
                (blobs, deleted)
            }
            Err(_) => return sync_error(cv),
        }
    } else {
        match user_blobs::list(user_id) {
            Ok(blobs) => (blobs, Vec::new()),
            Err(_) => return sync_error(cv),
        }
    };
    let blocked_users = match blocked_users::list(user_id) {
        Ok(users) => users,
        Err(_) => return sync_error(cv),
    };
    let receipt_policy = match receipt_policy::get(user_id) {
        Ok(policy) => policy,
        Err(_) => return sync_error(cv),
    };
    let message_storage_policy = match message_storage_policy::get(user_id) {
        Ok(policy) => policy,
        Err(_) => return sync_error(cv),
    };
    let contact_ids = match current_contact_ids(user_id) {
        Ok(contact_ids) => contact_ids,
        Err(_) => return error_response(cv, CommunicationType::ErrorInternal),
    };
    let retention_duration = match message_storage_policy.retention {
        message_storage_policy::MessageRetention::Forever => None,
        message_storage_policy::MessageRetention::Duration { duration_ms } => Some(duration_ms),
    };
    let mut response = CommunicationValue::new(CommunicationType::ClientStateSync)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(user_id))
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(head as i128),
        )
        .add_typed_default(
            DataType::CacheSchemaVersion,
            DataValue::SignedNumber(CACHE_SCHEMA_VERSION as i128),
        )
        .add_typed_default(DataType::SyncMode, DataValue::Str(mode.into()))
        .add_typed_default(
            DataType::Contacts,
            DataValue::Array(
                contacts
                    .iter()
                    .map(|contact| contact_value(contact, &messages, user_id))
                    .collect(),
            ),
        )
        .add_typed_default(DataType::Messages, DataValue::Array(message_values))
        .add_typed_default(
            DataType::Settings,
            DataValue::Array(settings.iter().map(synced_setting_value).collect()),
        )
        .add_typed_default(
            DataType::Blobs,
            DataValue::Array(blobs.iter().map(blob_value).collect()),
        )
        .add_typed_default(
            DataType::DeletedBlobIds,
            DataValue::Array(
                deleted_blobs
                    .iter()
                    .map(|blob| DataValue::Str(blob.blob_id.clone()))
                    .collect(),
            ),
        )
        .add_typed_default(
            DataType::BlockedUserIds,
            DataValue::Array(
                blocked_users
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id.into()))
                    .collect(),
            ),
        )
        .add_typed_default(
            DataType::SendReadReceipts,
            DataValue::Bool(receipt_policy.send_read_receipts),
        )
        .add_typed_default(
            DataType::SendReceivedReceipts,
            DataValue::Bool(receipt_policy.send_received_receipts),
        )
        .add_typed_default(
            DataType::MessageHistoryMode,
            DataValue::Str(match message_storage_policy.history_mode {
                message_storage_policy::MessageHistoryMode::Retain => "retain".into(),
                message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery => {
                    "delete_after_client_delivery".into()
                }
            }),
        )
        .add_typed_default(
            DataType::Communities,
            DataValue::Array(community_values(user_id)),
        )
        .add_typed_default(
            DataType::DeletedMessageIds,
            DataValue::Array(
                deleted_messages
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id as i128))
                    .collect(),
            ),
        )
        .add_typed_default(
            DataType::DeletedContactIds,
            DataValue::Array(
                deleted_contacts
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id as i128))
                    .collect(),
            ),
        )
        .add_typed_default(
            DataType::DeletedSettingIds,
            DataValue::Array(
                deleted_settings
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id as i128))
                    .collect(),
            ),
        )
        .add_typed_default(DataType::UserIds, contact_ids)
        .add_typed_default(DataType::Calls, DataValue::Array(Vec::new()));
    if let Some(duration_ms) = retention_duration {
        response = response.add_typed_default(
            DataType::MessageRetentionDuration,
            DataValue::SignedNumber(duration_ms.into()),
        );
    }
    response
}

pub fn handle_client_state_ack(cv: &CommunicationValue) -> CommunicationValue {
    use iota_storage::util::sync::CACHE_SCHEMA_VERSION;
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return sync_error(cv),
    };
    let session_id = match data_i64(cv, DataType::SessionId) {
        Some(id) if id > 0 => id,
        _ => return sync_error(cv),
    };
    let version = match data_i64(cv, DataType::VersionNumber) {
        Some(version) if version >= 0 => version,
        _ => return sync_error(cv),
    };
    if iota_storage::util::client_message_delivery::acknowledge_client_state(
        user_id,
        session_id,
        version,
        CACHE_SCHEMA_VERSION,
    )
    .is_err()
    {
        return sync_error(cv);
    }
    success_response(cv)
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(version as i128),
        )
}

pub fn handle_messages_get(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(partner_id) = data_i64(cv, DataType::UserId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(offset) = data_i64(cv, DataType::Offset).filter(|offset| *offset >= 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(amount) = data_i64(cv, DataType::Amount).filter(|amount| *amount > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let messages = chat_files::get_messages(my_id_i64, partner_id, offset, amount);
    let mut msg_array: Vec<DataValue> = Vec::new();
    for m in &messages {
        msg_array.push(stored_message_value(m, my_id_i64, partner_id));
    }

    CommunicationValue::new(CommunicationType::MessagesGet)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Messages, DataValue::Array(msg_array))
}

pub fn handle_message_get(cv: &CommunicationValue) -> CommunicationValue {
    let Some(send_time) = data_i64(cv, DataType::SendTime) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let partner_id = data_i64(cv, DataType::ChatPartnerId);
    let owner = match required_sender_id(cv) {
        Ok(owner) => owner,
        Err(response) => return response,
    };

    let (message, offset) = match partner_id {
        Some(partner_id) => match chat_files::get_message_with_offset(owner, partner_id, send_time)
        {
            Ok(Some((message, offset))) => (message, Some(offset)),
            Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
            Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
        },
        None => match chat_files::get_message(owner, send_time, None) {
            Ok(Some(message)) => (message, None),
            Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
            Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
        },
    };

    let mut response = CommunicationValue::new(CommunicationType::MessageGet)
        .with_request_id(cv)
        .with_receiver(u64::try_from(owner).expect("authenticated sender is non-negative"));
    for (data_type, value) in stored_message_fields(&message, owner, message.external_user) {
        response = response.add_typed_default(data_type, value);
    }
    if let Some(offset) = offset {
        response =
            response.add_typed_default(DataType::Offset, DataValue::SignedNumber(offset as i128));
    }
    response
}

pub fn handle_get_chats(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match cv.require_sender() {
        Ok(user_id) => user_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(user_id_i64) = i64::try_from(user_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let users = match chats_util::get_users(user_id_i64) {
        Ok(users) => users,
        Err(_) => return error_response(cv, CommunicationType::ErrorInternal),
    };
    let mut user_array = Vec::new();
    for user in users {
        let mut container = Vec::new();
        container.push((
            DataType::UserId,
            DataValue::SignedNumber(user.user_id as i128),
        ));
        if let Some(name) = user.user_name {
            container.push((DataType::Username, DataValue::Str(name)));
        }
        if user.created_at > 0 {
            container.push((
                DataType::CreatedAt,
                DataValue::SignedNumber(user.created_at.into()),
            ));
        }
        if let Some(ts) = user.last_message_at {
            container.push((DataType::LastMessageAt, DataValue::SignedNumber(ts as i128)));
        }
        user_array.push(typed_container(container));
    }
    CommunicationValue::new(CommunicationType::GetChats)
        .with_request_id(cv)
        .with_receiver(user_id)
        .add_typed_default(DataType::UserIds, DataValue::Array(user_array))
}

pub fn handle_add_community(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let Some(address) = cv.get_data(DataType::CommunityAddress).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(title) = cv.get_data(DataType::CommunityTitle).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(position) = cv.get_data(DataType::Position).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    CommunitiesUtil::add_community(
        sender_id,
        address.to_string(),
        title.to_string(),
        position.to_string(),
    );
    CommunicationValue::new(CommunicationType::AddCommunity)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
}

pub fn handle_get_communities(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    CommunicationValue::new(CommunicationType::GetCommunities)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
        .add_typed_default(
            DataType::Communities,
            DataValue::Array(community_values(sender_id)),
        )
}

fn community_values(storage_owner: i64) -> Vec<DataValue> {
    CommunitiesUtil::get_communities(storage_owner)
        .into_iter()
        .map(|community| {
            typed_container(vec![
                (
                    DataType::CommunityAddress,
                    DataValue::Str(community.address),
                ),
                (DataType::CommunityTitle, DataValue::Str(community.title)),
                (DataType::Position, DataValue::Str(community.position)),
            ])
        })
        .collect()
}

pub fn handle_remove_community(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let Some(address) = cv.get_data(DataType::CommunityAddress).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if CommunitiesUtil::remove_community(sender_id, address.to_string()).is_err() {
        return error_response(cv, CommunicationType::ErrorInternal);
    }
    CommunicationValue::new(CommunicationType::RemoveCommunity)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
}

pub fn handle_global_settings_save(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings payload".to_string()),
            );
    };

    if settings::save_global(my_id_i64, settings_value).is_err() {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }

    let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsSave)
        .with_receiver(my_id)
        .with_request_id(cv);

    if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
        response = response.add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        );
    }

    response
}

pub fn handle_global_settings_load(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Ok(settings_value) = settings::load_global(my_id_i64) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_value_str) = settings_value else {
        let mut response = CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Path,
                DataValue::Str("global.settings".to_string()),
            );

        if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
            response = response.add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
        }

        return response;
    };

    let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsLoad)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str));

    if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
        response = response.add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        );
    }

    response
}

pub fn handle_settings_save(
    cv: &CommunicationValue,
    _expected_session_id: i128,
) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid session_id".to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    };
    let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings_name".to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    };
    let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings payload".to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    };

    if !settings_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        || settings_name.contains("..")
    {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid settings_name".to_string()),
            )
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str(settings_name.to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    if settings::save(my_id_i64, session_id_i64, settings_name, settings_value).is_err() {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }

    CommunicationValue::new(CommunicationType::SettingsSave)
        .with_receiver(my_id)
        .with_request_id(cv)
        .add_typed_default(
            DataType::SettingsName,
            DataValue::Str(settings_name.to_string()),
        )
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        )
}

pub fn handle_settings_load(
    cv: &CommunicationValue,
    _expected_session_id: i128,
) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid session_id".to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings_name".to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    };

    if !settings_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        || settings_name.contains("..")
    {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid settings_name".to_string()),
            )
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str(settings_name.to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    }

    let Ok(settings_value) = settings::load(my_id_i64, session_id_i64, settings_name) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_value_str) = settings_value else {
        return CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str(settings_name.to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    };

    CommunicationValue::new(CommunicationType::SettingsLoad)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str))
        .add_typed_default(
            DataType::SettingsName,
            DataValue::Str(settings_name.to_string()),
        )
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        )
}

pub fn handle_settings_list(
    cv: &CommunicationValue,
    _expected_session_id: i128,
) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid session_id".to_string()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id as i128),
            );
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    let Ok(settings) = settings::list(my_id_i64, session_id_i64) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let settings_json = settings.into_iter().map(DataValue::Str).collect();
    CommunicationValue::new(CommunicationType::SettingsList)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Settings, DataValue::Array(settings_json))
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        )
}

fn setting_response(
    cv: &CommunicationValue,
    response_type: CommunicationType,
    setting: &SyncedSetting,
) -> CommunicationValue {
    CommunicationValue::new(response_type)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(setting.user_id))
        .add_typed_default(
            DataType::SettingId,
            DataValue::SignedNumber(setting.id.into()),
        )
        .add_typed_default(
            DataType::SettingScope,
            DataValue::Str(setting.scope.as_str().to_string()),
        )
        .add_typed_default(
            DataType::SettingTarget,
            DataValue::Str(setting.scope_key.clone()),
        )
        .add_typed_default(DataType::SettingsName, DataValue::Str(setting.name.clone()))
        .add_typed_default(DataType::Payload, DataValue::Str(setting.payload.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(setting.revision.into()),
        )
}

fn blob_value(blob: &UserBlob) -> DataValue {
    typed_container(vec![
        (DataType::BlobId, DataValue::Str(blob.blob_id.clone())),
        (DataType::Blob, DataValue::Bytes(blob.blob.clone())),
        (
            DataType::VersionNumber,
            DataValue::SignedNumber(blob.revision.into()),
        ),
        (
            DataType::UpdatedAt,
            DataValue::SignedNumber(blob.updated_at.into()),
        ),
    ])
}

fn blob_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    blob: &UserBlob,
) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(blob.user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob.blob_id.clone()))
        .add_typed_default(DataType::Blob, DataValue::Bytes(blob.blob.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(blob.revision.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(blob.updated_at.into()),
        )
}

fn blob_changed(user_id: i64, blob_id: String, revision: i64, deleted: bool) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::UserBlobChanged)
        .with_id(next_notification_id())
        .with_receiver(sender_wire_id(user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob_id))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(revision.into()),
        )
        .add_typed_default(DataType::Deleted, DataValue::Bool(deleted))
}

fn blob_request(cv: &CommunicationValue) -> Result<(i64, String), CommunicationValue> {
    let user_id = required_sender_id(cv)?;
    if user_id <= 0 {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    let id = cv
        .get_data(DataType::BlobId)
        .and_then(DataValue::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorInvalidData))?;
    Ok((user_id, id.to_owned()))
}

fn setting_changed(setting: &SyncedSetting) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::SyncedSettingChanged)
        .with_receiver(sender_wire_id(setting.user_id))
        .add_typed_default(
            DataType::SettingId,
            DataValue::SignedNumber(setting.id.into()),
        )
        .add_typed_default(
            DataType::SettingScope,
            DataValue::Str(setting.scope.as_str().to_string()),
        )
        .add_typed_default(
            DataType::SettingTarget,
            DataValue::Str(setting.scope_key.clone()),
        )
        .add_typed_default(DataType::SettingsName, DataValue::Str(setting.name.clone()))
        .add_typed_default(DataType::Payload, DataValue::Str(setting.payload.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(setting.revision.into()),
        )
}

fn setting_deleted(user_id: i64, deleted: &synced_settings::DeletedSetting) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::SyncedSettingChanged)
        .with_receiver(sender_wire_id(user_id))
        .add_typed_default(
            DataType::DeletedSettingIds,
            DataValue::Array(vec![DataValue::SignedNumber(deleted.id.into())]),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(deleted.revision.into()),
        )
}

fn parse_setting_locator(cv: &CommunicationValue) -> Result<SettingLocator, CommunicationValue> {
    let Some(scope_name) = cv.get_data(DataType::SettingScope).as_str() else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    let Some(scope) = SettingScope::parse(scope_name) else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    let Some(scope_key) = cv.get_data(DataType::SettingTarget).as_str() else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    let Some(name) = cv.get_data(DataType::SettingsName).as_str() else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    if !synced_settings::is_valid_name(name) {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    match scope {
        SettingScope::User if !scope_key.is_empty() => {
            Err(error_response(cv, CommunicationType::ErrorInvalidData))
        }
        SettingScope::Contact if !scope_key.parse::<i64>().is_ok_and(|id| id > 0) => {
            Err(error_response(cv, CommunicationType::ErrorInvalidData))
        }
        SettingScope::Community if scope_key.is_empty() => {
            Err(error_response(cv, CommunicationType::ErrorInvalidData))
        }
        _ => Ok(SettingLocator {
            scope,
            scope_key: scope_key.to_string(),
            name: name.to_string(),
        }),
    }
}

fn validate_setting_target(
    user_id: i64,
    locator: &SettingLocator,
) -> Result<(), CommunicationType> {
    match locator.scope {
        SettingScope::User => Ok(()),
        SettingScope::Contact => {
            let contact_id = locator
                .scope_key
                .parse::<i64>()
                .map_err(|_| CommunicationType::ErrorInvalidData)?;
            match has_user(user_id, contact_id) {
                Ok(true) => Ok(()),
                Ok(false) => Err(CommunicationType::ErrorInvalidData),
                Err(_) => Err(CommunicationType::ErrorInternal),
            }
        }
        SettingScope::Community => {
            match CommunitiesUtil::has_community(user_id, &locator.scope_key) {
                Ok(true) => Ok(()),
                Ok(false) => Err(CommunicationType::ErrorInvalidData),
                Err(_) => Err(CommunicationType::ErrorInternal),
            }
        }
    }
}

fn setting_mutation_error(
    cv: &CommunicationValue,
    error_type: CommunicationType,
) -> SettingMutation {
    SettingMutation {
        response: error_response(cv, error_type),
        changed: None,
    }
}

pub fn handle_synced_setting_set(cv: &CommunicationValue) -> SettingMutation {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return setting_mutation_error(cv, CommunicationType::ErrorInvalidData),
    };
    let locator = match parse_setting_locator(cv) {
        Ok(locator) => locator,
        Err(response) => {
            return SettingMutation {
                response,
                changed: None,
            };
        }
    };
    if let Err(error_type) = validate_setting_target(user_id, &locator) {
        return setting_mutation_error(cv, error_type);
    }
    let Some(payload) = cv.get_data(DataType::Payload).as_str() else {
        return setting_mutation_error(cv, CommunicationType::ErrorInvalidData);
    };
    match synced_settings::set(
        user_id,
        locator.scope,
        &locator.scope_key,
        &locator.name,
        payload,
    ) {
        Ok(setting) => SettingMutation {
            response: setting_response(cv, CommunicationType::SyncedSettingSet, &setting),
            changed: Some(setting_changed(&setting)),
        },
        Err(_) => setting_mutation_error(cv, CommunicationType::ErrorInternal),
    }
}

pub fn handle_synced_setting_get(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let locator = match parse_setting_locator(cv) {
        Ok(locator) => locator,
        Err(response) => return response,
    };
    if let Err(error_type) = validate_setting_target(user_id, &locator) {
        return error_response(cv, error_type);
    }
    match synced_settings::get(user_id, locator.scope, &locator.scope_key, &locator.name) {
        Ok(Some(setting)) => setting_response(cv, CommunicationType::SyncedSettingGet, &setting),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

pub fn handle_synced_setting_delete(cv: &CommunicationValue) -> SettingMutation {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return setting_mutation_error(cv, CommunicationType::ErrorInvalidData),
    };
    let locator = match parse_setting_locator(cv) {
        Ok(locator) => locator,
        Err(response) => {
            return SettingMutation {
                response,
                changed: None,
            };
        }
    };
    if let Err(error_type) = validate_setting_target(user_id, &locator) {
        return setting_mutation_error(cv, error_type);
    }
    match synced_settings::delete(user_id, locator.scope, &locator.scope_key, &locator.name) {
        Ok(Some(deleted)) => SettingMutation {
            response: CommunicationValue::new(CommunicationType::SyncedSettingDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::SettingId,
                    DataValue::SignedNumber(deleted.id.into()),
                )
                .add_typed_default(
                    DataType::VersionNumber,
                    DataValue::SignedNumber(deleted.revision.into()),
                ),
            changed: deleted.changed.then(|| setting_deleted(user_id, &deleted)),
        },
        Ok(None) => SettingMutation {
            response: CommunicationValue::new(CommunicationType::SyncedSettingDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id)),
            changed: None,
        },
        Err(_) => setting_mutation_error(cv, CommunicationType::ErrorInternal),
    }
}

pub fn handle_synced_settings_list(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    match synced_settings::list(user_id) {
        Ok(settings) => CommunicationValue::new(CommunicationType::SyncedSettingsList)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(
                DataType::Settings,
                DataValue::Array(settings.iter().map(synced_setting_value).collect()),
            ),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

pub fn handle_user_blob_put(cv: &CommunicationValue) -> BlobMutation {
    let Ok((user_id, blob_id)) = blob_request(cv) else {
        return BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(blob) = cv.get_data(DataType::Blob).and_then(DataValue::as_bytes) else {
        return BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let expected_revision = data_i64(cv, DataType::ExpectedRevision);
    match user_blobs::put(user_id, &blob_id, &blob, expected_revision) {
        Ok(stored) => BlobMutation {
            response: blob_response(cv, CommunicationType::UserBlobPut, &stored),
            changed: Some(blob_changed(
                user_id,
                stored.blob_id.clone(),
                stored.revision,
                false,
            )),
        },
        Err(iota_storage::storage_error::StorageError::RevisionConflict) => BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        },
        Err(_) => BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        },
    }
}

pub fn handle_user_blob_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok((user_id, blob_id)) = blob_request(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_blobs::get(user_id, &blob_id) {
        Ok(Some(blob)) => blob_response(cv, CommunicationType::UserBlobGet, &blob),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

pub fn handle_user_blob_delete(cv: &CommunicationValue) -> BlobMutation {
    let Ok((user_id, blob_id)) = blob_request(cv) else {
        return BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match user_blobs::delete(user_id, &blob_id, data_i64(cv, DataType::ExpectedRevision)) {
        Ok(Some(deleted)) => BlobMutation {
            response: CommunicationValue::new(CommunicationType::UserBlobDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(DataType::BlobId, DataValue::Str(blob_id.clone()))
                .add_typed_default(
                    DataType::VersionNumber,
                    DataValue::SignedNumber(deleted.revision.into()),
                ),
            changed: deleted
                .changed
                .then(|| blob_changed(user_id, blob_id, deleted.revision, true)),
        },
        Ok(None) => BlobMutation {
            response: CommunicationValue::new(CommunicationType::UserBlobDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id)),
            changed: None,
        },
        Err(iota_storage::storage_error::StorageError::RevisionConflict) => BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        },
        Err(_) => BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        },
    }
}

pub fn handle_user_blob_list(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = required_sender_id(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if user_id <= 0 {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    match user_blobs::list(user_id) {
        Ok(blobs) => CommunicationValue::new(CommunicationType::UserBlobList)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(
                DataType::Blobs,
                DataValue::Array(blobs.iter().map(blob_value).collect()),
            ),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

fn authenticated_user(cv: &CommunicationValue) -> Result<i64, CommunicationValue> {
    let user_id = required_sender_id(cv)?;
    if user_id <= 0 {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    Ok(user_id)
}

pub fn handle_user_block(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(blocked_user_id) = data_i64(cv, DataType::BlockedUserId).filter(|id| *id > 0) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match blocked_users::block(user_id, blocked_user_id) {
        Ok(record) => PolicyMutation {
            response: CommunicationValue::new(CommunicationType::UserBlock)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::BlockedUserId,
                    DataValue::SignedNumber(blocked_user_id.into()),
                )
                .add_typed_default(
                    DataType::VersionNumber,
                    DataValue::SignedNumber(record.revision.into()),
                ),
            changed: Some(
                CommunicationValue::new(CommunicationType::BlockedUsersChanged)
                    .with_id(next_notification_id())
                    .with_receiver(sender_wire_id(user_id))
                    .add_typed_default(
                        DataType::BlockedUserId,
                        DataValue::SignedNumber(blocked_user_id.into()),
                    )
                    .add_typed_default(
                        DataType::VersionNumber,
                        DataValue::SignedNumber(record.revision.into()),
                    )
                    .add_typed_default(DataType::Deleted, DataValue::Bool(record.deleted)),
            ),
        },
        Err(_) => PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        },
    }
}

pub fn handle_user_unblock(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(blocked_user_id) = data_i64(cv, DataType::BlockedUserId).filter(|id| *id > 0) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match blocked_users::unblock(user_id, blocked_user_id) {
        Ok(mutation) => PolicyMutation {
            response: CommunicationValue::new(CommunicationType::UserUnblock)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::BlockedUserId,
                    DataValue::SignedNumber(blocked_user_id.into()),
                ),
            changed: mutation.map(|mutation| {
                CommunicationValue::new(CommunicationType::BlockedUsersChanged)
                    .with_id(next_notification_id())
                    .with_receiver(sender_wire_id(user_id))
                    .add_typed_default(
                        DataType::BlockedUserId,
                        DataValue::SignedNumber(blocked_user_id.into()),
                    )
                    .add_typed_default(
                        DataType::VersionNumber,
                        DataValue::SignedNumber(mutation.revision.into()),
                    )
                    .add_typed_default(DataType::Deleted, DataValue::Bool(mutation.deleted))
            }),
        },
        Err(_) => PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        },
    }
}

pub fn handle_blocked_users_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = authenticated_user(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match blocked_users::list(user_id) {
        Ok(users) => CommunicationValue::new(CommunicationType::BlockedUsersGet)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(
                DataType::BlockedUserIds,
                DataValue::Array(
                    users
                        .into_iter()
                        .map(|id| DataValue::SignedNumber(id.into()))
                        .collect(),
                ),
            ),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

fn receipt_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    policy: receipt_policy::ReceiptPolicy,
) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(policy.user_id))
        .add_typed_default(
            DataType::SendReadReceipts,
            DataValue::Bool(policy.send_read_receipts),
        )
        .add_typed_default(
            DataType::SendReceivedReceipts,
            DataValue::Bool(policy.send_received_receipts),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(policy.revision.into()),
        )
}
pub fn handle_receipt_policy_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = authenticated_user(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match receipt_policy::get(user_id) {
        Ok(policy) => receipt_response(cv, CommunicationType::ReceiptPolicyGet, policy),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}
pub fn handle_receipt_policy_set(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let (Some(read), Some(received)) = (
        cv.get_data(DataType::SendReadReceipts)
            .and_then(DataValue::as_bool),
        cv.get_data(DataType::SendReceivedReceipts)
            .and_then(DataValue::as_bool),
    ) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match receipt_policy::set(user_id, read, received) {
        Ok(policy) => {
            let response = receipt_response(cv, CommunicationType::ReceiptPolicySet, policy);
            let changed = receipt_response(cv, CommunicationType::ReceiptPolicyChanged, policy)
                .with_id(next_notification_id());
            PolicyMutation {
                response,
                changed: Some(changed),
            }
        }
        Err(_) => PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        },
    }
}

fn storage_policy_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    policy: message_storage_policy::MessageStoragePolicy,
) -> CommunicationValue {
    let (history_mode, duration) = match policy.history_mode {
        message_storage_policy::MessageHistoryMode::Retain => ("retain", None),
        message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery => {
            ("delete_after_client_delivery", None)
        }
    };
    let retention_duration = match policy.retention {
        message_storage_policy::MessageRetention::Forever => None,
        message_storage_policy::MessageRetention::Duration { duration_ms } => Some(duration_ms),
    };
    let mut response = CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(policy.user_id))
        .add_typed_default(
            DataType::MessageHistoryMode,
            DataValue::Str(history_mode.into()),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(policy.revision.into()),
        );
    if let Some(duration_ms) = retention_duration.or(duration) {
        response = response.add_typed_default(
            DataType::MessageRetentionDuration,
            DataValue::SignedNumber(duration_ms.into()),
        );
    }
    response
}

pub fn handle_message_storage_policy_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = authenticated_user(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match message_storage_policy::get(user_id) {
        Ok(policy) => {
            storage_policy_response(cv, CommunicationType::MessageStoragePolicyGet, policy)
        }
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

pub fn handle_message_storage_policy_set(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(history_mode) = cv
        .get_data(DataType::MessageHistoryMode)
        .and_then(DataValue::as_str)
    else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let history_mode = match history_mode {
        "retain" => message_storage_policy::MessageHistoryMode::Retain,
        "delete_after_client_delivery" => {
            message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery
        }
        _ => {
            return PolicyMutation {
                response: error_response(cv, CommunicationType::ErrorInvalidData),
                changed: None,
            };
        }
    };
    let retention = match data_i64(cv, DataType::MessageRetentionDuration) {
        Some(duration_ms) => message_storage_policy::MessageRetention::Duration { duration_ms },
        None => message_storage_policy::MessageRetention::Forever,
    };
    match message_storage_policy::set(user_id, history_mode, retention) {
        Ok(policy) => {
            let response =
                storage_policy_response(cv, CommunicationType::MessageStoragePolicySet, policy);
            let changed =
                storage_policy_response(cv, CommunicationType::MessageStoragePolicyChanged, policy)
                    .with_id(next_notification_id());
            PolicyMutation {
                response,
                changed: Some(changed),
            }
        }
        Err(_) => PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        },
    }
}

/* This request is issued over Omikron's trusted Iota connection. Clients have
 * no route to it, preventing arbitrary block-relationship disclosure. */
pub fn handle_user_block_check(cv: &CommunicationValue) -> CommunicationValue {
    let Some(sender_id) = data_i64(cv, DataType::SenderId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(receiver_id) = data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match blocked_users::is_blocked(receiver_id, sender_id) {
        Ok(blocked) => CommunicationValue::new(CommunicationType::UserBlockCheck)
            .with_request_id(cv)
            .add_typed_default(DataType::IsBlocked, DataValue::Bool(blocked)),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

#[cfg(test)]
mod stored_message_tests {
    use super::stored_message_value;
    use iota_storage::util::chat_files::StoredMessage;
    use mtp::codec::DataValue;

    #[test]
    fn relay_message_value_has_a_single_sender_id() {
        let message = StoredMessage {
            id: 1,
            external_user: 9,
            relay_signer_id: Some(9),
            relay_message_id: Some("relay-1".to_string()),
            message_time: 2,
            authored_at: None,
            origin_iota_received_at: None,
            destination_iota_received_at: None,
            client_received_at: None,
            client_received_recorded_at: None,
            read_at: None,
            read_recorded_at: None,
            delivery_failed_at: None,
            delivery_failure: None,
            content: "message".to_string(),
            edited: false,
            sent_by_self: false,
            message_state: "sent".to_string(),
            height: 1,
            key_version: 1,
            reply_to: None,
            reactions: Vec::new(),
        };

        let value = stored_message_value(&message, 7, 9);

        assert!(matches!(value, DataValue::Container(_)));
        assert!(value.to_bytes().is_ok());
    }
}

#[cfg(test)]
mod synced_settings_tests {
    use super::{handle_synced_setting_get, handle_synced_setting_set, parse_setting_locator};
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    fn request() -> CommunicationValue {
        CommunicationValue::new(CommunicationType::SyncedSettingSet)
            .with_id(1)
            .with_sender(7)
            .add_typed_default(DataType::SettingScope, DataValue::Str("user".to_string()))
            .add_typed_default(DataType::SettingTarget, DataValue::Str(String::new()))
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str("notifications.enabled".to_string()),
            )
    }

    #[test]
    fn missing_sender_is_rejected_for_synced_settings() {
        let response = handle_synced_setting_get(&request().without_sender());

        assert!(response.is_type(CommunicationType::ErrorInvalidData));
        assert_eq!(response.id(), Some(1));
        assert_eq!(response.receiver(), None);
    }

    #[test]
    fn user_scope_rejects_a_non_empty_target() {
        let request =
            request().add_typed_default(DataType::SettingTarget, DataValue::Str("123".to_string()));

        let response = handle_synced_setting_set(&request).response;

        assert!(response.is_type(CommunicationType::ErrorInvalidData));
    }

    #[test]
    fn contact_scope_rejects_a_malformed_target() {
        let request = request()
            .add_typed_default(
                DataType::SettingScope,
                DataValue::Str("contact".to_string()),
            )
            .add_typed_default(
                DataType::SettingTarget,
                DataValue::Str("not-a-user".to_string()),
            );

        let response = handle_synced_setting_set(&request).response;

        assert!(response.is_type(CommunicationType::ErrorInvalidData));
    }

    #[test]
    fn community_scope_requires_an_address() {
        let request = request()
            .add_typed_default(
                DataType::SettingScope,
                DataValue::Str("community".to_string()),
            )
            .add_typed_default(DataType::SettingTarget, DataValue::Str(String::new()));

        let response = handle_synced_setting_set(&request).response;

        assert!(response.is_type(CommunicationType::ErrorInvalidData));
    }

    #[test]
    fn invalid_setting_name_is_rejected() {
        let request = request().add_typed_default(
            DataType::SettingsName,
            DataValue::Str("notifications..enabled".to_string()),
        );

        let response = parse_setting_locator(&request);

        assert!(response.is_err());
    }
}
