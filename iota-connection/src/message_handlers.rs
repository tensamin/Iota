use crate::message_common::*;
use iota_storage::util::chat_files::{self, MessageState};
use iota_storage::util::chats_util::{self, get_user, mod_user};
use iota_storage::util::communities_util::CommunitiesUtil;
use iota_storage::util::e2ee_storage::{self, ChatSecretQuery};
use iota_storage::util::settings;
use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, TypeMap, VerifiedRelayContent,
};

use crate::relay::VerifiedRelayContext;

pub struct MessageMutation {
    pub sender_id: i64,
    pub partner_id: i64,
    pub send_time: i64,
}

pub fn message_mutation(cv: &CommunicationValue) -> Result<MessageMutation, CommunicationValue> {
    let sender_id = i64::try_from(cv.get_sender())
        .map_err(|_| error_response(cv, CommunicationType::ErrorInvalidData))?;
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
) -> Result<(), String> {
    validate_relay_identity(context, &content.content)?;
    let sender_id = i64::try_from(context.signer_id)
        .map_err(|_| "Relay signer ID exceeds the local storage range".to_string())?;
    let recipient_id = i64::try_from(context.final_recipient_id)
        .map_err(|_| "Relay recipient ID exceeds the local storage range".to_string())?;
    let created_at = i64::try_from(context.created_at)
        .map_err(|_| "Relay creation time exceeds the local storage range".to_string())?;

    match content.message_type.as_str() {
        "MessageSend" => {
            let message = relay_string(&content.content, DataType::Content, &context.type_map)
                .ok_or_else(|| "Relay MessageSend is missing Content".to_string())?;
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .unwrap_or(created_at);
            let height = relay_number(&content.content, DataType::Height, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .unwrap_or_default();
            let reply_to = relay_number(&content.content, DataType::ReplyId, &context.type_map)
                .and_then(|value| i64::try_from(value).ok());
            chat_files::add_message(
                u128::try_from(send_time)
                    .map_err(|_| "Relay MessageSend has a negative SendTime".to_string())?,
                false,
                recipient_id,
                sender_id,
                message,
                height,
                reply_to,
            );
            Ok(())
        }
        "MessageEdit" => {
            let message = relay_string(&content.content, DataType::Content, &context.type_map)
                .ok_or_else(|| "Relay MessageEdit is missing Content".to_string())?;
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay MessageEdit is missing SendTime".to_string())?;
            chat_files::apply_remote_edit(recipient_id, sender_id, send_time, sender_id, message)
                .map_err(|error| error.to_string())
        }
        "MessageReactionAdd" | "MessageReactionRemove" => {
            let reaction = relay_string(&content.content, DataType::Reaction, &context.type_map)
                .filter(|value| !value.is_empty() && value.len() <= 64)
                .ok_or_else(|| "Relay reaction is invalid".to_string())?;
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay reaction is missing SendTime".to_string())?;
            let result = if content.message_type == "MessageReactionAdd" {
                chat_files::add_reaction(recipient_id, sender_id, send_time, sender_id, reaction)
            } else {
                chat_files::remove_reaction(recipient_id, sender_id, send_time, sender_id, reaction)
            };
            result.map_err(|error| error.to_string())
        }
        "MessageDeleteLive" => {
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay MessageDeleteLive is missing SendTime".to_string())?;
            chat_files::apply_remote_delete(recipient_id, sender_id, send_time, sender_id)
                .map_err(|error| error.to_string())
        }
        "SetChatSecret" => {
            let frame = CommunicationValue::new(CommunicationType::SetChatSecret)
                .with_payload(content.content.clone());
            let recipients = chat_secret_recipients(&frame)
                .ok_or_else(|| "Relay SetChatSecret has no recipients".to_string())?;
            let recipient = recipients
                .into_iter()
                .find(|value| value.user_id == context.final_recipient_id.to_string())
                .ok_or_else(|| "Relay SetChatSecret recipient mismatch".to_string())?;
            let chat_id = data_string(&frame, DataType::ChatId)
                .ok_or_else(|| "Relay SetChatSecret is missing ChatId".to_string())?;
            let secret_id = data_string(&frame, DataType::SecretId)
                .ok_or_else(|| "Relay SetChatSecret is missing SecretId".to_string())?;
            let version = data_i64(&frame, DataType::VersionNumber)
                .ok_or_else(|| "Relay SetChatSecret is missing VersionNumber".to_string())?;
            let wrapping_scheme = data_string(&frame, DataType::WrappingScheme)
                .ok_or_else(|| "Relay SetChatSecret is missing WrappingScheme".to_string())?;
            e2ee_storage::put_chat_secret(e2ee_storage::StoredChatSecret {
                user_id: context.final_recipient_id.to_string(),
                chat_id,
                secret_id,
                version,
                encrypted_secret: recipient.encrypted_secret,
                kem_ciphertext: recipient.kem_ciphertext,
                wrapping_scheme,
                created_at,
                updated_at: now_millis_i64(),
            })
            .map_err(|error| error.to_string())
        }
        _ => Ok(()),
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
            DataType::SenderId,
            DataValue::UnsignedNumber(if message.sent_by_self {
                storage_owner as u128
            } else {
                partner_id as u128
            }),
        ),
    ];
    if message.edited {
        fields.push((DataType::Edited, DataValue::Bool(true)));
    }
    if let Some(reply_to) = message.reply_to {
        fields.push((
            DataType::ReplyId,
            DataValue::UnsignedNumber(reply_to as u64 as u128),
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

pub fn handle_get_chat_secret(cv: &CommunicationValue) -> CommunicationValue {
    let Some(user_id) = data_string(cv, DataType::UserId) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if user_id != cv.get_sender().to_string() {
        return error_response(cv, CommunicationType::ErrorNotFound);
    }
    let Some(chat_id) = data_string(cv, DataType::ChatId) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    match e2ee_storage::get_chat_secret(ChatSecretQuery {
        user_id,
        chat_id,
        secret_id: data_string(cv, DataType::SecretId),
    }) {
        Ok(Some(record)) => CommunicationValue::new(CommunicationType::ChatSecretResponse)
            .with_id(cv.get_id())
            .with_receiver(cv.get_sender())
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
    let sender_id = cv.get_sender() as i64;
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
        if let Some(mut user) = iota_storage::users::user_manager::get_user(sender_id) {
            if !user.trusted_apps.contains_key(&app_identifier) {
                user.trusted_apps.insert(app_identifier, app_public_key);
                iota_storage::users::user_manager::update_user(user);
            }
        }
    }

    CommunicationValue::new(CommunicationType::CreateApp)
        .with_id(cv.get_id())
        .with_receiver(sender_id as u64)
}

pub fn handle_delete_app(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = cv.get_sender() as i64;
    let app_identifier = cv
        .get_data(DataType::AppIdentifier)
        .as_str()
        .unwrap_or("")
        .to_string();

    if !app_identifier.is_empty() {
        if let Some(mut user) = iota_storage::users::user_manager::get_user(sender_id) {
            if user.trusted_apps.contains_key(&app_identifier) {
                user.trusted_apps.remove(&app_identifier);
                iota_storage::users::user_manager::update_user(user);
            }
        }
    }

    CommunicationValue::new(CommunicationType::DeleteApp)
        .with_id(cv.get_id())
        .with_receiver(sender_id as u64)
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

fn current_contact_ids(user_id: i64) -> DataValue {
    contact_ids_value(
        chats_util::get_users(user_id)
            .into_iter()
            .map(|contact| contact.user_id),
    )
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
    use super::contact_ids_value;
    use mtp::codec::DataValue;

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
    let user_id = match i64::try_from(cv.get_sender()) {
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
    let full = !cache_valid
        || reported_version == 0
        || !known_session
        || reported_version > head
        || schema != CACHE_SCHEMA_VERSION;
    let (contacts, messages, deleted_messages, deleted_contacts, mode) = if full {
        (
            chats_util::get_users(user_id),
            chat_files::get_all_messages(user_id),
            Vec::new(),
            Vec::new(),
            "full",
        )
    } else {
        match sync::delta(user_id, reported_version, head) {
            Ok(delta) => (
                chats_util::get_users_by_ids(user_id, &delta.contact_upserts),
                chat_files::get_messages_by_ids(user_id, &delta.message_upserts),
                delta.deleted_message_ids,
                delta.deleted_contact_ids,
                "delta",
            ),
            Err(_) => (
                chats_util::get_users(user_id),
                chat_files::get_all_messages(user_id),
                Vec::new(),
                Vec::new(),
                "full",
            ),
        }
    };
    let message_values = messages
        .iter()
        .map(|message| stored_message_value(message, user_id, message.external_user))
        .collect();
    CommunicationValue::new(CommunicationType::ClientStateSync)
        .with_id(cv.get_id())
        .with_receiver(cv.get_sender())
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
        .add_typed_default(DataType::UserIds, current_contact_ids(user_id))
        .add_typed_default(DataType::Calls, DataValue::Array(Vec::new()))
}

pub fn handle_client_state_ack(cv: &CommunicationValue) -> CommunicationValue {
    use iota_storage::util::sync::{self, CACHE_SCHEMA_VERSION};
    let user_id = match i64::try_from(cv.get_sender()) {
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
    if sync::acknowledge(user_id, session_id, version, CACHE_SCHEMA_VERSION).is_err() {
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

pub fn handle_message_state(cv: &CommunicationValue) {
    let sender_id = &cv.get_sender();
    let receiver_id = match cv.get_data(DataType::ChatPartnerId).as_number() {
        Some(id) => id,
        _ => return,
    };

    let timestamp_i64 = if let Some(n) = cv.get_data(DataType::SendTime).as_number() {
        n as i64
    } else if let Some(s) = cv.get_data(DataType::SendTime).as_str() {
        s.parse::<i64>().unwrap_or_else(|_| now_millis_i64())
    } else {
        now_millis_i64()
    };

    let _ = chat_files::change_message_state(
        timestamp_i64,
        receiver_id as i64,
        *sender_id as i64,
        MessageState::from_str(cv.get_data(DataType::MessageState).as_str().unwrap_or("")),
    );
}

pub fn handle_messages_get(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = cv.get_sender();
    let partner_id = cv.get_data(DataType::UserId).as_number().unwrap_or(0);
    let offset = cv.get_data(DataType::Offset).as_number().unwrap_or(0);
    let amount = cv.get_data(DataType::Amount).as_number().unwrap_or(0);
    let messages = chat_files::get_messages(
        my_id as i64,
        partner_id as i64,
        offset as i64,
        amount as i64,
    );
    let mut msg_array: Vec<DataValue> = Vec::new();
    for m in &messages {
        msg_array.push(stored_message_value(m, my_id as i64, partner_id as i64));
    }

    CommunicationValue::new(CommunicationType::MessagesGet)
        .with_id(cv.get_id())
        .with_receiver(my_id)
        .add_typed_default(DataType::Messages, DataValue::Array(msg_array))
}

pub fn handle_message_get(cv: &CommunicationValue) -> CommunicationValue {
    let Some(send_time) = data_i64(cv, DataType::SendTime) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let partner_id = data_i64(cv, DataType::ChatPartnerId);
    let owner = cv.get_sender() as i64;

    let message = match chat_files::get_message(owner, send_time, partner_id) {
        Ok(Some(message)) => message,
        Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };

    let mut response = CommunicationValue::new(CommunicationType::MessageGet)
        .with_id(cv.get_id())
        .with_receiver(cv.get_sender());
    for (data_type, value) in stored_message_fields(&message, owner, message.external_user) {
        response = response.add_typed_default(data_type, value);
    }
    response
}

pub fn handle_get_chats(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = cv.get_sender();
    let users = chats_util::get_users(user_id as i64);
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
        if let Some(ts) = user.last_message_at {
            container.push((DataType::LastMessageAt, DataValue::SignedNumber(ts as i128)));
        }
        user_array.push(typed_container(container));
    }
    CommunicationValue::new(CommunicationType::GetChats)
        .with_id(cv.get_id())
        .with_receiver(user_id)
        .add_typed_default(DataType::UserIds, DataValue::Array(user_array))
}

pub fn handle_add_conversation(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = cv.get_sender();
    let session_id = match data_i64(cv, DataType::SessionId) {
        Some(id) if id > 0 => id,
        _ => return sync_error(cv),
    };
    let other_id = match cv.get_data(DataType::ChatPartnerId).as_number() {
        Some(n) => n as i64,
        None => cv
            .get_data(DataType::ChatPartnerId)
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0),
    };
    let mut contact = get_user(user_id as i64, other_id)
        .unwrap_or(iota_storage::users::contact::Contact::new(other_id));

    if let Some(name) = cv.get_data(DataType::ChatPartnerName).as_str() {
        contact.user_name = Some(name.to_string());
    }

    contact.set_last_message_at(now_millis_i64());
    mod_user(user_id as i64, &contact);
    CommunicationValue::new(CommunicationType::AddConversation)
        .with_id(cv.get_id())
        .with_receiver(user_id)
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        )
        .add_typed_default(DataType::UserIds, current_contact_ids(user_id as i64))
}

pub fn handle_add_community(cv: &CommunicationValue) -> CommunicationValue {
    CommunitiesUtil::add_community(
        cv.get_sender() as i64,
        cv.get_data(DataType::CommunityAddress)
            .as_str()
            .unwrap()
            .to_string(),
        cv.get_data(DataType::CommunityTitle)
            .as_str()
            .unwrap()
            .to_string(),
        cv.get_data(DataType::Position)
            .as_str()
            .unwrap()
            .to_string(),
    );
    CommunicationValue::new(CommunicationType::AddCommunity)
        .with_id(cv.get_id())
        .with_receiver(cv.get_sender())
}

pub fn handle_get_communities(cv: &CommunicationValue) -> CommunicationValue {
    let mut comm_array = Vec::new();
    for c in CommunitiesUtil::get_communities(cv.get_sender() as i64) {
        let mut container: Vec<(DataType, DataValue)> = Vec::new();
        container.push((
            DataType::CommunityAddress,
            DataValue::Str(c.address.clone()),
        ));
        container.push((DataType::CommunityTitle, DataValue::Str(c.title.clone())));
        container.push((DataType::Position, DataValue::Str(c.position.clone())));
        comm_array.push(typed_container(container));
    }

    CommunicationValue::new(CommunicationType::GetCommunities)
        .with_id(cv.get_id())
        .with_receiver(cv.get_sender())
        .add_typed_default(DataType::Communities, DataValue::Array(comm_array))
}

pub fn handle_remove_community(cv: &CommunicationValue) -> CommunicationValue {
    CommunitiesUtil::remove_community(
        cv.get_sender() as i64,
        cv.get_data(DataType::CommunityAddress)
            .as_str()
            .unwrap()
            .to_string(),
    );
    CommunicationValue::new(CommunicationType::RemoveCommunity)
        .with_id(cv.get_id())
        .with_receiver(cv.get_sender())
}

pub fn handle_global_settings_save(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = cv.get_sender();
    let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings payload".to_string()),
            );
    };

    if settings::save_global(my_id as i64, settings_value).is_err() {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }

    let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsSave)
        .with_receiver(my_id)
        .with_id(cv.get_id());

    if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
        response = response.add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        );
    }

    response
}

pub fn handle_global_settings_load(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = cv.get_sender();
    let Ok(settings_value) = settings::load_global(my_id as i64) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_value_str) = settings_value else {
        let mut response = CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_id(cv.get_id())
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
        .with_id(cv.get_id())
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
    let my_id = cv.get_sender();
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
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
            .with_id(cv.get_id())
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
            .with_id(cv.get_id())
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
            .with_id(cv.get_id())
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

    if settings::save(
        my_id as i64,
        session_id as i64,
        settings_name,
        settings_value,
    )
    .is_err()
    {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }

    CommunicationValue::new(CommunicationType::SettingsSave)
        .with_receiver(my_id)
        .with_id(cv.get_id())
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
    let my_id = cv.get_sender();
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
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
    let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
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
            .with_id(cv.get_id())
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

    let Ok(settings_value) = settings::load(my_id as i64, session_id as i64, settings_name) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_value_str) = settings_value else {
        return CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_id(cv.get_id())
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
        .with_id(cv.get_id())
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
    let my_id = cv.get_sender();
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(cv.get_id())
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

    let Ok(settings) = settings::list(my_id as i64, session_id as i64) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let settings_json = settings.into_iter().map(DataValue::Str).collect();
    CommunicationValue::new(CommunicationType::SettingsList)
        .with_id(cv.get_id())
        .with_receiver(my_id)
        .add_typed_default(DataType::Settings, DataValue::Array(settings_json))
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(session_id as i128),
        )
}
