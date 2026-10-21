#![allow(
    clippy::result_large_err,
    reason = "return protocol error frames directly to the sender"
)]

use crate::message_common::*;
use iota_logger::{LogLevel, PrintType, log_event};
use iota_storage::util::call_envelopes::{self, CallEnvelope};
use iota_storage::util::chat_files::{self, MessageState};
use iota_storage::util::chats_util::{self, get_user, has_user, mod_user};
use iota_storage::util::communities_util::CommunitiesUtil;
use iota_storage::util::e2ee_storage::{self, ChatSecretQuery};
use iota_storage::util::settings;
use iota_storage::util::synced_settings::{self, SettingScope, SyncedSetting};
use iota_storage::util::user_assets::{self, UploadStatus, UserAssetMetadata};
use iota_storage::util::user_blobs::{self, UserBlob, UserBlobMetadata};
use iota_storage::util::{blocked_users, message_storage_policy, receipt_policy};
use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, TypeMap, VerifiedRelayContent,
};

use crate::relay::VerifiedRelayContext;
use iota_storage::storage_error::StorageError;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_NOTIFICATION_ID: AtomicU32 = AtomicU32::new(1);

fn internal_handler_error(
    cv: &CommunicationValue,
    operation: &'static str,
    error: impl std::fmt::Display,
) -> CommunicationValue {
    log_event!(
        PrintType::Client,
        LogLevel::Error,
        "request.internal_error",
        "operation={} message_id={:?} sender={:?} error={}",
        operation,
        cv.id(),
        cv.sender(),
        error
    );
    error_response(cv, CommunicationType::ErrorInternal)
}

fn next_notification_id() -> u32 {
    NEXT_NOTIFICATION_ID.fetch_add(1, Ordering::Relaxed).max(1)
}

#[derive(Debug)]
pub struct MessageMutation {
    pub sender_id: i64,
    pub partner_id: i64,
    pub partner_principal: iota_identity::PrincipalHandle,
    pub sender_principal: iota_identity::PrincipalHandle,
    pub send_time: i64,
}

#[derive(Clone, Debug)]
pub enum AppliedMessageMutation {
    State {
        send_time: i64,
        state: MessageState,
    },
    Edit {
        send_time: i64,
        content: String,
        version: i64,
    },
    Reaction {
        send_time: i64,
        reaction: String,
        accepted: bool,
    },
    Delete {
        send_time: i64,
    },
}

#[derive(Clone, Debug, Default)]
pub struct RelayApplicationResult {
    pub mutation: Option<AppliedMessageMutation>,
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

pub type AssetMutation = BlobMutation;

#[derive(Debug)]
pub struct PolicyMutation {
    pub response: CommunicationValue,
    pub changed: Option<CommunicationValue>,
}

#[derive(Debug)]
pub struct NotificationMutation {
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
    let partner_principal = chats_util::get_user(sender_id, partner_id)
        .map_err(|_| error_response(cv, CommunicationType::ErrorInternal))?
        .and_then(|contact| contact.principal)
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorNotFound))?;
    let sender_principal = iota_storage::identity::SqlitePrincipalStore
        .principal_for_local_user(iota_identity::LocalUserId(sender_id))
        .map_err(|_| error_response(cv, CommunicationType::ErrorInternal))?
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorNotFound))?;

    Ok(MessageMutation {
        sender_id,
        partner_id,
        partner_principal,
        sender_principal,
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
    signer_principal: iota_identity::PrincipalHandle,
    recipient_principal: iota_identity::PrincipalHandle,
    accepted_at: i64,
    storage_owner: i64,
    sent_by_self: bool,
) -> Result<RelayApplicationResult, String> {
    validate_relay_identity(context, &content.content)?;
    let sender_id = i64::try_from(context.signer_id)
        .map_err(|_| "Relay signer ID exceeds the local storage range".to_string())?;
    let recipient_id = i64::try_from(context.final_recipient_id)
        .map_err(|_| "Relay recipient ID exceeds the local storage range".to_string())?;
    let created_at = i64::try_from(context.created_at)
        .map_err(|_| "Relay creation time exceeds the local storage range".to_string())?;

    match content.message_type {
        CommunicationType::MessageState => {
            let _partner_id =
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
            let update = if sent_by_self {
                chat_files::change_message_state_by_relay_id(
                    storage_owner,
                    recipient_id,
                    recipient_principal,
                    relay_message_id,
                    state,
                )
                .map_err(|error| error.to_string())?
            } else {
                chat_files::record_message_receipt(
                    storage_owner,
                    recipient_id,
                    recipient_principal,
                    relay_message_id,
                    sender_id,
                    signer_principal,
                    &context.message_id,
                    state,
                    event_at,
                    now_millis_i64(),
                )
                .map_err(|error| error.to_string())?
            };
            Ok(RelayApplicationResult {
                mutation: update.map(|update| AppliedMessageMutation::State {
                    send_time: update.send_time,
                    state: update.state,
                }),
            })
        }
        CommunicationType::MessageSend => {
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
            let chat_id = e2ee_storage::principal_chat_id(signer_principal, recipient_principal)
                .ok_or_else(|| "Relay MessageSend has an invalid principal pair".to_string())?;
            let legacy_chat_id = if sender_id < recipient_id {
                format!("{sender_id}:{recipient_id}")
            } else {
                format!("{recipient_id}:{sender_id}")
            };
            e2ee_storage::migrate_chat_secret_namespace(
                &storage_owner.to_string(),
                &legacy_chat_id,
                &format!("chat:{legacy_chat_id}:main"),
                &chat_id,
                &e2ee_storage::principal_secret_id(&chat_id),
            )
            .map_err(|error| error.to_string())?;
            let latest_secret = e2ee_storage::get_chat_secret(ChatSecretQuery {
                user_id: storage_owner.to_string(),
                chat_id: chat_id.clone(),
                secret_id: Some(e2ee_storage::principal_secret_id(&chat_id)),
                version: None,
            })
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Relay MessageSend has no committed chat secret".to_string())?;
            if latest_secret.version != key_version {
                return Err("Relay MessageSend uses a stale chat secret version".into());
            }
            chat_files::add_message(chat_files::NewMessage {
                relay_signer_id: sender_id,
                relay_signer_principal: signer_principal,
                relay_message_id: &context.message_id,
                authored_at: created_at,
                send_time,
                storage_owner,
                external_user: if sent_by_self {
                    recipient_id
                } else {
                    sender_id
                },
                external_principal: if sent_by_self {
                    recipient_principal
                } else {
                    signer_principal
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
            Ok(RelayApplicationResult::default())
        }
        CommunicationType::MessageEdit => {
            let message = relay_string(&content.content, DataType::Content, &context.type_map)
                .ok_or_else(|| "Relay MessageEdit is missing Content".to_string())?;
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay MessageEdit is missing SendTime".to_string())?;
            let version =
                relay_number(&content.content, DataType::VersionNumber, &context.type_map)
                    .and_then(|value| i64::try_from(value).ok())
                    .filter(|value| *value > 0)
                    .ok_or_else(|| "Relay MessageEdit has an invalid VersionNumber".to_string())?;
            let external_user = if sent_by_self {
                recipient_id
            } else {
                sender_id
            };
            let external_principal = if sent_by_self {
                recipient_principal
            } else {
                signer_principal
            };
            let result = if sent_by_self {
                chat_files::edit_message_for_principal(
                    storage_owner,
                    external_user,
                    external_principal,
                    send_time,
                    sender_id,
                    message,
                )
            } else {
                chat_files::apply_remote_edit_for_principal(
                    storage_owner,
                    external_user,
                    external_principal,
                    send_time,
                    sender_id,
                    message,
                )
            };
            result.map_err(|error| error.to_string())?;
            Ok(RelayApplicationResult {
                mutation: Some(AppliedMessageMutation::Edit {
                    send_time,
                    content: message.to_string(),
                    version,
                }),
            })
        }
        CommunicationType::MessageReactionAdd | CommunicationType::MessageReactionRemove => {
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
            let external_principal = if sent_by_self {
                recipient_principal
            } else {
                signer_principal
            };
            let result = if content.message_type == CommunicationType::MessageReactionAdd {
                chat_files::add_reaction_for_principal(
                    storage_owner,
                    external_user,
                    external_principal,
                    send_time,
                    sender_id,
                    signer_principal,
                    reaction,
                )
            } else {
                chat_files::remove_reaction_for_principal(
                    storage_owner,
                    external_user,
                    external_principal,
                    send_time,
                    sender_id,
                    signer_principal,
                    reaction,
                )
            };
            result.map_err(|error| error.to_string())?;
            Ok(RelayApplicationResult {
                mutation: Some(AppliedMessageMutation::Reaction {
                    send_time,
                    reaction: reaction.to_string(),
                    accepted: content.message_type == CommunicationType::MessageReactionAdd,
                }),
            })
        }
        CommunicationType::MessageDelete | CommunicationType::MessageDeleteLive => {
            let send_time = relay_number(&content.content, DataType::SendTime, &context.type_map)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Relay MessageDeleteLive is missing SendTime".to_string())?;
            let external_user = if sent_by_self {
                recipient_id
            } else {
                sender_id
            };
            let external_principal = if sent_by_self {
                recipient_principal
            } else {
                signer_principal
            };
            let result = if sent_by_self {
                chat_files::delete_message_for_principal(
                    storage_owner,
                    external_user,
                    external_principal,
                    send_time,
                )
            } else {
                chat_files::apply_remote_delete_for_principal(
                    storage_owner,
                    external_user,
                    external_principal,
                    send_time,
                    sender_id,
                )
            };
            result.map_err(|error| error.to_string())?;
            Ok(RelayApplicationResult {
                mutation: Some(AppliedMessageMutation::Delete { send_time }),
            })
        }
        CommunicationType::SetChatSecret => {
            let frame = CommunicationValue::new(CommunicationType::SetChatSecret)
                .with_payload(content.content.clone());
            let recipients = chat_secret_recipients(&frame)
                .ok_or_else(|| "Relay SetChatSecret has no recipients".to_string())?;
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
            if storage_owner != sender_id && storage_owner != recipient_id {
                return Err("Relay SetChatSecret storage owner is not a participant".into());
            }
            if secret_id != format!("chat:{chat_id}:main") {
                return Err("Relay SetChatSecret has an invalid secret namespace".into());
            }
            let principals = iota_storage::identity::SqlitePrincipalStore;
            let shared_iota = principals
                .principal_for_local_user(iota_identity::LocalUserId(sender_id))
                .map_err(|error| error.to_string())?
                == Some(signer_principal)
                && principals
                    .principal_for_local_user(iota_identity::LocalUserId(recipient_id))
                    .map_err(|error| error.to_string())?
                    == Some(recipient_principal);
            // A shared Iota can choose both version-one envelopes in one
            // transaction. Cross-Iota publication and later rotations retain
            // their single authoritative writer.
            if context.signer_id != participants[0] && !(shared_iota && version == 1) {
                return Err(
                    "Relay SetChatSecret was signed by a non-authoritative participant".into(),
                );
            }
            if context.final_recipient_id == context.signer_id {
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
            let principal_chat_id =
                e2ee_storage::principal_chat_id(signer_principal, recipient_principal).ok_or_else(
                    || "Relay SetChatSecret has an invalid principal pair".to_string(),
                )?;
            let principal_secret_id = e2ee_storage::principal_secret_id(&principal_chat_id);
            let owners = if shared_iota {
                vec![sender_id, recipient_id]
            } else {
                vec![storage_owner]
            };
            let records = owners
                .iter()
                .map(|owner| {
                    let recipient = recipients
                        .iter()
                        .find(|value| value.user_id == owner.to_string())
                        .ok_or_else(|| "Relay SetChatSecret recipient mismatch".to_string())?;
                    e2ee_storage::migrate_chat_secret_namespace(
                        &owner.to_string(),
                        &chat_id,
                        &secret_id,
                        &principal_chat_id,
                        &principal_secret_id,
                    )?;
                    Ok(e2ee_storage::StoredChatSecret {
                        user_id: owner.to_string(),
                        chat_id: principal_chat_id.clone(),
                        secret_id: principal_secret_id.clone(),
                        version,
                        encrypted_secret: recipient.encrypted_secret.clone(),
                        kem_ciphertext: recipient.kem_ciphertext.clone(),
                        wrapping_scheme: wrapping_scheme.clone(),
                        created_at,
                        updated_at: now_millis_i64(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            e2ee_storage::put_chat_secrets(&records).map_err(|error| error.to_string())?;
            Ok(RelayApplicationResult::default())
        }
        CommunicationType::AddConversation => {
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
            .map_err(|error| format!("AddConversation persistence failed: {error}"))?;
            Ok(RelayApplicationResult::default())
        }
        _ => Ok(RelayApplicationResult::default()),
    }
}

/* Local receipt disclosure is checked before the relay enters durable state. */
pub fn validate_outgoing_receipt_policy(
    sender_id: i64,
    context: &VerifiedRelayContext,
    content: &VerifiedRelayContent,
) -> Result<(), String> {
    if content.message_type != CommunicationType::MessageState {
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

    match chat_files::edit_message_for_principal(
        mutation.sender_id,
        mutation.partner_id,
        mutation.partner_principal,
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
        chat_files::add_reaction_for_principal(
            mutation.sender_id,
            mutation.partner_id,
            mutation.partner_principal,
            mutation.send_time,
            mutation.sender_id,
            mutation.sender_principal,
            reaction,
        )
    } else {
        chat_files::remove_reaction_for_principal(
            mutation.sender_id,
            mutation.partner_id,
            mutation.partner_principal,
            mutation.send_time,
            mutation.sender_id,
            mutation.sender_principal,
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

    match chat_files::delete_message_for_principal(
        mutation.sender_id,
        mutation.partner_id,
        mutation.partner_principal,
        mutation.send_time,
    ) {
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

    let mut participants = match chat_id
        .split(':')
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(participants) => participants,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    if participants.len() != 2
        || participants.iter().any(|participant| *participant <= 0)
        || participants[0] == participants[1]
        || !participants.contains(&sender_id)
    {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    participants.sort_unstable();
    if chat_id != format!("{}:{}", participants[0], participants[1]) {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let partner_id = if participants[0] == sender_id {
        participants[1]
    } else {
        participants[0]
    };
    let partner_principal = match chats_util::get_user(sender_id, partner_id) {
        Ok(Some(contact)) => match contact.principal {
            Some(principal) => principal,
            None => return error_response(cv, CommunicationType::ErrorNotFound),
        },
        Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => return internal_handler_error(cv, "chat_secret.contact_get", error),
    };
    let owner_principal = match iota_storage::identity::SqlitePrincipalStore
        .principal_for_local_user(iota_identity::LocalUserId(sender_id))
    {
        Ok(Some(principal)) => principal,
        Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => return internal_handler_error(cv, "chat_secret.principal_get", error),
    };
    let Some(principal_chat_id) =
        e2ee_storage::principal_chat_id(owner_principal, partner_principal)
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let requested_secret_id = data_string(cv, DataType::SecretId);
    let legacy_main_secret_id = format!("chat:{chat_id}:main");
    if e2ee_storage::migrate_chat_secret_namespace(
        &user_id,
        &chat_id,
        &legacy_main_secret_id,
        &principal_chat_id,
        &e2ee_storage::principal_secret_id(&principal_chat_id),
    )
    .is_err()
    {
        return error_response(cv, CommunicationType::ErrorInternal);
    }
    let principal_secret_id = requested_secret_id.as_ref().map(|secret_id| {
        if secret_id == &legacy_main_secret_id {
            e2ee_storage::principal_secret_id(&principal_chat_id)
        } else {
            format!("{principal_chat_id}:{secret_id}")
        }
    });

    match e2ee_storage::get_chat_secret(ChatSecretQuery {
        user_id,
        chat_id: principal_chat_id.clone(),
        secret_id: principal_secret_id,
        version: data_i64(cv, DataType::VersionNumber),
    }) {
        Ok(Some(record)) => CommunicationValue::new(CommunicationType::ChatSecretResponse)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(sender_id))
            .add_typed_default(DataType::UserId, DataValue::Str(record.user_id))
            .add_typed_default(DataType::ChatId, DataValue::Str(chat_id))
            .add_typed_default(
                DataType::SecretId,
                DataValue::Str(requested_secret_id.unwrap_or_else(|| {
                    if record.secret_id == e2ee_storage::principal_secret_id(&principal_chat_id) {
                        legacy_main_secret_id
                    } else {
                        record.secret_id
                    }
                })),
            )
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
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
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
        DataType::Notifications,
        DataValue::SignedNumber(contact.notifications.into()),
    ));
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

fn account_state_error(cv: &CommunicationValue) -> CommunicationValue {
    error_response(cv, CommunicationType::ErrorInvalidData)
}

fn add_receipt_policy_data(
    response: CommunicationValue,
    policy: &receipt_policy::ReceiptPolicy,
) -> CommunicationValue {
    response
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

/// The sender is authenticated by MTP; a UserId embedded by a client is never trusted here.
pub fn handle_account_state_request(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return account_state_error(cv),
    };
    let contacts = match chats_util::get_users(user_id) {
        Ok(contacts) => contacts,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let messages = match chat_files::get_all_messages(user_id) {
        Ok(messages) => messages,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let settings = match synced_settings::list(user_id) {
        Ok(settings) => settings,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let message_values = messages
        .iter()
        .map(|message| stored_message_value(message, user_id, message.external_user))
        .collect();
    let blocked_users = match blocked_users::list(user_id) {
        Ok(users) => users,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let receipt_policy = match receipt_policy::get(user_id) {
        Ok(policy) => policy,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let message_storage_policy = match message_storage_policy::get(user_id) {
        Ok(policy) => policy,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let contact_ids = match current_contact_ids(user_id) {
        Ok(contact_ids) => contact_ids,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let communities = match community_values(user_id) {
        Ok(communities) => communities,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let retention_duration = match message_storage_policy.retention {
        message_storage_policy::MessageRetention::Forever => None,
        message_storage_policy::MessageRetention::Duration { duration_ms } => Some(duration_ms),
    };
    let response = CommunicationValue::new(CommunicationType::AccountStateSnapshot)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(user_id))
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
            DataType::BlockedUserIds,
            DataValue::Array(
                blocked_users
                    .into_iter()
                    .map(|blocked| DataValue::SignedNumber(blocked.blocked_user_id.into()))
                    .collect(),
            ),
        );
    let mut response = add_receipt_policy_data(response, &receipt_policy)
        .add_typed_default(
            DataType::MessageHistoryMode,
            DataValue::Str(match message_storage_policy.history_mode {
                message_storage_policy::MessageHistoryMode::Retain => "retain".into(),
                message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery => {
                    "delete_after_client_delivery".into()
                }
            }),
        )
        .add_typed_default(DataType::Communities, DataValue::Array(communities))
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

pub fn handle_account_state_applied(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return account_state_error(cv),
    };
    let _ = user_id;
    success_response(cv)
}

#[cfg(test)]
mod account_state_tests {
    use super::add_receipt_policy_data;
    use iota_storage::util::receipt_policy::ReceiptPolicy;
    use iota_util::mtp_compat::OptionalDataValueExt;
    use mtp::codec::{CommunicationType, CommunicationValue, DataType};

    #[test]
    fn snapshot_receipt_policy_includes_its_revision() {
        let policy = ReceiptPolicy {
            user_id: 7,
            send_read_receipts: false,
            send_received_receipts: true,
            revision: 42,
            updated_at: 100,
        };

        let response = add_receipt_policy_data(
            CommunicationValue::new(CommunicationType::AccountStateSnapshot),
            &policy,
        );

        assert_eq!(
            response
                .get_data(DataType::VersionNumber)
                .as_signed_number(),
            Some(42)
        );
        assert_eq!(
            response.get_data(DataType::SendReadReceipts).as_bool(),
            Some(false)
        );
        assert_eq!(
            response.get_data(DataType::SendReceivedReceipts).as_bool(),
            Some(true)
        );
    }
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
    let messages = match chat_files::get_messages(my_id_i64, partner_id, offset, amount) {
        Ok(messages) => messages,
        Err(error) => return internal_handler_error(cv, "messages.get", error),
    };
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
            Err(error) => return internal_handler_error(cv, "message.get", error),
        },
        None => match chat_files::get_message(owner, send_time, None, None) {
            Ok(Some(message)) => (message, None),
            Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
            Err(error) => return internal_handler_error(cv, "message.get", error),
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
        Err(error) => return internal_handler_error(cv, "chats.get", error),
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
        container.push((
            DataType::Notifications,
            DataValue::SignedNumber(user.notifications.into()),
        ));
        user_array.push(typed_container(container));
    }
    CommunicationValue::new(CommunicationType::GetChats)
        .with_request_id(cv)
        .with_receiver(user_id)
        .add_typed_default(DataType::UserIds, DataValue::Array(user_array))
}

fn notification_response(
    ty: CommunicationType,
    request: &CommunicationValue,
    owner: i64,
    contact: &iota_storage::users::contact::Contact,
) -> CommunicationValue {
    let mut response = CommunicationValue::new(ty)
        .with_request_id(request)
        .with_receiver(sender_wire_id(owner))
        .add_typed_default(
            DataType::ChatPartnerId,
            DataValue::SignedNumber(contact.user_id.into()),
        )
        .add_typed_default(
            DataType::Notifications,
            DataValue::SignedNumber(contact.notifications.into()),
        );
    if let Some(last_message_at) = contact.last_message_at {
        response = response.add_typed_default(
            DataType::LastMessageAt,
            DataValue::SignedNumber(last_message_at.into()),
        );
    }
    response
}

pub fn handle_read_notification(cv: &CommunicationValue) -> NotificationMutation {
    let Ok(owner) = required_sender_id(cv) else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(partner_id) = data_i64(cv, DataType::ChatPartnerId).filter(|id| *id > 0) else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(through) = data_i64(cv, DataType::LastMessageAt).filter(|time| *time >= 0) else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };

    let Ok(Some(contact)) = chats_util::get_user(owner, partner_id) else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        };
    };
    let Some(principal) = contact.principal else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        };
    };

    match chats_util::read_notifications(owner, principal, through) {
        Ok(Some(contact)) => NotificationMutation {
            response: notification_response(
                CommunicationType::ReadNotification,
                cv,
                owner,
                &contact,
            ),
            changed: Some(
                notification_response(CommunicationType::PushNotification, cv, owner, &contact)
                    .with_id(next_notification_id()),
            ),
        },
        Ok(None) => NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        },
        Err(_) => NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        },
    }
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
    if CommunitiesUtil::add_community(
        sender_id,
        address.to_string(),
        title.to_string(),
        position.to_string(),
    )
    .is_err()
    {
        return error_response(cv, CommunicationType::ErrorInternal);
    }
    CommunicationValue::new(CommunicationType::AddCommunity)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
}

pub fn handle_get_communities(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let communities = match community_values(sender_id) {
        Ok(communities) => communities,
        Err(_) => return error_response(cv, CommunicationType::ErrorInternal),
    };
    CommunicationValue::new(CommunicationType::GetCommunities)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
        .add_typed_default(DataType::Communities, DataValue::Array(communities))
}

fn community_values(storage_owner: i64) -> Result<Vec<DataValue>, StorageError> {
    Ok(CommunitiesUtil::get_communities(storage_owner)?
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
        .collect())
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

    if let Err(error) = settings::save_global(my_id_i64, settings_value) {
        return internal_handler_error(cv, "settings.global_save", error);
    }

    let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsSave)
        .with_receiver(my_id)
        .with_request_id(cv);

    if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
        response =
            response.add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
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
        return error_response(cv, CommunicationType::ErrorInternal);
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
            response = response
                .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
        }

        return response;
    };

    let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsLoad)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str));

    if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
        response =
            response.add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
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
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };
    let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings_name".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };
    let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings payload".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
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
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    if let Err(error) = settings::save(my_id_i64, session_id_i64, settings_name, settings_value) {
        return internal_handler_error(cv, "settings.save", error);
    }

    CommunicationValue::new(CommunicationType::SettingsSave)
        .with_receiver(my_id)
        .with_request_id(cv)
        .add_typed_default(
            DataType::SettingsName,
            DataValue::Str(settings_name.to_string()),
        )
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id))
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
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
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
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
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
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }

    let Ok(settings_value) = settings::load(my_id_i64, session_id_i64, settings_name) else {
        return error_response(cv, CommunicationType::ErrorInternal);
    };
    let Some(settings_value_str) = settings_value else {
        return CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str(settings_name.to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };

    CommunicationValue::new(CommunicationType::SettingsLoad)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str))
        .add_typed_default(
            DataType::SettingsName,
            DataValue::Str(settings_name.to_string()),
        )
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id))
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
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    let Ok(settings) = settings::list(my_id_i64, session_id_i64) else {
        return error_response(cv, CommunicationType::ErrorInternal);
    };
    let settings_json = settings.into_iter().map(DataValue::Str).collect();
    CommunicationValue::new(CommunicationType::SettingsList)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Settings, DataValue::Array(settings_json))
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id))
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

fn blob_metadata_value(blob: &UserBlobMetadata) -> DataValue {
    typed_container(vec![
        (DataType::BlobId, DataValue::Str(blob.blob_id.clone())),
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

fn blob_mutation_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    blob: &UserBlob,
) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(blob.user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob.blob_id.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(blob.revision.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(blob.updated_at.into()),
        )
}

fn blob_changed(blob: &UserBlob) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::UserBlobChanged)
        .with_id(next_notification_id())
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
        .add_typed_default(DataType::Deleted, DataValue::Bool(false))
}

fn blob_deleted(user_id: i64, blob_id: String, revision: i64) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::UserBlobChanged)
        .with_id(next_notification_id())
        .with_receiver(sender_wire_id(user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob_id))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(revision.into()),
        )
        .add_typed_default(DataType::Deleted, DataValue::Bool(true))
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

fn asset_metadata_value(asset: &UserAssetMetadata) -> DataValue {
    typed_container(vec![
        (DataType::AssetId, DataValue::Str(asset.asset_id.clone())),
        (DataType::Size, DataValue::SignedNumber(asset.size.into())),
        (DataType::Sha256, DataValue::Bytes(asset.sha256.clone())),
        (DataType::MimeType, DataValue::Str(asset.mime_type.clone())),
        (
            DataType::VersionNumber,
            DataValue::SignedNumber(asset.revision.into()),
        ),
        (
            DataType::CreatedAt,
            DataValue::SignedNumber(asset.created_at.into()),
        ),
        (
            DataType::UpdatedAt,
            DataValue::SignedNumber(asset.updated_at.into()),
        ),
    ])
}

fn asset_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    asset: &UserAssetMetadata,
) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(asset.user_id))
        .add_typed_default(DataType::AssetId, DataValue::Str(asset.asset_id.clone()))
        .add_typed_default(DataType::Size, DataValue::SignedNumber(asset.size.into()))
        .add_typed_default(DataType::Sha256, DataValue::Bytes(asset.sha256.clone()))
        .add_typed_default(DataType::MimeType, DataValue::Str(asset.mime_type.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(asset.revision.into()),
        )
        .add_typed_default(
            DataType::CreatedAt,
            DataValue::SignedNumber(asset.created_at.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(asset.updated_at.into()),
        )
}

fn upload_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    status: &UploadStatus,
) -> CommunicationValue {
    let mut response = CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(cv.sender().unwrap_or_default())
        .add_typed_default(DataType::UploadId, DataValue::Str(status.upload_id.clone()))
        .add_typed_default(DataType::AssetId, DataValue::Str(status.asset_id.clone()))
        .add_typed_default(DataType::Size, DataValue::SignedNumber(status.size.into()))
        .add_typed_default(DataType::Sha256, DataValue::Bytes(status.sha256.clone()))
        .add_typed_default(DataType::MimeType, DataValue::Str(status.mime_type.clone()))
        .add_typed_default(
            DataType::Offset,
            DataValue::SignedNumber(status.offset.into()),
        )
        .add_typed_default(DataType::State, DataValue::Str(status.state.clone()))
        .add_typed_default(
            DataType::CreatedAt,
            DataValue::SignedNumber(status.created_at.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(status.updated_at.into()),
        );
    if let Some(revision) = status.revision {
        response = response.add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(revision.into()),
        );
    }
    if let Some(committed_at) = status.committed_at {
        response = response.add_typed_default(
            DataType::CommittedAt,
            DataValue::SignedNumber(committed_at.into()),
        );
    }
    response
}

fn asset_error(cv: &CommunicationValue, error: StorageError) -> CommunicationValue {
    let (kind, category) = match &error {
        StorageError::AssetResourceLimit(_) => {
            (CommunicationType::ErrorInvalidData, "asset_resource_limit")
        }
        _ => (CommunicationType::ErrorInternal, "asset_request_failed"),
    };
    if kind == CommunicationType::ErrorInternal {
        log_event!(
            PrintType::Client,
            LogLevel::Error,
            "request.internal_error",
            "operation=user_assets message_id={:?} sender={:?} error={}",
            cv.id(),
            cv.sender(),
            error
        );
    }
    error_response(cv, kind).add_typed_default(DataType::ErrorType, DataValue::Str(category.into()))
}

#[cfg(test)]
mod asset_error_tests {
    use super::*;

    #[test]
    fn storage_errors_do_not_expose_internal_paths() {
        let request = CommunicationValue::new(CommunicationType::UserAssetUploadStart).with_id(7);
        let internal = asset_error(
            &request,
            StorageError::Other("private path /srv/assets/key".into()),
        );
        assert!(internal.is_type(CommunicationType::ErrorInternal));
        assert_eq!(
            internal
                .get_data(DataType::ErrorType)
                .and_then(DataValue::as_str),
            Some("asset_request_failed")
        );
        let limit = asset_error(
            &request,
            StorageError::AssetResourceLimit("max_asset_bytes"),
        );
        assert!(limit.is_type(CommunicationType::ErrorInvalidData));
        assert_eq!(
            limit
                .get_data(DataType::ErrorType)
                .and_then(DataValue::as_str),
            Some("asset_resource_limit")
        );
    }
}

fn upload_request(cv: &CommunicationValue) -> Result<(i64, String), CommunicationValue> {
    let user_id = required_sender_id(cv)?;
    let upload_id = cv
        .get_data(DataType::UploadId)
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorInvalidData))?;
    Ok((user_id, upload_id.to_owned()))
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
    cv: &CommunicationValue,
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
                Err(error) => {
                    internal_handler_error(cv, "settings.validate_contact", error);
                    Err(CommunicationType::ErrorInternal)
                }
            }
        }
        SettingScope::Community => {
            match CommunitiesUtil::has_community(user_id, &locator.scope_key) {
                Ok(true) => Ok(()),
                Ok(false) => Err(CommunicationType::ErrorInvalidData),
                Err(error) => {
                    internal_handler_error(cv, "settings.validate_community", error);
                    Err(CommunicationType::ErrorInternal)
                }
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
    if let Err(error_type) = validate_setting_target(cv, user_id, &locator) {
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
        Err(error) => SettingMutation {
            response: internal_handler_error(cv, "settings.set", error),
            changed: None,
        },
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
    if let Err(error_type) = validate_setting_target(cv, user_id, &locator) {
        return error_response(cv, error_type);
    }
    match synced_settings::get(user_id, locator.scope, &locator.scope_key, &locator.name) {
        Ok(Some(setting)) => setting_response(cv, CommunicationType::SyncedSettingGet, &setting),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => internal_handler_error(cv, "settings.get", error),
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
    if let Err(error_type) = validate_setting_target(cv, user_id, &locator) {
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
        Err(error) => SettingMutation {
            response: internal_handler_error(cv, "settings.delete", error),
            changed: None,
        },
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
        Err(error) => internal_handler_error(cv, "settings.list", error),
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
            response: blob_mutation_response(cv, CommunicationType::UserBlobPut, &stored),
            changed: Some(blob_changed(&stored)),
        },
        Err(iota_storage::storage_error::StorageError::RevisionConflict) => BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        },
        Err(error) => BlobMutation {
            response: internal_handler_error(cv, "user_blobs.put", error),
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
        Err(error) => internal_handler_error(cv, "user_blobs.get", error),
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
                .then(|| blob_deleted(user_id, blob_id, deleted.revision)),
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
        Err(error) => BlobMutation {
            response: internal_handler_error(cv, "user_blobs.delete", error),
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
    let after_id = match cv.get_data(DataType::Offset).and_then(DataValue::as_number) {
        Some(raw) => match i64::try_from(raw) {
            Ok(id) if id > 0 => Some(id),
            _ => return error_response(cv, CommunicationType::ErrorInvalidData),
        },
        None => None,
    };
    match user_blobs::list_metadata_page(user_id, after_id) {
        Ok((blobs, next)) => CommunicationValue::new(CommunicationType::UserBlobList)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(
                DataType::Offset,
                DataValue::SignedNumber(next.unwrap_or(0).into()),
            )
            .add_typed_default(
                DataType::Blobs,
                DataValue::Array(blobs.iter().map(blob_metadata_value).collect()),
            ),
        Err(error) => internal_handler_error(cv, "user_blobs.list", error),
    }
}

pub fn handle_user_asset_upload_start(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Some(upload_id) = cv.get_data(DataType::UploadId).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(asset_id) = cv.get_data(DataType::AssetId).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(size) = data_i64(cv, DataType::Size) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(sha256) = cv.get_data(DataType::Sha256).and_then(DataValue::as_bytes) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(mime_type) = cv.get_data(DataType::MimeType).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_assets::start(user_id, upload_id, asset_id, size, &sha256, mime_type) {
        Ok(status) => upload_response(cv, CommunicationType::UserAssetUploadStart, &status),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_upload_chunk(cv: &CommunicationValue) -> CommunicationValue {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(offset) = data_i64(cv, DataType::Offset) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(chunk) = cv.get_data(DataType::Blob).and_then(DataValue::as_bytes) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_assets::append(user_id, &upload_id, offset, &chunk) {
        Ok(status) => upload_response(cv, CommunicationType::UserAssetUploadChunk, &status),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_upload_status(cv: &CommunicationValue) -> CommunicationValue {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match user_assets::status(user_id, &upload_id) {
        Ok(Some(status)) => upload_response(cv, CommunicationType::UserAssetUploadStatus, &status),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_upload_commit(cv: &CommunicationValue) -> AssetMutation {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => {
            return AssetMutation {
                response,
                changed: None,
            };
        }
    };
    match user_assets::commit(user_id, &upload_id) {
        Ok((asset, changed)) => AssetMutation {
            response: asset_response(cv, CommunicationType::UserAssetUploadCommit, &asset),
            changed: changed.then(|| {
                asset_response(cv, CommunicationType::UserAssetChanged, &asset)
                    .with_id(next_notification_id())
                    .add_typed_default(DataType::Deleted, DataValue::Bool(false))
            }),
        },
        Err(error) => AssetMutation {
            response: asset_error(cv, error),
            changed: None,
        },
    }
}

pub fn handle_user_asset_upload_abort(cv: &CommunicationValue) -> CommunicationValue {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match user_assets::abort(user_id, &upload_id) {
        Ok(_) => CommunicationValue::new(CommunicationType::UserAssetUploadAbort)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(DataType::UploadId, DataValue::Str(upload_id)),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_get_chunk(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Some(asset_id) = cv.get_data(DataType::AssetId).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(offset) = data_i64(cv, DataType::Offset) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(amount) = data_i64(cv, DataType::Amount).and_then(|value| usize::try_from(value).ok())
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_assets::read_chunk(user_id, asset_id, offset, amount) {
        Ok(Some((asset, bytes))) => {
            asset_response(cv, CommunicationType::UserAssetGetChunk, &asset)
                .add_typed_default(DataType::Offset, DataValue::SignedNumber(offset.into()))
                .add_typed_default(DataType::Blob, DataValue::Bytes(bytes))
        }
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_list(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let after_id = match cv.get_data(DataType::Offset).and_then(DataValue::as_number) {
        Some(raw) => match i64::try_from(raw) {
            Ok(id) if id > 0 => Some(id),
            _ => return error_response(cv, CommunicationType::ErrorInvalidData),
        },
        None => None,
    };
    match user_assets::list_page(user_id, after_id) {
        Ok((assets, next)) => CommunicationValue::new(CommunicationType::UserAssetList)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(
                DataType::Offset,
                DataValue::SignedNumber(next.unwrap_or(0).into()),
            )
            .add_typed_default(
                DataType::Assets,
                DataValue::Array(assets.iter().map(asset_metadata_value).collect()),
            ),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_delete(cv: &CommunicationValue) -> AssetMutation {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => {
            return AssetMutation {
                response: error_response(cv, CommunicationType::ErrorInvalidData),
                changed: None,
            };
        }
    };
    let Some(asset_id) = cv.get_data(DataType::AssetId).as_str() else {
        return AssetMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match user_assets::delete(user_id, asset_id) {
        Ok(Some(asset)) => AssetMutation {
            response: asset_response(cv, CommunicationType::UserAssetDelete, &asset),
            changed: Some(
                asset_response(cv, CommunicationType::UserAssetChanged, &asset)
                    .with_id(next_notification_id())
                    .add_typed_default(DataType::Deleted, DataValue::Bool(true)),
            ),
        },
        Ok(None) => AssetMutation {
            response: CommunicationValue::new(CommunicationType::UserAssetDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(DataType::AssetId, DataValue::Str(asset_id.to_owned())),
            changed: None,
        },
        Err(error) => AssetMutation {
            response: asset_error(cv, error),
            changed: None,
        },
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
    let Ok(Some(contact)) = chats_util::get_user(user_id, blocked_user_id) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        };
    };
    let Some(blocked_principal) = contact.principal else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        };
    };
    match blocked_users::block(user_id, blocked_principal) {
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
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "blocked_users.block", error),
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
    let Ok(Some(contact)) = chats_util::get_user(user_id, blocked_user_id) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        };
    };
    let Some(blocked_principal) = contact.principal else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        };
    };
    match blocked_users::unblock(user_id, blocked_principal) {
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
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "blocked_users.unblock", error),
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
                        .map(|blocked| DataValue::SignedNumber(blocked.blocked_user_id.into()))
                        .collect(),
                ),
            ),
        Err(error) => internal_handler_error(cv, "blocked_users.get", error),
    }
}

fn receipt_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    policy: receipt_policy::ReceiptPolicy,
) -> CommunicationValue {
    let response = CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(policy.user_id));
    add_receipt_policy_data(response, &policy)
}
pub fn handle_receipt_policy_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = authenticated_user(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match receipt_policy::get(user_id) {
        Ok(policy) => receipt_response(cv, CommunicationType::ReceiptPolicyGet, policy),
        Err(error) => internal_handler_error(cv, "receipt_policy.get", error),
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
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "receipt_policy.set", error),
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
        Err(error) => internal_handler_error(cv, "message_storage_policy.get", error),
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
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "message_storage_policy.set", error),
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
        Err(error) => internal_handler_error(cv, "blocked_users.check", error),
    }
}

pub fn handle_call_contact_check(cv: &CommunicationValue) -> CommunicationValue {
    let (Some(sender), Some(recipient)) = (
        data_i64(cv, DataType::SenderId).filter(|id| *id > 0),
        data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0),
    ) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match chats_util::get_user(sender, recipient) {
        Ok(contact) => CommunicationValue::new(CommunicationType::CallContactCheck)
            .with_request_id(cv)
            .add_typed_default(DataType::IsBlocked, DataValue::Bool(contact.is_some())),
        Err(error) => internal_handler_error(cv, "call.contact_check", error),
    }
}

pub fn handle_call_envelope_store(
    cv: &CommunicationValue,
    owner_omikron_id: i64,
) -> CommunicationValue {
    let Some(recipient_id) = data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(inviter_id) = data_i64(cv, DataType::CallInviterId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(call_id) =
        data_string(cv, DataType::CallId).filter(|id| uuid::Uuid::parse_str(id).is_ok())
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(created_at) = data_i64(cv, DataType::CreatedAt) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let secret_value = cv.get_data(DataType::CallSecret);
    let Some(secret) = secret_value.as_ref() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let tm = TypeMap::latest();
    let field = |dt: DataType| secret.get_field(dt.try_to_id(&tm)?);
    let (
        Some(secret_id),
        Some(version_number),
        Some(encrypted_secret),
        Some(kem_ciphertext),
        Some(wrapping_scheme),
    ) = (
        field(DataType::SecretId).and_then(DataValue::as_str),
        field(DataType::VersionNumber)
            .and_then(DataValue::as_number)
            .and_then(|n| i64::try_from(n).ok()),
        field(DataType::EncryptedSecret).and_then(DataValue::as_bytes),
        field(DataType::KemCiphertext).and_then(DataValue::as_bytes),
        field(DataType::WrappingScheme).and_then(DataValue::as_str),
    )
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let now = now_millis_i64();
    let expires_at = created_at.saturating_add(3 * 24 * 60 * 60 * 1000);
    if created_at > now + 60_000
        || expires_at <= now
        || secret_id.len() > 256
        || encrypted_secret.len() > 1024
        || kem_ciphertext.len() > 4096
        || wrapping_scheme.len() > 128
    {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let envelope = CallEnvelope {
        recipient_id,
        call_id,
        owner_omikron_id,
        inviter_id,
        created_at,
        expires_at,
        secret_id: secret_id.to_string(),
        version_number,
        encrypted_secret,
        kem_ciphertext,
        wrapping_scheme: wrapping_scheme.to_string(),
    };
    match call_envelopes::store(&envelope, now) {
        Ok(true) => success_response(cv),
        Ok(false) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => internal_handler_error(cv, "call.envelope_store", error),
    }
}

pub fn handle_call_envelope_get(
    cv: &CommunicationValue,
    owner_omikron_id: i64,
) -> CommunicationValue {
    let (Some(recipient_id), Some(call_id)) = (
        data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0),
        data_string(cv, DataType::CallId).filter(|id| uuid::Uuid::parse_str(id).is_ok()),
    ) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match call_envelopes::get(recipient_id, &call_id, owner_omikron_id, now_millis_i64()) {
        Ok(Some(envelope)) => {
            let secret = typed_container(vec![
                (DataType::SecretId, DataValue::Str(envelope.secret_id)),
                (
                    DataType::VersionNumber,
                    DataValue::SignedNumber(envelope.version_number.into()),
                ),
                (
                    DataType::EncryptedSecret,
                    DataValue::Bytes(envelope.encrypted_secret),
                ),
                (
                    DataType::KemCiphertext,
                    DataValue::Bytes(envelope.kem_ciphertext),
                ),
                (
                    DataType::WrappingScheme,
                    DataValue::Str(envelope.wrapping_scheme),
                ),
            ]);
            CommunicationValue::new(CommunicationType::CallEnvelopeGet)
                .with_request_id(cv)
                .add_typed_default(DataType::CallSecret, secret)
                .add_typed_default(
                    DataType::CallInviterId,
                    DataValue::SignedNumber(envelope.inviter_id.into()),
                )
                .add_typed_default(
                    DataType::CreatedAt,
                    DataValue::SignedNumber(envelope.created_at.into()),
                )
        }
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => internal_handler_error(cv, "call.envelope_get", error),
    }
}

pub fn handle_call_contact_accept(cv: &CommunicationValue) -> CommunicationValue {
    let (Some(recipient), Some(inviter)) = (
        data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0),
        data_i64(cv, DataType::CallInviterId).filter(|id| *id > 0),
    ) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match add_conversation_for_user(recipient, inviter, None) {
        Ok(()) => success_response(cv),
        Err(error) => internal_handler_error(cv, "call.contact_accept", error),
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
            external_principal: None,
            id: 1,
            external_user: 9,
            relay_signer_id: Some(9),
            relay_signer_principal: None,
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
#[derive(Clone, Debug)]
pub struct RelayApplicationContext {
    pub signer: iota_identity::PrincipalHandle,
    pub recipient: iota_identity::PrincipalHandle,
    pub signer_principal: iota_identity::PrincipalId,
    pub recipient_principal: iota_identity::PrincipalId,
    pub hosted_sender: Option<iota_identity::LocalUserId>,
    pub hosted_recipient: Option<iota_identity::LocalUserId>,
    pub legacy: Option<LegacyRelayApplicationData>,
}

#[derive(Clone, Debug)]
pub struct LegacyRelayApplicationData {
    pub signer_id: u64,
    pub recipient_id: u64,
}

pub fn apply_relay_application_content(
    application: &RelayApplicationContext,
    context: &VerifiedRelayContext,
    content: &VerifiedRelayContent,
    accepted_at: i64,
) -> Result<RelayApplicationResult, String> {
    if application.signer_principal.user_id != context.signer_id
        || application.recipient_principal.user_id != context.final_recipient_id
    {
        return Err("Relay application identity does not match verified content".into());
    }
    let (storage_owner, sent_by_self) =
        match (application.hosted_sender, application.hosted_recipient) {
            (Some(sender), _) => (sender.0, true),
            (None, Some(recipient)) => (recipient.0, false),
            (None, None) => return Err("Relay application has no hosted principal".into()),
        };
    apply_verified_relay_content(
        context,
        content,
        application.signer,
        application.recipient,
        accepted_at,
        storage_owner,
        sent_by_self,
    )
}
