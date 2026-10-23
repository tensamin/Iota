#![allow(
    clippy::result_large_err,
    reason = "return protocol error frames directly to the sender"
)]

mod messages;
use messages::stored_message_value;
pub use messages::{
    handle_get_chats, handle_message_delete, handle_message_edit, handle_message_get,
    handle_message_reaction, handle_messages_get,
};
mod setting_handlers;
#[cfg(test)]
use setting_handlers::parse_setting_locator;
use setting_handlers::synced_setting_value;
pub use setting_handlers::{
    handle_global_settings_load, handle_global_settings_save, handle_settings_list,
    handle_settings_load, handle_settings_save, handle_synced_setting_delete,
    handle_synced_setting_get, handle_synced_setting_set, handle_synced_settings_list,
};
mod chat_secrets;
use chat_secrets::contact_value;
pub use chat_secrets::handle_get_chat_secret;
mod account_state;
use account_state::add_receipt_policy_data;
#[cfg(test)]
use account_state::{contact_ids_value, read_fenced_snapshot};
pub use account_state::{
    handle_account_state_applied, handle_account_state_request, handle_relay_receipt_page,
};
mod identity;
pub use identity::handle_user_resolve;
mod notifications;
pub use notifications::handle_read_notification;
mod communities;
use communities::community_values;
pub use communities::{handle_add_community, handle_get_communities, handle_remove_community};
mod blobs;
pub use blobs::{
    handle_user_blob_delete, handle_user_blob_get, handle_user_blob_list, handle_user_blob_put,
};
mod assets;
#[cfg(test)]
use assets::asset_error;
pub use assets::{
    handle_user_asset_delete, handle_user_asset_get_chunk, handle_user_asset_list,
    handle_user_asset_upload_abort, handle_user_asset_upload_chunk,
    handle_user_asset_upload_commit, handle_user_asset_upload_start,
    handle_user_asset_upload_status,
};
mod policies;
pub use policies::{
    handle_blocked_users_get, handle_message_storage_policy_get, handle_message_storage_policy_set,
    handle_receipt_policy_get, handle_receipt_policy_set, handle_user_block,
    handle_user_block_check, handle_user_unblock,
};
mod calls;
pub use calls::{
    handle_call_contact_accept, handle_call_contact_check, handle_call_envelope_get,
    handle_call_envelope_store,
};

use crate::message_common::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iota_identity::{NodeIdentityResolver, PrincipalStore};
use iota_logger::{LogLevel, PrintType, log_event};
use iota_storage::storage_error::StorageError;
use iota_storage::util::call_envelopes::{self, CallEnvelope};
use iota_storage::util::chat_files;
use iota_storage::util::chats_util;
use iota_storage::util::communities_util::CommunitiesUtil;
use iota_storage::util::e2ee_storage::{self, ChatSecretQuery};
use iota_storage::util::settings;
use iota_storage::util::synced_settings::{self, SettingScope, SyncedSetting};
use iota_storage::util::user_assets::{self, UploadStatus, UserAssetMetadata};
use iota_storage::util::user_blobs::{self, UserBlob, UserBlobMetadata};
use iota_storage::util::{blocked_users, message_storage_policy, receipt_policy};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
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
    let contact =
        chats_util::get_user_by_principal(sender_id, iota_identity::PrincipalHandle(partner_id))
            .map_err(|_| error_response(cv, CommunicationType::ErrorInternal))?
            .ok_or_else(|| error_response(cv, CommunicationType::ErrorNotFound))?;
    let partner_principal = contact
        .principal
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorInternal))?;
    let sender_principal = iota_storage::identity::SqlitePrincipalStore
        .principal_for_local_user(iota_identity::LocalUserId(sender_id))
        .map_err(|_| error_response(cv, CommunicationType::ErrorInternal))?
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorNotFound))?;

    Ok(MessageMutation {
        sender_id,
        partner_id: contact.user_id,
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
    chats_util::add_conversation(user_id, other_id, name)
}

#[cfg(test)]
mod presence_tests;

#[cfg(test)]
mod account_state_tests;

#[cfg(test)]
mod asset_error_tests;

#[cfg(test)]
mod stored_message_tests;

#[cfg(test)]
mod synced_settings_tests;
