mod edits;
pub use edits::{
    apply_remote_edit, apply_remote_edit_for_principal, apply_remote_edit_for_principal_in_tx,
    apply_remote_edit_for_principal_versioned_in_tx, edit_message, edit_message_for_principal,
    edit_message_for_principal_in_tx, edit_message_for_principal_versioned_in_tx,
    require_edit_key_in_tx,
};
mod deletion;
pub use deletion::{
    apply_remote_delete, apply_remote_delete_for_principal,
    apply_remote_delete_for_principal_in_tx, delete_edit_history, delete_edit_history_in_tx,
    delete_message, delete_message_for_principal, delete_message_for_principal_in_tx,
    flag_deleted_by_external, hard_delete_message, purge_message, purge_message_in_tx,
    remove_message_history, remove_message_history_by_relay_identity, remove_message_history_in_tx,
};
mod reactions;
pub use reactions::{
    add_reaction, add_reaction_for_principal, add_reaction_for_principal_in_tx, remove_reaction,
    remove_reaction_for_principal, remove_reaction_for_principal_in_tx,
};
mod queries;
pub use queries::{
    add_message, add_message_in_tx, get_all_messages, get_message, get_message_with_offset,
    get_messages, get_messages_by_ids, get_messages_for_principal,
};
mod receipts;
use crate::storage_error::StorageError;
use crate::util::db;
use crate::util::message_storage_policy::{self, MessageRetention};
use crate::util::sync::{self, EntityType, Operation};
pub use receipts::{
    change_message_state, change_message_state_by_relay_id, change_message_state_by_relay_id_in_tx,
    record_delivery_failure, record_delivery_failure_in_tx, record_destination_iota_received,
    record_destination_iota_received_in_tx, record_message_receipt, record_message_receipt_in_tx,
};
use rusqlite::{OptionalExtension, Transaction, params};

pub const MAX_UNIQUE_REACTIONS_PER_MESSAGE: usize = 10;

#[derive(PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MessageState {
    Read,
    Received,
    Sent,
    Sending,
}

#[derive(Clone, Debug)]
pub struct MessageStateUpdate {
    pub send_time: i64,
    pub state: MessageState,
}

impl MessageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageState::Read => "read",
            MessageState::Received => "received",
            MessageState::Sent => "sent",
            MessageState::Sending => "sending",
        }
    }

    #[expect(
        clippy::should_implement_trait,
        reason = "unknown stored states fall back rather than fail parsing"
    )]
    pub fn from_str(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "read" => MessageState::Read,
            "received" => MessageState::Received,
            "sent" => MessageState::Sent,
            _ => MessageState::Sending,
        }
    }

    pub fn upgrade(self, other: Self) -> Self {
        if other == Self::Read || self == Self::Read {
            Self::Read
        } else if other == Self::Received || self == Self::Received {
            Self::Received
        } else if other == Self::Sent || self == Self::Sent {
            Self::Sent
        } else {
            Self::Sending
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: i64,
    pub external_user: i64,
    pub external_principal: Option<iota_identity::PrincipalHandle>,
    pub relay_signer_id: Option<i64>,
    pub relay_signer_principal: Option<iota_identity::PrincipalHandle>,
    pub relay_message_id: Option<String>,
    pub message_time: i64,
    pub authored_at: Option<i64>,
    pub origin_iota_received_at: Option<i64>,
    pub destination_iota_received_at: Option<i64>,
    pub client_received_at: Option<i64>,
    pub client_received_recorded_at: Option<i64>,
    pub read_at: Option<i64>,
    pub read_recorded_at: Option<i64>,
    pub delivery_failed_at: Option<i64>,
    pub delivery_failure: Option<String>,
    pub content: String,
    pub edited: bool,
    pub sent_by_self: bool,
    pub message_state: String,
    pub height: i64,
    pub key_version: i64,
    pub reply_to: Option<i64>,
    pub reactions: Vec<StoredReaction>,
}

pub struct NewMessage<'a> {
    pub relay_signer_id: i64,
    pub relay_signer_principal: iota_identity::PrincipalHandle,
    pub relay_message_id: &'a str,
    pub authored_at: i64,
    pub send_time: i64,
    pub storage_owner: i64,
    pub external_user: i64,
    pub external_principal: iota_identity::PrincipalHandle,
    pub sent_by_self: bool,
    pub content: &'a str,
    pub height: i64,
    pub key_version: i64,
    pub reply_to: Option<i64>,
    pub origin_iota_received_at: Option<i64>,
    pub destination_iota_received_at: Option<i64>,
    pub initial_state: MessageState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReaction {
    pub reaction: String,
    pub user_id: i64,
    pub principal: Option<iota_identity::PrincipalHandle>,
}

#[cfg(test)]
mod tests;
