use crate::storage_error::StorageError;
use crate::util::db;
use crate::util::message_storage_policy::{self, MessageRetention};
use crate::util::sync::{self, EntityType, Operation};
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

/*
 * Each edit is recorded in message_edits with the before/after content and a
 * timestamp. Only the original sender (sent_by_self = 1) may edit.
 */
pub fn edit_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    update_message_content(
        storage_owner,
        external_user,
        None,
        message_time,
        editor_id,
        new_content,
        true,
    )
}

pub fn edit_message_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    update_message_content(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        true,
    )
}

pub fn edit_message_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        true,
        None,
    )
}

/* Applies an edit received from the message sender to the recipient's copy. */
pub fn apply_remote_edit(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }

    update_message_content(
        storage_owner,
        external_user,
        None,
        message_time,
        editor_id,
        new_content,
        false,
    )
}

/// VersionNumber identifies the replacement ciphertext's key, as used by the
/// client's encryptChatText/decryptChatText calls. It may be an older available
/// epoch or a new epoch, independent of the original message's key version.
/// The relay calls require_edit_key_in_tx with the authenticated chat first.
/// See client/packages/chat/src/components/message.tsx and context.tsx in the
/// sibling client repository for edit production and live decryption.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit edit identity, key version and caller transaction"
)]
pub fn edit_message_for_principal_versioned_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    key_version: i64,
) -> Result<(), StorageError> {
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        true,
        Some(key_version),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit edit identity, key version and caller transaction"
)]
pub fn apply_remote_edit_for_principal_versioned_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    key_version: i64,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        false,
        Some(key_version),
    )
}

/// Check the exact ciphertext epoch, rather than the latest chat secret. A
/// missing epoch is recoverable when its secret arrives, including after restart.
pub fn require_edit_key_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    chat_id: &str,
    key_version: i64,
) -> Result<(), StorageError> {
    if key_version <= 0 {
        return Err(StorageError::InvalidRelayPayload("edit key version"));
    }
    crate::util::e2ee_storage::get_chat_secret_on(
        tx,
        &crate::util::e2ee_storage::ChatSecretQuery {
            user_id: storage_owner.to_string(),
            chat_id: chat_id.to_owned(),
            secret_id: Some(crate::util::e2ee_storage::principal_secret_id(chat_id)),
            version: Some(key_version),
        },
    )?
    .ok_or(StorageError::MissingRelayDependency)?;
    Ok(())
}

pub fn apply_remote_edit_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        false,
    )
}

fn update_message_content(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    require_sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        update_message_content_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            editor_id,
            new_content,
            require_sent_by_self,
            None,
        )
    })
}

pub fn apply_remote_edit_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        false,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit message identity and caller transaction"
)]
fn update_message_content_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    require_sent_by_self: bool,
    key_version: Option<i64>,
) -> Result<(), StorageError> {
    if key_version.is_some_and(|version| version <= 0) {
        return Err(StorageError::InvalidRelayPayload("edit key version"));
    }
    let msg = tx
        .query_row(
            r#"
            SELECT id, content, sent_by_self, history_deleted, key_version
            FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            ORDER BY id DESC LIMIT 1
            "#,
            params![
                storage_owner,
                external_user,
                message_time,
                external_principal.map(|principal| principal.0)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(StorageError::MissingRelayDependency)?;

    let (msg_id, old_content, sent_by_self, history_deleted, old_key_version) = msg;
    if require_sent_by_self && sent_by_self != 1 {
        return Err(StorageError::MessageUnauthorized);
    }
    if !require_sent_by_self && sent_by_self != 0 {
        return Err(StorageError::MessageUnauthorized);
    }

    if history_deleted != 0 {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    tx.execute(
            r#"
            INSERT INTO message_edits (message_id, content_before, content_after, edited_at, edited_by, content_before_key_version, content_after_key_version)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![msg_id, old_content, new_content, now, editor_id, old_key_version, key_version.unwrap_or(old_key_version)],
        )?;

    tx.execute(
        r#"
            UPDATE messages
            SET content = ?1, edited_count = edited_count + 1,
                key_version = COALESCE(?3, key_version)
            WHERE id = ?2
            "#,
        params![new_content, msg_id, key_version],
    )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn hard_delete_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    hard_delete_message_with_principal(storage_owner, external_user, None, message_time)
}

fn hard_delete_message_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        hard_delete_message_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        )
    })
}

fn hard_delete_message_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    let msg_id = tx
        .query_row(
            r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            ORDER BY id DESC LIMIT 1
            "#,
            params![
                storage_owner,
                external_user,
                message_time,
                external_principal.map(|principal| principal.0)
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(msg_id) = msg_id else {
        return Ok(());
    };

    purge_message_in_tx(tx, storage_owner, msg_id)?;
    Ok(())
}

pub fn purge_message(storage_owner: i64, message_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| purge_message_in_tx(tx, storage_owner, message_id))
}

pub fn remove_message_history(storage_owner: i64, message_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| remove_message_history_in_tx(tx, storage_owner, message_id))
}

/* Resolves the protocol identity retained in a tombstone before removing visible history. */
pub fn remove_message_history_by_relay_identity(
    storage_owner: i64,
    relay_signer_id: i64,
    relay_message_id: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let message_id = tx.query_row(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_id = ?2 AND relay_message_id = ?3",
            params![storage_owner, relay_signer_id, relay_message_id],
            |row| row.get::<_, i64>(0),
        ).optional()?;
        if let Some(message_id) = message_id {
            remove_message_history_in_tx(tx, storage_owner, message_id)?;
        }
        Ok(())
    })
}

pub fn remove_message_history_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    message_id: i64,
) -> Result<(), StorageError> {
    let message: Option<(i64, Option<i64>, i64)> = tx
        .query_row(
            "SELECT external_user, external_principal, history_deleted FROM messages WHERE id = ?1 AND storage_owner = ?2",
            params![message_id, storage_owner],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((external_user, external_principal, history_deleted)) = message else {
        return Ok(());
    };
    if history_deleted != 0 {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM message_edits WHERE message_id = ?1",
        [message_id],
    )?;
    tx.execute("DELETE FROM reactions WHERE message_id = ?1", [message_id])?;
    tx.execute("DELETE FROM message_receipts WHERE storage_owner = ?1 AND EXISTS (SELECT 1 FROM messages WHERE id = ?2 AND relay_signer_principal = message_receipts.target_signer_principal AND relay_message_id = message_receipts.target_message_id)", params![storage_owner, message_id])?;
    tx.execute("UPDATE messages SET content = '', history_deleted = 1, history_deleted_at = ?2, expires_at = NULL, client_received_at = NULL, client_received_recorded_at = NULL, read_at = NULL, read_recorded_at = NULL WHERE id = ?1", params![message_id, sync::now_millis()])?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Delete,
    )?;
    update_contact_last_message_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal.map(iota_identity::PrincipalHandle),
    )?;
    Ok(())
}

fn update_contact_last_message_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE contacts SET last_message_at = (SELECT MAX(COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, message_time)) FROM messages WHERE storage_owner = ?1 AND ((?3 IS NULL AND external_user = ?2) OR external_principal = ?3) AND deleted_by_external = 0 AND history_deleted = 0) WHERE storage_owner = ?1 AND ((?3 IS NULL AND user_id = ?2) OR principal_handle = ?3)",
        params![storage_owner, external_user, external_principal.map(|principal| principal.0)],
    )?;
    Ok(())
}

pub fn purge_message_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    message_id: i64,
) -> Result<(), StorageError> {
    let (external_user, external_principal, relay_signer_principal, relay_message_id) = tx.query_row(
        "SELECT external_user, external_principal, relay_signer_principal, relay_message_id FROM messages WHERE id = ?1 AND storage_owner = ?2",
        params![message_id, storage_owner],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, Option<String>>(3)?)),
    )?;
    if let (Some(relay_signer_principal), Some(relay_message_id)) =
        (relay_signer_principal, relay_message_id)
    {
        tx.execute(
            "DELETE FROM message_receipts WHERE storage_owner = ?1 AND target_signer_principal = ?2 AND target_message_id = ?3",
            params![storage_owner, relay_signer_principal, relay_message_id],
        )?;
    }
    tx.execute(
        "DELETE FROM message_edits WHERE message_id = ?1",
        [message_id],
    )?;
    tx.execute("DELETE FROM reactions WHERE message_id = ?1", [message_id])?;
    tx.execute("DELETE FROM messages WHERE id = ?1", [message_id])?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Delete,
    )?;
    update_contact_last_message_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal.map(iota_identity::PrincipalHandle),
    )?;
    Ok(())
}

/* Deletes a message from the sender's local copy after checking ownership. */
pub fn delete_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    delete_message_with_principal(storage_owner, external_user, None, message_time, true)
}

pub fn delete_message_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
) -> Result<(), StorageError> {
    delete_message_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        true,
    )
}

fn delete_message_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        delete_message_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            sent_by_self,
        )
    })
}

pub fn delete_message_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
) -> Result<(), StorageError> {
    delete_message_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        true,
    )
}

pub fn apply_remote_delete_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    sender_id: i64,
) -> Result<(), StorageError> {
    if sender_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    delete_message_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        false,
    )
}

fn delete_message_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    sent_by_self: bool,
) -> Result<(), StorageError> {
    match ensure_message_direction_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal,
        message_time,
        sent_by_self,
    ) {
        Ok(()) if sent_by_self => hard_delete_message_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        ),
        Ok(()) => flag_deleted_by_external_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        ),
        Err(StorageError::Db(rusqlite::Error::QueryReturnedNoRows)) => Ok(()),
        Err(error) => Err(error),
    }
}

/* Flags the recipient's local copy after validating its sender, preserving its history. */
pub fn apply_remote_delete(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    sender_id: i64,
) -> Result<(), StorageError> {
    if sender_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    delete_message_with_principal(storage_owner, external_user, None, message_time, false)
}

pub fn apply_remote_delete_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    sender_id: i64,
) -> Result<(), StorageError> {
    if sender_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    delete_message_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        false,
    )
}

fn ensure_message_direction_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    expected_sent_by_self: bool,
) -> Result<(), StorageError> {
    let sent_by_self: i64 = tx.query_row(
        r#"
            SELECT sent_by_self FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            ORDER BY id DESC LIMIT 1
            "#,
        params![
            storage_owner,
            external_user,
            message_time,
            external_principal.map(|principal| principal.0)
        ],
        |row| row.get(0),
    )?;
    if (sent_by_self != 0) != expected_sent_by_self {
        return Err(StorageError::MessageUnauthorized);
    }
    Ok(())
}

/*
 * Marks a message as deleted by the external user rather than removing the row,
 * so the storage owner still sees a tombstone in the UI.
 */
pub fn flag_deleted_by_external(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    flag_deleted_by_external_with_principal(storage_owner, external_user, None, message_time)
}

fn flag_deleted_by_external_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        flag_deleted_by_external_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        )
    })
}

fn flag_deleted_by_external_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    let affected = tx.execute(
        r#"
            UPDATE messages
            SET deleted_by_external = 1
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            "#,
        params![
            storage_owner,
            external_user,
            message_time,
            external_principal.map(|principal| principal.0)
        ],
    )?;
    if affected == 0 {
        return Err(StorageError::Other("Message not found".into()));
    }
    let msg_id: i64 = tx.query_row(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND message_time = ?3 AND ((?4 IS NULL AND external_user = ?2) OR external_principal = ?4) ORDER BY id DESC LIMIT 1",
            params![storage_owner, external_user, message_time, external_principal.map(|principal| principal.0)],
            |r| r.get(0),
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Delete,
    )?;
    update_contact_last_message_in_tx(tx, storage_owner, external_user, external_principal)?;
    Ok(())
}

/*
 * Removes the edit trail but keeps the message with edited_count > 0 so
 * the UI still shows the "edited" indicator.  Only the own user should
 * call this.
 */
pub fn delete_edit_history(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        delete_edit_history_in_tx(tx, storage_owner, external_user, message_time)
    })
}

pub fn delete_edit_history_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    let (msg_id, history_deleted): (i64, i64) = tx.query_row(
        r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
        params![storage_owner, external_user, message_time],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if history_deleted != 0 {
        return Ok(());
    }

    tx.execute(
        "DELETE FROM message_edits WHERE message_id = ?1",
        params![msg_id],
    )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn add_reaction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    user_id: i64,
    reaction: &str,
) -> Result<(), StorageError> {
    add_reaction_with_principal(
        storage_owner,
        external_user,
        None,
        message_time,
        user_id,
        None,
        reaction,
    )
}

pub fn add_reaction_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    add_reaction_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

fn add_reaction_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        add_reaction_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            user_id,
            user_principal,
            reaction,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
pub fn add_reaction_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    add_reaction_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
fn add_reaction_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    let (msg_id, history_deleted): (i64, i64) = tx
        .query_row(
            r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            ORDER BY id DESC LIMIT 1
            "#,
            params![
                storage_owner,
                external_user,
                message_time,
                external_principal.map(|principal| principal.0)
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(StorageError::MissingRelayDependency)?;
    if history_deleted != 0 {
        return Ok(());
    }

    let reaction_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM reactions WHERE message_id = ?1 AND reaction = ?2)",
        params![msg_id, reaction],
        |row| row.get(0),
    )?;
    if !reaction_exists {
        let unique_reactions: i64 = tx.query_row(
            "SELECT COUNT(DISTINCT reaction) FROM reactions WHERE message_id = ?1",
            [msg_id],
            |row| row.get(0),
        )?;
        if unique_reactions >= MAX_UNIQUE_REACTIONS_PER_MESSAGE as i64 {
            return Err(StorageError::ReactionLimitReached);
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let inserted = tx.execute(
            r#"
            INSERT OR IGNORE INTO reactions (message_id, user_id, user_principal, reaction, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                msg_id,
                user_id,
                user_principal.map(|principal| principal.0),
                reaction,
                now
            ],
        )?;
    if inserted > 0 {
        sync::record_event(
            tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Upsert,
        )?;
        Ok(())
    } else {
        Ok(())
    }
}

pub fn remove_reaction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    user_id: i64,
    reaction: &str,
) -> Result<(), StorageError> {
    remove_reaction_with_principal(
        storage_owner,
        external_user,
        None,
        message_time,
        user_id,
        None,
        reaction,
    )
}

pub fn remove_reaction_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    remove_reaction_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

fn remove_reaction_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        remove_reaction_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            user_id,
            user_principal,
            reaction,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
pub fn remove_reaction_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    remove_reaction_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
fn remove_reaction_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    let (msg_id, history_deleted): (i64, i64) = tx
        .query_row(
            r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            ORDER BY id DESC LIMIT 1
            "#,
            params![
                storage_owner,
                external_user,
                message_time,
                external_principal.map(|principal| principal.0)
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(StorageError::MissingRelayDependency)?;
    if history_deleted != 0 {
        return Ok(());
    }

    tx.execute(
            "DELETE FROM reactions WHERE message_id = ?1 AND ((?3 IS NULL AND user_id = ?2) OR user_principal = ?3) AND reaction = ?4",
            params![
                msg_id,
                user_id,
                user_principal.map(|principal| principal.0),
                reaction
            ],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn add_message(message: NewMessage<'_>) -> Result<i64, StorageError> {
    db::with_immediate_transaction(|tx| add_message_in_tx(tx, message))
}

pub fn add_message_in_tx(
    tx: &Transaction<'_>,
    message: NewMessage<'_>,
) -> Result<i64, StorageError> {
    let NewMessage {
        relay_signer_id,
        relay_signer_principal,
        relay_message_id,
        authored_at,
        send_time,
        storage_owner,
        external_user,
        external_principal,
        sent_by_self,
        content,
        height,
        key_version,
        reply_to,
        origin_iota_received_at,
        destination_iota_received_at,
        initial_state,
    } = message;
    let stored_at = sync::now_millis();
    let policy = message_storage_policy::get_in_tx(tx, storage_owner)?;
    let expires_at = match policy.retention {
        MessageRetention::Forever => None,
        MessageRetention::Duration { duration_ms } => Some(
            stored_at
                .checked_add(duration_ms)
                .ok_or_else(|| StorageError::Other("message expiry overflow".into()))?,
        ),
    };
    tx.execute(
            r#"
            INSERT INTO messages (
                storage_owner, external_user, message_time, content, sent_by_self,
                message_state, height, key_version, reply_to, relay_signer_id, relay_message_id,
                authored_at, origin_iota_received_at, destination_iota_received_at, stored_at,
                expires_at, external_principal, relay_signer_principal
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
            "#,
            params![
                storage_owner,
                external_user,
                send_time,
                content,
                i64::from(sent_by_self),
                initial_state.as_str(),
                height,
                key_version,
                reply_to,
                relay_signer_id,
                relay_message_id,
                authored_at,
                origin_iota_received_at,
                destination_iota_received_at,
                stored_at,
                expires_at,
                external_principal.0,
                relay_signer_principal.0,
            ],
        )?;
    let msg_id = tx.last_insert_rowid();
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    let mut contact =
        crate::users::contact::Contact::for_principal(external_user, external_principal);
    contact.set_last_message_at(
        destination_iota_received_at
            .or(origin_iota_received_at)
            .unwrap_or(authored_at),
    );
    crate::util::chats_util::upsert_contact(tx, storage_owner, &contact)?;
    if !sent_by_self {
        tx.execute(
                "UPDATE contacts SET notifications = CASE WHEN notifications < 9223372036854775807 THEN notifications + 1 ELSE notifications END WHERE storage_owner = ?1 AND principal_handle = ?2",
                params![storage_owner, external_principal.0],
            )?;
    }
    Ok(msg_id)
}

pub fn change_message_state_by_relay_id(
    storage_owner: i64,
    _relay_signer_id: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    new_state: MessageState,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    db::with_immediate_transaction(|tx| {
        change_message_state_by_relay_id_in_tx(
            tx,
            storage_owner,
            relay_signer_principal,
            relay_message_id,
            new_state,
        )
    })
}

pub fn change_message_state_by_relay_id_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    new_state: MessageState,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    let Some((msg_id, current, message_time)) = tx
            .query_row(
                "SELECT id, message_state, message_time FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_principal.0, relay_message_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
    let final_state = MessageState::from_str(&current).upgrade(new_state);
    tx.execute(
        "UPDATE messages SET message_state = ?1 WHERE id = ?2",
        params![final_state.as_str(), msg_id],
    )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    Ok(Some(MessageStateUpdate {
        send_time: message_time,
        state: final_state,
    }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit persisted receipt fields"
)]
pub fn record_message_receipt(
    storage_owner: i64,
    target_signer_id: i64,
    target_signer_principal: iota_identity::PrincipalHandle,
    target_message_id: &str,
    receipt_signer_id: i64,
    receipt_signer_principal: iota_identity::PrincipalHandle,
    receipt_message_id: &str,
    receipt_type: MessageState,
    event_at: i64,
    recorded_at: i64,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    db::with_immediate_transaction(|tx| {
        record_message_receipt_in_tx(
            tx,
            storage_owner,
            target_signer_id,
            target_signer_principal,
            target_message_id,
            receipt_signer_id,
            receipt_signer_principal,
            receipt_message_id,
            receipt_type,
            event_at,
            recorded_at,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit persisted receipt fields and caller transaction"
)]
pub fn record_message_receipt_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    target_signer_id: i64,
    target_signer_principal: iota_identity::PrincipalHandle,
    target_message_id: &str,
    receipt_signer_id: i64,
    receipt_signer_principal: iota_identity::PrincipalHandle,
    receipt_message_id: &str,
    receipt_type: MessageState,
    event_at: i64,
    recorded_at: i64,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    let receipt_type = match receipt_type {
        MessageState::Received => "received",
        MessageState::Read => "read",
        _ => return Err(StorageError::Other("invalid message receipt state".into())),
    };
    let Some((message_id, message_time, external_principal, authored_at, history_deleted)) = tx
            .query_row(
                "SELECT id, message_time, external_principal, authored_at, history_deleted FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, target_signer_principal.0, target_message_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(StorageError::MissingRelayDependency);
        };
    if external_principal != receipt_signer_principal.0 {
        return Err(StorageError::MessageUnauthorized);
    }
    if event_at > recorded_at.saturating_add(5 * 60 * 1000)
        || authored_at.is_some_and(|authored_at| event_at < authored_at)
    {
        return Err(StorageError::InvalidRelayPayload(
            "receipt event time outside accepted clock range",
        ));
    }
    if history_deleted != 0 {
        return Ok(None);
    }
    tx.execute(
            "INSERT OR IGNORE INTO message_receipts (storage_owner, target_signer_id, target_signer_principal, target_message_id, receipt_signer_id, receipt_signer_principal, receipt_message_id, receipt_type, event_at, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![storage_owner, target_signer_id, target_signer_principal.0, target_message_id, receipt_signer_id, receipt_signer_principal.0, receipt_message_id, receipt_type, event_at, recorded_at],
        )?;
    let (state_column, recorded_column) = if receipt_type == "read" {
        ("read_at", "read_recorded_at")
    } else {
        ("client_received_at", "client_received_recorded_at")
    };
    let final_state = MessageState::from_str(&tx.query_row(
        "SELECT message_state FROM messages WHERE id = ?1",
        [message_id],
        |row| row.get::<_, String>(0),
    )?)
    .upgrade(MessageState::from_str(receipt_type));
    tx.execute(
            &format!("UPDATE messages SET {state_column} = COALESCE({state_column}, ?1), {recorded_column} = COALESCE({recorded_column}, ?2), message_state = ?3 WHERE id = ?4"),
            params![event_at, recorded_at, final_state.as_str(), message_id],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Upsert,
    )?;
    Ok(Some(MessageStateUpdate {
        send_time: message_time,
        state: final_state,
    }))
}

pub fn record_destination_iota_received(
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    accepted_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        record_destination_iota_received_in_tx(
            tx,
            storage_owner,
            relay_signer_principal,
            relay_message_id,
            accepted_at,
        )
    })
}

pub fn record_destination_iota_received_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    accepted_at: i64,
) -> Result<(), StorageError> {
    let Some(message_id) = tx
            .query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_principal.0, relay_message_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(());
        };
    tx.execute(
            "UPDATE messages SET destination_iota_received_at = COALESCE(destination_iota_received_at, ?1), delivery_failed_at = NULL, delivery_failure = NULL, message_state = CASE WHEN message_state = 'sending' THEN 'sent' ELSE message_state END WHERE id = ?2",
            params![accepted_at, message_id],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn record_delivery_failure(
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    failure: &str,
    failed_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        record_delivery_failure_in_tx(
            tx,
            storage_owner,
            relay_signer_principal,
            relay_message_id,
            failure,
            failed_at,
        )
    })
}

pub fn record_delivery_failure_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    failure: &str,
    failed_at: i64,
) -> Result<(), StorageError> {
    let Some(message_id) = tx
            .query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_principal.0, relay_message_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(());
        };
    tx.execute(
            "UPDATE messages SET delivery_failed_at = ?1, delivery_failure = ?2 WHERE id = ?3 AND destination_iota_received_at IS NULL",
            params![failed_at, failure, message_id],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn change_message_state(
    timestamp: i64,
    storage_owner: i64,
    external_user: i64,
    new_state: MessageState,
) -> std::io::Result<()> {
    db::with_db(|conn| {
        let current: Option<String> = match conn.query_row(
            r#"
            SELECT message_state
            FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, timestamp],
            |row| row.get(0),
        ) {
            Ok(state) => Some(state),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        let Some(current_state_raw) = current else {
            return Ok(());
        };

        let upgraded = MessageState::from_str(&current_state_raw)
            .upgrade(new_state)
            .as_str()
            .to_string();

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            r#"
            UPDATE messages
            SET message_state = ?1
            WHERE id = (
                SELECT id FROM messages
                WHERE storage_owner = ?2 AND external_user = ?3 AND message_time = ?4
                ORDER BY id DESC LIMIT 1
            )
            "#,
            params![upgraded, storage_owner, external_user, timestamp],
        )?;
        let msg_id: i64 = tx.query_row(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3 ORDER BY id DESC LIMIT 1",
            params![storage_owner, external_user, timestamp],
            |row| row.get(0),
        )?;
        sync::record_event(&tx, storage_owner, EntityType::Message, msg_id, Operation::Upsert)?;
        tx.commit()?;
        Ok(())
    })
    .map_err(|e: StorageError| std::io::Error::other(e.to_string()))
}

fn load_reactions(
    conn: &rusqlite::Connection,
    msg_ids: &[i64],
) -> Result<std::collections::HashMap<i64, Vec<StoredReaction>>, StorageError> {
    if msg_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let placeholders: Vec<String> = msg_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();
    let query = format!(
        "SELECT message_id, reaction, user_id, user_principal FROM reactions WHERE message_id IN ({}) ORDER BY created_at ASC, id ASC",
        placeholders.join(", ")
    );

    let mut map: std::collections::HashMap<i64, Vec<StoredReaction>> =
        std::collections::HashMap::new();
    let mut stmt = conn.prepare(&query)?;
    let params: Vec<&dyn rusqlite::types::ToSql> = msg_ids
        .iter()
        .map(|id| id as &dyn rusqlite::types::ToSql)
        .collect();
    let rows = stmt.query_map(params.as_slice(), |row| {
        Ok((
            row.get::<_, i64>(0)?,
            StoredReaction {
                reaction: row.get(1)?,
                user_id: row.get(2)?,
                principal: row
                    .get::<_, Option<i64>>(3)?
                    .map(iota_identity::PrincipalHandle),
            },
        ))
    })?;
    for row in rows {
        let row = row?;
        let reactions = map.entry(row.0).or_default();
        if reactions
            .iter()
            .any(|stored: &StoredReaction| stored.reaction == row.1.reaction)
            || reactions.len() < MAX_UNIQUE_REACTIONS_PER_MESSAGE
        {
            reactions.push(row.1);
        }
    }
    Ok(map)
}

pub fn get_messages(
    storage_owner: i64,
    external_user: i64,
    loaded_messages: i64,
    amount: i64,
) -> Result<Vec<StoredMessage>, StorageError> {
    let Some(principal) = crate::util::chats_util::get_user(storage_owner, external_user)?
        .and_then(|contact| contact.principal)
    else {
        return Ok(Vec::new());
    };
    get_messages_for_principal(storage_owner, principal, loaded_messages, amount)
}

pub fn get_messages_for_principal(
    storage_owner: i64,
    external_principal: iota_identity::PrincipalHandle,
    loaded_messages: i64,
    amount: i64,
) -> Result<Vec<StoredMessage>, StorageError> {
    if amount <= 0 || loaded_messages < 0 {
        return Ok(Vec::new());
    }

    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, relay_signer_id, relay_message_id, message_time, authored_at,
                   origin_iota_received_at, destination_iota_received_at,
                   client_received_at, client_received_recorded_at, read_at,
                   read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version,
                   reply_to, edited_count, external_user, relay_signer_principal
            FROM messages
            WHERE storage_owner = ?1 AND external_principal = ?2 AND deleted_by_external = 0 AND history_deleted = 0
            ORDER BY COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) DESC, id DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )?;

        let rows = stmt.query_map(
            params![storage_owner, external_principal.0, amount, loaded_messages],
            |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    external_user: row.get(20)?,
                    external_principal: Some(external_principal),
                    relay_signer_id: row.get(1)?,
                    relay_signer_principal: row
                        .get::<_, Option<i64>>(21)?
                        .map(iota_identity::PrincipalHandle),
                    relay_message_id: row.get(2)?,
                    message_time: row.get(3)?,
                    authored_at: row.get(4)?,
                    origin_iota_received_at: row.get(5)?,
                    destination_iota_received_at: row.get(6)?,
                    client_received_at: row.get(7)?,
                    client_received_recorded_at: row.get(8)?,
                    read_at: row.get(9)?,
                    read_recorded_at: row.get(10)?,
                    delivery_failed_at: row.get(11)?,
                    delivery_failure: row.get(12)?,
                    content: row.get(13)?,
                    sent_by_self: row.get::<_, i64>(14)? != 0,
                    message_state: row.get(15)?,
                    height: row.get(16)?,
                    key_version: row.get(17)?,
                    reply_to: row.get(18)?,
                    edited: row.get::<_, i64>(19)? > 0,
                    reactions: Vec::new(),
                })
            },
        )?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }

        let msg_ids: Vec<i64> = out.iter().map(|m| m.id).collect();
        let reaction_map = load_reactions(conn, &msg_ids)?;
        for msg in &mut out {
            msg.reactions = reaction_map.get(&msg.id).cloned().unwrap_or_default();
        }

        Ok(out)
    })
}

pub fn get_message(
    storage_owner: i64,
    message_time: i64,
    external_user: Option<i64>,
    external_principal: Option<iota_identity::PrincipalHandle>,
) -> Result<Option<StoredMessage>, StorageError> {
    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, relay_signer_id, relay_message_id, message_time, authored_at,
                   origin_iota_received_at, destination_iota_received_at,
                   client_received_at, client_received_recorded_at, read_at,
                   read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version,
                   reply_to, edited_count, external_user, external_principal,
                   relay_signer_principal
            FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?2
              AND deleted_by_external = 0
              AND history_deleted = 0
              AND (
                  ?3 IS NULL
                  OR (?4 IS NULL AND external_user = ?3)
                  OR external_principal = ?4
              )
            ORDER BY id DESC
            "#,
        )?;

        let rows = stmt.query_map(
            params![
                storage_owner,
                message_time,
                external_user,
                external_principal.map(|principal| principal.0)
            ],
            |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    relay_signer_id: row.get(1)?,
                    relay_signer_principal: row
                        .get::<_, Option<i64>>(22)?
                        .map(iota_identity::PrincipalHandle),
                    relay_message_id: row.get(2)?,
                    message_time: row.get(3)?,
                    authored_at: row.get(4)?,
                    origin_iota_received_at: row.get(5)?,
                    destination_iota_received_at: row.get(6)?,
                    client_received_at: row.get(7)?,
                    client_received_recorded_at: row.get(8)?,
                    read_at: row.get(9)?,
                    read_recorded_at: row.get(10)?,
                    delivery_failed_at: row.get(11)?,
                    delivery_failure: row.get(12)?,
                    content: row.get(13)?,
                    sent_by_self: row.get::<_, i64>(14)? != 0,
                    message_state: row.get(15)?,
                    height: row.get(16)?,
                    key_version: row.get(17)?,
                    reply_to: row.get(18)?,
                    edited: row.get::<_, i64>(19)? > 0,
                    external_user: row.get(20)?,
                    external_principal: row
                        .get::<_, Option<i64>>(21)?
                        .map(iota_identity::PrincipalHandle),
                    reactions: Vec::new(),
                })
            },
        )?;

        let messages: Vec<StoredMessage> = rows.collect::<Result<_, _>>()?;
        if messages.is_empty() {
            return Ok(None);
        }
        if external_user.is_none()
            && messages
                .iter()
                .filter_map(|message| message.external_principal)
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1
        {
            return Ok(None);
        }

        let mut message = messages.into_iter().next().expect("checked non-empty");
        let reaction_map = load_reactions(conn, &[message.id])?;
        message.reactions = reaction_map.get(&message.id).cloned().unwrap_or_default();
        Ok(Some(message))
    })
}

pub fn get_message_with_offset(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<Option<(StoredMessage, i64)>, StorageError> {
    let Some(external_principal) = crate::util::chats_util::get_user(storage_owner, external_user)?
        .and_then(|contact| contact.principal)
    else {
        return Ok(None);
    };
    let Some(message) = get_message(
        storage_owner,
        message_time,
        Some(external_user),
        Some(external_principal),
    )?
    else {
        return Ok(None);
    };
    let offset = db::with_db(|conn| {
        conn.query_row(
            r#"
            SELECT COUNT(*)
            FROM messages
            WHERE storage_owner = ?1
              AND external_principal = ?2
              AND deleted_by_external = 0
              AND history_deleted = 0
              AND (
                   COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) >
                       COALESCE(?3, ?4)
                   OR (COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) =
                       COALESCE(?3, ?4) AND id > ?4)
              )
            "#,
            params![
                storage_owner,
                external_principal.0,
                message.destination_iota_received_at.or(message.origin_iota_received_at).or(message.authored_at),
                message.id
            ],
            |row| row.get(0),
        )
        .map_err(StorageError::from)
    })?;
    Ok(Some((message, offset)))
}

pub fn get_messages_by_ids(
    storage_owner: i64,
    ids: &[i64],
) -> Result<Vec<StoredMessage>, StorageError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let wanted: std::collections::HashSet<i64> = ids.iter().copied().collect();
    // A journal id uniquely identifies a row. Load all messages for this owner and retain only
    // those ids; this keeps reaction hydration identical to normal message loading.
    db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT id, relay_signer_id, relay_message_id, message_time, authored_at, origin_iota_received_at, destination_iota_received_at, client_received_at, client_received_recorded_at, read_at, read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version, reply_to, edited_count, external_user, external_principal, relay_signer_principal FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0 AND history_deleted = 0")?;
        let rows = stmt.query_map([storage_owner], |row| {
            let external_user: i64 = row.get(20)?;
            Ok(StoredMessage {
                id: row.get(0)?,
                external_user,
                external_principal: row
                    .get::<_, Option<i64>>(21)?
                    .map(iota_identity::PrincipalHandle),
                relay_signer_id: row.get(1)?,
                relay_signer_principal: row
                    .get::<_, Option<i64>>(22)?
                    .map(iota_identity::PrincipalHandle),
                relay_message_id: row.get(2)?,
                message_time: row.get(3)?,
                authored_at: row.get(4)?,
                origin_iota_received_at: row.get(5)?,
                destination_iota_received_at: row.get(6)?,
                client_received_at: row.get(7)?,
                client_received_recorded_at: row.get(8)?,
                read_at: row.get(9)?,
                read_recorded_at: row.get(10)?,
                delivery_failed_at: row.get(11)?,
                delivery_failure: row.get(12)?,
                content: row.get(13)?,
                sent_by_self: row.get::<_, i64>(14)? != 0,
                message_state: row.get(15)?,
                height: row.get(16)?,
                key_version: row.get(17)?,
                reply_to: row.get(18)?,
                edited: row.get::<_, i64>(19)? > 0,
                reactions: Vec::new(),
            })
        })?;
        let mut messages = Vec::new();
        for row in rows {
            let message = row?;
            if wanted.contains(&message.id) {
                messages.push(message);
            }
        }
        let reaction_map =
            load_reactions(conn, &messages.iter().map(|m| m.id).collect::<Vec<_>>())?;
        for message in &mut messages {
            message.reactions = reaction_map.get(&message.id).cloned().unwrap_or_default();
        }
        Ok(messages)
    })
}

pub fn get_all_messages(storage_owner: i64) -> Result<Vec<StoredMessage>, StorageError> {
    let ids = db::with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0 AND history_deleted = 0",
        )?;
        Ok(stmt
            .query_map([storage_owner], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?)
    })?;
    get_messages_by_ids(storage_owner, &ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_identity::PrincipalHandle;
    use rusqlite::Connection;

    fn edit_fixture(conn: &Connection) -> Result<(), StorageError> {
        conn.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, storage_owner INTEGER,
                external_user INTEGER, external_principal INTEGER, message_time INTEGER,
                content TEXT, sent_by_self INTEGER, history_deleted INTEGER DEFAULT 0,
                edited_count INTEGER DEFAULT 0, key_version INTEGER);
             CREATE TABLE message_edits (message_id INTEGER, content_before TEXT,
                 content_after TEXT, edited_at INTEGER, edited_by INTEGER,
                 content_before_key_version INTEGER, content_after_key_version INTEGER);
             CREATE TABLE sync_heads (user_id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
             CREATE TABLE sync_events (user_id INTEGER, version INTEGER, entity_type TEXT,
                entity_id INTEGER, operation TEXT, created_at INTEGER);
             CREATE TABLE chat_secrets (user_id TEXT, chat_id TEXT, secret_id TEXT,
                version INTEGER, encrypted_secret BLOB, kem_ciphertext BLOB,
                wrapping_scheme TEXT, created_at INTEGER, updated_at INTEGER);
             INSERT INTO messages (id, storage_owner, external_user, external_principal,
                message_time, content, sent_by_self, key_version)
             VALUES (1, 7, 8, 71, 10, 'original', 1, 2),
                    (2, 8, 7, 70, 10, 'original', 0, 2);
             INSERT INTO chat_secrets VALUES
                ('7', 'principal:70:71', 'chat:principal:70:71:main', 1, X'01', X'02', 'test', 0, 0),
                ('7', 'principal:70:71', 'chat:principal:70:71:main', 2, X'03', X'04', 'test', 0, 0);",
        )?;
        Ok(())
    }

    fn edit_state(conn: &Connection) -> Result<(String, i64, i64, i64, i64), StorageError> {
        Ok(conn.query_row(
            "SELECT content, key_version, edited_count,
                (SELECT count(*) FROM message_edits), (SELECT count(*) FROM sync_events)
             FROM messages WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?)
    }

    #[test]
    fn edit_epochs_update_ciphertext_metadata_history_and_sync_together() -> Result<(), StorageError>
    {
        let mut conn = Connection::open_in_memory()?;
        edit_fixture(&conn)?;
        let tx = conn.transaction()?;
        // An older epoch remains usable after rotation, even when it differs
        // from the key of the original ciphertext.
        require_edit_key_in_tx(&tx, 7, "principal:70:71", 1)?;
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "old-key edit",
            1,
        )?;
        require_edit_key_in_tx(&tx, 7, "principal:70:71", 2)?;
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "new-key edit",
            2,
        )?;
        apply_remote_edit_for_principal_versioned_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            7,
            "old-key edit",
            1,
        )?;
        // Legacy callers do not declare a new epoch and preserve the current one.
        edit_message_for_principal_in_tx(&tx, 7, 8, PrincipalHandle(71), 10, 7, "compatible edit")?;
        tx.commit()?;
        assert_eq!(edit_state(&conn)?, ("compatible edit".into(), 2, 3, 4, 4));
        assert_eq!(
            conn.query_row(
                "SELECT content, key_version, edited_count FROM messages WHERE id = 2",
                [],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?
                )),
            )?,
            ("old-key edit".into(), 1, 1)
        );
        let history: Vec<(String, String, i64)> = conn.prepare(
            "SELECT content_before, content_after, edited_by FROM message_edits WHERE message_id = 1 ORDER BY rowid",
        )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;
        assert_eq!(
            history,
            vec![
                ("original".into(), "old-key edit".into(), 7),
                ("old-key edit".into(), "new-key edit".into(), 7),
                ("new-key edit".into(), "compatible edit".into(), 7),
            ]
        );
        let epochs: Vec<(i64, i64)> = conn.prepare("SELECT content_before_key_version, content_after_key_version FROM message_edits WHERE message_id = 1 ORDER BY rowid")?
            .query_map([], |row| Ok((row.get(0)?,row.get(1)?)))?.collect::<Result<_,_>>()?;
        assert_eq!(epochs, vec![(2, 1), (1, 2), (2, 2)]);
        Ok(())
    }

    #[test]
    fn edit_sync_failure_rolls_back_both_copies_and_can_retry() -> Result<(), StorageError> {
        let mut conn = Connection::open_in_memory()?;
        edit_fixture(&conn)?;
        let before = edit_state(&conn)?;
        conn.execute_batch(
            "CREATE TRIGGER fail_recipient_sync BEFORE INSERT ON sync_events
             WHEN NEW.user_id = 8
             BEGIN SELECT RAISE(ABORT, 'injected sync failure'); END;",
        )?;
        let tx = conn.transaction()?;
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "edited",
            1,
        )?;
        assert!(matches!(
            apply_remote_edit_for_principal_versioned_in_tx(
                &tx,
                8,
                7,
                PrincipalHandle(70),
                10,
                7,
                "edited",
                1,
            ),
            Err(StorageError::Db(_))
        ));
        tx.rollback()?;
        assert_eq!(edit_state(&conn)?, before);
        assert_eq!(conn.query_row(
            "SELECT count(*) FROM messages WHERE content = 'original' AND key_version = 2 AND edited_count = 0",
            [], |row| row.get::<_, i64>(0),
        )?, 2);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM sync_heads", [], |row| row
                .get::<_, i64>(0))?,
            0
        );

        conn.execute_batch("DROP TRIGGER fail_recipient_sync;")?;
        let tx = conn.transaction()?;
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "edited",
            1,
        )?;
        apply_remote_edit_for_principal_versioned_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            7,
            "edited",
            1,
        )?;
        tx.commit()?;
        assert_eq!(edit_state(&conn)?, ("edited".into(), 1, 1, 2, 2));
        assert_eq!(conn.query_row(
            "SELECT count(*) FROM messages WHERE content = 'edited' AND key_version = 1 AND edited_count = 1",
            [], |row| row.get::<_, i64>(0),
        )?, 2);
        Ok(())
    }

    #[test]
    fn invalid_or_unauthorized_edits_do_not_change_history_or_sync() -> Result<(), StorageError> {
        let mut conn = Connection::open_in_memory()?;
        edit_fixture(&conn)?;
        let before = edit_state(&conn)?;
        let tx = conn.transaction()?;
        for version in [0, -1] {
            assert!(matches!(
                require_edit_key_in_tx(&tx, 7, "principal:70:71", version),
                Err(StorageError::InvalidRelayPayload(_))
            ));
            assert!(matches!(
                edit_message_for_principal_versioned_in_tx(
                    &tx,
                    7,
                    8,
                    PrincipalHandle(71),
                    10,
                    7,
                    "invalid",
                    version,
                ),
                Err(StorageError::InvalidRelayPayload(_))
            ));
        }
        assert!(matches!(
            apply_remote_edit_for_principal_versioned_in_tx(
                &tx,
                8,
                7,
                PrincipalHandle(70),
                10,
                9,
                "forged",
                1,
            ),
            Err(StorageError::MessageUnauthorized)
        ));
        assert!(matches!(
            apply_remote_edit_for_principal_versioned_in_tx(
                &tx,
                7,
                8,
                PrincipalHandle(71),
                10,
                8,
                "wrong direction",
                1,
            ),
            Err(StorageError::MessageUnauthorized)
        ));
        assert!(matches!(
            edit_message_for_principal_versioned_in_tx(
                &tx,
                8,
                7,
                PrincipalHandle(70),
                10,
                8,
                "wrong direction",
                1,
            ),
            Err(StorageError::MessageUnauthorized)
        ));
        assert!(matches!(
            edit_message_for_principal_versioned_in_tx(
                &tx,
                7,
                8,
                PrincipalHandle(999),
                10,
                7,
                "wrong authority",
                1,
            ),
            Err(StorageError::MissingRelayDependency)
        ));
        assert!(matches!(
            edit_message_for_principal_versioned_in_tx(
                &tx,
                7,
                8,
                PrincipalHandle(71),
                11,
                7,
                "missing target",
                1,
            ),
            Err(StorageError::MissingRelayDependency)
        ));
        tx.commit()?;
        assert_eq!(edit_state(&conn)?, before);
        Ok(())
    }

    #[test]
    fn missing_edit_epoch_can_recover_after_reopen_without_partial_mutation()
    -> Result<(), StorageError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("edit.sqlite3");
        {
            let mut conn = Connection::open(&path)?;
            edit_fixture(&conn)?;
            let before = edit_state(&conn)?;
            let tx = conn.transaction()?;
            // The other owner's key and another authority's namespace do not satisfy this edit.
            for (owner, chat, version) in [
                (8, "principal:70:71", 1),
                (7, "principal:70:99", 1),
                (7, "principal:70:71", 3),
            ] {
                assert!(matches!(
                    require_edit_key_in_tx(&tx, owner, chat, version),
                    Err(StorageError::MissingRelayDependency)
                ));
            }
            edit_message_for_principal_versioned_in_tx(
                &tx,
                7,
                8,
                PrincipalHandle(71),
                10,
                7,
                "uncommitted",
                1,
            )?;
            // A failed second local effect must roll back key metadata and history too.
            assert!(matches!(
                require_edit_key_in_tx(&tx, 8, "principal:70:71", 1),
                Err(StorageError::MissingRelayDependency)
            ));
            tx.rollback()?;
            assert_eq!(edit_state(&conn)?, before);
        }
        let mut conn = Connection::open(&path)?;
        let tx = conn.transaction()?;
        tx.execute("INSERT INTO chat_secrets SELECT user_id, chat_id, secret_id, 3, encrypted_secret, kem_ciphertext, wrapping_scheme, created_at, updated_at FROM chat_secrets WHERE version = 2", [])?;
        require_edit_key_in_tx(&tx, 7, "principal:70:71", 3)?;
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "recovered",
            3,
        )?;
        tx.commit()?;
        assert_eq!(edit_state(&conn)?, ("recovered".into(), 3, 1, 1, 1));
        Ok(())
    }

    #[test]
    fn versioned_edit_does_not_restore_removed_history() -> Result<(), StorageError> {
        let mut conn = Connection::open_in_memory()?;
        edit_fixture(&conn)?;
        conn.execute("UPDATE messages SET content = '', history_deleted = 1", [])?;
        let before = edit_state(&conn)?;
        let tx = conn.transaction()?;
        edit_message_for_principal_versioned_in_tx(
            &tx,
            7,
            8,
            PrincipalHandle(71),
            10,
            7,
            "restore",
            1,
        )?;
        apply_remote_edit_for_principal_versioned_in_tx(
            &tx,
            8,
            7,
            PrincipalHandle(70),
            10,
            7,
            "restore",
            1,
        )?;
        tx.commit()?;
        assert_eq!(edit_state(&conn)?, before);
        Ok(())
    }

    #[test]
    fn upgrade_prefers_highest_state() {
        assert_eq!(
            MessageState::Sending.upgrade(MessageState::Sent),
            MessageState::Sent
        );
        assert_eq!(
            MessageState::Sent.upgrade(MessageState::Received),
            MessageState::Received
        );
        assert_eq!(
            MessageState::Received.upgrade(MessageState::Read),
            MessageState::Read
        );
        assert_eq!(
            MessageState::Read.upgrade(MessageState::Received),
            MessageState::Read
        );
    }

    #[test]
    fn from_str_is_case_insensitive() {
        assert_eq!(MessageState::from_str("READ"), MessageState::Read);
        assert_eq!(MessageState::from_str("received"), MessageState::Received);
        assert_eq!(MessageState::from_str("Sent"), MessageState::Sent);
        assert_eq!(MessageState::from_str("unknown"), MessageState::Sending);
    }
}
