use crate::storage_error::StorageError;
use crate::util::db;
use crate::util::message_storage_policy::{self, MessageRetention};
use crate::util::sync::{self, EntityType, Operation};
use iota_logger::log;
use rusqlite::{OptionalExtension, Transaction, params};

pub const MAX_UNIQUE_REACTIONS_PER_MESSAGE: usize = 10;

#[derive(PartialEq, Debug, Clone)]
pub enum MessageState {
    Read,
    Received,
    Sent,
    Sending,
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
    pub relay_signer_id: Option<i64>,
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
    pub relay_message_id: &'a str,
    pub authored_at: i64,
    pub send_time: i64,
    pub storage_owner: i64,
    pub external_user: i64,
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
        message_time,
        editor_id,
        new_content,
        true,
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
        return Err(StorageError::Other(
            "Remote editor does not match chat partner".into(),
        ));
    }

    update_message_content(
        storage_owner,
        external_user,
        message_time,
        editor_id,
        new_content,
        false,
    )
}

fn update_message_content(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    require_sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let msg = conn.query_row(
            r#"
            SELECT id, content, sent_by_self, history_deleted
            FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, message_time],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;

        let (msg_id, old_content, sent_by_self, history_deleted) = msg;
        if require_sent_by_self && sent_by_self != 1 {
            return Err(StorageError::Other(
                "Only the original sender can edit this message".into(),
            ));
        }
        if !require_sent_by_self && sent_by_self != 0 {
            return Err(StorageError::Other(
                "Remote edits may only update received messages".into(),
            ));
        }

        if history_deleted != 0 {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            r#"
            INSERT INTO message_edits (message_id, content_before, content_after, edited_at, edited_by)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![msg_id, old_content, new_content, now, editor_id],
        )?;

        tx.execute(
            r#"
            UPDATE messages
            SET content = ?1, edited_count = edited_count + 1
            WHERE id = ?2
            "#,
            params![new_content, msg_id],
        )?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Upsert,
        )?;
        tx.commit()?;

        Ok(())
    })
}

pub fn hard_delete_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let msg_id = conn
            .query_row(
                r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
                params![storage_owner, external_user, message_time],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(msg_id) = msg_id else {
            return Ok(());
        };

        let tx = conn.unchecked_transaction()?;
        purge_message_in_tx(&tx, storage_owner, msg_id)?;
        tx.commit()?;
        Ok(())
    })
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
    let message: Option<(i64, i64)> = tx
        .query_row(
            "SELECT external_user, history_deleted FROM messages WHERE id = ?1 AND storage_owner = ?2",
            params![message_id, storage_owner],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((external_user, history_deleted)) = message else {
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
    tx.execute("DELETE FROM message_receipts WHERE storage_owner = ?1 AND EXISTS (SELECT 1 FROM messages WHERE id = ?2 AND relay_signer_id = message_receipts.target_signer_id AND relay_message_id = message_receipts.target_message_id)", params![storage_owner, message_id])?;
    tx.execute("UPDATE messages SET content = '', history_deleted = 1, history_deleted_at = ?2, expires_at = NULL, client_received_at = NULL, client_received_recorded_at = NULL, read_at = NULL, read_recorded_at = NULL WHERE id = ?1", params![message_id, sync::now_millis()])?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Delete,
    )?;
    update_contact_last_message_in_tx(tx, storage_owner, external_user)?;
    Ok(())
}

fn update_contact_last_message_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
) -> Result<(), StorageError> {
    tx.execute("UPDATE contacts SET last_message_at = (SELECT MAX(COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, message_time)) FROM messages WHERE storage_owner = ?1 AND external_user = ?2 AND deleted_by_external = 0 AND history_deleted = 0) WHERE storage_owner = ?1 AND user_id = ?2", params![storage_owner, external_user])?;
    Ok(())
}

pub fn purge_message_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    message_id: i64,
) -> Result<(), StorageError> {
    let (external_user, relay_signer_id, relay_message_id) = tx.query_row(
        "SELECT external_user, relay_signer_id, relay_message_id FROM messages WHERE id = ?1 AND storage_owner = ?2",
        params![message_id, storage_owner],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<String>>(2)?)),
    )?;
    if let (Some(relay_signer_id), Some(relay_message_id)) = (relay_signer_id, relay_message_id) {
        tx.execute(
            "DELETE FROM message_receipts WHERE storage_owner = ?1 AND target_signer_id = ?2 AND target_message_id = ?3",
            params![storage_owner, relay_signer_id, relay_message_id],
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
    update_contact_last_message_in_tx(tx, storage_owner, external_user)?;
    Ok(())
}

/* Deletes a message from the sender's local copy after checking ownership. */
pub fn delete_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    match ensure_message_direction(storage_owner, external_user, message_time, true) {
        Ok(()) => hard_delete_message(storage_owner, external_user, message_time),
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
        return Err(StorageError::Other(
            "Remote sender does not match chat partner".into(),
        ));
    }
    match ensure_message_direction(storage_owner, external_user, message_time, false) {
        Ok(()) => flag_deleted_by_external(storage_owner, external_user, message_time),
        Err(StorageError::Db(rusqlite::Error::QueryReturnedNoRows)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn ensure_message_direction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    expected_sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let sent_by_self: i64 = conn.query_row(
            r#"
            SELECT sent_by_self FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, message_time],
            |row| row.get(0),
        )?;
        if (sent_by_self != 0) != expected_sent_by_self {
            return Err(StorageError::Other(
                "Message sender is not authorized".into(),
            ));
        }
        Ok(())
    })
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
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        let affected = tx.execute(
            r#"
            UPDATE messages
            SET deleted_by_external = 1
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            "#,
            params![storage_owner, external_user, message_time],
        )?;
        if affected == 0 {
            return Err(StorageError::Other("Message not found".into()));
        }
        let msg_id: i64 = tx.query_row("SELECT id FROM messages WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3 ORDER BY id DESC LIMIT 1", params![storage_owner, external_user, message_time], |r| r.get(0))?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Delete,
        )?;
        update_contact_last_message_in_tx(&tx, storage_owner, external_user)?;
        tx.commit()?;
        Ok(())
    })
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
    db::with_db(|conn| {
        let (msg_id, history_deleted): (i64, i64) = conn.query_row(
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

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM message_edits WHERE message_id = ?1",
            params![msg_id],
        )?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Upsert,
        )?;
        tx.commit()?;
        Ok(())
    })
}

pub fn add_reaction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    user_id: i64,
    reaction: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
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
            INSERT OR IGNORE INTO reactions (message_id, user_id, reaction, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![msg_id, user_id, reaction, now],
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
    })
}

pub fn remove_reaction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    user_id: i64,
    reaction: &str,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let (msg_id, history_deleted): (i64, i64) = conn.query_row(
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

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM reactions WHERE message_id = ?1 AND user_id = ?2 AND reaction = ?3",
            params![msg_id, user_id, reaction],
        )?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Upsert,
        )?;
        tx.commit()?;
        Ok(())
    })
}

pub fn add_message(message: NewMessage<'_>) -> Result<i64, StorageError> {
    let NewMessage {
        relay_signer_id,
        relay_message_id,
        authored_at,
        send_time,
        storage_owner,
        external_user,
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
    let policy = message_storage_policy::get(storage_owner)?;
    let expires_at = match policy.retention {
        MessageRetention::Forever => None,
        MessageRetention::Duration { duration_ms } => Some(
            stored_at
                .checked_add(duration_ms)
                .ok_or_else(|| StorageError::Other("message expiry overflow".into()))?,
        ),
    };
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            r#"
            INSERT INTO messages (
                storage_owner, external_user, message_time, content, sent_by_self,
                message_state, height, key_version, reply_to, relay_signer_id, relay_message_id,
                authored_at, origin_iota_received_at, destination_iota_received_at, stored_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
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
            ],
        )?;
        let msg_id = tx.last_insert_rowid();
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Upsert,
        )?;
        let mut contact = crate::users::contact::Contact::new(external_user);
        contact.set_last_message_at(
            destination_iota_received_at
                .or(origin_iota_received_at)
                .unwrap_or(authored_at),
        );
        crate::util::chats_util::upsert_contact(&tx, storage_owner, &contact)?;
        if !sent_by_self {
            tx.execute(
                "UPDATE contacts SET notifications = CASE WHEN notifications < 9223372036854775807 THEN notifications + 1 ELSE notifications END WHERE storage_owner = ?1 AND user_id = ?2",
                params![storage_owner, external_user],
            )?;
        }
        tx.commit()?;
        Ok(msg_id)
    })
}

pub fn change_message_state_by_relay_id(
    storage_owner: i64,
    relay_signer_id: i64,
    relay_message_id: &str,
    new_state: MessageState,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        let Some((msg_id, current)) = tx
            .query_row(
                "SELECT id, message_state FROM messages WHERE storage_owner = ?1 AND relay_signer_id = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_id, relay_message_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        else {
            return Ok(());
        };
        let state = MessageState::from_str(&current).upgrade(new_state).as_str();
        tx.execute(
            "UPDATE messages SET message_state = ?1 WHERE id = ?2",
            params![state, msg_id],
        )?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Upsert,
        )?;
        tx.commit()?;
        Ok(())
    })
}

pub fn record_message_receipt(
    storage_owner: i64,
    target_signer_id: i64,
    target_message_id: &str,
    receipt_signer_id: i64,
    receipt_message_id: &str,
    receipt_type: MessageState,
    event_at: i64,
    recorded_at: i64,
) -> Result<(), StorageError> {
    let receipt_type = match receipt_type {
        MessageState::Received => "received",
        MessageState::Read => "read",
        _ => return Err(StorageError::Other("invalid message receipt state".into())),
    };
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        let Some((message_id, external_user, authored_at, history_deleted)) = tx
            .query_row(
                "SELECT id, external_user, authored_at, history_deleted FROM messages WHERE storage_owner = ?1 AND relay_signer_id = ?2 AND relay_message_id = ?3",
                params![storage_owner, target_signer_id, target_message_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, i64>(3)?)),
            )
            .optional()?
        else {
            return Err(StorageError::Other("message receipt target was not found".into()));
        };
        if external_user != receipt_signer_id {
            return Err(StorageError::Other(
                "message receipt signer is not the chat partner".into(),
            ));
        }
        if event_at > recorded_at.saturating_add(5 * 60 * 1000)
            || authored_at.is_some_and(|authored_at| event_at < authored_at)
        {
            return Err(StorageError::Other(
                "message receipt event time is outside the accepted clock range".into(),
            ));
        }
        if history_deleted != 0 {
            return Ok(());
        }
        tx.execute(
            "INSERT OR IGNORE INTO message_receipts (storage_owner, target_signer_id, target_message_id, receipt_signer_id, receipt_message_id, receipt_type, event_at, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![storage_owner, target_signer_id, target_message_id, receipt_signer_id, receipt_message_id, receipt_type, event_at, recorded_at],
        )?;
        let (state_column, recorded_column) = if receipt_type == "read" {
            ("read_at", "read_recorded_at")
        } else {
            ("client_received_at", "client_received_recorded_at")
        };
        let state = MessageState::from_str(&tx.query_row(
            "SELECT message_state FROM messages WHERE id = ?1",
            [message_id],
            |row| row.get::<_, String>(0),
        )?)
        .upgrade(MessageState::from_str(receipt_type))
        .as_str()
        .to_string();
        tx.execute(
            &format!("UPDATE messages SET {state_column} = COALESCE({state_column}, ?1), {recorded_column} = COALESCE({recorded_column}, ?2), message_state = ?3 WHERE id = ?4"),
            params![event_at, recorded_at, state, message_id],
        )?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            message_id,
            Operation::Upsert,
        )?;
        tx.commit()?;
        Ok(())
    })
}

pub fn record_destination_iota_received(
    storage_owner: i64,
    relay_signer_id: i64,
    relay_message_id: &str,
    accepted_at: i64,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        let Some(message_id) = tx
            .query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_id = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_id, relay_message_id],
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
            &tx,
            storage_owner,
            EntityType::Message,
            message_id,
            Operation::Upsert,
        )?;
        tx.commit()?;
        Ok(())
    })
}

pub fn record_delivery_failure(
    storage_owner: i64,
    relay_signer_id: i64,
    relay_message_id: &str,
    failure: &str,
    failed_at: i64,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        let Some(message_id) = tx
            .query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_id = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_id, relay_message_id],
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
            &tx,
            storage_owner,
            EntityType::Message,
            message_id,
            Operation::Upsert,
        )?;
        tx.commit()?;
        Ok(())
    })
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
    .map_err(|e: StorageError| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

fn load_reactions(
    conn: &rusqlite::Connection,
    msg_ids: &[i64],
) -> std::collections::HashMap<i64, Vec<StoredReaction>> {
    if msg_ids.is_empty() {
        return std::collections::HashMap::new();
    }

    let placeholders: Vec<String> = msg_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();
    let query = format!(
        "SELECT message_id, reaction, user_id FROM reactions WHERE message_id IN ({}) ORDER BY created_at ASC, id ASC",
        placeholders.join(", ")
    );

    let mut map: std::collections::HashMap<i64, Vec<StoredReaction>> =
        std::collections::HashMap::new();
    if let Ok(mut stmt) = conn.prepare(&query) {
        let params: Vec<&dyn rusqlite::types::ToSql> = msg_ids
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        if let Ok(rows) = stmt.query_map(params.as_slice(), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                StoredReaction {
                    reaction: row.get(1)?,
                    user_id: row.get(2)?,
                },
            ))
        }) {
            for row in rows.flatten() {
                let reactions = map.entry(row.0).or_default();
                if reactions
                    .iter()
                    .any(|stored: &StoredReaction| stored.reaction == row.1.reaction)
                {
                    reactions.push(row.1);
                } else if reactions.len() < MAX_UNIQUE_REACTIONS_PER_MESSAGE {
                    reactions.push(row.1);
                }
            }
        }
    }
    map
}

pub fn get_messages(
    storage_owner: i64,
    external_user: i64,
    loaded_messages: i64,
    amount: i64,
) -> Vec<StoredMessage> {
    if amount <= 0 || loaded_messages < 0 {
        return Vec::new();
    }

    match db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, relay_signer_id, relay_message_id, message_time, authored_at,
                   origin_iota_received_at, destination_iota_received_at,
                   client_received_at, client_received_recorded_at, read_at,
                   read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version,
                   reply_to, edited_count
            FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND deleted_by_external = 0 AND history_deleted = 0
            ORDER BY COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) DESC, id DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )?;

        let rows = stmt.query_map(
            params![storage_owner, external_user, amount, loaded_messages],
            |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    external_user,
                    relay_signer_id: row.get(1)?,
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
                    height: row.get(16).unwrap_or(0),
                    key_version: row.get(17).unwrap_or(1),
                    reply_to: row.get(18).ok().flatten(),
                    edited: row.get::<_, i64>(19).unwrap_or(0) > 0,
                    reactions: Vec::new(),
                })
            },
        )?;

        let mut out = Vec::new();
        for row in rows {
            match row {
                Ok(msg) => out.push(msg),
                Err(e) => log!("Failed to read row from sqlite: {}", e),
            }
        }

        let msg_ids: Vec<i64> = out.iter().map(|m| m.id).collect();
        let reaction_map = load_reactions(conn, &msg_ids);
        for msg in &mut out {
            msg.reactions = reaction_map.get(&msg.id).cloned().unwrap_or_default();
        }

        Ok(out)
    }) {
        Ok(v) => v,
        Err(e) => {
            log!("Failed to query messages: {}", e);
            Vec::new()
        }
    }
}

pub fn get_message(
    storage_owner: i64,
    message_time: i64,
    external_user: Option<i64>,
) -> Result<Option<StoredMessage>, StorageError> {
    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, relay_signer_id, relay_message_id, message_time, authored_at,
                   origin_iota_received_at, destination_iota_received_at,
                   client_received_at, client_received_recorded_at, read_at,
                   read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version,
                   reply_to, edited_count, external_user
            FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?2
              AND deleted_by_external = 0
              AND history_deleted = 0
              AND (?3 IS NULL OR external_user = ?3)
            ORDER BY id DESC
            "#,
        )?;

        let rows = stmt.query_map(params![storage_owner, message_time, external_user], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                relay_signer_id: row.get(1)?,
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
                height: row.get(16).unwrap_or(0),
                key_version: row.get(17).unwrap_or(1),
                reply_to: row.get(18).ok().flatten(),
                edited: row.get::<_, i64>(19).unwrap_or(0) > 0,
                external_user: row.get(20)?,
                reactions: Vec::new(),
            })
        })?;

        let messages: Vec<StoredMessage> = rows.collect::<Result<_, _>>()?;
        if messages.is_empty() {
            return Ok(None);
        }
        if external_user.is_none()
            && messages
                .iter()
                .map(|message| message.external_user)
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1
        {
            return Ok(None);
        }

        let mut message = messages.into_iter().next().expect("checked non-empty");
        let reaction_map = load_reactions(conn, &[message.id]);
        message.reactions = reaction_map.get(&message.id).cloned().unwrap_or_default();
        Ok(Some(message))
    })
}

pub fn get_message_with_offset(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<Option<(StoredMessage, i64)>, StorageError> {
    let Some(message) = get_message(storage_owner, message_time, Some(external_user))? else {
        return Ok(None);
    };
    let offset = db::with_db(|conn| {
        conn.query_row(
            r#"
            SELECT COUNT(*)
            FROM messages
            WHERE storage_owner = ?1
              AND external_user = ?2
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
                external_user,
                message.destination_iota_received_at.or(message.origin_iota_received_at).or(message.authored_at),
                message.id
            ],
            |row| row.get(0),
        )
        .map_err(StorageError::from)
    })?;
    Ok(Some((message, offset)))
}

pub fn get_messages_by_ids(storage_owner: i64, ids: &[i64]) -> Vec<StoredMessage> {
    if ids.is_empty() {
        return Vec::new();
    }
    let wanted: std::collections::HashSet<i64> = ids.iter().copied().collect();
    // A journal id uniquely identifies a row. Load all messages for this owner and retain only
    // those ids; this keeps reaction hydration identical to normal message loading.
    match db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT id, relay_signer_id, relay_message_id, message_time, authored_at, origin_iota_received_at, destination_iota_received_at, client_received_at, client_received_recorded_at, read_at, read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version, reply_to, edited_count, external_user FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0 AND history_deleted = 0")?;
        let rows = stmt.query_map([storage_owner], |row| {
            let external_user: i64 = row.get(20)?;
            Ok(StoredMessage {
                id: row.get(0)?,
                external_user,
                relay_signer_id: row.get(1)?,
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
                height: row.get(16).unwrap_or(0),
                key_version: row.get(17).unwrap_or(1),
                reply_to: row.get(18).ok().flatten(),
                edited: row.get::<_, i64>(19).unwrap_or(0) > 0,
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
        let reaction_map = load_reactions(conn, &messages.iter().map(|m| m.id).collect::<Vec<_>>());
        for message in &mut messages {
            message.reactions = reaction_map.get(&message.id).cloned().unwrap_or_default();
        }
        Ok(messages)
    }) {
        Ok(messages) => messages,
        Err(e) => {
            log!("Failed to query messages by id: {}", e);
            Vec::new()
        }
    }
}

pub fn get_all_messages(storage_owner: i64) -> Vec<StoredMessage> {
    let ids = match db::with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0 AND history_deleted = 0",
        )?;
        Ok(stmt
            .query_map([storage_owner], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?)
    }) {
        Ok(ids) => ids,
        Err(e) => {
            log!("Failed to query all messages: {}", e);
            return Vec::new();
        }
    };
    get_messages_by_ids(storage_owner, &ids)
}

#[cfg(test)]
mod tests {
    use super::MessageState;

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
    }

    #[test]
    fn from_str_is_case_insensitive() {
        assert_eq!(MessageState::from_str("READ"), MessageState::Read);
        assert_eq!(MessageState::from_str("received"), MessageState::Received);
        assert_eq!(MessageState::from_str("Sent"), MessageState::Sent);
        assert_eq!(MessageState::from_str("unknown"), MessageState::Sending);
    }
}
