use crate::storage_error::StorageError;
use crate::util::db;
use crate::util::sync::{self, EntityType, Operation};
use iota_logger::log;
use rusqlite::params;

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
    pub message_time: i64,
    pub content: String,
    pub edited: bool,
    pub sent_by_self: bool,
    pub message_state: String,
    pub height: i64,
    pub reply_to: Option<i64>,
    pub reactions: Vec<StoredReaction>,
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
            SELECT id, content, sent_by_self
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
                ))
            },
        )?;

        let (msg_id, old_content, sent_by_self) = msg;
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

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
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
        let msg_id: i64 = conn.query_row(
            r#"
            SELECT id FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, message_time],
            |row| row.get(0),
        )?;

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM message_edits WHERE message_id = ?1",
            params![msg_id],
        )?;
        tx.execute(
            "DELETE FROM reactions WHERE message_id = ?1",
            params![msg_id],
        )?;
        tx.execute("DELETE FROM messages WHERE id = ?1", params![msg_id])?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Delete,
        )?;
        tx.commit()?;
        Ok(())
    })
}

/* Deletes a message from the sender's local copy after checking ownership. */
pub fn delete_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    ensure_message_direction(storage_owner, external_user, message_time, true)?;
    hard_delete_message(storage_owner, external_user, message_time)
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
    ensure_message_direction(storage_owner, external_user, message_time, false)?;
    flag_deleted_by_external(storage_owner, external_user, message_time)
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
        let msg_id: i64 = conn.query_row(
            r#"
            SELECT id FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, message_time],
            |row| row.get(0),
        )?;

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
    db::with_db(|conn| {
        let msg_id: i64 = conn.query_row(
            r#"
            SELECT id FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, message_time],
            |row| row.get(0),
        )?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            r#"
            INSERT OR IGNORE INTO reactions (message_id, user_id, reaction, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![msg_id, user_id, reaction, now],
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

pub fn remove_reaction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    user_id: i64,
    reaction: &str,
) -> Result<(), StorageError> {
    db::with_db(|conn| {
        let msg_id: i64 = conn.query_row(
            r#"
            SELECT id FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, message_time],
            |row| row.get(0),
        )?;

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

pub fn add_message(
    send_time: u128,
    storage_owner_is_sender: bool,
    storage_owner: i64,
    external_user: i64,
    message: &str,
    height: i64,
    reply_to: Option<i64>,
) {
    let message_time = match i64::try_from(send_time) {
        Ok(v) => v,
        Err(_) => {
            log!("Failed to store message: send_time out of range for i64 ({send_time})");
            return;
        }
    };

    if let Err(e) = db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            r#"
            INSERT INTO messages (
                storage_owner, external_user, message_time, content,
                sent_by_self, message_state, height, reply_to
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                storage_owner,
                external_user,
                message_time,
                message,
                if storage_owner_is_sender {
                    1_i64
                } else {
                    0_i64
                },
                MessageState::Sending.as_str(),
                height,
                reply_to,
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
        tx.commit()?;
        Ok(())
    }) {
        log!("Failed to insert message into sqlite: {}", e);
        return;
    }

    let mut contact = crate::users::contact::Contact::new(external_user);
    contact.set_last_message_at(message_time);
    crate::util::chats_util::mod_user(storage_owner, &contact);
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
                map.entry(row.0).or_default().push(row.1);
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
            SELECT id, message_time, content, sent_by_self, message_state, height, reply_to, edited_count
            FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND deleted_by_external = 0
            ORDER BY message_time DESC, id DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )?;

        let rows = stmt.query_map(
            params![storage_owner, external_user, amount, loaded_messages],
            |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    external_user,
                    message_time: row.get(1)?,
                    content: row.get(2)?,
                    sent_by_self: row.get::<_, i64>(3)? != 0,
                    message_state: row.get(4)?,
                    height: row.get(5).unwrap_or(0),
                    reply_to: row.get(6).ok().flatten(),
                    edited: row.get::<_, i64>(7).unwrap_or(0) > 0,
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
            SELECT id, message_time, content, sent_by_self, message_state, height,
                   reply_to, edited_count, external_user
            FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?2
              AND deleted_by_external = 0
              AND (?3 IS NULL OR external_user = ?3)
            ORDER BY id DESC
            "#,
        )?;

        let rows = stmt.query_map(params![storage_owner, message_time, external_user], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                message_time: row.get(1)?,
                content: row.get(2)?,
                sent_by_self: row.get::<_, i64>(3)? != 0,
                message_state: row.get(4)?,
                height: row.get(5).unwrap_or(0),
                reply_to: row.get(6).ok().flatten(),
                edited: row.get::<_, i64>(7).unwrap_or(0) > 0,
                external_user: row.get(8)?,
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

pub fn get_messages_by_ids(storage_owner: i64, ids: &[i64]) -> Vec<StoredMessage> {
    if ids.is_empty() {
        return Vec::new();
    }
    let wanted: std::collections::HashSet<i64> = ids.iter().copied().collect();
    // A journal id uniquely identifies a row. Load all messages for this owner and retain only
    // those ids; this keeps reaction hydration identical to normal message loading.
    match db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT id, message_time, content, sent_by_self, message_state, height, reply_to, edited_count, external_user FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0")?;
        let rows = stmt.query_map([storage_owner], |row| {
            let external_user: i64 = row.get(8)?;
            Ok(StoredMessage {
                id: row.get(0)?,
                external_user,
                message_time: row.get(1)?,
                content: row.get(2)?,
                sent_by_self: row.get::<_, i64>(3)? != 0,
                message_state: row.get(4)?,
                height: row.get(5).unwrap_or(0),
                reply_to: row.get(6).ok().flatten(),
                edited: row.get::<_, i64>(7).unwrap_or(0) > 0,
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
            "SELECT id FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0",
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
