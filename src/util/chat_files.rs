use crate::log;
use crate::util::db;
use json::{JsonValue, array, object};
use rusqlite::params;
use std::io;
use std::sync::{Arc, LazyLock, Mutex};

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

// Shared DB created via helper.
// The db helper constructs the messages sqlite file and ensures PRAGMAs and schema exist.
static MESSAGES_DB: LazyLock<Arc<Mutex<rusqlite::Connection>>> = LazyLock::new(|| {
    db::create_general_messages_db().expect("Failed to create or initialize general messages DB")
});

pub fn add_message(
    send_time: u128,
    storage_owner_is_sender: bool,
    storage_owner: i64,
    external_user: i64,
    message: &str,
    height: i64,
) {
    let message_time = match i64::try_from(send_time) {
        Ok(v) => v,
        Err(_) => {
            log!("Failed to store message: send_time out of range for i64 ({send_time})");
            return;
        }
    };

    // Insert the message into the DB
    let insert_result = db::with_conn(&MESSAGES_DB, |conn| {
        conn.execute(
            r#"
            INSERT INTO messages (
                storage_owner,
                external_user,
                message_time,
                content,
                sent_by_self,
                message_state,
                height
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
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
            ],
        )?;
        Ok(())
    });

    if let Err(e) = insert_result {
        log!("Failed to insert message into sqlite: {}", e);
        return;
    }

    // Update contacts table to reflect that this conversation exists and has a recent message.
    // Use the Contact helper to set last_message_at to the message timestamp.
    let mut contact = crate::users::contact::Contact::new(external_user);
    contact.set_last_message_at(message_time);
    // This will insert or update the contact for the storage owner.
    crate::util::chats_util::mod_user(storage_owner, &contact);
}

pub fn change_message_state(
    timestamp: i64,
    storage_owner: i64,
    external_user: i64,
    new_state: MessageState,
) -> io::Result<()> {
    // Run the SELECT and UPDATE inside with_conn to centralize connection access.
    let res: Result<(), String> = db::with_conn(&MESSAGES_DB, |conn| {
        let current: Option<String> = match conn.query_row(
            r#"
            SELECT message_state
            FROM messages
            WHERE storage_owner = ?1
              AND external_user = ?2
              AND message_time = ?3
            ORDER BY id DESC
            LIMIT 1
            "#,
            params![storage_owner, external_user, timestamp],
            |row| row.get(0),
        ) {
            Ok(state) => Some(state),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e),
        };

        let Some(current_state_raw) = current else {
            return Ok(());
        };

        let upgraded = MessageState::from_str(&current_state_raw)
            .upgrade(new_state)
            .as_str()
            .to_string();

        conn.execute(
            r#"
            UPDATE messages
            SET message_state = ?1
            WHERE id = (
                SELECT id
                FROM messages
                WHERE storage_owner = ?2
                  AND external_user = ?3
                  AND message_time = ?4
                ORDER BY id DESC
                LIMIT 1
            )
            "#,
            params![upgraded, storage_owner, external_user, timestamp],
        )?;
        Ok(())
    });

    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

pub fn get_messages(
    storage_owner: i64,
    external_user: i64,
    loaded_messages: i64,
    amount: i64,
) -> JsonValue {
    let messages = array![];

    if amount <= 0 || loaded_messages < 0 {
        return messages;
    }

    let res: Result<JsonValue, String> = db::with_conn(&MESSAGES_DB, |conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT
                message_time,
                content,
                sent_by_self,
                message_state,
                height
            FROM messages
            WHERE storage_owner = ?1
              AND external_user = ?2
            ORDER BY message_time DESC, id DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )?;

        let rows = stmt.query_map(
            params![storage_owner, external_user, amount, loaded_messages],
            |row| {
                let message_time: i64 = row.get(0)?;
                let content: String = row.get(1)?;
                let sent_by_self: i64 = row.get(2)?;
                let message_state: String = row.get(3)?;
                let height: i64 = row.get(4).unwrap_or(0);
                Ok((message_time, content, sent_by_self, message_state, height))
            },
        )?;

        let mut out = array![];
        for row in rows {
            match row {
                Ok((message_time, content, sent_by_self, message_state, height)) => {
                    let msg = object! {
                        "message_time" => message_time,
                        "content" => content,
                        "sent_by_self" => (sent_by_self != 0),
                        "message_state" => message_state,
                        "height" => height
                    };
                    if let Err(e) = out.push(msg) {
                        // out.push returns a JsonError; log it instead of using `?` to avoid
                        // incompatible error conversions inside the DB closure.
                        log!("Failed to append message to output array: {:?}", e);
                    }
                }
                Err(e) => {
                    log!("Failed to read row from sqlite: {}", e);
                }
            }
        }
        Ok(out)
    });

    match res {
        Ok(v) => v,
        Err(e) => {
            log!("Failed to query messages: {}", e);
            messages
        }
    }
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
