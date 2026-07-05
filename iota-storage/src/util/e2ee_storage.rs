use crate::util::db;
use rusqlite::{params, OptionalExtension};
use std::sync::{Arc, LazyLock, Mutex};

pub type StorageError = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEncryptedMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_client_id: String,
    pub recipient_client_id: String,
    pub sender_user_id: Option<String>,
    pub recipient_user_id: Option<String>,
    pub created_at: i64,
    pub encryption_version: i64,
    pub encrypted_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEncryptedDeviceSecret {
    pub user_id: String,
    pub device_id: String,
    pub secret_id: String,
    pub version: i64,
    pub encrypted_secret: Vec<u8>,
    pub wrapping_public_key_id: Option<String>,
    pub wrapping_scheme: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct EncryptedMessageQuery {
    pub sender_user_id: Option<String>,
    pub recipient_client_id: Option<String>,
    pub recipient_user_id: Option<String>,
    pub conversation_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct EncryptedDeviceSecretQuery {
    pub user_id: String,
    pub device_id: Option<String>,
    pub secret_id: Option<String>,
}

static E2EE_DB: LazyLock<Arc<Mutex<rusqlite::Connection>>> = LazyLock::new(|| {
    db::create_shared_connection(
        "e2ee",
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        CREATE TABLE IF NOT EXISTS encrypted_messages (
            message_id TEXT NOT NULL PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_client_id TEXT NOT NULL,
            recipient_client_id TEXT NOT NULL,
            sender_user_id TEXT,
            recipient_user_id TEXT,
            created_at INTEGER NOT NULL,
            encryption_version INTEGER NOT NULL,
            encrypted_payload BLOB NOT NULL,
            acked_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_encrypted_messages_recipient
            ON encrypted_messages (recipient_client_id, created_at ASC);
        CREATE INDEX IF NOT EXISTS idx_encrypted_messages_recipient_user
            ON encrypted_messages (recipient_user_id, created_at ASC);
        CREATE INDEX IF NOT EXISTS idx_encrypted_messages_conversation
            ON encrypted_messages (conversation_id, created_at ASC);

        CREATE TABLE IF NOT EXISTS encrypted_device_secrets (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            secret_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            encrypted_secret BLOB NOT NULL,
            wrapping_public_key_id TEXT,
            wrapping_scheme TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, device_id, secret_id)
        );

        CREATE INDEX IF NOT EXISTS idx_encrypted_device_secrets_owner
            ON encrypted_device_secrets (user_id, device_id, secret_id);
    "#,
    )
    .expect("Failed to create or initialize E2EE DB")
});

pub fn put_encrypted_message(record: StoredEncryptedMessage) -> Result<(), StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        conn.execute(
            r#"
            INSERT OR REPLACE INTO encrypted_messages (
                message_id, conversation_id, sender_client_id, recipient_client_id,
                sender_user_id, recipient_user_id, created_at, encryption_version,
                encrypted_payload
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                record.message_id,
                record.conversation_id,
                record.sender_client_id,
                record.recipient_client_id,
                record.sender_user_id,
                record.recipient_user_id,
                record.created_at,
                record.encryption_version,
                record.encrypted_payload,
            ],
        )?;
        Ok(())
    })
}

pub fn get_encrypted_messages(
    query: EncryptedMessageQuery,
) -> Result<Vec<StoredEncryptedMessage>, StorageError> {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);

    db::with_conn(&E2EE_DB, |conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT message_id, conversation_id, sender_client_id, recipient_client_id,
                   sender_user_id, recipient_user_id, created_at, encryption_version,
                   encrypted_payload
            FROM encrypted_messages
            WHERE (?2 IS NULL OR recipient_client_id = ?2)
              AND (
                  (?1 IS NULL AND (?3 IS NULL OR sender_user_id = ?3 OR recipient_user_id = ?3))
                  OR (?1 IS NOT NULL AND ?3 IS NOT NULL AND (
                      (sender_user_id = ?1 AND recipient_user_id = ?3)
                      OR (sender_user_id = ?3 AND recipient_user_id = ?1)
                  ))
                  OR (?1 IS NOT NULL AND ?3 IS NULL AND (sender_user_id = ?1 OR recipient_user_id = ?1))
              )
              AND (?4 IS NULL OR conversation_id = ?4)
            ORDER BY created_at ASC
            LIMIT ?5 OFFSET ?6
            "#,
        )?;

        let rows = stmt.query_map(
            params![
                query.sender_user_id,
                query.recipient_client_id,
                query.recipient_user_id,
                query.conversation_id,
                limit,
                offset,
            ],
            encrypted_message_from_row,
        )?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
}

pub fn ack_encrypted_message(
    message_id: &str,
    recipient_client_id: &str,
) -> Result<(), StorageError> {
    let now = now_millis();
    db::with_conn(&E2EE_DB, |conn| {
        conn.execute(
            r#"
            UPDATE encrypted_messages
            SET acked_at = ?1
            WHERE message_id = ?2 AND recipient_client_id = ?3
            "#,
            params![now, message_id, recipient_client_id],
        )?;
        Ok(())
    })
}

pub fn put_encrypted_device_secret(
    record: StoredEncryptedDeviceSecret,
) -> Result<(), StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        conn.execute(
            r#"
            INSERT INTO encrypted_device_secrets (
                user_id, device_id, secret_id, version, encrypted_secret,
                wrapping_public_key_id, wrapping_scheme, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(user_id, device_id, secret_id) DO UPDATE SET
                version = excluded.version,
                encrypted_secret = excluded.encrypted_secret,
                wrapping_public_key_id = excluded.wrapping_public_key_id,
                wrapping_scheme = excluded.wrapping_scheme,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#,
            params![
                record.user_id,
                record.device_id,
                record.secret_id,
                record.version,
                record.encrypted_secret,
                record.wrapping_public_key_id,
                record.wrapping_scheme,
                record.created_at,
                record.updated_at,
            ],
        )?;
        Ok(())
    })
}

pub fn get_encrypted_device_secret(
    query: EncryptedDeviceSecretQuery,
) -> Result<Option<StoredEncryptedDeviceSecret>, StorageError> {
    if query.user_id.is_empty() {
        return Ok(None);
    }

    db::with_conn(&E2EE_DB, |conn| {
        conn.query_row(
            r#"
            SELECT user_id, device_id, secret_id, version, encrypted_secret,
                   wrapping_public_key_id, wrapping_scheme, created_at, updated_at
            FROM encrypted_device_secrets
            WHERE user_id = ?1
              AND (?2 IS NULL OR device_id = ?2)
              AND (?3 IS NULL OR secret_id = ?3)
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
            params![query.user_id, query.device_id, query.secret_id],
            encrypted_device_secret_from_row,
        )
        .optional()
    })
}

fn encrypted_message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEncryptedMessage> {
    Ok(StoredEncryptedMessage {
        message_id: row.get(0)?,
        conversation_id: row.get(1)?,
        sender_client_id: row.get(2)?,
        recipient_client_id: row.get(3)?,
        sender_user_id: row.get(4)?,
        recipient_user_id: row.get(5)?,
        created_at: row.get(6)?,
        encryption_version: row.get(7)?,
        encrypted_payload: row.get(8)?,
    })
}

fn encrypted_device_secret_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredEncryptedDeviceSecret> {
    Ok(StoredEncryptedDeviceSecret {
        user_id: row.get(0)?,
        device_id: row.get(1)?,
        secret_id: row.get(2)?,
        version: row.get(3)?,
        encrypted_secret: row.get(4)?,
        wrapping_public_key_id: row.get(5)?,
        wrapping_scheme: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffix(name: &str) -> String {
        format!("{name}-{}", now_millis())
    }

    #[test]
    fn stores_encrypted_message_as_opaque_ciphertext() {
        let message_id = suffix("msg");
        put_encrypted_message(StoredEncryptedMessage {
            message_id: message_id.clone(),
            conversation_id: suffix("conversation"),
            sender_client_id: "sender".to_string(),
            recipient_client_id: "recipient".to_string(),
            sender_user_id: Some("sender-user".to_string()),
            recipient_user_id: Some(suffix("recipient-user")),
            created_at: now_millis(),
            encryption_version: 1,
            encrypted_payload: vec![9, 8, 7],
        })
        .unwrap();

        let messages = get_encrypted_messages(EncryptedMessageQuery {
            recipient_client_id: Some("recipient".to_string()),
            limit: Some(10),
            ..Default::default()
        })
        .unwrap();
        assert!(messages.iter().any(|m| m.message_id == message_id && m.encrypted_payload == vec![9, 8, 7]));
    }

    #[test]
    fn encrypted_history_query_returns_both_directions_for_peer() {
        let user = suffix("user");
        let peer = suffix("peer");
        let incoming_id = suffix("incoming");
        let outgoing_id = suffix("outgoing");
        let other_id = suffix("other");

        put_encrypted_message(StoredEncryptedMessage {
            message_id: incoming_id.clone(),
            conversation_id: suffix("conversation"),
            sender_client_id: "peer-client".to_string(),
            recipient_client_id: "user-client".to_string(),
            sender_user_id: Some(peer.clone()),
            recipient_user_id: Some(user.clone()),
            created_at: now_millis(),
            encryption_version: 1,
            encrypted_payload: vec![1],
        })
        .unwrap();
        put_encrypted_message(StoredEncryptedMessage {
            message_id: outgoing_id.clone(),
            conversation_id: suffix("conversation"),
            sender_client_id: "user-client".to_string(),
            recipient_client_id: "peer-client".to_string(),
            sender_user_id: Some(user.clone()),
            recipient_user_id: Some(peer.clone()),
            created_at: now_millis() + 1,
            encryption_version: 1,
            encrypted_payload: vec![2],
        })
        .unwrap();
        put_encrypted_message(StoredEncryptedMessage {
            message_id: other_id.clone(),
            conversation_id: suffix("conversation"),
            sender_client_id: "other-client".to_string(),
            recipient_client_id: "user-client".to_string(),
            sender_user_id: Some(suffix("other")),
            recipient_user_id: Some(user.clone()),
            created_at: now_millis() + 2,
            encryption_version: 1,
            encrypted_payload: vec![3],
        })
        .unwrap();

        let messages = get_encrypted_messages(EncryptedMessageQuery {
            sender_user_id: Some(peer),
            recipient_user_id: Some(user),
            limit: Some(10),
            ..Default::default()
        })
        .unwrap();

        assert!(messages.iter().any(|m| m.message_id == incoming_id));
        assert!(messages.iter().any(|m| m.message_id == outgoing_id));
        assert!(!messages.iter().any(|m| m.message_id == other_id));
    }

    #[test]
    fn stores_and_retrieves_encrypted_device_secret_blob_for_owner_only() {
        let user_id = suffix("user");
        put_encrypted_device_secret(StoredEncryptedDeviceSecret {
            user_id: user_id.clone(),
            device_id: "device".to_string(),
            secret_id: "main".to_string(),
            version: 1,
            encrypted_secret: vec![42, 43],
            wrapping_public_key_id: None,
            wrapping_scheme: "mtp-chacha20poly1305-hkdf-sha256-v1".to_string(),
            created_at: 1,
            updated_at: 2,
        })
        .unwrap();

        let found = get_encrypted_device_secret(EncryptedDeviceSecretQuery {
            user_id: user_id.clone(),
            device_id: Some("device".to_string()),
            secret_id: Some("main".to_string()),
        })
        .unwrap()
        .unwrap();
        assert_eq!(found.encrypted_secret, vec![42, 43]);

        let denied = get_encrypted_device_secret(EncryptedDeviceSecretQuery {
            user_id: suffix("other-user"),
            device_id: Some("device".to_string()),
            secret_id: Some("main".to_string()),
        })
        .unwrap();
        assert!(denied.is_none());
    }
}
