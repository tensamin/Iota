use crate::util::db;
use rusqlite::{params, OptionalExtension};
use std::sync::{Arc, LazyLock, Mutex};

pub type StorageError = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredChatSecret {
    pub user_id: String,
    pub chat_id: String,
    pub secret_id: String,
    pub version: i64,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub wrapping_scheme: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ChatSecretQuery {
    pub user_id: String,
    pub chat_id: String,
    pub secret_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChatSecretForward {
    pub recipient_user_id: String,
    pub chat_id: String,
    pub sender_user_id: String,
    pub secret_id: String,
    pub version: i64,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub wrapping_scheme: String,
    pub created_at: i64,
}

static E2EE_DB: LazyLock<Arc<Mutex<rusqlite::Connection>>> = LazyLock::new(|| {
    db::create_shared_connection(
        "e2ee",
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        DROP TABLE IF EXISTS encrypted_messages;
        DROP TABLE IF EXISTS encrypted_device_secrets;

        CREATE TABLE IF NOT EXISTS chat_secrets (
            user_id TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            secret_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            encrypted_secret BLOB NOT NULL,
            kem_ciphertext BLOB NOT NULL,
            wrapping_scheme TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, chat_id, secret_id)
        );

        CREATE INDEX IF NOT EXISTS idx_chat_secrets_owner
            ON chat_secrets (user_id, chat_id, secret_id);

        CREATE TABLE IF NOT EXISTS pending_chat_secret_forwards (
            recipient_user_id TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            sender_user_id TEXT NOT NULL,
            secret_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            encrypted_secret BLOB NOT NULL,
            kem_ciphertext BLOB NOT NULL,
            wrapping_scheme TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recipient_user_id, chat_id, secret_id)
        );

        CREATE INDEX IF NOT EXISTS idx_pending_chat_secret_forwards_recipient
            ON pending_chat_secret_forwards (recipient_user_id, created_at);
    "#,
    )
    .expect("Failed to create or initialize E2EE DB")
});

pub fn put_chat_secret(record: StoredChatSecret) -> Result<(), StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        conn.execute(
            r#"
            INSERT INTO chat_secrets (
                user_id, chat_id, secret_id, version, encrypted_secret,
                kem_ciphertext, wrapping_scheme, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(user_id, chat_id, secret_id) DO UPDATE SET
                version = excluded.version,
                encrypted_secret = excluded.encrypted_secret,
                kem_ciphertext = excluded.kem_ciphertext,
                wrapping_scheme = excluded.wrapping_scheme,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#,
            params![
                record.user_id,
                record.chat_id,
                record.secret_id,
                record.version,
                record.encrypted_secret,
                record.kem_ciphertext,
                record.wrapping_scheme,
                record.created_at,
                record.updated_at,
            ],
        )?;
        Ok(())
    })
}

pub fn put_pending_chat_secret_forward(
    record: PendingChatSecretForward,
) -> Result<(), StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        conn.execute(
            r#"
            INSERT INTO pending_chat_secret_forwards (
                recipient_user_id, chat_id, sender_user_id, secret_id, version,
                encrypted_secret, kem_ciphertext, wrapping_scheme, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(recipient_user_id, chat_id, secret_id) DO UPDATE SET
                sender_user_id = excluded.sender_user_id,
                version = excluded.version,
                encrypted_secret = excluded.encrypted_secret,
                kem_ciphertext = excluded.kem_ciphertext,
                wrapping_scheme = excluded.wrapping_scheme,
                created_at = excluded.created_at
            "#,
            params![
                record.recipient_user_id,
                record.chat_id,
                record.sender_user_id,
                record.secret_id,
                record.version,
                record.encrypted_secret,
                record.kem_ciphertext,
                record.wrapping_scheme,
                record.created_at,
            ],
        )?;
        Ok(())
    })
}

pub fn get_pending_chat_secret_forwards(
    limit: i64,
) -> Result<Vec<PendingChatSecretForward>, StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT recipient_user_id, chat_id, sender_user_id, secret_id, version,
                   encrypted_secret, kem_ciphertext, wrapping_scheme, created_at
            FROM pending_chat_secret_forwards
            ORDER BY created_at ASC
            LIMIT ?1
            "#,
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 500)], pending_forward_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
}

pub fn delete_pending_chat_secret_forward(
    recipient_user_id: &str,
    chat_id: &str,
    secret_id: &str,
) -> Result<(), StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        conn.execute(
            r#"
            DELETE FROM pending_chat_secret_forwards
            WHERE recipient_user_id = ?1 AND chat_id = ?2 AND secret_id = ?3
            "#,
            params![recipient_user_id, chat_id, secret_id],
        )?;
        Ok(())
    })
}

pub fn get_chat_secret(query: ChatSecretQuery) -> Result<Option<StoredChatSecret>, StorageError> {
    if query.user_id.is_empty() || query.chat_id.is_empty() {
        return Ok(None);
    }

    db::with_conn(&E2EE_DB, |conn| {
        conn.query_row(
            r#"
            SELECT user_id, chat_id, secret_id, version, encrypted_secret,
                   kem_ciphertext, wrapping_scheme, created_at, updated_at
            FROM chat_secrets
            WHERE user_id = ?1
              AND chat_id = ?2
              AND (?3 IS NULL OR secret_id = ?3)
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
            params![query.user_id, query.chat_id, query.secret_id],
            chat_secret_from_row,
        )
        .optional()
    })
}

fn chat_secret_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredChatSecret> {
    Ok(StoredChatSecret {
        user_id: row.get(0)?,
        chat_id: row.get(1)?,
        secret_id: row.get(2)?,
        version: row.get(3)?,
        encrypted_secret: row.get(4)?,
        kem_ciphertext: row.get(5)?,
        wrapping_scheme: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn pending_forward_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingChatSecretForward> {
    Ok(PendingChatSecretForward {
        recipient_user_id: row.get(0)?,
        chat_id: row.get(1)?,
        sender_user_id: row.get(2)?,
        secret_id: row.get(3)?,
        version: row.get(4)?,
        encrypted_secret: row.get(5)?,
        kem_ciphertext: row.get(6)?,
        wrapping_scheme: row.get(7)?,
        created_at: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffix(name: &str) -> String {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{name}-{unix}")
    }

    #[test]
    fn stores_and_retrieves_chat_secret_blob_for_owner_chat() {
        let user_id = suffix("user");
        let chat_id = suffix("chat");

        put_chat_secret(StoredChatSecret {
            user_id: user_id.clone(),
            chat_id: chat_id.clone(),
            secret_id: "main".to_string(),
            version: 1,
            encrypted_secret: vec![42, 43],
            kem_ciphertext: vec![9, 8, 7],
            wrapping_scheme: "mtp-kem-chacha20poly1305-hkdf-sha256-v1".to_string(),
            created_at: 1,
            updated_at: 2,
        })
        .unwrap();

        let found = get_chat_secret(ChatSecretQuery {
            user_id: user_id.clone(),
            chat_id: chat_id.clone(),
            secret_id: Some("main".to_string()),
        })
        .unwrap()
        .unwrap();
        assert_eq!(found.encrypted_secret, vec![42, 43]);
        assert_eq!(found.kem_ciphertext, vec![9, 8, 7]);

        let denied = get_chat_secret(ChatSecretQuery {
            user_id: suffix("other-user"),
            chat_id,
            secret_id: Some("main".to_string()),
        })
        .unwrap();
        assert!(denied.is_none());
    }
}
