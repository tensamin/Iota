use crate::util::db;
use rusqlite::{OptionalExtension, params};
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
    pub version: Option<i64>,
}

static E2EE_DB: LazyLock<Arc<Mutex<rusqlite::Connection>>> = LazyLock::new(|| {
    let database = db::create_shared_connection(
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
            PRIMARY KEY (user_id, chat_id, secret_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_chat_secrets_owner
            ON chat_secrets (user_id, chat_id, secret_id);

    "#,
    )
    .expect("Failed to create or initialize E2EE DB");
    if let Ok(connection) = database.lock() {
        let legacy = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('chat_secrets') WHERE name = 'version' AND pk = 4",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            == 0;
        if legacy {
            connection
                .execute_batch(
                    "ALTER TABLE chat_secrets RENAME TO chat_secrets_legacy;
                     CREATE TABLE chat_secrets (
                         user_id TEXT NOT NULL, chat_id TEXT NOT NULL,
                         secret_id TEXT NOT NULL, version INTEGER NOT NULL,
                         encrypted_secret BLOB NOT NULL, kem_ciphertext BLOB NOT NULL,
                         wrapping_scheme TEXT NOT NULL, created_at INTEGER NOT NULL,
                         updated_at INTEGER NOT NULL,
                         PRIMARY KEY (user_id, chat_id, secret_id, version)
                     );
                     INSERT INTO chat_secrets SELECT * FROM chat_secrets_legacy;
                     DROP TABLE chat_secrets_legacy;",
                )
                .expect("Failed to migrate E2EE secret history schema");
        }
    }
    database
});

pub fn put_chat_secret(record: StoredChatSecret) -> Result<(), StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        let tx = conn.unchecked_transaction()?;
        let existing = tx.query_row(
                "SELECT encrypted_secret, kem_ciphertext, wrapping_scheme FROM chat_secrets WHERE user_id = ?1 AND chat_id = ?2 AND secret_id = ?3 AND version = ?4",
                params![&record.user_id, &record.chat_id, &record.secret_id, record.version],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?)),
            ).optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    record.encrypted_secret.clone(),
                    record.kem_ciphertext.clone(),
                    record.wrapping_scheme.clone(),
                )
            {
                return Err(rusqlite::Error::InvalidParameterName(
                    "immutable chat secret version conflict".into(),
                ));
            }
            return Ok(());
        }
        let latest = tx.query_row(
            "SELECT MAX(version) FROM chat_secrets WHERE user_id = ?1 AND chat_id = ?2 AND secret_id = ?3",
            params![&record.user_id, &record.chat_id, &record.secret_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        let expected = match latest {
            None => 1,
            Some(version) => version.checked_add(1).ok_or_else(|| {
                rusqlite::Error::InvalidParameterName("chat secret version overflow".into())
            })?,
        };
        if record.version != expected {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "chat secret version is out of sequence: expected {expected}, got {}",
                record.version
            )));
        }
        tx.execute(
            "INSERT INTO chat_secrets (user_id, chat_id, secret_id, version, encrypted_secret, kem_ciphertext, wrapping_scheme, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![record.user_id, record.chat_id, record.secret_id, record.version, record.encrypted_secret, record.kem_ciphertext, record.wrapping_scheme, record.created_at, record.updated_at],
        )?;
        tx.commit()?;
        Ok(())
    })
}

/// Erase every E2EE record owned by a user. The operation is
/// intentionally idempotent so it can be retried after an interrupted remote
/// erasure request.
pub fn purge_user(user_id: i64) -> Result<(), StorageError> {
    let user_id = user_id.to_string();
    db::with_conn(&E2EE_DB, |conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM chat_secrets WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.commit()?;
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
              AND (?4 IS NULL OR version = ?4)
            ORDER BY version DESC, updated_at DESC
            LIMIT 1
            "#,
            params![query.user_id, query.chat_id, query.secret_id, query.version],
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
