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

pub fn principal_chat_id(
    first: iota_identity::PrincipalHandle,
    second: iota_identity::PrincipalHandle,
) -> Option<String> {
    if first.0 <= 0 || second.0 <= 0 || first == second {
        return None;
    }
    let (first, second) = if first.0 < second.0 {
        (first.0, second.0)
    } else {
        (second.0, first.0)
    };
    Some(format!("principal:{first}:{second}"))
}

pub fn principal_secret_id(chat_id: &str) -> String {
    format!("chat:{chat_id}:main")
}

pub fn migrate_chat_secret_namespace(
    user_id: &str,
    legacy_chat_id: &str,
    legacy_secret_id: &str,
    principal_chat_id: &str,
    principal_secret_id: &str,
) -> Result<(), StorageError> {
    if [
        user_id,
        legacy_chat_id,
        legacy_secret_id,
        principal_chat_id,
        principal_secret_id,
    ]
    .iter()
    .any(|value| value.is_empty())
    {
        return Err("chat secret namespace is incomplete".into());
    }
    db::with_conn(&E2EE_DB, |conn| {
        conn.execute(
            r#"
            INSERT OR IGNORE INTO chat_secrets (
                user_id, chat_id, secret_id, version, encrypted_secret,
                kem_ciphertext, wrapping_scheme, created_at, updated_at
            )
            SELECT user_id, ?4, ?5, version, encrypted_secret,
                   kem_ciphertext, wrapping_scheme, created_at, updated_at
            FROM chat_secrets
            WHERE user_id = ?1 AND chat_id = ?2 AND secret_id = ?3
            "#,
            params![
                user_id,
                legacy_chat_id,
                legacy_secret_id,
                principal_chat_id,
                principal_secret_id
            ],
        )?;
        Ok(())
    })
}

static E2EE_DB: LazyLock<Arc<Mutex<rusqlite::Connection>>> = LazyLock::new(|| {
    let database = db::create_shared_connection(
        "e2ee",
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;

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
    put_chat_secrets(&[record])
}

/// Commit every local recipient envelope together. In particular, concurrent
/// initializers on a shared Iota must never leave one user's winning envelope
/// paired with another user's losing envelope.
pub fn put_chat_secrets(records: &[StoredChatSecret]) -> Result<(), StorageError> {
    db::with_conn(&E2EE_DB, |conn| {
        put_chat_secrets_in_connection(conn, records)
    })
}

fn put_chat_secrets_in_connection(
    conn: &rusqlite::Connection,
    records: &[StoredChatSecret],
) -> rusqlite::Result<()> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    for record in records {
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
            continue;
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
    }
    tx.commit()
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

#[cfg(test)]
mod tests {
    use super::{
        StoredChatSecret, principal_chat_id, principal_secret_id, put_chat_secrets_in_connection,
    };
    use iota_identity::PrincipalHandle;

    fn initialize(connection: &rusqlite::Connection) {
        connection
            .execute_batch(
                "CREATE TABLE chat_secrets (
                user_id TEXT NOT NULL, chat_id TEXT NOT NULL, secret_id TEXT NOT NULL,
                version INTEGER NOT NULL, encrypted_secret BLOB NOT NULL,
                kem_ciphertext BLOB NOT NULL, wrapping_scheme TEXT NOT NULL,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, chat_id, secret_id, version)
            );",
            )
            .unwrap();
    }

    fn envelopes(proposal: u8) -> [StoredChatSecret; 2] {
        [1, 2].map(|owner| StoredChatSecret {
            user_id: owner.to_string(),
            chat_id: "principal:1:2".into(),
            secret_id: "chat:principal:1:2:main".into(),
            version: 1,
            encrypted_secret: vec![proposal, owner],
            kem_ciphertext: vec![proposal, owner, 3],
            wrapping_scheme: "test-envelope".into(),
            created_at: 1,
            updated_at: 1,
        })
    }

    #[test]
    fn shared_envelopes_commit_together_and_identical_replays_are_idempotent() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&connection);
        let records = envelopes(7);
        put_chat_secrets_in_connection(&connection, &records).unwrap();
        put_chat_secrets_in_connection(&connection, &records).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM chat_secrets", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
        for record in records {
            let stored = connection.query_row(
                "SELECT user_id, chat_id, secret_id, version, encrypted_secret, kem_ciphertext, wrapping_scheme, created_at, updated_at FROM chat_secrets WHERE user_id = ?1",
                [&record.user_id], super::chat_secret_from_row,
            ).unwrap();
            assert_eq!(stored, record);
        }
    }

    #[test]
    fn conflict_in_second_envelope_rolls_back_the_first() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&connection);
        let existing = envelopes(4);
        put_chat_secrets_in_connection(&connection, &existing[1..]).unwrap();
        assert!(put_chat_secrets_in_connection(&connection, &envelopes(9)).is_err());
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM chat_secrets WHERE user_id = '1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        let stored: Vec<u8> = connection
            .query_row(
                "SELECT encrypted_secret FROM chat_secrets WHERE user_id = '2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, existing[1].encrypted_secret);
    }

    #[test]
    fn rotation_requires_consecutive_versions_for_every_recipient() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        initialize(&connection);
        let initial = envelopes(1);
        put_chat_secrets_in_connection(&connection, &initial[..1]).unwrap();
        let mut rotation = envelopes(2);
        for record in &mut rotation {
            record.version = 2;
        }
        assert!(put_chat_secrets_in_connection(&connection, &rotation).is_err());
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM chat_secrets WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        put_chat_secrets_in_connection(&connection, &initial[1..]).unwrap();
        put_chat_secrets_in_connection(&connection, &rotation).unwrap();
        assert!(put_chat_secrets_in_connection(&connection, &envelopes(3)).is_err());
    }

    #[test]
    fn concurrent_initializers_choose_one_pair_that_survives_reopening() {
        let storage = tempfile::tempdir().unwrap();
        let path = storage.path().join("e2ee.sqlite3");
        let connection = rusqlite::Connection::open(&path).unwrap();
        initialize(&connection);
        drop(connection);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers = [6, 8].map(|proposal| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let connection = rusqlite::Connection::open(path).unwrap();
                connection
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                let mut records = envelopes(proposal);
                if proposal == 8 {
                    records.reverse();
                }
                barrier.wait();
                put_chat_secrets_in_connection(&connection, &records).is_ok()
            })
        });
        let winners = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap().then_some(()))
            .count();
        assert_eq!(winners, 1);
        let connection = rusqlite::Connection::open(path).unwrap();
        let mut statement = connection
            .prepare("SELECT encrypted_secret FROM chat_secrets ORDER BY user_id")
            .unwrap();
        let stored = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0][0], stored[1][0]);
        assert_ne!(stored[0], stored[1]);
    }

    #[test]
    fn chat_secret_namespace_uses_principals() {
        let first = principal_chat_id(PrincipalHandle(3), PrincipalHandle(9));
        let second = principal_chat_id(PrincipalHandle(9), PrincipalHandle(3));

        assert_eq!(first, Some("principal:3:9".to_string()));
        assert_eq!(first, second);
        assert_eq!(
            principal_secret_id("principal:3:9"),
            "chat:principal:3:9:main"
        );
    }

    #[test]
    fn equal_or_invalid_principals_have_no_chat_namespace() {
        assert_eq!(
            principal_chat_id(PrincipalHandle(7), PrincipalHandle(7)),
            None
        );
        assert_eq!(
            principal_chat_id(PrincipalHandle(0), PrincipalHandle(7)),
            None
        );
    }
}
