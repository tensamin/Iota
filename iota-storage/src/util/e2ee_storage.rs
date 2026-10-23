use crate::storage_error::StorageError as TransactionError;
use crate::util::db;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub type StorageError = String;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Import before publishing the database pool. The legacy database is read-only
/// and remains available for recovery. The marker commits with the imported rows.
pub(crate) fn import_legacy_database(
    connection: &Connection,
    path: &std::path::Path,
) -> Result<(), TransactionError> {
    let tx = Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)?;
    if tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM storage_imports WHERE name = 'e2ee')",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(());
    }
    if path.try_exists()? {
        let legacy = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let exists: bool = legacy.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chat_secrets')",
            [], |row| row.get(0),
        )?;
        if exists {
            let mut statement = legacy.prepare(
                "SELECT user_id, chat_id, secret_id, version, encrypted_secret,
                    kem_ciphertext, wrapping_scheme, created_at, updated_at
                 FROM chat_secrets ORDER BY user_id, chat_id, secret_id, version",
            )?;
            for record in statement.query_map([], chat_secret_from_row)? {
                let record = record?;
                let existing = get_chat_secret_on(
                    &tx,
                    &ChatSecretQuery {
                        user_id: record.user_id.clone(),
                        chat_id: record.chat_id.clone(),
                        secret_id: Some(record.secret_id.clone()),
                        version: Some(record.version),
                    },
                )?;
                if let Some(existing) = existing {
                    if existing != record {
                        return Err(TransactionError::ChatSecretConflict);
                    }
                } else {
                    // Historical stores may contain only the latest version.
                    // Import their exact records without inventing earlier secrets.
                    insert_chat_secret(&tx, &record)?;
                }
            }
        }
    }
    tx.execute(
        "INSERT INTO storage_imports (name, completed_at) VALUES ('e2ee', ?1)",
        [crate::util::sync::now_millis()],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn migrate_chat_secret_namespace(
    user_id: &str,
    legacy_chat_id: &str,
    legacy_secret_id: &str,
    principal_chat_id: &str,
    principal_secret_id: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        migrate_chat_secret_namespace_in_tx(
            tx,
            user_id,
            legacy_chat_id,
            legacy_secret_id,
            principal_chat_id,
            principal_secret_id,
        )
    })
    .map_err(|error| error.to_string())
}

pub fn migrate_chat_secret_namespace_in_tx(
    tx: &Transaction<'_>,
    user_id: &str,
    legacy_chat_id: &str,
    legacy_secret_id: &str,
    principal_chat_id: &str,
    principal_secret_id: &str,
) -> Result<(), TransactionError> {
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
        return Err(TransactionError::Other(
            "chat secret namespace is incomplete".into(),
        ));
    }
    let handles = principal_chat_id
        .strip_prefix("principal:")
        .ok_or(TransactionError::InvalidRelayPayload(
            "principal chat namespace",
        ))?
        .split(':')
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TransactionError::InvalidRelayPayload("principal chat namespace"))?;
    if handles.len() != 2
        || handles[0] <= 0
        || handles[0] >= handles[1]
        || principal_secret_id != self::principal_secret_id(principal_chat_id)
    {
        return Err(TransactionError::ChatSecretConflict);
    }
    let identities = {
        let mut statement = tx.prepare("SELECT authority_id, remote_user_id FROM principals WHERE principal_pk IN (?1, ?2) ORDER BY principal_pk")?;
        statement
            .query_map(params![handles[0], handles[1]], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if identities.len() != 2 {
        return Err(TransactionError::MissingRelayDependency);
    }
    // Numeric legacy namespaces authenticate a pair only when each numeric ID
    // has one canonical meaning. Never copy another authority's secret by ID.
    if identities[0].0 != identities[1].0 {
        return Ok(());
    }
    let first = identities[0].1.min(identities[1].1);
    let second = identities[0].1.max(identities[1].1);
    if legacy_chat_id != format!("{first}:{second}")
        || legacy_secret_id != format!("chat:{legacy_chat_id}:main")
    {
        return Err(TransactionError::ChatSecretConflict);
    }
    let meanings: i64 = tx.query_row(
        "SELECT COUNT(*) FROM principals WHERE remote_user_id IN (?1, ?2)",
        params![first, second],
        |row| row.get(0),
    )?;
    if meanings != 2 {
        return Ok(());
    }
    let conflict: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM chat_secrets legacy JOIN chat_secrets canonical
            ON canonical.user_id = legacy.user_id AND canonical.version = legacy.version
            AND canonical.chat_id = ?4 AND canonical.secret_id = ?5
         WHERE legacy.user_id = ?1 AND legacy.chat_id = ?2 AND legacy.secret_id = ?3
            AND (canonical.encrypted_secret <> legacy.encrypted_secret
                OR canonical.kem_ciphertext <> legacy.kem_ciphertext
                OR canonical.wrapping_scheme <> legacy.wrapping_scheme))",
        params![
            user_id,
            legacy_chat_id,
            legacy_secret_id,
            principal_chat_id,
            principal_secret_id
        ],
        |row| row.get(0),
    )?;
    if conflict {
        return Err(TransactionError::ChatSecretConflict);
    }
    tx.execute(
        "INSERT OR IGNORE INTO chat_secrets (
            user_id, chat_id, secret_id, version, encrypted_secret, kem_ciphertext,
            wrapping_scheme, created_at, updated_at
         ) SELECT user_id, ?4, ?5, version, encrypted_secret, kem_ciphertext,
            wrapping_scheme, created_at, updated_at FROM chat_secrets
         WHERE user_id = ?1 AND chat_id = ?2 AND secret_id = ?3",
        params![
            user_id,
            legacy_chat_id,
            legacy_secret_id,
            principal_chat_id,
            principal_secret_id
        ],
    )?;
    Ok(())
}

pub fn put_chat_secret(record: StoredChatSecret) -> Result<(), StorageError> {
    put_chat_secrets(&[record])
}

/// Commit every local recipient envelope together, including during initialization.
pub fn put_chat_secrets(records: &[StoredChatSecret]) -> Result<(), StorageError> {
    db::with_db(|connection| put_chat_secrets_in_connection(connection, records))
        .map_err(|error| error.to_string())
}

fn put_chat_secrets_in_connection(
    connection: &Connection,
    records: &[StoredChatSecret],
) -> Result<(), TransactionError> {
    let tx = Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)?;
    for record in records {
        put_chat_secret_in_tx(&tx, record)?;
    }
    tx.commit()?;
    Ok(())
}

pub fn put_chat_secret_in_tx(
    tx: &Transaction<'_>,
    record: &StoredChatSecret,
) -> Result<(), TransactionError> {
    let existing = get_chat_secret_on(
        tx,
        &ChatSecretQuery {
            user_id: record.user_id.clone(),
            chat_id: record.chat_id.clone(),
            secret_id: Some(record.secret_id.clone()),
            version: Some(record.version),
        },
    )?;
    if let Some(existing) = existing {
        if existing.encrypted_secret != record.encrypted_secret
            || existing.kem_ciphertext != record.kem_ciphertext
            || existing.wrapping_scheme != record.wrapping_scheme
        {
            return Err(TransactionError::ChatSecretConflict);
        }
        return Ok(());
    }
    let latest: Option<i64> = tx.query_row(
        "SELECT MAX(version) FROM chat_secrets WHERE user_id = ?1 AND chat_id = ?2 AND secret_id = ?3",
        params![record.user_id, record.chat_id, record.secret_id], |row| row.get(0),
    )?;
    let expected = match latest {
        None => 1,
        Some(version) => version
            .checked_add(1)
            .ok_or(TransactionError::ChatSecretSequence)?,
    };
    if record.version != expected {
        return Err(TransactionError::ChatSecretSequence);
    }
    insert_chat_secret(tx, record)
}

fn insert_chat_secret(
    tx: &Transaction<'_>,
    record: &StoredChatSecret,
) -> Result<(), TransactionError> {
    tx.execute(
        "INSERT INTO chat_secrets (user_id, chat_id, secret_id, version, encrypted_secret,
            kem_ciphertext, wrapping_scheme, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            record.user_id,
            record.chat_id,
            record.secret_id,
            record.version,
            record.encrypted_secret,
            record.kem_ciphertext,
            record.wrapping_scheme,
            record.created_at,
            record.updated_at
        ],
    )?;
    Ok(())
}

/// Idempotent account erasure now uses the authoritative database transaction.
pub fn purge_user(user_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "DELETE FROM chat_secrets WHERE user_id = ?1",
            [user_id.to_string()],
        )?;
        Ok(())
    })
    .map_err(|error| error.to_string())
}

pub fn get_chat_secret(query: ChatSecretQuery) -> Result<Option<StoredChatSecret>, StorageError> {
    db::with_db(|connection| get_chat_secret_on(connection, &query))
        .map_err(|error| error.to_string())
}

pub fn get_chat_secret_on(
    connection: &Connection,
    query: &ChatSecretQuery,
) -> Result<Option<StoredChatSecret>, TransactionError> {
    if query.user_id.is_empty() || query.chat_id.is_empty() {
        return Ok(None);
    }
    Ok(connection
        .query_row(
            "SELECT user_id, chat_id, secret_id, version, encrypted_secret,
            kem_ciphertext, wrapping_scheme, created_at, updated_at FROM chat_secrets
         WHERE user_id = ?1 AND chat_id = ?2 AND (?3 IS NULL OR secret_id = ?3)
            AND (?4 IS NULL OR version = ?4)
         ORDER BY version DESC, updated_at DESC LIMIT 1",
            params![query.user_id, query.chat_id, query.secret_id, query.version],
            chat_secret_from_row,
        )
        .optional()?)
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
