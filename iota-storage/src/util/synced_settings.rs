use crate::storage_error::StorageError;
use crate::util::db;
use crate::util::sync::{self, EntityType, Operation};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingScope {
    User,
    Contact,
    Community,
}

impl SettingScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Contact => "contact",
            Self::Community => "community",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "contact" => Some(Self::Contact),
            "community" => Some(Self::Community),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedSetting {
    pub id: i64,
    pub user_id: i64,
    pub scope: SettingScope,
    pub scope_key: String,
    pub name: String,
    pub payload: String,
    pub revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletedSetting {
    pub id: i64,
    pub revision: i64,
    pub changed: bool,
}

pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_alphanumeric() || "_-.".contains(character))
        && !name.contains("..")
}

fn validate_locator(scope: SettingScope, scope_key: &str, name: &str) -> Result<(), StorageError> {
    if !is_valid_name(name) {
        return Err(StorageError::Other(
            "invalid synchronized setting name".into(),
        ));
    }

    match scope {
        SettingScope::User if !scope_key.is_empty() => Err(StorageError::Other(
            "user settings must not have a target".into(),
        )),
        SettingScope::Contact => {
            let valid_contact = scope_key.parse::<i64>().is_ok_and(|id| id > 0);
            if valid_contact {
                Ok(())
            } else {
                Err(StorageError::Other("invalid contact setting target".into()))
            }
        }
        SettingScope::Community if scope_key.is_empty() => Err(StorageError::Other(
            "community settings require a target".into(),
        )),
        _ => Ok(()),
    }
}

fn normalized_scope_key(scope: SettingScope, scope_key: &str) -> Result<String, StorageError> {
    match scope {
        SettingScope::Contact => scope_key
            .parse::<i64>()
            .map(|id| id.to_string())
            .map_err(|_| StorageError::Other("invalid contact setting target".into())),
        SettingScope::User | SettingScope::Community => Ok(scope_key.to_string()),
    }
}

fn setting_from_parts(
    id: i64,
    user_id: i64,
    scope_type: String,
    scope_key: String,
    name: String,
    payload: String,
    revision: i64,
) -> Result<SyncedSetting, StorageError> {
    let scope = SettingScope::parse(&scope_type)
        .ok_or_else(|| StorageError::Other("database contains an invalid setting scope".into()))?;
    Ok(SyncedSetting {
        id,
        user_id,
        scope,
        scope_key,
        name,
        payload,
        revision,
    })
}

fn row_parts(row: &Row<'_>) -> rusqlite::Result<(i64, i64, String, String, String, String, i64)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn load_setting_from_tx(
    tx: &Transaction<'_>,
    setting_id: i64,
) -> Result<SyncedSetting, StorageError> {
    let parts = tx.query_row(
        "SELECT id, user_id, scope_type, scope_key, name, payload, revision
         FROM synced_settings
         WHERE id = ?1 AND deleted = 0",
        [setting_id],
        row_parts,
    )?;
    setting_from_parts(
        parts.0, parts.1, parts.2, parts.3, parts.4, parts.5, parts.6,
    )
}

pub fn set(
    user_id: i64,
    scope: SettingScope,
    scope_key: &str,
    name: &str,
    payload: &str,
) -> Result<SyncedSetting, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid setting owner".into()));
    }
    validate_locator(scope, scope_key, name)?;
    let scope_key = normalized_scope_key(scope, scope_key)?;

    db::with_immediate_transaction(|tx| set_in_tx(tx, user_id, scope, &scope_key, name, payload))
}

fn set_in_tx(
    tx: &Transaction<'_>,
    user_id: i64,
    scope: SettingScope,
    scope_key: &str,
    name: &str,
    payload: &str,
) -> Result<SyncedSetting, StorageError> {
    tx.execute(
        "INSERT INTO synced_settings
            (user_id, scope_type, scope_key, name, payload, revision, deleted)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)
         ON CONFLICT(user_id, scope_type, scope_key, name) DO NOTHING",
        params![user_id, scope.as_str(), scope_key, name, payload],
    )?;
    let setting_id: i64 = tx.query_row(
        "SELECT id FROM synced_settings
         WHERE user_id = ?1 AND scope_type = ?2 AND scope_key = ?3 AND name = ?4",
        params![user_id, scope.as_str(), scope_key, name],
        |row| row.get(0),
    )?;
    let revision = sync::record_event(
        tx,
        user_id,
        EntityType::Setting,
        setting_id,
        Operation::Upsert,
    )?;
    tx.execute(
        "UPDATE synced_settings
         SET payload = ?2, deleted = 0, revision = ?3
         WHERE id = ?1",
        params![setting_id, payload, revision],
    )?;
    load_setting_from_tx(tx, setting_id)
}

pub fn get(
    user_id: i64,
    scope: SettingScope,
    scope_key: &str,
    name: &str,
) -> Result<Option<SyncedSetting>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid setting owner".into()));
    }
    validate_locator(scope, scope_key, name)?;
    let scope_key = normalized_scope_key(scope, scope_key)?;
    db::with_db(|conn| get_from_connection(conn, user_id, scope, &scope_key, name))
}

fn get_from_connection(
    conn: &Connection,
    user_id: i64,
    scope: SettingScope,
    scope_key: &str,
    name: &str,
) -> Result<Option<SyncedSetting>, StorageError> {
    let parts = conn
        .query_row(
            "SELECT id, user_id, scope_type, scope_key, name, payload, revision
             FROM synced_settings
             WHERE user_id = ?1 AND scope_type = ?2 AND scope_key = ?3
               AND name = ?4 AND deleted = 0",
            params![user_id, scope.as_str(), scope_key, name],
            row_parts,
        )
        .optional()?;
    parts
        .map(|parts| {
            setting_from_parts(
                parts.0, parts.1, parts.2, parts.3, parts.4, parts.5, parts.6,
            )
        })
        .transpose()
}

pub fn list(user_id: i64) -> Result<Vec<SyncedSetting>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid setting owner".into()));
    }
    db::with_db(|conn| list_from_connection(conn, user_id))
}

fn list_from_connection(
    conn: &Connection,
    user_id: i64,
) -> Result<Vec<SyncedSetting>, StorageError> {
    let mut statement = conn.prepare(
        "SELECT id, user_id, scope_type, scope_key, name, payload, revision
         FROM synced_settings
         WHERE user_id = ?1 AND deleted = 0
         ORDER BY id ASC",
    )?;
    let rows = statement.query_map([user_id], row_parts)?;
    let mut settings = Vec::new();
    for row in rows {
        let parts = row?;
        settings.push(setting_from_parts(
            parts.0, parts.1, parts.2, parts.3, parts.4, parts.5, parts.6,
        )?);
    }
    Ok(settings)
}

pub fn list_by_ids(user_id: i64, ids: &[i64]) -> Result<Vec<SyncedSetting>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid setting owner".into()));
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    db::with_db(|conn| list_by_ids_from_connection(conn, user_id, ids))
}

fn list_by_ids_from_connection(
    conn: &Connection,
    user_id: i64,
    ids: &[i64],
) -> Result<Vec<SyncedSetting>, StorageError> {
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "SELECT id, user_id, scope_type, scope_key, name, payload, revision
         FROM synced_settings
         WHERE user_id = ? AND deleted = 0 AND id IN ({placeholders})
         ORDER BY id ASC"
    );
    let mut values = Vec::with_capacity(ids.len() + 1);
    values.push(user_id);
    values.extend_from_slice(ids);
    let mut statement = conn.prepare(&query)?;
    let rows = statement.query_map(rusqlite::params_from_iter(values), row_parts)?;
    let mut settings = Vec::new();
    for row in rows {
        let parts = row?;
        settings.push(setting_from_parts(
            parts.0, parts.1, parts.2, parts.3, parts.4, parts.5, parts.6,
        )?);
    }
    Ok(settings)
}

pub fn delete(
    user_id: i64,
    scope: SettingScope,
    scope_key: &str,
    name: &str,
) -> Result<Option<DeletedSetting>, StorageError> {
    if user_id <= 0 {
        return Err(StorageError::Other("invalid setting owner".into()));
    }
    validate_locator(scope, scope_key, name)?;
    let scope_key = normalized_scope_key(scope, scope_key)?;
    db::with_immediate_transaction(|tx| delete_in_tx(tx, user_id, scope, &scope_key, name))
}

fn delete_in_tx(
    tx: &Transaction<'_>,
    user_id: i64,
    scope: SettingScope,
    scope_key: &str,
    name: &str,
) -> Result<Option<DeletedSetting>, StorageError> {
    let existing = tx
        .query_row(
            "SELECT id, revision, deleted FROM synced_settings
             WHERE user_id = ?1 AND scope_type = ?2 AND scope_key = ?3 AND name = ?4",
            params![user_id, scope.as_str(), scope_key, name],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((setting_id, current_revision, deleted)) = existing else {
        return Ok(None);
    };
    if deleted != 0 {
        return Ok(Some(DeletedSetting {
            id: setting_id,
            revision: current_revision,
            changed: false,
        }));
    }

    let revision = sync::record_event(
        tx,
        user_id,
        EntityType::Setting,
        setting_id,
        Operation::Delete,
    )?;
    tx.execute(
        "UPDATE synced_settings SET deleted = 1, revision = ?2 WHERE id = ?1",
        params![setting_id, revision],
    )?;
    Ok(Some(DeletedSetting {
        id: setting_id,
        revision,
        changed: true,
    }))
}

pub(crate) fn delete_scope_in_tx(
    tx: &Transaction<'_>,
    user_id: i64,
    scope: SettingScope,
    scope_key: &str,
) -> Result<(), StorageError> {
    let setting_ids = {
        let mut statement = tx.prepare(
            "SELECT id FROM synced_settings
             WHERE user_id = ?1 AND scope_type = ?2 AND scope_key = ?3 AND deleted = 0",
        )?;
        let rows = statement.query_map(params![user_id, scope.as_str(), scope_key], |row| {
            row.get::<_, i64>(0)
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    for setting_id in setting_ids {
        let revision = sync::record_event(
            tx,
            user_id,
            EntityType::Setting,
            setting_id,
            Operation::Delete,
        )?;
        tx.execute(
            "UPDATE synced_settings SET deleted = 1, revision = ?2 WHERE id = ?1",
            params![setting_id, revision],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        delete_in_tx, get_from_connection, is_valid_name, list_by_ids_from_connection,
        list_from_connection, set_in_tx, SettingScope,
    };
    use rusqlite::Connection;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE sync_heads (
                    user_id INTEGER PRIMARY KEY,
                    version INTEGER NOT NULL
                );
                CREATE TABLE sync_events (
                    user_id INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    operation TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (user_id, version)
                );
                CREATE TABLE synced_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    scope_type TEXT NOT NULL,
                    scope_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    deleted INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(user_id, scope_type, scope_key, name)
                );
                ",
            )
            .unwrap();
        connection
    }

    fn set(
        connection: &mut Connection,
        user_id: i64,
        scope: SettingScope,
        scope_key: &str,
        name: &str,
        payload: &str,
    ) -> super::SyncedSetting {
        let transaction = connection.transaction().unwrap();
        let setting = set_in_tx(&transaction, user_id, scope, scope_key, name, payload).unwrap();
        transaction.commit().unwrap();
        setting
    }

    #[test]
    fn parses_supported_setting_scopes() {
        assert_eq!(SettingScope::parse("user"), Some(SettingScope::User));
        assert_eq!(SettingScope::parse("contact"), Some(SettingScope::Contact));
        assert_eq!(
            SettingScope::parse("community"),
            Some(SettingScope::Community)
        );
    }

    #[test]
    fn rejects_unknown_setting_scope() {
        assert_eq!(SettingScope::parse("device"), None);
    }

    #[test]
    fn validates_setting_name_syntax() {
        assert!(is_valid_name("notifications.enabled"));
        assert!(!is_valid_name("notifications..enabled"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("notifications/enabled"));
    }

    #[test]
    fn stores_and_loads_a_user_setting() {
        let mut connection = connection();
        let stored = set(
            &mut connection,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
            "true",
        );
        let loaded = get_from_connection(
            &connection,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
        )
        .unwrap();

        assert_eq!(loaded, Some(stored));
    }

    #[test]
    fn contact_and_community_targets_are_distinct() {
        let mut connection = connection();
        set(
            &mut connection,
            1,
            SettingScope::Contact,
            "123",
            "notifications.enabled",
            "false",
        );
        set(
            &mut connection,
            1,
            SettingScope::Community,
            "community-a",
            "notifications.enabled",
            "true",
        );

        assert_eq!(list_from_connection(&connection, 1).unwrap().len(), 2);
    }

    #[test]
    fn users_store_same_setting_independently() {
        let mut connection = connection();
        set(
            &mut connection,
            1,
            SettingScope::User,
            "",
            "receipts.user_read",
            "true",
        );
        set(
            &mut connection,
            2,
            SettingScope::User,
            "",
            "receipts.user_read",
            "false",
        );

        assert_eq!(
            get_from_connection(&connection, 1, SettingScope::User, "", "receipts.user_read")
                .unwrap()
                .unwrap()
                .payload,
            "true"
        );
        assert_eq!(
            get_from_connection(&connection, 2, SettingScope::User, "", "receipts.user_read")
                .unwrap()
                .unwrap()
                .payload,
            "false"
        );
    }

    #[test]
    fn update_retains_id_and_advances_revision() {
        let mut connection = connection();
        let first = set(
            &mut connection,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
            "true",
        );
        let second = set(
            &mut connection,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
            "false",
        );

        assert_eq!(second.id, first.id);
        assert!(second.revision > first.revision);
    }

    #[test]
    fn delete_tombstones_setting_and_records_delta_delete() {
        let mut connection = connection();
        let stored = set(
            &mut connection,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
            "true",
        );
        let transaction = connection.transaction().unwrap();
        let deleted = delete_in_tx(
            &transaction,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
        )
        .unwrap()
        .unwrap();
        transaction.commit().unwrap();
        let journal_operation: String = connection
            .query_row(
                "SELECT operation FROM sync_events WHERE entity_id = ?1 ORDER BY version DESC LIMIT 1",
                [stored.id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(deleted.id, stored.id);
        assert!(deleted.changed);
        assert_eq!(journal_operation, "delete");
        assert!(list_from_connection(&connection, 1).unwrap().is_empty());
        assert!(list_by_ids_from_connection(&connection, 1, &[stored.id])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn setting_can_be_recreated_with_the_same_id() {
        let mut connection = connection();
        let first = set(
            &mut connection,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
            "true",
        );
        let transaction = connection.transaction().unwrap();
        delete_in_tx(
            &transaction,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
        )
        .unwrap();
        transaction.commit().unwrap();
        let recreated = set(
            &mut connection,
            1,
            SettingScope::User,
            "",
            "notifications.enabled",
            "false",
        );

        assert_eq!(recreated.id, first.id);
        assert_eq!(recreated.payload, "false");
    }
}
