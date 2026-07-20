use crate::storage_error::StorageError;
use crate::util::db;
use iota_util::file_util::get_directory;
use rusqlite::{OptionalExtension, params};
use std::fs;
use std::path::Path;

pub const GLOBAL_SESSION_ID: i64 = 0;
const GLOBAL_SETTINGS_NAME: &str = "__global__";

pub fn save(user_id: i64, session_id: i64, name: &str, payload: &str) -> Result<(), StorageError> {
    db::with_db(|conn| {
        conn.execute(
            "INSERT INTO settings (user_id, session_id, name, payload) VALUES (?1, ?2, ?3, ?4)\n             ON CONFLICT(user_id, session_id, name) DO UPDATE SET payload = excluded.payload",
            params![user_id, session_id, name, payload],
        )?;
        Ok(())
    })
}

pub fn load(user_id: i64, session_id: i64, name: &str) -> Result<Option<String>, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT payload FROM settings WHERE user_id = ?1 AND session_id = ?2 AND name = ?3",
            params![user_id, session_id, name],
            |row| row.get(0),
        )
        .optional()
        .map_err(StorageError::from)
    })
}

pub fn list(user_id: i64, session_id: i64) -> Result<Vec<String>, StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT name FROM settings WHERE user_id = ?1 AND session_id = ?2 ORDER BY name",
        )?;
        let rows = statement.query_map(params![user_id, session_id], |row| row.get(0))?;
        rows.collect::<Result<Vec<String>, _>>()
            .map_err(StorageError::from)
    })
}

pub fn save_global(user_id: i64, payload: &str) -> Result<(), StorageError> {
    save(user_id, GLOBAL_SESSION_ID, GLOBAL_SETTINGS_NAME, payload)
}

pub fn load_global(user_id: i64) -> Result<Option<String>, StorageError> {
    load(user_id, GLOBAL_SESSION_ID, GLOBAL_SETTINGS_NAME)
}

pub fn migrate_legacy_files() -> Result<(), StorageError> {
    let users_dir = Path::new(&get_directory()).join("users");
    let Ok(users) = fs::read_dir(users_dir) else {
        return Ok(());
    };

    for user_entry in users {
        let user_entry = user_entry?;
        let Ok(user_id) = user_entry.file_name().to_string_lossy().parse::<i64>() else {
            continue;
        };
        let user_dir = user_entry.path();

        migrate_file_if_missing(
            user_id,
            GLOBAL_SESSION_ID,
            GLOBAL_SETTINGS_NAME,
            &user_dir.join("global.settings"),
        )?;

        let settings_dir = user_dir.join("settings");
        let Ok(settings_entries) = fs::read_dir(settings_dir) else {
            continue;
        };
        for settings_entry in settings_entries {
            let settings_entry = settings_entry?;
            let path = settings_entry.path();
            if path.is_file() {
                if let Some(name) = setting_name(&path) {
                    migrate_file_if_missing(user_id, GLOBAL_SESSION_ID, &name, &path)?;
                }
                continue;
            }

            let Ok(session_id) = settings_entry.file_name().to_string_lossy().parse::<i64>() else {
                continue;
            };
            let Ok(device_settings) = fs::read_dir(path) else {
                continue;
            };
            for setting_entry in device_settings {
                let setting_entry = setting_entry?;
                let path = setting_entry.path();
                if let Some(name) = setting_name(&path) {
                    migrate_file_if_missing(user_id, session_id, &name, &path)?;
                }
            }
        }
    }

    Ok(())
}

fn setting_name(path: &Path) -> Option<String> {
    (path.extension()?.to_str()? == "settings").then(|| {
        path.file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string()
    })
}

fn migrate_file_if_missing(
    user_id: i64,
    session_id: i64,
    name: &str,
    path: &Path,
) -> Result<(), StorageError> {
    if !path.is_file() || load(user_id, session_id, name)?.is_some() {
        return Ok(());
    }
    let payload = fs::read_to_string(path)?;
    save(user_id, session_id, name, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn settings_schema_supports_user_and_session_keys() -> Result<(), StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE settings (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (user_id, session_id, name)
            );",
        )?;

        conn.execute(
            "INSERT INTO settings VALUES (?1, ?2, ?3, ?4)",
            params![7, 11, "theme", "dark"],
        )?;
        conn.execute(
            "INSERT INTO settings VALUES (?1, ?2, ?3, ?4)",
            params![7, 12, "theme", "light"],
        )?;

        let payload: String = conn.query_row(
            "SELECT payload FROM settings WHERE user_id = 7 AND session_id = 11 AND name = 'theme'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(payload, "dark");

        Ok(())
    }
}
