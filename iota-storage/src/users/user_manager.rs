use crate::users::user_profile::UserProfile;
use crate::util::db;
use iota_util::file_util::{delete_user_directory, load_file, remove_user_credential, save_file};
use rusqlite::params;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalUserState {
    Managed,
    Released,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserResidency {
    pub user_id: i64,
    pub username: String,
    pub state: LocalUserState,
    pub data_present: bool,
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn add_user(user: UserProfile) {
    if let Err(e) = try_add_user(user) {
        eprintln!("Failed to add_user: {}", e);
    }
}

pub fn try_add_user(user: UserProfile) -> Result<(), crate::storage_error::StorageError> {
    db::with_db(|conn| {
        conn.execute(
            r#"
            INSERT INTO users (user_id, username, public_key, private_key_hash, reset_token, created_at, display_name)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                public_key = excluded.public_key,
                private_key_hash = excluded.private_key_hash,
                reset_token = excluded.reset_token,
                display_name = excluded.display_name
            "#,
            params![
                user.user_id,
                user.username,
                user.public_key,
                user.private_key_hash,
                user.reset_token,
                user.created_at,
                user.display_name,
            ],
        )?;

        for (app_id, app_secret) in &user.trusted_apps {
            conn.execute(
                r#"
                INSERT OR REPLACE INTO trusted_apps (user_id, app_id, app_secret)
                VALUES (?1, ?2, ?3)
                "#,
                params![user.user_id, app_id, app_secret],
            )?;
        }
        conn.execute(
            r#"INSERT INTO user_residency (user_id, username, lifecycle_state, data_state, updated_at)
               VALUES (?1, ?2, 'managed', COALESCE((SELECT data_state FROM user_residency WHERE user_id = ?1), 'present'), ?3)
               ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, lifecycle_state = 'managed', updated_at = excluded.updated_at"#,
            params![user.user_id, user.username, now_millis()],
        )?;
        Ok(())
    })
}

pub fn update_user(user: UserProfile) {
    add_user(user);
}

pub fn get_user_by_username(username: &str) -> Option<UserProfile> {
    match db::with_db(|conn| {
        match conn.query_row(
            "SELECT user_id, username, public_key, private_key_hash, reset_token, created_at, display_name FROM users WHERE username = ?1 LIMIT 1",
            params![username],
            |r| {
                let user_id: i64 = r.get(0)?;
                Ok(UserProfile {
                    user_id,
                    username: r.get(1)?,
                    display_name: r.get(6)?,
                    public_key: r.get(2)?,
                    private_key_hash: r.get(3)?,
                    created_at: r.get(5)?,
                    reset_token: r.get(4)?,
                    trusted_apps: load_trusted_apps(user_id),
                })
            },
        ) {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }) {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error querying user by username: {}", e);
            None
        }
    }
}

pub fn get_user(user_id: i64) -> Option<UserProfile> {
    match db::with_db(|conn| {
        match conn.query_row(
            "SELECT user_id, username, public_key, private_key_hash, reset_token, created_at, display_name FROM users WHERE user_id = ?1 LIMIT 1",
            params![user_id],
            |r| {
                let user_id: i64 = r.get(0)?;
                Ok(UserProfile {
                    user_id,
                    username: r.get(1)?,
                    display_name: r.get(6)?,
                    public_key: r.get(2)?,
                    private_key_hash: r.get(3)?,
                    created_at: r.get(5)?,
                    reset_token: r.get(4)?,
                    trusted_apps: load_trusted_apps(user_id),
                })
            },
        ) {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }) {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error querying user: {}", e);
            None
        }
    }
}

pub fn get_users() -> Vec<UserProfile> {
    match db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT user_id, username, public_key, private_key_hash, reset_token, created_at, display_name
            FROM users
            ORDER BY username
            "#,
        )?;

        let rows = stmt.query_map([], |r| {
            let user_id: i64 = r.get(0)?;
            let username: String = r.get(1)?;
            let public_key: String = r.get(2)?;
            let private_key_hash: String = r.get(3)?;
            let reset_token: String = r.get(4)?;
            let created_at: i64 = r.get(5)?;
            let display_name: Option<String> = r.get(6)?;

            Ok(UserProfile {
                user_id,
                username,
                display_name,
                public_key,
                private_key_hash,
                created_at,
                reset_token,
                trusted_apps: std::collections::HashMap::new(),
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            match row {
                Ok(mut user) => {
                    user.trusted_apps = load_trusted_apps(user.user_id);
                    out.push(user);
                }
                Err(e) => eprintln!("Failed to read user row: {}", e),
            }
        }
        Ok(out)
    }) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to query users: {}", e);
            Vec::new()
        }
    }
}

fn load_trusted_apps(user_id: i64) -> std::collections::HashMap<String, String> {
    match db::with_db(|conn| {
        let mut stmt =
            conn.prepare("SELECT app_id, app_secret FROM trusted_apps WHERE user_id = ?1")?;
        let rows = stmt.query_map(params![user_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;

        let mut map = std::collections::HashMap::new();
        for row in rows {
            if let Ok((k, v)) = row {
                map.insert(k, v);
            }
        }
        Ok(map)
    }) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to load trusted apps: {}", e);
            std::collections::HashMap::new()
        }
    }
}

pub fn remove_user(user_id: i64) {
    if let Err(e) = db::with_db(|conn| {
        conn.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        conn.execute("DELETE FROM users WHERE user_id = ?1", params![user_id])?;
        Ok(())
    }) {
        eprintln!("Failed to remove_user: {}", e);
    }
}

/// Remove only local management authority. Hosted content is intentionally
/// retained and is indexed as released for a later purge operation.
pub fn release_user(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    let username = get_user(user_id).map(|user| user.username).ok_or_else(|| {
        crate::storage_error::StorageError::Other("managed user was not found".into())
    })?;
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute("DELETE FROM users WHERE user_id = ?1", params![user_id])?;
        tx.execute(
            r#"INSERT INTO user_residency (user_id, username, lifecycle_state, data_state, updated_at)
               VALUES (?1, ?2, 'released', COALESCE((SELECT data_state FROM user_residency WHERE user_id = ?1), 'present'), ?3)
               ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, lifecycle_state = 'released', updated_at = excluded.updated_at"#,
            params![user_id, username, now_millis()],
        )?;
        tx.commit()?;
        Ok(())
    })?;
    remove_user_credential(user_id)
        .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()))
}

/// Authoritative hosted-data erasure used by local purge and future Omega
/// erasure delivery. Management metadata and credentials are left intact.
pub fn purge_user_data(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM message_edits WHERE message_id IN (SELECT id FROM messages WHERE storage_owner = ?1)", params![user_id])?;
        tx.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE storage_owner = ?1)", params![user_id])?;
        tx.execute(
            "DELETE FROM messages WHERE storage_owner = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM contacts WHERE storage_owner = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM communities WHERE storage_owner = ?1",
            params![user_id],
        )?;
        tx.execute("DELETE FROM settings WHERE user_id = ?1", params![user_id])?;
        tx.execute(
            "DELETE FROM synced_settings WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM sync_events WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM sync_heads WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM client_sync_state WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "UPDATE user_residency SET data_state = 'empty', updated_at = ?2 WHERE user_id = ?1",
            params![user_id, now_millis()],
        )?;
        tx.commit()?;
        Ok(())
    })?;
    crate::util::e2ee_storage::purge_user(user_id)
        .map_err(crate::storage_error::StorageError::Other)?;
    delete_user_directory(user_id)
        .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()))
}

/// Complete local erasure is idempotent and is the target for a durable
/// Omega-hosted erasure request after account deletion.
pub fn erase_user_locally(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    purge_user_data(user_id)?;
    db::with_db(|conn| {
        conn.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        conn.execute("DELETE FROM users WHERE user_id = ?1", params![user_id])?;
        conn.execute(
            "DELETE FROM user_residency WHERE user_id = ?1",
            params![user_id],
        )?;
        Ok(())
    })?;
    remove_user_credential(user_id)
        .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()))
}

pub fn get_residency() -> Vec<UserResidency> {
    db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT user_id, username, lifecycle_state, data_state FROM user_residency ORDER BY username")?;
        let rows = stmt.query_map([], |row| {
            let lifecycle: String = row.get(2)?;
            Ok(UserResidency {
                user_id: row.get(0)?, username: row.get(1)?,
                state: if lifecycle == "managed" { LocalUserState::Managed } else { LocalUserState::Released },
                data_present: row.get::<_, String>(3)? == "present",
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }).unwrap_or_default()
}

pub fn clear() {
    if let Err(e) = db::with_db(|conn| {
        conn.execute_batch(
            "DELETE FROM trusted_apps; DELETE FROM users; DELETE FROM user_residency;",
        )?;
        Ok(())
    }) {
        eprintln!("Failed to clear users: {}", e);
    }
}

pub fn save_users() {
    // No-op: users are auto-saved via SQLite.
}

pub fn load_users_sync() -> std::io::Result<()> {
    // Users are loaded from SQLite on demand. This function is kept for API compat.
    // If we need to migrate from a legacy users.json file, we can do so here.
    let content = load_file("", "users.json");
    if content.trim().is_empty() {
        return Ok(());
    }
    if let Ok(parsed) = json::parse(&content) {
        if let json::JsonValue::Array(arr) = parsed {
            for j in arr.iter() {
                if let Some(up) = UserProfile::from_json(j) {
                    add_user(up);
                }
            }
        }
    }
    // Rename the old file so we don't re-import
    let _ = std::fs::rename(
        std::path::PathBuf::from(iota_util::file_util::get_directory()).join("users.json"),
        std::path::PathBuf::from(iota_util::file_util::get_directory()).join("users.json.imported"),
    );
    Ok(())
}

pub fn save_app_data(user_id: i64, app_identifier: &str, data: &str) {
    let path = format!("users/{}/apps", user_id);
    let name = format!("{}.json", app_identifier);
    save_file(&path, &name, data);
}

pub fn load_app_data(user_id: i64, app_identifier: &str) -> String {
    let path = format!("users/{}/apps", user_id);
    let name = format!("{}.json", app_identifier);
    load_file(&path, &name)
}
