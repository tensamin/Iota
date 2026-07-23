use crate::users::user_profile::UserProfile;
use crate::util::db;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_util::crypto_helper::{self, hex_hash, keyring_from_base64, public_key_bundle_to_base64};
use iota_util::file_util::{load_file, save_file};
use rand_core::{OsRng, RngCore};
use rusqlite::params;

pub fn add_user(user: UserProfile) {
    if let Err(e) = db::with_db(|conn| {
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
        Ok(())
    }) {
        eprintln!("Failed to add_user: {}", e);
    }
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

pub fn clear() {
    if let Err(e) = db::with_db(|conn| {
        conn.execute_batch("DELETE FROM trusted_apps; DELETE FROM users;")?;
        Ok(())
    }) {
        eprintln!("Failed to clear users: {}", e);
    }
}

#[allow(dead_code)]
pub async fn load_from_tu(username: &str) -> Result<(), ()> {
    let file_content = load_file("", &format!("{}.tu", username));
    let segments = file_content.split("::").collect::<Vec<&str>>();
    let (uuid_str, _omega_host) = segments[0].split_once('@').unwrap_or((segments[0], ""));
    let uuid = uuid_str.parse::<i64>().unwrap_or(0);
    let b64_private_key = segments[1];

    let keyring = keyring_from_base64(b64_private_key).unwrap();
    let pub_key_bundle = keyring.public_key_bundle();
    let keyring_b64 = crypto_helper::keyring_to_base64(&keyring);

    let mut bytes = [0u8; 192];
    OsRng.fill_bytes(&mut bytes);
    let reset_token = STANDARD.encode(&bytes);

    let user_profile = UserProfile::new(
        uuid,
        username.to_string(),
        Some(username.to_string()),
        public_key_bundle_to_base64(&pub_key_bundle),
        hex_hash(&keyring_b64),
        reset_token,
    );
    add_user(user_profile);
    Ok(())
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
