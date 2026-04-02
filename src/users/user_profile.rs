use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::file_util::{has_file, load_file, used_dir_space};
use base64::{Engine as _, engine::general_purpose};
use json::{JsonValue, object};
use rand::Rng;
use rand::rngs::OsRng;

// --- UserProfile ---
#[derive(Clone, Debug)]
pub struct UserProfile {
    pub user_id: i64,
    pub username: String,
    pub public_key: String,
    pub private_key_hash: String,
    pub reset_token: String,
    pub created_at: i64,
    pub display_name: Option<String>,
}

impl UserProfile {
    pub fn new(
        user_id: i64,
        username: String,
        display_name: Option<String>,
        public_key: String,
        private_key_hash: String,
        reset_token: String,
    ) -> Self {
        Self {
            user_id,
            username,
            display_name,
            public_key,
            private_key_hash,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
            reset_token,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        let mut obj = object! {
            "uuid" => self.user_id,
            "username" => self.username.clone(),
            "public_key" => self.public_key.clone(),
            "private_key_hash" => self.private_key_hash.clone(),
            "created_at" => self.created_at,
            "reset_token" => self.reset_token.clone()
        };
        if let Some(d) = &self.display_name {
            obj["display_name"] = d.clone().into();
        }
        obj
    }
    pub fn frontend(&self) -> JsonValue {
        let mut obj = object! {
            "uuid" => self.user_id,
            "username" => self.username.clone(),
            "public_key" => self.public_key.clone(),
            "private_key_hash" => self.private_key_hash.clone(),
            "created_at" => self.created_at,
            "storage" => used_dir_space(&format!("users/{}", self.user_id.to_string())),
        };
        if let Some(d) = &self.display_name {
            obj["display_name"] = d.clone().into();
        }
        if has_file("", &format!("{}.tu", self.username.clone())) {
            obj["tu"] = load_file("", &format!("{}.tu", self.username.clone())).into();
        }

        obj
    }
    pub async fn from_json(j: &JsonValue) -> Option<Self> {
        let user_id = j["uuid"].as_i64()?;
        let username = j["username"].as_str()?.to_string();
        let public_key = j["public_key"].as_str()?.to_string();
        let private_key_hash = j["private_key_hash"].as_str()?.to_string();
        let reset_token = j["reset_token"].as_str()?.to_string();
        let created_at = j["created_at"].as_i64()?;
        let display_name = j["display_name"].as_str().map(|s| s.to_string());

        let up = UserProfile {
            user_id,
            username,
            display_name,
            public_key,
            private_key_hash,
            created_at,
            reset_token,
        };

        // TODO: Migrate to Omikron / Wss
        /* if j.has_key("migrate")
            || j.has_key("migrating")
            || j.has_key("changing")
            || j.has_key("move")
            || j.has_key("moving")
        {
            if auth_connector::migrate_user(&mut up).await {
                log_message(format!("[INFO] Migration triggered for {}", up.username));
                user_manager::set_unique(true);
            }
        } */

        Some(up)
    }

    #[allow(dead_code)]
    pub fn randomize_reset_token(&mut self) -> String {
        let mut bytes = [0u8; 192];
        OsRng.fill(bytes.as_mut());
        let new_token = general_purpose::STANDARD.encode(&bytes);
        self.reset_token = new_token.clone();
        new_token
    }

    #[allow(dead_code)]
    pub fn get_display_name(&self) -> String {
        self.display_name
            .clone()
            .unwrap_or_else(|| self.username.clone())
    }
}
