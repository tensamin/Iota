use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose};
use iota_util::file_util::{read_user_credential_with_legacy, used_dir_space};
use json::{JsonValue, object};
use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: i64,
    pub username: String,
    pub public_key: String,
    pub private_key_hash: String,
    pub reset_token: String,
    pub created_at: i64,
    pub display_name: Option<String>,
    pub trusted_apps: std::collections::HashMap<String, String>,
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
        Self::new_with_created_at(
            user_id,
            username,
            display_name,
            public_key,
            private_key_hash,
            reset_token,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        )
    }

    pub fn new_with_created_at(
        user_id: i64,
        username: String,
        display_name: Option<String>,
        public_key: String,
        private_key_hash: String,
        reset_token: String,
        created_at: i64,
    ) -> Self {
        Self {
            user_id,
            username,
            display_name,
            public_key,
            private_key_hash,
            created_at,
            reset_token,
            trusted_apps: std::collections::HashMap::new(),
        }
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
        // Frontend consumers must never receive private credential material.
        obj["has_tu"] = read_user_credential_with_legacy(self.user_id, &self.username)
            .map(|credential| credential.is_some())
            .unwrap_or(false)
            .into();
        obj
    }

    /// Legacy JSON import - used when migrating from users.json to SQLite.
    pub fn from_json(j: &JsonValue) -> Option<Self> {
        let user_id = j["uuid"].as_i64()?;
        let username = j["username"].as_str()?.to_string();
        let public_key = j["public_key"].as_str()?.to_string();
        let private_key_hash = j["private_key_hash"].as_str()?.to_string();
        let reset_token = j["reset_token"].as_str()?.to_string();
        let created_at = j["created_at"].as_i64()?;
        let display_name = j["display_name"].as_str().map(|s| s.to_string());

        let mut trusted_apps = std::collections::HashMap::new();
        if j["trusted_apps"].is_object() {
            for (key, value) in j["trusted_apps"].entries() {
                if let Some(s) = value.as_str() {
                    trusted_apps.insert(key.to_string(), s.to_string());
                }
            }
        }

        Some(UserProfile {
            user_id,
            username,
            display_name,
            public_key,
            private_key_hash,
            created_at,
            reset_token,
            trusted_apps,
        })
    }

    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
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
