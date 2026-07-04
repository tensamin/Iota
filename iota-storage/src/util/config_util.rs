use arc_swap::ArcSwap;
use iota_util::file_util::{load_file, save_file};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub static CONFIG: Lazy<ArcSwap<IotaConfig>> =
    Lazy::new(|| ArcSwap::new(Arc::new(IotaConfig::default())));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotaConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iota_id: Option<u64>,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omikron_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omikron_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyring: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default = "default_read_receipts_enabled")]
    pub read_receipts_enabled: bool,
}

const fn default_port() -> u16 {
    1984
}

const fn default_read_receipts_enabled() -> bool {
    true
}

impl Default for IotaConfig {
    fn default() -> Self {
        Self {
            iota_id: None,
            port: default_port(),
            omikron_host: None,
            omikron_port: None,
            keyring: None,
            public_key: None,
            private_key: None,
            read_receipts_enabled: default_read_receipts_enabled(),
        }
    }
}

pub fn load_config() {
    let s = load_file("", "config.json");
    if s.is_empty() {
        return;
    }

    match serde_json::from_str::<IotaConfig>(&s) {
        Ok(parsed) => {
            CONFIG.store(Arc::new(parsed));
        }
        Err(e) => {
            eprintln!("Failed to parse config.json: {}. Content: '{}'", e, s);
        }
    }
}

pub fn clear_config() {
    CONFIG.store(Arc::new(IotaConfig::default()));
    save_config();
}

pub fn save_config() {
    if let Ok(json) = serde_json::to_string(&**CONFIG.load()) {
        save_file("", "config.json", &json);
    }
}

pub fn modify_config(f: impl FnOnce(&mut IotaConfig)) {
    let mut cfg = IotaConfig::clone(&**CONFIG.load());
    f(&mut cfg);
    CONFIG.store(Arc::new(cfg));
    save_config();
}
