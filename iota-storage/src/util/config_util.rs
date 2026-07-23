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
    #[serde(default)]
    pub web: WebSettings,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebMode {
    Disabled,
    Loopback,
    Network,
}
impl Default for WebMode {
    fn default() -> Self {
        Self::Disabled
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSettings {
    #[serde(default)]
    pub mode: WebMode,
    #[serde(default = "default_web_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_web_asset_dir")]
    pub asset_dir: String,
    pub certificate: Option<String>,
    pub key: Option<String>,
    #[serde(default)]
    pub required: bool,
}
fn default_web_bind() -> String {
    "127.0.0.1".into()
}
fn default_web_asset_dir() -> String {
    "web".into()
}
impl Default for WebSettings {
    fn default() -> Self {
        Self {
            mode: WebMode::default(),
            bind: default_web_bind(),
            port: default_port(),
            asset_dir: default_web_asset_dir(),
            certificate: None,
            key: None,
            required: false,
        }
    }
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
            web: WebSettings::default(),
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
    let s = load_file("", "config.yaml");
    if s.is_empty() {
        return;
    }

    match serde_yaml::from_str::<IotaConfig>(&s) {
        Ok(parsed) => {
            CONFIG.store(Arc::new(parsed));
        }
        Err(e) => {
            eprintln!("Failed to parse config.yaml: {}. Content: '{}'", e, s);
        }
    }
}

pub fn clear_config() {
    CONFIG.store(Arc::new(IotaConfig::default()));
    save_config();
}

pub fn save_config() {
    if let Ok(yaml) = serde_yaml::to_string(&**CONFIG.load()) {
        save_file("", "config.yaml", &yaml);
    }
}

pub fn modify_config(f: impl FnOnce(&mut IotaConfig)) {
    let mut cfg = IotaConfig::clone(&**CONFIG.load());
    f(&mut cfg);
    CONFIG.store(Arc::new(cfg));
    save_config();
}
