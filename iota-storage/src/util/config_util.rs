use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;

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
    #[serde(skip_serializing)]
    pub keyring: Option<String>,
    #[serde(skip_serializing)]
    pub public_key: Option<String>,
    #[serde(skip_serializing)]
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
    String::new()
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
    load_config_from(&default_config_path());
}

/// Loading is intentionally side-effect free: a missing configuration means
/// documented defaults, not a newly-created file.
pub fn load_config_from(path: &Path) {
    let s = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            eprintln!("Failed to read {}: {error}", path.display());
            return;
        }
    };

    match serde_yaml::from_str::<IotaConfig>(&s) {
        Ok(parsed) => {
            CONFIG.store(Arc::new(parsed));
        }
        Err(e) => {
            eprintln!("Failed to parse {}: {e}", path.display());
        }
    }
}

pub fn clear_config() {
    CONFIG.store(Arc::new(IotaConfig::default()));
    save_config();
}

pub fn save_config() {
    save_config_to(&default_config_path());
}

pub fn save_config_to(path: &Path) {
    if let Ok(yaml) = serde_yaml::to_string(&**CONFIG.load()) {
        if let Some(parent) = path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                eprintln!(
                    "Cannot create configuration directory {}: {error}",
                    parent.display()
                );
                return;
            }
        }
        if let Err(error) = iota_util::atomic_file::replace(path, yaml.as_bytes(), 3) {
            eprintln!("Cannot save {}: {error}", path.display());
        }
    }
}

fn default_config_path() -> PathBuf {
    if let Some(path) = CONFIG_PATH.get() {
        return path.clone();
    }
    iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
        .expect("resolve Iota user paths")
        .config_file
}

pub fn modify_config(f: impl FnOnce(&mut IotaConfig)) {
    let mut cfg = IotaConfig::clone(&**CONFIG.load());
    f(&mut cfg);
    CONFIG.store(Arc::new(cfg));
    save_config();
}

pub fn modify_config_value(key: &str, value: &str) -> Result<(), &'static str> {
    match key {
        "iota_id" => {
            let parsed: u64 = value.parse().map_err(|_| "invalid iota_id")?;
            modify_config(|cfg| cfg.iota_id = Some(parsed));
            Ok(())
        }
        "port" => {
            let parsed: u16 = value.parse().map_err(|_| "invalid port")?;
            modify_config(|cfg| cfg.port = parsed);
            Ok(())
        }
        "omikron_host" => {
            let host = value.to_string();
            modify_config(|cfg| cfg.omikron_host = Some(host));
            Ok(())
        }
        "omikron_port" => {
            let parsed: u16 = value.parse().map_err(|_| "invalid omikron_port")?;
            modify_config(|cfg| cfg.omikron_port = Some(parsed));
            Ok(())
        }
        "read_receipts_enabled" => {
            let parsed: bool = value.parse().map_err(|_| "invalid boolean")?;
            modify_config(|cfg| cfg.read_receipts_enabled = parsed);
            Ok(())
        }
        "web.mode" => {
            let mode = match value {
                "disabled" => WebMode::Disabled,
                "loopback" => WebMode::Loopback,
                "network" => WebMode::Network,
                _ => return Err("invalid web.mode; use disabled, loopback, or network"),
            };
            modify_config(|cfg| cfg.web.mode = mode);
            Ok(())
        }
        "web.port" => {
            let parsed: u16 = value.parse().map_err(|_| "invalid web.port")?;
            modify_config(|cfg| cfg.web.port = parsed);
            Ok(())
        }
        "web.bind" => {
            let bind = value.to_string();
            modify_config(|cfg| cfg.web.bind = bind);
            Ok(())
        }
        _ => Err("unknown config key"),
    }
}
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn configure_config_path(path: PathBuf) {
    let _ = CONFIG_PATH.set(path);
}
