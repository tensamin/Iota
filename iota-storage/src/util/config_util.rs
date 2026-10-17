use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use thiserror::Error;

pub static CONFIG: Lazy<ArcSwap<IotaConfig>> =
    Lazy::new(|| ArcSwap::new(Arc::new(IotaConfig::default())));

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid web.bind {bind:?}: {source}")]
    InvalidWebBind {
        bind: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("invalid federation endpoint {endpoint:?}: {source}")]
    InvalidFederationEndpoint {
        endpoint: String,
        #[source]
        source: iota_identity::IdentityError,
    },
    #[error("invalid relay router public key: {0}")]
    InvalidRelayRouterKey(String),
    #[error("relay router certificate path must not be empty")]
    MissingRelayRouterCertificate,
    #[error("web MTP session limits must be greater than zero")]
    InvalidMaxMtpSessions,
    #[error("max_ipc_clients must be greater than zero")]
    InvalidMaxIpcClients,
    #[error("invalid storage limit: {0}")]
    InvalidStorageLimit(&'static str),
    #[error("invalid max_relay_future_skew_millis")]
    InvalidRelayFutureSkew,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IotaConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iota_id: Option<u64>,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub web: WebSettings,
    #[serde(default)]
    pub relay_routers: Vec<RelayRouterSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omikron_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omikron_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omikron_id: Option<i64>,
    #[serde(skip_serializing)]
    pub keyring: Option<String>,
    #[serde(skip_serializing)]
    pub public_key: Option<String>,
    #[serde(skip_serializing)]
    pub private_key: Option<String>,
    #[serde(default = "default_read_receipts_enabled")]
    pub read_receipts_enabled: bool,
    #[serde(default = "default_max_ipc_clients")]
    pub max_ipc_clients: usize,
    #[serde(default)]
    pub storage_limits: StorageLimits,
    #[serde(default = "default_max_relay_future_skew_millis")]
    pub max_relay_future_skew_millis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageLimits {
    pub max_asset_bytes: i64,
    pub max_user_asset_bytes: i64,
    #[serde(default = "default_max_user_blobs")]
    pub max_user_blobs: i64,
    pub max_active_asset_uploads_per_user: usize,
    pub min_free_asset_storage_bytes: u64,
    #[serde(default = "default_max_asset_io_workers")]
    pub max_asset_io_workers: usize,
}

const fn default_max_user_blobs() -> i64 {
    4096
}

const fn default_max_asset_io_workers() -> usize {
    4
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            max_asset_bytes: 256 * 1024 * 1024,
            max_user_asset_bytes: 2 * 1024 * 1024 * 1024,
            max_user_blobs: default_max_user_blobs(),
            max_active_asset_uploads_per_user: 4,
            min_free_asset_storage_bytes: 512 * 1024 * 1024,
            max_asset_io_workers: default_max_asset_io_workers(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRouterSettings {
    pub endpoint: String,
    pub public_key: String,
    pub certificate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum WebMode {
    #[default]
    Disabled,
    Loopback,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default = "default_max_mtp_sessions")]
    pub max_mtp_sessions: usize,
    #[serde(default = "default_max_mtp_sessions_per_user")]
    pub max_mtp_sessions_per_user: usize,
    #[serde(default = "default_shutdown_budget_secs")]
    pub shutdown_budget_secs: u64,
    #[serde(default)]
    pub direct_endpoints: Vec<String>,
    #[serde(default)]
    pub relay_hints: Vec<String>,
}
const fn default_max_mtp_sessions() -> usize {
    256
}
const fn default_shutdown_budget_secs() -> u64 {
    60
}
const fn default_max_mtp_sessions_per_user() -> usize {
    4
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
            max_mtp_sessions: default_max_mtp_sessions(),
            max_mtp_sessions_per_user: default_max_mtp_sessions_per_user(),
            shutdown_budget_secs: default_shutdown_budget_secs(),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
        }
    }
}

const fn default_port() -> u16 {
    1984
}

const fn default_read_receipts_enabled() -> bool {
    true
}

const fn default_max_ipc_clients() -> usize {
    64
}

const fn default_max_relay_future_skew_millis() -> u64 {
    5 * 60 * 1_000
}

impl Default for IotaConfig {
    fn default() -> Self {
        Self {
            iota_id: None,
            port: default_port(),
            web: WebSettings::default(),
            relay_routers: Vec::new(),
            omikron_host: None,
            omikron_port: None,
            omikron_id: None,
            keyring: None,
            public_key: None,
            private_key: None,
            read_receipts_enabled: default_read_receipts_enabled(),
            max_ipc_clients: default_max_ipc_clients(),
            storage_limits: StorageLimits::default(),
            max_relay_future_skew_millis: default_max_relay_future_skew_millis(),
        }
    }
}

pub fn load_config() -> Result<(), ConfigError> {
    load_config_from(&default_config_path())
}

/// Loading is intentionally side-effect free: a missing configuration means
/// documented defaults, not a newly-created file.
pub fn load_config_from(path: &Path) -> Result<(), ConfigError> {
    let s = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            CONFIG.store(Arc::new(IotaConfig::default()));
            return Ok(());
        }
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.into(),
                source,
            });
        }
    };

    let parsed = parse_config(path, &s)?;
    CONFIG.store(Arc::new(parsed));
    Ok(())
}

fn parse_config(path: &Path, yaml: &str) -> Result<IotaConfig, ConfigError> {
    let parsed = serde_yaml::from_str::<IotaConfig>(yaml).map_err(|source| ConfigError::Parse {
        path: path.into(),
        source,
    })?;
    validate_config(&parsed)?;
    Ok(parsed)
}

pub fn validate_config(config: &IotaConfig) -> Result<(), ConfigError> {
    config
        .web
        .bind
        .parse::<std::net::IpAddr>()
        .map_err(|source| ConfigError::InvalidWebBind {
            bind: config.web.bind.clone(),
            source,
        })?;
    if config.storage_limits.max_user_blobs <= 0 {
        return Err(ConfigError::InvalidStorageLimit("max_user_blobs"));
    }
    if config.web.max_mtp_sessions == 0 || config.web.max_mtp_sessions_per_user == 0 {
        return Err(ConfigError::InvalidMaxMtpSessions);
    }
    if config.max_ipc_clients == 0 {
        return Err(ConfigError::InvalidMaxIpcClients);
    }
    if config.max_relay_future_skew_millis > super::relay_replay::MAX_RELAY_FUTURE_SKEW_MILLIS {
        return Err(ConfigError::InvalidRelayFutureSkew);
    }
    let limits = &config.storage_limits;
    if limits.max_asset_bytes <= 0 {
        return Err(ConfigError::InvalidStorageLimit("max_asset_bytes"));
    }
    if limits.max_user_asset_bytes < limits.max_asset_bytes {
        return Err(ConfigError::InvalidStorageLimit("max_user_asset_bytes"));
    }
    if limits.max_active_asset_uploads_per_user == 0 {
        return Err(ConfigError::InvalidStorageLimit(
            "max_active_asset_uploads_per_user",
        ));
    }
    if limits.max_asset_io_workers == 0 {
        return Err(ConfigError::InvalidStorageLimit("max_asset_io_workers"));
    }
    for endpoint in config
        .web
        .direct_endpoints
        .iter()
        .chain(&config.web.relay_hints)
    {
        iota_identity::AuthorityLocator::new(endpoint.clone()).map_err(|source| {
            ConfigError::InvalidFederationEndpoint {
                endpoint: endpoint.clone(),
                source,
            }
        })?;
    }
    for router in &config.relay_routers {
        iota_identity::AuthorityLocator::new(router.endpoint.clone()).map_err(|source| {
            ConfigError::InvalidFederationEndpoint {
                endpoint: router.endpoint.clone(),
                source,
            }
        })?;
        iota_identity::PublicKeyBundle::from_base64(&router.public_key)
            .map_err(|error| ConfigError::InvalidRelayRouterKey(error.to_string()))?;
        if router.certificate.trim().is_empty() {
            return Err(ConfigError::MissingRelayRouterCertificate);
        }
    }
    Ok(())
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
        if let Some(parent) = path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            eprintln!(
                "Cannot create configuration directory {}: {error}",
                parent.display()
            );
            return;
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
        "max_ipc_clients" => {
            let parsed: usize = value.parse().map_err(|_| "invalid max_ipc_clients")?;
            if parsed == 0 {
                return Err("max_ipc_clients must be greater than zero");
            }
            modify_config(|cfg| cfg.max_ipc_clients = parsed);
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
            value
                .parse::<std::net::IpAddr>()
                .map_err(|_| "invalid web.bind")?;
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

#[cfg(test)]
mod tests {
    use super::{ConfigError, IotaConfig, RelayRouterSettings, parse_config, validate_config};
    use std::path::Path;

    #[test]
    fn asset_limits_reject_invalid_quota_and_upload_count() {
        let mut config = IotaConfig::default();
        config.storage_limits.max_asset_bytes = 0;
        assert!(matches!(
            validate_config(&config),
            Err(ConfigError::InvalidStorageLimit("max_asset_bytes"))
        ));
        config.storage_limits.max_asset_bytes = 10;
        config.storage_limits.max_user_asset_bytes = 9;
        assert!(matches!(
            validate_config(&config),
            Err(ConfigError::InvalidStorageLimit("max_user_asset_bytes"))
        ));
        config.storage_limits.max_user_asset_bytes = 10;
        config.storage_limits.max_active_asset_uploads_per_user = 0;
        assert!(matches!(
            validate_config(&config),
            Err(ConfigError::InvalidStorageLimit(
                "max_active_asset_uploads_per_user"
            ))
        ));
    }

    #[test]
    fn malformed_yaml_is_rejected() {
        assert!(matches!(
            parse_config(Path::new("config.yaml"), "web: ["),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn unknown_explicit_fields_are_rejected() {
        assert!(matches!(
            parse_config(Path::new("config.yaml"), "unexpected: true\n"),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn invalid_explicit_bind_is_rejected() {
        let mut config = IotaConfig::default();
        config.web.bind = "localhost:1984".into();
        assert!(matches!(
            validate_config(&config),
            Err(ConfigError::InvalidWebBind { .. })
        ));
    }

    #[test]
    fn zero_ipc_capacity_is_rejected() {
        let config = IotaConfig {
            max_ipc_clients: 0,
            ..IotaConfig::default()
        };
        assert!(matches!(
            validate_config(&config),
            Err(ConfigError::InvalidMaxIpcClients)
        ));
    }

    #[test]
    fn relay_router_requires_valid_explicit_trust_pins() {
        let mut config = IotaConfig::default();
        config.relay_routers.push(RelayRouterSettings {
            endpoint: "router.example:1984".into(),
            public_key: "invalid".into(),
            certificate: "router.pem".into(),
        });
        assert!(matches!(
            validate_config(&config),
            Err(ConfigError::InvalidRelayRouterKey(_))
        ));
    }

    #[test]
    fn relay_router_configuration_parses_with_all_trust_material() {
        let public_key = mtp::crypto::Keyring::generate()
            .public_key_bundle()
            .try_to_base64()
            .unwrap();
        let config = parse_config(
            Path::new("config.yaml"),
            &format!(
                "relay_routers:\n  - endpoint: router.example:1984\n    public_key: {public_key}\n    certificate: router.pem\n"
            ),
        )
        .unwrap();
        assert_eq!(config.relay_routers.len(), 1);
    }
}
