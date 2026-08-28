//! Platform and deployment aware locations used by Iota.
//!
//! This module deliberately keeps environment handling in one place.  In
//! particular, an override is never interpreted relative to the process
//! working directory.
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    User,
    System,
}

/// Compatibility name retained for callers which have not yet been migrated.
pub type SocketScope = Scope;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcEndpoint {
    UnixSocket(PathBuf),
    WindowsPipe(String),
}

#[derive(Debug)]
pub enum PathError {
    MissingPlatformDirectory(&'static str),
    MissingRequiredOverride(&'static str),
    EmptyOverride(&'static str),
    RelativeOverride {
        variable: &'static str,
        value: PathBuf,
    },
    InvalidPipeName(String),
    UnsupportedScope,
}
impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPlatformDirectory(name) => write!(f, "missing platform directory: {name}"),
            Self::MissingRequiredOverride(name) => write!(f, "{name} must be set"),
            Self::EmptyOverride(name) => write!(f, "{name} must not be empty"),
            Self::RelativeOverride { variable, value } => {
                write!(f, "{variable} must be absolute, got {}", value.display())
            }
            Self::InvalidPipeName(name) => write!(f, "invalid Windows pipe name: {name}"),
            Self::UnsupportedScope => write!(f, "this path scope is unsupported on this platform"),
        }
    }
}
impl std::error::Error for PathError {}

#[derive(Clone, Debug)]
pub struct IotaPaths {
    pub scope: Scope,
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub state_dir: PathBuf,
    pub storage_dir: PathBuf,
    pub identity_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: Option<PathBuf>,
    pub log_dir: PathBuf,
    /// Directory containing static web assets (not its parent).
    pub asset_dir: PathBuf,
    pub install_root: PathBuf,
    pub ipc_endpoint: IpcEndpoint,
}

impl IotaPaths {
    pub fn resolve(scope: Scope) -> Result<Self, PathError> {
        let defaults = Defaults::for_scope(scope)?;
        let data_root = if scope == Scope::User {
            absolute_env("IOTA_DATA_ROOT")?
        } else {
            None
        };
        let config_dir = override_first(&["IOTA_CONFIG_DIR"])?
            .or_else(|| data_root.as_ref().map(|root| root.join("config")))
            .unwrap_or(defaults.config_dir);
        // IOTA_DATA_DIR is intentionally only a compatibility alias.  Parse it
        // exactly like every other override; do not hide an invalid value.
        let state_dir = override_first(&["IOTA_STATE_DIR", "IOTA_DATA_DIR"])?
            .or_else(|| data_root.as_ref().map(|root| root.join("state")))
            .unwrap_or(defaults.state_dir);
        let cache_dir = override_first(&["IOTA_CACHE_DIR"])?
            .or_else(|| data_root.as_ref().map(|root| root.join("cache")))
            .unwrap_or(defaults.cache_dir);
        let runtime_dir = override_first(&["IOTA_RUNTIME_DIR"])?
            .or_else(|| data_root.as_ref().map(|root| root.join("runtime")))
            .or(defaults.runtime_dir);
        let log_dir = override_first(&["IOTA_LOG_DIR"])?
            .or_else(|| data_root.as_ref().map(|root| root.join("logs")))
            .unwrap_or(defaults.log_dir);
        let asset_dir = override_first(&["IOTA_ASSET_DIR", "IOTA_WEB_ASSET_DIR"])?
            .or_else(|| data_root.as_ref().map(|root| root.join("web")))
            .unwrap_or(defaults.asset_dir);
        let install_root = override_first(&["IOTA_INSTALL_ROOT"])?
            .or_else(|| data_root.as_ref().map(|root| root.join("bin")))
            .unwrap_or(defaults.install_root);
        let config_file = override_first(&["IOTA_CONFIG_FILE"])?
            .unwrap_or_else(|| config_dir.join("config.yaml"));
        let ipc_endpoint = resolve_ipc(scope, defaults.ipc_endpoint, data_root.as_deref())?;
        let runtime_dir = runtime_dir.or_else(|| match &ipc_endpoint {
            IpcEndpoint::UnixSocket(path) => path.parent().map(Path::to_path_buf),
            IpcEndpoint::WindowsPipe(_) => None,
        });
        Ok(Self {
            scope,
            config_dir,
            config_file,
            storage_dir: state_dir.join("storage"),
            identity_dir: state_dir.join("identity"),
            state_dir,
            cache_dir,
            runtime_dir,
            log_dir,
            asset_dir,
            install_root,
            ipc_endpoint,
        })
    }

    pub fn database_file(&self) -> PathBuf {
        self.storage_dir.join("messages.sqlite3")
    }
    pub fn keyring_file(&self) -> PathBuf {
        self.identity_dir.join("iota.mk")
    }
    pub fn update_staging_dir(&self) -> PathBuf {
        self.cache_dir.join("updates/staging")
    }
    pub fn update_status_file(&self) -> PathBuf {
        self.state_dir.join("update-status.json")
    }
    pub fn update_lock_file(&self) -> Result<PathBuf, PathError> {
        self.runtime_dir
            .as_ref()
            .map(|p| p.join("update.lock"))
            .ok_or(PathError::MissingPlatformDirectory("runtime directory"))
    }
    pub fn daemon_lock_file(&self) -> Result<PathBuf, PathError> {
        self.runtime_dir
            .as_ref()
            .map(|p| p.join("daemon.lock"))
            .ok_or(PathError::MissingPlatformDirectory("runtime directory"))
    }
    pub fn prepare_writable_directories(&self) -> std::io::Result<()> {
        for directory in [
            &self.state_dir,
            &self.storage_dir,
            &self.identity_dir,
            &self.cache_dir,
            &self.log_dir,
        ] {
            create_directory(directory, self.scope == Scope::User).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("cannot prepare {}: {error}", directory.display()),
                )
            })?;
        }
        if let Some(runtime) = &self.runtime_dir {
            create_directory(runtime, self.scope == Scope::User).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("cannot prepare {}: {error}", runtime.display()),
                )
            })?;
        }
        Ok(())
    }

    /// Move the pre-v2 resources that were all placed directly below the
    /// state root.  This is deliberately idempotent: an existing destination
    /// is never overwritten and the marker is only written after the moves.
    pub fn migrate_legacy_layout(&self) -> std::io::Result<()> {
        let marker = self.state_dir.join("path-layout-v2.json");
        if marker.exists() {
            return Ok(());
        }
        move_if_absent(&self.state_dir.join("config.yaml"), &self.config_file)?;
        move_if_absent(&self.state_dir.join("certs"), &self.config_dir.join("tls"))?;
        for suffix in [
            "messages.sqlite3",
            "messages.sqlite3-wal",
            "messages.sqlite3-shm",
        ] {
            move_if_absent(&self.state_dir.join(suffix), &self.storage_dir.join(suffix))?;
        }
        for name in ["users", "communities"] {
            move_if_absent(&self.state_dir.join(name), &self.storage_dir.join(name))?;
        }
        move_if_absent(&self.state_dir.join("iota.mk"), &self.keyring_file())?;
        move_if_absent(
            &self.state_dir.join("update-staging"),
            &self.update_staging_dir(),
        )?;
        // Runtime objects must not survive a layout migration or reboot.
        for name in ["update.lock", "iota.sock", "iota.sock.lock"] {
            let path = self.state_dir.join(name);
            if path.is_file() || path.is_symlink() {
                let _ = std::fs::remove_file(path);
            }
        }
        std::fs::create_dir_all(&self.state_dir)?;
        std::fs::write(marker, "{\"version\":2}\n")
    }
}

fn move_if_absent(source: &Path, destination: &Path) -> std::io::Result<()> {
    if !source.exists() || destination.exists() {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing symlink migration source {}", source.display()),
        ));
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc_exdev()) => {
            copy_recursively(source, destination)?;
            if source.is_dir() {
                std::fs::remove_dir_all(source)
            } else {
                std::fs::remove_file(source)
            }
        }
        Err(error) => Err(error),
    }
}

// EXDEV is stable on Unix.  A literal is used on non-Unix where the fallback
// copy is harmlessly skipped because rename normally remains on one volume.
#[cfg(unix)]
fn libc_exdev() -> i32 {
    18
}
#[cfg(not(unix))]
fn libc_exdev() -> i32 {
    -1
}
fn copy_recursively(source: &Path, destination: &Path) -> std::io::Result<()> {
    if source.is_dir() {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_recursively(&entry.path(), &destination.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(source, destination).map(|_| ())
    }
}

struct Defaults {
    config_dir: PathBuf,
    state_dir: PathBuf,
    cache_dir: PathBuf,
    runtime_dir: Option<PathBuf>,
    log_dir: PathBuf,
    asset_dir: PathBuf,
    install_root: PathBuf,
    ipc_endpoint: Option<IpcEndpoint>,
}
impl Defaults {
    fn for_scope(scope: Scope) -> Result<Self, PathError> {
        match scope {
            Scope::System => {
                #[cfg(target_os = "linux")]
                {
                    Ok(Self {
                        config_dir: "/etc/iota".into(),
                        state_dir: "/var/lib/iota".into(),
                        cache_dir: "/var/cache/iota".into(),
                        runtime_dir: Some("/run/iota".into()),
                        log_dir: "/var/log/iota".into(),
                        asset_dir: "/usr/local/share/iota/web".into(),
                        install_root: "/usr/local/libexec/iota".into(),
                        ipc_endpoint: Some(IpcEndpoint::UnixSocket("/run/iota/iota.sock".into())),
                    })
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Err(PathError::UnsupportedScope)
                }
            }
            Scope::User => user_defaults(),
        }
    }
}

#[cfg(unix)]
fn user_defaults() -> Result<Defaults, PathError> {
    let home =
        absolute_env("HOME")?.ok_or(PathError::MissingPlatformDirectory("home directory"))?;
    let config_base = xdg_or_home("XDG_CONFIG_HOME", &home, ".config")?;
    let state_base = xdg_or_home("XDG_STATE_HOME", &home, ".local/state")?;
    let cache_base = xdg_or_home("XDG_CACHE_HOME", &home, ".cache")?;
    let data_base = xdg_or_home("XDG_DATA_HOME", &home, ".local/share")?;
    Ok(Defaults {
        config_dir: config_base.join("iota"),
        state_dir: state_base.join("iota"),
        cache_dir: cache_base.join("iota"),
        runtime_dir: None,
        log_dir: state_base.join("iota/logs"),
        asset_dir: data_base.join("iota/web"),
        install_root: data_base.join("iota/bin"),
        ipc_endpoint: None,
    })
}
#[cfg(windows)]
fn user_defaults() -> Result<Defaults, PathError> {
    let config = absolute_env("APPDATA")?
        .ok_or(PathError::MissingPlatformDirectory("Roaming AppData"))?
        .join("Tensamin/Iota/config");
    let local = absolute_env("LOCALAPPDATA")?
        .ok_or(PathError::MissingPlatformDirectory("Local AppData"))?
        .join("Tensamin/Iota");
    Ok(Defaults {
        config_dir: config,
        state_dir: local.join("state"),
        cache_dir: local.join("cache"),
        runtime_dir: None,
        log_dir: local.join("logs"),
        asset_dir: local.join("data"),
        install_root: local.join("bin"),
        ipc_endpoint: Some(IpcEndpoint::WindowsPipe(
            r"\\.\pipe\Tensamin.Iota.User".into(),
        )),
    })
}

fn xdg_or_home(variable: &'static str, home: &Path, fallback: &str) -> Result<PathBuf, PathError> {
    Ok(absolute_env(variable)?.unwrap_or_else(|| home.join(fallback)))
}
fn absolute_env(name: &'static str) -> Result<Option<PathBuf>, PathError> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(PathError::EmptyOverride(name));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(PathError::RelativeOverride {
            variable: name,
            value: path,
        });
    }
    Ok(Some(path))
}
fn override_first(names: &[&'static str]) -> Result<Option<PathBuf>, PathError> {
    for name in names {
        if let Some(value) = absolute_env(name)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}
fn resolve_ipc(
    scope: Scope,
    default: Option<IpcEndpoint>,
    data_root: Option<&Path>,
) -> Result<IpcEndpoint, PathError> {
    #[cfg(unix)]
    {
        if let Some(path) = absolute_env("IOTA_SOCKET")? {
            return Ok(IpcEndpoint::UnixSocket(path));
        }
        if let Some(root) = data_root {
            return Ok(IpcEndpoint::UnixSocket(root.join("runtime/iota.sock")));
        }
        if scope == Scope::User {
            return Err(PathError::MissingRequiredOverride("IOTA_SOCKET"));
        }
    }
    #[cfg(windows)]
    {
        if let Some(name) = env::var_os("IOTA_PIPE") {
            let name = name.to_string_lossy().into_owned();
            if !name.starts_with(r"\\.\pipe\") {
                return Err(PathError::InvalidPipeName(name));
            }
            return Ok(IpcEndpoint::WindowsPipe(name));
        }
    }
    default.ok_or(PathError::UnsupportedScope)
}
fn create_directory(path: &Path, private: bool) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

// Compatibility helpers. New code should resolve IotaPaths once and pass it
// to its dependencies instead of calling these independently.
pub fn data_dir() -> PathBuf {
    IotaPaths::resolve(Scope::User)
        .expect("resolve Iota user paths")
        .state_dir
}
pub fn config_dir() -> PathBuf {
    IotaPaths::resolve(Scope::User)
        .expect("resolve Iota user paths")
        .config_dir
}
pub fn socket_override() -> Option<PathBuf> {
    absolute_env("IOTA_SOCKET").ok().flatten()
}
pub fn socket_path(scope: SocketScope) -> PathBuf {
    match IotaPaths::resolve(scope)
        .expect("resolve Iota paths")
        .ipc_endpoint
    {
        IpcEndpoint::UnixSocket(path) => path,
        IpcEndpoint::WindowsPipe(_) => panic!("Windows IPC endpoint is not a filesystem path"),
    }
}
pub fn socket_lock_path(scope: SocketScope) -> PathBuf {
    IotaPaths::resolve(scope)
        .expect("resolve Iota paths")
        .daemon_lock_file()
        .expect("runtime directory")
}
/// The compatibility installation helpers describe the machine installation,
/// not a user's data directory.  Per-user launchers should keep an
/// `IotaPaths` instance and use its `install_root` directly.
pub fn install_root() -> PathBuf {
    IotaPaths::resolve(Scope::System)
        .expect("resolve Iota system paths")
        .install_root
}
pub fn versions_dir() -> PathBuf {
    install_root().join("versions")
}
pub fn current_version_link() -> PathBuf {
    install_root().join("current")
}
pub fn updater_lock_path() -> PathBuf {
    IotaPaths::resolve(Scope::User)
        .expect("resolve Iota user paths")
        .update_lock_file()
        .expect("runtime directory")
}
pub fn updater_status_path() -> PathBuf {
    IotaPaths::resolve(Scope::User)
        .expect("resolve Iota user paths")
        .update_status_file()
}
pub fn updater_staging_dir() -> PathBuf {
    IotaPaths::resolve(Scope::User)
        .expect("resolve Iota user paths")
        .update_staging_dir()
}
pub fn web_asset_dir() -> PathBuf {
    IotaPaths::resolve(Scope::User)
        .expect("resolve Iota user paths")
        .asset_dir
}
pub fn daemon_executable() -> PathBuf {
    absolute_env("IOTA_DAEMON_PATH")
        .expect("valid IOTA_DAEMON_PATH")
        .unwrap_or_else(|| install_root().join("current/bin/iota-daemon"))
}
pub fn updater_executable() -> PathBuf {
    absolute_env("IOTA_UPDATER_PATH")
        .expect("valid IOTA_UPDATER_PATH")
        .unwrap_or_else(|| install_root().join("current/bin/iota-updater"))
}
pub fn daemon_endpoints() -> Vec<PathBuf> {
    vec![socket_path(Scope::User), socket_path(Scope::System)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    static TEST_ID: AtomicU64 = AtomicU64::new(0);
    static ENVIRONMENT: Mutex<()> = Mutex::new(());
    #[test]
    fn system_layout_is_fhs() {
        let p = IotaPaths::resolve(Scope::System).unwrap();
        assert_eq!(p.config_file, PathBuf::from("/etc/iota/config.yaml"));
        assert_eq!(
            p.database_file(),
            PathBuf::from("/var/lib/iota/storage/messages.sqlite3")
        );
        assert_eq!(
            p.update_staging_dir(),
            PathBuf::from("/var/cache/iota/updates/staging")
        );
    }

    #[test]
    fn migration_moves_state_resources_without_overwriting_destination() {
        let root = std::env::temp_dir().join(format!(
            "iota-paths-test-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let state = root.join("state");
        let config = root.join("config");
        let paths = IotaPaths {
            scope: Scope::User,
            config_dir: config.clone(),
            config_file: config.join("config.yaml"),
            storage_dir: state.join("storage"),
            identity_dir: state.join("identity"),
            cache_dir: root.join("cache"),
            runtime_dir: Some(root.join("runtime")),
            log_dir: state.join("logs"),
            asset_dir: root.join("data/web"),
            install_root: root.join("bin"),
            ipc_endpoint: IpcEndpoint::UnixSocket(root.join("runtime/iota.sock")),
            state_dir: state.clone(),
        };
        std::fs::create_dir_all(state.join("users")).unwrap();
        std::fs::write(state.join("messages.sqlite3"), b"db").unwrap();
        std::fs::write(state.join("config.yaml"), b"web: {}\n").unwrap();
        paths.migrate_legacy_layout().unwrap();
        assert!(paths.database_file().is_file());
        assert!(paths.storage_dir.join("users").is_dir());
        assert!(paths.config_file.is_file());
        assert!(state.join("path-layout-v2.json").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn data_root_keeps_unmanaged_user_paths_together() {
        let _guard = ENVIRONMENT.lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "iota-data-root-test-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        unsafe {
            std::env::set_var("IOTA_DATA_ROOT", &root);
        }
        let paths = IotaPaths::resolve(Scope::User).unwrap();
        unsafe {
            std::env::remove_var("IOTA_DATA_ROOT");
        }

        assert_eq!(paths.config_file, root.join("config/config.yaml"));
        assert_eq!(paths.state_dir, root.join("state"));
        assert_eq!(paths.cache_dir, root.join("cache"));
        assert_eq!(paths.log_dir, root.join("logs"));
        assert_eq!(paths.runtime_dir, Some(root.join("runtime")));
        assert_eq!(
            paths.ipc_endpoint,
            IpcEndpoint::UnixSocket(root.join("runtime/iota.sock"))
        );
    }
}
