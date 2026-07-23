use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketScope {
    User,
    System,
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("IOTA_DATA_DIR") {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "linux")]
    {
        return std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".local/state"))
            .join("iota");
    }
    #[cfg(target_os = "macos")]
    {
        return home_dir().join("Library/Application Support/Iota");
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home_dir)
            .join("Tensamin/Iota");
    }
    #[allow(unreachable_code)]
    home_dir().join(".iota")
}
pub fn config_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("IOTA_CONFIG_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "linux")]
    {
        return std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".config"))
            .join("iota");
    }
    #[cfg(target_os = "macos")]
    {
        return home_dir().join("Library/Application Support/Iota");
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home_dir)
            .join("Tensamin/Iota");
    }
    #[allow(unreachable_code)]
    home_dir().join(".iota")
}

pub fn socket_override() -> Option<PathBuf> {
    std::env::var_os("IOTA_SOCKET").map(PathBuf::from)
}

pub fn socket_path(scope: SocketScope) -> PathBuf {
    if let Some(path) = socket_override() {
        return path;
    }
    match scope {
        SocketScope::User => data_dir().join("iota.sock"),
        SocketScope::System => PathBuf::from("/run/iota/iota.sock"),
    }
}

pub fn socket_lock_path(scope: SocketScope) -> PathBuf {
    let socket = socket_path(scope);
    PathBuf::from(format!("{}.lock", socket.display()))
}

pub fn daemon_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("IOTA_DAEMON_PATH") {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(path) = exe.parent().map(|p| p.join("iota-daemon")) {
            if path.is_file() {
                return path;
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let installed = PathBuf::from("/usr/local/lib/iota/iota-daemon");
        if installed.is_file() {
            return installed;
        }
    }
    PathBuf::from("iota-daemon")
}

pub fn updater_executable() -> PathBuf {
    std::env::var_os("IOTA_UPDATER_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("iota-updater"))
}
pub fn install_root() -> PathBuf {
    std::env::var_os("IOTA_INSTALL_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/lib/iota"))
}
pub fn versions_dir() -> PathBuf {
    install_root().join("versions")
}
pub fn current_version_link() -> PathBuf {
    install_root().join("current")
}
pub fn updater_lock_path() -> PathBuf {
    data_dir().join("update.lock")
}
pub fn updater_status_path() -> PathBuf {
    data_dir().join("update-status.json")
}
pub fn updater_staging_dir() -> PathBuf {
    data_dir().join("update-staging")
}
pub fn web_asset_dir() -> PathBuf {
    std::env::var_os("IOTA_WEB_ASSET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join("web"))
}

pub fn daemon_endpoints() -> Vec<PathBuf> {
    if let Some(path) = socket_override() {
        return vec![path];
    }
    vec![
        socket_path(SocketScope::User),
        socket_path(SocketScope::System),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_data_directory_wins() {
        assert!(!data_dir().as_os_str().is_empty());
    }
}
