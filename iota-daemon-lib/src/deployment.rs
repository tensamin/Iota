use iota_ipc::{DeploymentMode, SupervisorKind};

#[derive(Clone, Copy, Debug)]
pub struct DeploymentContext {
    pub mode: DeploymentMode,
    pub supervisor: SupervisorKind,
}

impl Default for DeploymentContext {
    fn default() -> Self {
        Self {
            mode: DeploymentMode::External,
            supervisor: SupervisorKind::None,
        }
    }
}

pub fn from_environment() -> DeploymentContext {
    let mut mode = match std::env::var("IOTA_DEPLOYMENT_MODE").ok().as_deref() {
        Some("session_child") => DeploymentMode::SessionChild,
        Some("ui_auto_start") => DeploymentMode::UiAutoStart,
        Some("user_service") => DeploymentMode::UserService,
        Some("system_socket_activated") => DeploymentMode::SystemSocketActivated,
        Some("system_always_on") => DeploymentMode::SystemAlwaysOn,
        _ => DeploymentMode::External,
    };
    if std::env::var("LISTEN_FDS").ok().as_deref() == Some("1") {
        mode = DeploymentMode::SystemSocketActivated;
    }
    let supervisor = match std::env::var("IOTA_SUPERVISOR").ok().as_deref() {
        Some("iota_ui") => SupervisorKind::IotaUi,
        Some("systemd") => SupervisorKind::Systemd,
        Some("external") => SupervisorKind::External,
        _ => SupervisorKind::None,
    };
    DeploymentContext { mode, supervisor }
}
