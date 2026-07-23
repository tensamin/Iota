use crate::startup_error::StartupError;
use iota_cli::{
    ipc_client::IpcClient,
    screens::daemon_setup::{
        DaemonLaunchMode, DaemonSetupDecision, DaemonSetupScreen, DaemonStartingScreen,
        LaunchOption,
    },
    theme::UiConfig,
    ui::UI,
};
use iota_process_manager::ProcessManager;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::oneshot;

pub struct Capabilities {
    pub executable: Result<PathBuf, StartupError>,
    pub socket: Result<(), StartupError>,
    pub system: Result<Arc<dyn ProcessManager>, StartupError>,
}
pub struct DaemonEndpoints {
    pub local: PathBuf,
    pub system: PathBuf,
}
pub struct ConnectionContext {
    pub ipc: Arc<IpcClient>,
}
impl Capabilities {
    fn options(&self) -> Vec<LaunchOption> {
        let once = self
            .executable
            .as_ref()
            .and_then(|_| self.socket.as_ref())
            .map(|_| ())
            .map_err(ToString::to_string);
        let ui = once.clone();
        let system = self
            .system
            .as_ref()
            .map(|_| ())
            .map_err(ToString::to_string);
        vec![
            LaunchOption {
                mode: DaemonLaunchMode::Once,
                enabled: once.is_ok(),
                reason: once.err(),
            },
            LaunchOption {
                mode: DaemonLaunchMode::WithUi,
                enabled: ui.is_ok(),
                reason: ui.err(),
            },
            LaunchOption {
                mode: DaemonLaunchMode::WithSystem,
                enabled: system.is_ok(),
                reason: system.err(),
            },
        ]
    }
}
pub async fn run(
    ui: Arc<UI>,
    endpoints: &DaemonEndpoints,
    caps: Capabilities,
) -> Result<ConnectionContext, StartupError> {
    // Try connecting to an already-running daemon before starting a new one.
    if let Ok(ipc) = IpcClient::connect(&endpoints.local).await {
        return Ok(ConnectionContext { ipc });
    }
    let options = caps.options();
    if !options.iter().any(|o| o.enabled) {
        let _ = show(
            ui,
            options,
            "Daemon cannot be started. Correct the reported problem, then Retry, or Exit.",
        )
        .await?;
        return Err(StartupError::Cancelled);
    }
    if UiConfig::load()
        .map(|c| c.daemon_start_policy == iota_cli::theme::DaemonStartPolicy::WithUi)
        .unwrap_or(false)
        && options[0].enabled
    {
        if let Ok(context) = start_local_with_ui(
            ui.clone(),
            caps.executable.as_ref().unwrap(),
            &endpoints.local,
        )
        .await
        {
            return Ok(context);
        }
        if ui.is_shutdown() {
            return Err(StartupError::Cancelled);
        }
    }
    loop {
        let decision = show(
            ui.clone(),
            options.clone(),
            "The daemon is not running. Choose how to start it.",
        )
        .await?;
        let DaemonSetupDecision::Start(mode) = decision else {
            return Err(StartupError::Cancelled);
        };
        ui.set_root_screen(Box::new(DaemonStartingScreen)).await;
        let result = match mode {
            DaemonLaunchMode::Once | DaemonLaunchMode::WithUi => {
                start_local_with_ui(
                    ui.clone(),
                    caps.executable.as_ref().unwrap(),
                    &endpoints.local,
                )
                .await
            }
            DaemonLaunchMode::WithSystem => {
                let manager = caps.system.as_ref().unwrap();
                tokio::select! {
                    result = manager.set_iota_startup_mode(iota_process_manager::StartupMode::SocketActivated) => match result {
                        Ok(_) => tokio::select! {
                            result = IpcClient::connect_or_activate(&endpoints.system) => result.map(|ipc| ConnectionContext { ipc }).map_err(|e| StartupError::Other(e.to_string())),
                            _ = ui.wait_for_shutdown() => return Err(StartupError::Cancelled),
                        },
                        Err(e) => Err(map_process_manager_error(e)),
                    },
                    _ = ui.wait_for_shutdown() => return Err(StartupError::Cancelled),
                }
            }
        };
        if ui.is_shutdown() {
            return Err(StartupError::Cancelled);
        }
        match result {
            Ok(ipc) => {
                if mode == DaemonLaunchMode::WithUi {
                    let mut cfg =
                        UiConfig::load().map_err(|error| StartupError::Other(error.to_string()))?;
                    cfg.daemon_start_policy = iota_cli::theme::DaemonStartPolicy::WithUi;
                    cfg.save()
                        .map_err(|error| StartupError::Other(error.to_string()))?;
                }
                return Ok(ipc);
            }
            Err(error) => {
                let retry = show(
                    ui.clone(),
                    options.clone(),
                    format!("Daemon startup failed: {error}. Select an option to retry, or Exit."),
                )
                .await?;
                if matches!(retry, DaemonSetupDecision::Exit) {
                    return Err(StartupError::Cancelled);
                }
            }
        }
    }
}

fn map_process_manager_error(error: iota_process_manager::ProcessManagerError) -> StartupError {
    use iota_process_manager::ProcessManagerErrorKind;
    match error.kind() {
        ProcessManagerErrorKind::PermissionDenied => {
            StartupError::SystemPermissionDenied(error.to_string())
        }
        ProcessManagerErrorKind::TimedOut => StartupError::SystemCommandTimedOut(error.to_string()),
        _ => StartupError::Other(error.to_string()),
    }
}
async fn start_local_with_ui(
    ui: Arc<UI>,
    exe: &Path,
    path: &Path,
) -> Result<ConnectionContext, StartupError> {
    tokio::select! {
            result = crate::local_daemon::launch(ui.clone(), exe, path) => result.map(|ipc| ConnectionContext { ipc }),
        _ = ui.wait_for_shutdown() => Err(StartupError::Cancelled),
    }
}
async fn show(
    ui: Arc<UI>,
    options: Vec<LaunchOption>,
    message: impl Into<String>,
) -> Result<DaemonSetupDecision, StartupError> {
    let (tx, rx) = oneshot::channel();
    let screen = DaemonSetupScreen::new(options, message, tx).map_err(|error| {
        StartupError::Other(format!("Cannot construct daemon setup screen: {error:?}"))
    })?;
    ui.set_root_screen(Box::new(screen)).await;
    tokio::select! {
        decision = rx => Ok(decision.unwrap_or(DaemonSetupDecision::Exit)),
        _ = ui.wait_for_shutdown() => Err(StartupError::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_systemd_unit_disables_only_the_system_option() {
        let capabilities = Capabilities {
            executable: Ok(PathBuf::from("iota-daemon")),
            socket: Ok(()),
            system: Err(StartupError::Other(
                "systemd unit iota-daemon.service was not found".into(),
            )),
        };
        let options = capabilities.options();
        assert!(
            options
                .iter()
                .any(|option| option.mode == DaemonLaunchMode::Once && option.enabled)
        );
        let system = options
            .iter()
            .find(|option| option.mode == DaemonLaunchMode::WithSystem)
            .unwrap();
        assert!(!system.enabled);
        assert!(system.reason.as_deref().unwrap().contains("was not found"));
    }

    #[test]
    fn system_only_capabilities_do_not_select_disabled_local_mode() {
        let capabilities = Capabilities {
            executable: Err(StartupError::DaemonExecutableMissing(PathBuf::from(
                "iota-daemon",
            ))),
            socket: Err(StartupError::LocalSocketNotWritable(
                PathBuf::from("/tmp/iota.sock"),
                std::io::Error::other("unavailable"),
            )),
            system: Err(StartupError::Other("manager unavailable".into())),
        };
        let options = capabilities.options();
        assert!(options.iter().all(|option| !option.enabled));
    }
}
