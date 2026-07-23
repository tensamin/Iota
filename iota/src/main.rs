use iota_cli::{
    ipc_client::IpcClient, screens::main_screen::MainScreen, theme,
    ui::start_bootstrap_tui_with_theme,
};
use iota_ipc::{LocalRequest, ResponseResult};
use iota_process_manager::detect;
use std::{path::Path, process::ExitCode, sync::Arc};

mod cli_args;
mod daemon_setup_flow;
mod local_daemon;
mod startup_error;

use cli_args::{CliInvocation, Command};
use startup_error::StartupError;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !matches!(error, StartupError::Cancelled) {
                eprintln!("{error}");
            }
            startup_error::exit_code(&error)
        }
    }
}

async fn run() -> Result<(), StartupError> {
    let invocation =
        CliInvocation::parse(std::env::args().skip(1)).map_err(StartupError::InvalidCommand)?;
    let local_endpoint = match iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
        .map_err(|error| StartupError::Other(format!("Cannot resolve user IPC path: {error}")))?
        .ipc_endpoint
    {
        iota_paths::IpcEndpoint::UnixSocket(path) => path,
        iota_paths::IpcEndpoint::WindowsPipe(name) => {
            return Err(StartupError::Other(format!(
                "Windows IPC endpoint {name} is not supported by this client build"
            )));
        }
    };
    let system_endpoint = match iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| StartupError::Other(format!("Cannot resolve system IPC path: {error}")))?
        .ipc_endpoint
    {
        iota_paths::IpcEndpoint::UnixSocket(path) => path,
        iota_paths::IpcEndpoint::WindowsPipe(name) => {
            return Err(StartupError::Other(format!(
                "Windows IPC endpoint {name} is not supported by this client build"
            )));
        }
    };
    let endpoints = daemon_setup_flow::DaemonEndpoints {
        local: local_endpoint,
        system: system_endpoint,
    };

    match invocation.command {
        Command::Help => {
            print_help();
            Ok(())
        }
        Command::Install { bundle, operator } => {
            iota_installer::install_linux_bundle_with_operator(
                Path::new(&bundle),
                operator.as_deref(),
            )
            .map_err(|error| StartupError::Other(format!("Installation failed: {error}")))
        }
        command => {
            if matches!(
                command,
                Command::DaemonEnable { .. } | Command::DaemonDisableStartup
            ) {
                return run_startup_command(command).await;
            }
            if !matches!(command, Command::Dashboard) {
                match iota_core::consent_state::non_interactive_consent() {
                    iota_core::consent_state::NonInteractiveConsent::Accepted => {}
                    iota_core::consent_state::NonInteractiveConsent::RequiresInteractiveAcceptance => {
                        return Err(StartupError::Consent("Run `iota` in an interactive terminal to review and accept the required terms.".into()));
                    }
                }
                let ipc = tokio::select! {
                    result = connect_available(&endpoints) => result?,
                    _ = tokio::signal::ctrl_c() => return Err(StartupError::Cancelled),
                };
                return run_command(ipc, command).await;
            }
            run_dashboard(invocation.theme_override, endpoints).await
        }
    }
}

async fn run_startup_command(command: Command) -> Result<(), StartupError> {
    let manager = iota_process_manager::detect()
        .await
        .ok_or_else(|| StartupError::Other("no supported process manager detected".into()))?;
    let status = match command {
        Command::DaemonEnable { mode } => {
            let mode = match mode.as_str() {
                "socket" | "socket-activated" => iota_process_manager::StartupMode::SocketActivated,
                "always-on" => iota_process_manager::StartupMode::AlwaysOn,
                _ => {
                    return Err(StartupError::InvalidCommand(
                        "--mode must be socket or always-on".into(),
                    ));
                }
            };
            manager
                .enable_startup(mode)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?
        }
        Command::DaemonDisableStartup => manager
            .disable_startup()
            .await
            .map_err(|e| StartupError::Other(e.to_string()))?,
        _ => unreachable!(),
    };
    println!("deployment status: {:?}", status.detected);
    Ok(())
}

async fn connect_available(
    endpoints: &daemon_setup_flow::DaemonEndpoints,
) -> Result<Arc<IpcClient>, StartupError> {
    match IpcClient::connect(&endpoints.local).await {
        Ok(client) => Ok(client),
        Err(local_error) => IpcClient::connect(&endpoints.system)
            .await
            .map_err(|system_error| {
                if system_error.kind() == std::io::ErrorKind::TimedOut {
                    StartupError::IpcTimedOut(endpoints.system.clone())
                } else if local_error.kind() == std::io::ErrorKind::PermissionDenied {
                    StartupError::SocketPermissionDenied(endpoints.local.clone())
                } else {
                    StartupError::Other(format!(
                        "Could not connect to {} or {}: {local_error}; {system_error}",
                        endpoints.local.display(),
                        endpoints.system.display()
                    ))
                }
            }),
    }
}

async fn run_dashboard(
    theme_override: Option<theme::ThemeName>,
    endpoints: daemon_setup_flow::DaemonEndpoints,
) -> Result<(), StartupError> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(StartupError::Terminal(
            "stdin and stdout must be interactive terminals".into(),
        ));
    }
    if std::env::var("TERM").as_deref() == Ok("dumb") {
        return Err(StartupError::Terminal(
            "TERM=dumb does not support the interactive dashboard".into(),
        ));
    }
    let session = start_bootstrap_tui_with_theme(theme::resolve(theme::UiConfig::resolve_theme(
        theme_override,
    )))
    .map_err(|error| StartupError::Terminal(error.to_string()))?;
    let ui = session.ui();
    let result = async {
        let consent = iota_core::consent_state::check(ui.clone()).await
            .map_err(StartupError::Consent)?;
        if consent != (true, true) {
            return Err(StartupError::Consent("Cannot continue until the required terms are accepted.".into()));
        }
        let initial = tokio::select! {
            result = connect_available(&endpoints) => result,
            _ = ui.wait_for_shutdown() => Err(StartupError::Cancelled),
        };
        let context = match initial {
            Ok(client) => daemon_setup_flow::ConnectionContext { ipc: client },
            Err(_) => {
                let system = tokio::select! {
                    manager = detect() => manager.ok_or(StartupError::SystemManagerUnavailable),
                    _ = ui.wait_for_shutdown() => return Err(StartupError::Cancelled),
                }?;
                // A missing unit is expected before the system daemon has
                // been installed. Keep bootstrap alive and expose that state
                // as a disabled setup option instead of treating it as a
                // fatal startup error.
                let system_capability = tokio::select! {
                    status = system.iota_startup_status() => status.map(|_| system).map_err(map_process_manager_error),
                    _ = ui.wait_for_shutdown() => return Err(StartupError::Cancelled),
                };
                let caps = daemon_setup_flow::Capabilities {
                    executable: daemon_executable(),
                    socket: writable_socket_path(&endpoints.local),
                    system: system_capability,
                };
                daemon_setup_flow::run(ui.clone(), &endpoints, caps).await?
            }
        };
        let ipc = context.ipc.clone();
        ipc.spawn_reconnector();
        ui.attach_daemon(ipc).await;
        let main_screen = MainScreen::new(ui.clone()).await;
        ui.set_root_screen(Box::new(main_screen)).await;
        ui.render().await.map_err(|error| StartupError::Terminal(error.to_string()))?;
        ui.wait_for_shutdown().await;
        Ok(())
    }.await;
    let render_failure = session.shutdown().await;
    // Terminal restoration comes first; then stop IPC background tasks with
    // their own bounded shutdown so a lost daemon cannot retain the process.
    if let Some(ipc) = ui.ipc().await {
        ipc.shutdown().await;
    }

    match (result, render_failure) {
        (Err(error), _) => Err(error),
        (Ok(()), Some(error)) => Err(StartupError::Terminal(error)),
        (Ok(()), None) => Ok(()),
    }
}

fn map_process_manager_error(error: iota_process_manager::ProcessManagerError) -> StartupError {
    use iota_process_manager::ProcessManagerErrorKind::*;
    match error.kind() {
        PermissionDenied => StartupError::SystemPermissionDenied(error.to_string()),
        TimedOut => StartupError::SystemCommandTimedOut(error.to_string()),
        _ => StartupError::Other(error.to_string()),
    }
}

fn daemon_executable() -> Result<std::path::PathBuf, StartupError> {
    let candidate = iota_paths::daemon_executable();
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(StartupError::DaemonExecutableMissing(candidate))
    }
}

fn writable_socket_path(path: &Path) -> Result<(), StartupError> {
    let parent = path.parent().ok_or_else(|| {
        StartupError::LocalSocketNotWritable(
            path.to_path_buf(),
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "socket has no parent"),
        )
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|e| StartupError::LocalSocketNotWritable(path.to_path_buf(), e))?;
    let probe = parent.join(format!(".iota-write-probe-{}", std::process::id()));
    std::fs::File::create(&probe)
        .map_err(|e| StartupError::LocalSocketNotWritable(path.to_path_buf(), e))?;
    let _ = std::fs::remove_file(probe);
    Ok(())
}

fn print_help() {
    println!(
        "Iota operator console\n\nUsage:\n  iota [--theme <name>]    Open the dashboard\n  iota daemon install --bundle <release.zip> [--operator USER]\n  iota status              Print daemon readiness and tasks\n  iota tasks               Print active tasks\n  iota users list          List users\n  iota daemon restart --yes\n  iota daemon stop --yes\n\nRun the dashboard in an interactive terminal to review required terms."
    );
}

async fn run_command(ipc: Arc<IpcClient>, command: Command) -> Result<(), StartupError> {
    let request = match command {
        Command::Status => LocalRequest::GetStatus,
        Command::Tasks => LocalRequest::ListTasks,
        Command::UsersList => LocalRequest::ListUsers,
        Command::DaemonRestart { confirmed: true } => LocalRequest::RequestProcessExit {
            intent: iota_ipc::ExitIntent::Restart,
        },
        Command::DaemonStop { confirmed: true } => LocalRequest::RequestProcessExit {
            intent: iota_ipc::ExitIntent::Stop,
        },
        Command::DaemonStopProcess => LocalRequest::RequestProcessExit {
            intent: iota_ipc::ExitIntent::Stop,
        },
        Command::DaemonDaemonStatus => LocalRequest::GetDaemonStatus,
        Command::DaemonRestart { confirmed: false } | Command::DaemonStop { confirmed: false } => {
            return Err(StartupError::InvalidCommand(
                "Refusing destructive command without --yes.".into(),
            ));
        }
        _ => {
            return Err(StartupError::InvalidCommand(
                "Command cannot be run headlessly.".into(),
            ));
        }
    };
    match ipc
        .send_request(request)
        .await
        .map_err(|e| StartupError::Other(e.to_string()))?
    {
        ResponseResult::Ok(message) => {
            println!("{message}");
            Ok(())
        }
        ResponseResult::Error(code) => Err(StartupError::Other(format!(
            "Daemon request failed: {code:?}"
        ))),
    }
}
