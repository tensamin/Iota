use iota_cli::{
    ipc_client::IpcClient, screens::main_screen::MainScreen, theme,
    ui::start_bootstrap_tui_with_theme,
};
use iota_ipc::{LocalRequest, ResponsePayload, ResponseResult};
use iota_process_manager::detect;
use std::{path::Path, process::ExitCode, sync::Arc};

mod cli_args;
mod daemon_setup_flow;
mod local_daemon;
mod startup_error;

use cli_args::{CapabilityPolicy, CliInvocation, Command, OutputFormat};
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
    let CliInvocation {
        theme_override,
        output,
        color,
        unicode,
        command,
    } = invocation;
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

    match command {
        Command::Help => {
            print_help();
            Ok(())
        }
        Command::Version => {
            println!("iota {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Completions { shell } => print_completions(&shell),
        Command::ManPage => {
            print_man_page();
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
                Command::DaemonEnable { .. }
                    | Command::DaemonDisableStartup
                    | Command::DaemonStartupStatus
                    | Command::DaemonStart
                    | Command::DaemonRestartService
                    | Command::DaemonStopService
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
                return run_command(ipc, command, output).await;
            }
            run_dashboard(theme_override, color, unicode, endpoints).await
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
        Command::DaemonStartupStatus => {
            let status = manager
                .iota_startup_status()
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("service active: {}", status.service.active);
            println!("service enabled: {}", status.service.enabled);
            println!("socket active: {}", status.socket.active);
            println!("socket enabled: {}", status.socket.enabled);
            println!("detected mode: {:?}", status.detected);
            return Ok(());
        }
        Command::DaemonStart => {
            let status = manager
                .process_action(iota_process_manager::ProcessAction::Start)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("Daemon started. detected mode: {:?}", status.detected);
            return Ok(());
        }
        Command::DaemonRestartService => {
            let status = manager
                .process_action(iota_process_manager::ProcessAction::Restart)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("Daemon restarted. detected mode: {:?}", status.detected);
            return Ok(());
        }
        Command::DaemonStopService => {
            let status = manager
                .process_action(iota_process_manager::ProcessAction::Stop)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("Daemon stopped. detected mode: {:?}", status.detected);
            return Ok(());
        }
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
    color_policy: CapabilityPolicy,
    unicode_policy: CapabilityPolicy,
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
    let stored_terminal = theme::UiConfig::load().unwrap_or_default();
    let color_policy = match color_policy {
        CapabilityPolicy::Auto => match stored_terminal.color {
            theme::TerminalPolicy::Auto => CapabilityPolicy::Auto,
            theme::TerminalPolicy::Always => CapabilityPolicy::Always,
            theme::TerminalPolicy::Never => CapabilityPolicy::Never,
        },
        policy => policy,
    };
    let unicode_policy = match unicode_policy {
        CapabilityPolicy::Auto => match stored_terminal.unicode {
            theme::TerminalPolicy::Auto => CapabilityPolicy::Auto,
            theme::TerminalPolicy::Always => CapabilityPolicy::Always,
            theme::TerminalPolicy::Never => CapabilityPolicy::Never,
        },
        policy => policy,
    };
    let color_enabled = match color_policy {
        CapabilityPolicy::Always => true,
        CapabilityPolicy::Never => false,
        CapabilityPolicy::Auto => {
            std::env::var_os("NO_COLOR").is_none()
                && std::env::var("TERM").as_deref() != Ok("dumb")
        }
    };
    let unicode_enabled = match unicode_policy {
        CapabilityPolicy::Always => true,
        CapabilityPolicy::Never => false,
        CapabilityPolicy::Auto => std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_CTYPE"))
            .or_else(|_| std::env::var("LANG"))
            .map(|locale| {
                let locale = locale.to_ascii_lowercase();
                locale.contains("utf-8") || locale.contains("utf8")
            })
            .unwrap_or(false),
    };
    let truecolor_enabled = std::env::var("COLORTERM")
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("truecolor") || value.contains("24bit")
        })
        .unwrap_or(false);
    let session = start_bootstrap_tui_with_theme(theme::resolve_with_terminal_profile(
        theme::UiConfig::resolve_theme(theme_override),
        color_enabled,
        unicode_enabled,
        truecolor_enabled,
    ))
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
    println!("{}", CliInvocation::help_text());
}

fn print_completions(shell: &str) -> Result<(), StartupError> {
    let command_paths = CliInvocation::command_paths();
    let words = command_paths
        .iter()
        .flat_map(|command| command.split_whitespace())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ");
    match shell {
        "bash" => println!(
            "_iota() {{ local words='{} --help --version --theme --output --color --unicode --yes --mode --bundle --operator'; COMPREPLY=( $(compgen -W \"$words\" -- \"${{COMP_WORDS[COMP_CWORD]}}\") ); }}\ncomplete -F _iota iota",
            words
        ),
        "zsh" => println!(
            "#compdef iota\n_arguments '1:command:({})' '*::argument:->args'",
            words
        ),
        "fish" => {
            for command in words.split_whitespace() {
                println!("complete -c iota -f -a '{command}'");
            }
        }
        _ => {
            return Err(StartupError::InvalidCommand(
                "completion shell must be bash, zsh, or fish".into(),
            ));
        }
    }
    Ok(())
}

fn print_man_page() {
    println!(".TH IOTA 1");
    println!(".SH NAME\n iota \\- Iota operator console");
    println!(".SH SYNOPSIS\n.B iota\n[global options] [command]");
    println!(".SH COMMANDS");
    for command in CliInvocation::command_paths() {
        println!(".TP\n.B {command}");
    }
    println!(".SH GLOBAL OPTIONS");
    println!(".TP\n.B --output text|json|yaml");
    println!(".TP\n.B --color auto|always|never");
    println!(".TP\n.B --unicode auto|always|never");
}

async fn run_command(
    ipc: Arc<IpcClient>,
    command: Command,
    output: OutputFormat,
) -> Result<(), StartupError> {
    let request = match command {
        Command::Status => LocalRequest::GetStatus,
        Command::Tasks => LocalRequest::ListTasks,
        Command::UsersList => LocalRequest::ListUsers,
        Command::UsersShow { user_id } => LocalRequest::GetUser { user_id },
        Command::UsersAdd { username } => LocalRequest::CreateUser { username },
        Command::UsersRemove {
            user_id,
            confirmed: true,
        } => LocalRequest::RemoveUser { user_id },
        Command::UsersImport { username } => LocalRequest::ImportUser { username },
        Command::OmikronReconnect => LocalRequest::ReconnectOmikron,
        Command::IdentityRotate { confirmed: true } => LocalRequest::RotateIotaIdentity,
        Command::RegenerateKeys { confirmed: true } => LocalRequest::RotateIotaIdentity,
        Command::DaemonRestart { confirmed: true } => LocalRequest::RequestProcessExit {
            intent: iota_ipc::ExitIntent::Restart,
        },
        Command::DaemonStop { confirmed: true } => LocalRequest::RequestProcessExit {
            intent: iota_ipc::ExitIntent::Stop,
        },
        Command::DaemonDaemonStatus => LocalRequest::GetDaemonStatus,
        Command::OmikronStatus => LocalRequest::GetOmikronStatus,
        Command::ConfigGet => LocalRequest::GetConfig,
        Command::ConfigSet { key, value } => LocalRequest::SetConfig { key, value },
        Command::ConfigReload => LocalRequest::ReloadConfig,
        Command::Components => LocalRequest::ListComponents,
        Command::Logs { limit } => LocalRequest::GetLogs { limit },
        Command::UpdateCheck => LocalRequest::CheckUpdate,
        Command::CommunityList => LocalRequest::ListCommunities,
        Command::UsersRemove {
            confirmed: false, ..
        }
        | Command::IdentityRotate { confirmed: false }
        | Command::RegenerateKeys { confirmed: false }
        | Command::DaemonRestart { confirmed: false }
        | Command::DaemonStop { confirmed: false } => {
            return Err(StartupError::InvalidCommand(
                "Refusing destructive command without --yes.".into(),
            ));
        }
        Command::Dashboard | Command::Help | Command::Version | Command::Completions { .. }
        | Command::ManPage | Command::Install { .. }
        | Command::DaemonEnable { .. } | Command::DaemonDisableStartup
        | Command::DaemonStartupStatus | Command::DaemonStart
        | Command::DaemonRestartService | Command::DaemonStopService => {
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
        ResponseResult::Ok(payload) => {
            if !matches!(output, OutputFormat::Text) {
                return render_structured(&payload, output);
            }
            match payload {
                ResponsePayload::Status(status) => {
                    print!("Phase: {}", status.phase);
                    if !status.tasks.is_empty() {
                        print!(", Tasks: {}", status.tasks.join(", "));
                    }
                    if let Some(reason) = status.degraded_reason {
                        print!(", Degraded: {}", reason);
                    }
                    println!();
                }
                ResponsePayload::Tasks(tasks) => {
                    if tasks.is_empty() {
                        println!("No active tasks.");
                    } else {
                        for task in &tasks {
                            println!("{}", task.name);
                        }
                    }
                }
                ResponsePayload::Users(users) => {
                    if users.is_empty() {
                        println!("No users.");
                    } else {
                        for user in &users {
                            println!("{} ({})", user.username, user.user_id);
                        }
                    }
                }
                ResponsePayload::UserCreated { user_id, username } => {
                    println!("Created user {} ({})", username, user_id);
                }
                ResponsePayload::UserRemoved { user_id } => {
                    println!("Removed user {}", user_id);
                }
                ResponsePayload::Acknowledged { message } => {
                    println!("{}", message);
                }
                ResponsePayload::DaemonStatus(status) => {
                    println!("{}", status.formatted);
                }
                ResponsePayload::Config(config) => {
                    println!("{}", config.yaml);
                }
                ResponsePayload::OmikronStatus(status) => {
                    println!("Connected: {}", status.connected);
                    if let Some(id) = status.iota_id {
                        println!("Iota ID: {}", id);
                    }
                }
                ResponsePayload::Components(components) => {
                    if components.is_empty() {
                        println!("No component health data available.");
                    } else {
                        for comp in &components {
                            let status_str = match comp.status {
                                iota_ipc::HealthStatus::Healthy => "healthy",
                                iota_ipc::HealthStatus::Degraded => "degraded",
                                iota_ipc::HealthStatus::Failed => "failed",
                            };
                            let suffix = comp
                                .message
                                .as_deref()
                                .map(|m| format!(" ({m})"))
                                .unwrap_or_default();
                            println!("{:?}: {}{}", comp.id, status_str, suffix);
                        }
                    }
                }
                ResponsePayload::UserDetail(user) => {
                    println!("User: {} ({})", user.username, user.user_id);
                    if let Some(ref name) = user.display_name {
                        println!("Display Name: {name}");
                    }
                    println!("Created At: {}", user.created_at);
                    if !user.trusted_apps.is_empty() {
                        println!("Trusted Apps: {}", user.trusted_apps.join(", "));
                    }
                }
                ResponsePayload::LogEntries(logs) => {
                    for entry in &logs.entries {
                        let ts = entry.timestamp_ms;
                        let level = if entry.is_error { "ERR" } else { "INF" };
                        println!("[{ts}] {level} {}: {}", entry.sender, entry.message);
                    }
                }
                ResponsePayload::UpdateStatus(status) => {
                    if status.available {
                        println!("Update available.");
                    } else {
                        println!("Up to date.");
                    }
                }
                ResponsePayload::Communities(communities) => {
                    if communities.is_empty() {
                        println!("No communities.");
                    } else {
                        for c in &communities {
                            println!("{} ({})", c.title, c.name);
                        }
                    }
                }
            }
            Ok(())
        }
        ResponseResult::Error(code) => Err(StartupError::Other(format!(
            "Daemon request failed: {code}"
        ))),
    }
}

/// The IPC payload is the versioned, tagged schema used by headless clients.
/// Text remains an operator-oriented presentation; JSON and YAML must never
/// require consumers to parse it.
fn render_structured(payload: &ResponsePayload, output: OutputFormat) -> Result<(), StartupError> {
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(payload).map_err(|error| StartupError::Other(format!(
                "Cannot encode JSON output: {error}"
            )))?
        ),
        OutputFormat::Yaml => print!(
            "{}",
            serde_yaml::to_string(payload).map_err(|error| StartupError::Other(format!(
                "Cannot encode YAML output: {error}"
            )))?
        ),
        OutputFormat::Text => unreachable!(),
    }
    Ok(())
}
