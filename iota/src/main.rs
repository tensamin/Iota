use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_cli::{
    ipc_client::IpcClient, screens::main_screen::MainScreen, theme,
    ui::start_bootstrap_tui_with_config,
};
use iota_ipc::{LocalRequest, ResponsePayload, ResponseResult};
use iota_process_manager::detect;
use std::{path::Path, process::ExitCode, sync::Arc};

mod cli_args;
mod cli_color;
mod daemon_setup_flow;
mod local_daemon;
mod startup_error;
mod terms;

use cli_args::{CapabilityPolicy, CliInvocation, Command, OutputFormat};
use cli_color::ColorConfig;
use startup_error::StartupError;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !matches!(error, StartupError::Cancelled) {
                startup_error::print_error(&error);
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
        Command::TermsStatus { system } => terms::run(terms::TermsCommand::Status { system }).await,
        Command::TermsShow { document } => terms::run(terms::TermsCommand::Show { document }).await,
        Command::TermsAccept { system } => terms::run(terms::TermsCommand::Accept { system }).await,
        Command::Install { bundle, operator } => {
            iota_installer::install_linux_bundle_with_operator(
                Path::new(&bundle),
                operator.as_deref(),
            )
            .map_err(|error| StartupError::Other(format!("Installation failed: {error}")))
        }
        Command::Bootstrap { bundle, operator } => {
            iota_installer::bootstrap_linux_bundle(Path::new(&bundle), operator.as_deref())
                .map_err(|error| StartupError::Other(format!("Bootstrap failed: {error}")))
        }
        command @ (Command::UpdateCheck | Command::UpdateApply | Command::UpdateChannel { .. }) => {
            let mut updater = std::process::Command::new(
                iota_paths::current_version_link().join("bin/iota-updater"),
            );
            match command {
                Command::UpdateCheck => {
                    updater.arg("check");
                }
                Command::UpdateApply => {
                    updater.arg("apply");
                }
                Command::UpdateChannel { channel } => {
                    updater.arg("channel");
                    if let Some(channel) = channel {
                        updater.arg(channel);
                    }
                }
                _ => unreachable!(),
            }
            let status = updater
                .status()
                .map_err(|error| StartupError::Other(format!("Run updater: {error}")))?;
            if !status.success() {
                return Err(StartupError::Other(format!("Updater failed with {status}")));
            }
            Ok(())
        }
        command => {
            let endpoints = resolve_endpoints()?;
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
                let state_dir = iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
                    .map_err(|error| {
                        StartupError::Other(format!("Cannot resolve consent storage: {error}"))
                    })?
                    .state_dir;
                if !iota_terms::consent::load(&state_dir).has_all_required() {
                    return Err(StartupError::Consent("Run `iota terms accept` in an interactive terminal to review and accept the required terms.".into()));
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

fn resolve_endpoints() -> Result<daemon_setup_flow::DaemonEndpoints, StartupError> {
    let local = match iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
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
    let system = match iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
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
    Ok(daemon_setup_flow::DaemonEndpoints { local, system })
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
    let to_terminal_policy = |policy| match policy {
        CapabilityPolicy::Auto => theme::TerminalPolicy::Auto,
        CapabilityPolicy::Always => theme::TerminalPolicy::Always,
        CapabilityPolicy::Never => theme::TerminalPolicy::Never,
    };
    let session = start_bootstrap_tui_with_config(
        theme::UiConfig::resolve_theme(theme_override),
        to_terminal_policy(color_policy),
        to_terminal_policy(unicode_policy),
    )
    .map_err(|error| StartupError::Terminal(error.to_string()))?;
    let ui = session.ui();
    let result = async {
        let consent = iota_core::consent_state::check(ui.clone()).await
            .map_err(StartupError::Consent)?;
        if !consent.accepted_eula || !consent.accepted_services {
            return Err(StartupError::Consent("Cannot continue until the required terms are accepted.".into()));
        }
        persist_dashboard_consent(&consent.documents)?;
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
        ui.attach_daemon(ipc.clone()).await;
        let main_screen = MainScreen::new(ipc.clone());
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

fn persist_dashboard_consent(
    documents: &[iota_terms::LegalDocument; 3],
) -> Result<(), StartupError> {
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
        .map_err(|error| StartupError::Other(format!("Cannot resolve consent storage: {error}")))?;
    let mut record = iota_terms::consent::load(&paths.state_dir);
    for document in documents {
        record.accept(&document.metadata());
    }
    iota_terms::consent::save(&paths.state_dir, &record)
        .map_err(|error| StartupError::Consent(format!("Could not save consent: {error}")))
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
    let color = cli_color::ColorConfig::new();
    println!("{}", cli_color::heading(&color, "Iota Operator Console"));
    println!();
    println!("Usage: iota [OPTIONS] [COMMAND]");
    println!();
    println!("{}", cli_color::info(&color, "Commands:"));
    println!("  (no command)           Launch the interactive dashboard");
    println!("  status                 Show daemon status");
    println!("  tasks                  List active tasks");
    println!("  users list             List all users");
    println!("  users show <ID>        Show user details");
    println!("  users add create <NAME> Create a new user");
    println!("  users add tu <PATH>    Attach an existing account credential");
    println!("  users data purge <ID>  Purge hosted data (requires --yes)");
    println!("  users hosting release <ID> Release from this Iota (requires --yes)");
    println!("  users account delete <ID> Delete the Tensamin account (requires --yes)");
    println!("  users repair reconcile <ID> Compare local state with Omega");
    println!("  users repair diagnostics <ID> Show local lifecycle diagnostics");
    println!("  users repair force-detach <ID> Remove local management (requires --yes)");
    println!("  users forget <ID>      Forget an empty released residency (requires --yes)");
    println!("  users apps revoke <ID> <APP> Revoke a trusted app (requires --yes)");
    println!("  users apps revoke-all <ID> Revoke all TAuth grants (requires --yes)");
    println!("  users credential export <ID> --output <PATH> Export the local TU");
    println!("  apps list              List owned TAuth apps");
    println!("  apps show <APP_ID>     Show an owned TAuth app");
    println!("  apps create ...        Create and export a TAuth app");
    println!("  apps export <APP_ID> --output <PATH> Export an existing .ta");
    println!("  apps delete <APP_ID>   Delete app key and registration (requires --yes)");
    println!("  omikron status         Show Omikron connection status");
    println!("  omikron reconnect      Reconnect to Omikron");
    println!("  identity rotate        Rotate identity keys (requires --yes)");
    println!("  config get             Show current configuration");
    println!("  config set <KEY> <VAL> Set a configuration value");
    println!("  config reload          Reload configuration");
    println!("  health                 Show component health");
    println!("  components             Show component health");
    println!("  logs [--limit N]       Show recent log entries");
    println!("  update check           Check for updates");
    println!("  update apply           Apply the selected channel's signed update");
    println!("  update channel [stable|canary]  Show or select the update channel");
    println!("  community list         List communities");
    println!("  terms status           Show terms acceptance status");
    println!("  terms show <DOC>       Show a terms document");
    println!("  terms accept           Accept required terms");
    println!("  daemon restart         Restart the daemon (requires --yes)");
    println!("  daemon stop            Stop the daemon (requires --yes)");
    println!("  daemon enable          Enable daemon at startup");
    println!("  daemon disable-startup Disable daemon at startup");
    println!("  daemon startup-status  Show startup configuration");
    println!("  daemon start           Start the daemon");
    println!("  daemon restart-service Restart the daemon service");
    println!("  daemon stop-service    Stop the daemon service");
    println!("  daemon install         Install from a bundle");
    println!("  daemon bootstrap       Install and enable a Linux systemd bundle");
    println!("  help                   Show this help message");
    println!("  completions <SHELL>    Generate shell completions");
    println!("  man                    Show the man page");
    println!();
    println!("{}", cli_color::info(&color, "Options:"));
    println!("  --theme <THEME>        Theme: monospace, binary, ansi, surface");
    println!("  --output <FORMAT>      Output format: text, json, yaml, table");
    println!("  --color <WHEN>         Color: auto, always, never");
    println!("  --unicode <WHEN>       Unicode: auto, always, never");
    println!("  --no-color             Disable colored output");
    println!("  --yes, -y              Confirm destructive operations");
    println!("  -h, --help             Show help");
    println!("  -V, --version          Show version");
    println!();
    println!("{}", cli_color::info(&color, "Examples:"));
    println!("  iota                        Launch the interactive dashboard");
    println!("  iota status                 Show daemon status");
    println!("  iota users list --output=json   List users in JSON format");
    println!("  iota users add alice       Create a user named 'alice'");
    println!("  iota users data purge 42 --yes  Purge hosted data");
    println!("  iota config get --output=yaml   Show config in YAML format");
    println!("  iota logs --limit 50       Show last 50 log entries");
    println!("  iota completions bash      Generate bash completions");
    println!();
    println!("{}", cli_color::info(&color, "Exit Codes:"));
    println!("  0    Success");
    println!("  1    General error");
    println!("  2    Invalid command or arguments");
    println!("  130  Interrupted (Ctrl+C)");
    println!();
    println!("{}", cli_color::muted(&color, "Environment Variables:"));
    println!("  NO_COLOR      Disable colored output when set");
    println!("  TERM          Terminal type (dumb disables colors)");
    println!("  IOTA_THEME    Default theme override");
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
    println!(".SH DESCRIPTION");
    println!("Iota is the operator console for managing Iota daemon instances.");
    println!("It provides both an interactive dashboard and headless CLI commands.");
    println!(".SH COMMANDS");
    for command in CliInvocation::command_paths() {
        println!(".TP\n.B {command}");
    }
    println!(".SH GLOBAL OPTIONS");
    println!(".TP\n.B --output text|json|yaml|table");
    println!("Set the output format for headless commands.");
    println!(".TP\n.B --color auto|always|never");
    println!("Control colored output.");
    println!(".TP\n.B --unicode auto|always|never");
    println!("Control Unicode character rendering.");
    println!(".TP\n.B --yes, -y");
    println!("Confirm destructive operations without prompting.");
    println!(".SH EXIT CODES");
    println!(".TP\n.B 0");
    println!("Success");
    println!(".TP\n.B 1");
    println!("General error");
    println!(".TP\n.B 2");
    println!("Invalid command or arguments");
    println!(".TP\n.B 130");
    println!("Interrupted (Ctrl+C)");
    println!(".SH EXAMPLES");
    println!(".TP\n.B iota");
    println!("Launch the interactive dashboard");
    println!(".TP\n.B iota status");
    println!("Show daemon status");
    println!(".TP\n.B iota users list --output=json");
    println!("List users in JSON format");
    println!(".TP\n.B iota users add alice");
    println!("Create a user named 'alice'");
    println!(".SH ENVIRONMENT");
    println!(".TP\n.B NO_COLOR");
    println!("Disable colored output when set");
    println!(".TP\n.B TERM");
    println!("Terminal type (dumb disables colors)");
    println!(".TP\n.B IOTA_THEME");
    println!("Default theme override");
}

async fn run_command(
    ipc: Arc<IpcClient>,
    command: Command,
    output: OutputFormat,
) -> Result<(), StartupError> {
    let color = ColorConfig::new();
    let mut credential_output = None;
    let mut tauth_credential_output = None;
    let mut tauth_manifest_output = None;
    let request = match command {
        Command::Status => LocalRequest::GetStatus,
        Command::Tasks => LocalRequest::ListTasks,
        Command::UsersList => LocalRequest::ListUsers,
        Command::UsersShow { user_id } => LocalRequest::GetUser { user_id },
        Command::UsersAdd {
            username: Some(username),
            tu: None,
        } => LocalRequest::CreateUser { username },
        Command::UsersAdd {
            username: None,
            tu: Some(path),
        } => {
            let contents = std::fs::read_to_string(&path).map_err(|error| {
                StartupError::InvalidCommand(format!("Cannot read {}: {error}", path.display()))
            })?;
            iota_util::tu::TuCredential::parse(&contents).map_err(|error| {
                StartupError::InvalidCommand(format!(
                    "Invalid credential {}: {error}",
                    path.display()
                ))
            })?;
            LocalRequest::AttachUserFromTu {
                credential: iota_ipc::SecretString(contents),
            }
        }
        Command::UsersAdd { .. } => {
            return Err(StartupError::InvalidCommand(
                "users add requires exactly one of <username> or --tu <PATH>".into(),
            ));
        }
        Command::UsersRelease {
            user_id,
            confirmed: true,
        } => LocalRequest::ReleaseUser { user_id },
        Command::UsersPurgeData {
            user_id,
            confirmed: true,
        } => LocalRequest::PurgeUserData { user_id },
        Command::UsersCompleteDelete {
            user_id,
            tu,
            confirmed: true,
        } => {
            let credential = match tu {
                Some(path) => {
                    let contents = std::fs::read_to_string(&path).map_err(|error| {
                        StartupError::InvalidCommand(format!(
                            "Cannot read {}: {error}",
                            path.display()
                        ))
                    })?;
                    let parsed =
                        iota_util::tu::TuCredential::parse(&contents).map_err(|error| {
                            StartupError::InvalidCommand(format!(
                                "Invalid credential {}: {error}",
                                path.display()
                            ))
                        })?;
                    if parsed.user_id != user_id {
                        return Err(StartupError::InvalidCommand(
                            "credential user ID does not match complete-delete target".into(),
                        ));
                    }
                    Some(iota_ipc::SecretString(contents))
                }
                None => None,
            };
            LocalRequest::CompleteDeleteUser {
                user_id,
                credential,
            }
        }
        Command::UsersReconcile { user_id } => LocalRequest::ReconcileUser { user_id },
        Command::UsersDiagnostics { user_id } => LocalRequest::GetUserDiagnostics { user_id },
        Command::UsersForceDetach {
            user_id,
            confirmed: true,
        } => LocalRequest::ForceDetachUser { user_id },
        Command::UsersForget {
            user_id,
            confirmed: true,
        } => LocalRequest::ForgetReleasedUser { user_id },
        Command::UsersRevokeApp {
            user_id,
            app_id,
            confirmed: true,
        } => LocalRequest::RevokeTAuthGrant { user_id, app_id },
        Command::UsersRevokeAllApps {
            user_id,
            confirmed: true,
        } => LocalRequest::RevokeAllTAuthGrants { user_id },
        Command::UsersExportCredential { user_id, output } => {
            let daemon_status = ipc.daemon_status();
            if !daemon_status
                .borrow()
                .capabilities
                .iter()
                .any(|capability| capability == "credential_export_v1")
            {
                return Err(StartupError::InvalidCommand(
                    "The connected daemon does not support credential export.".into(),
                ));
            }
            credential_output = Some(output);
            LocalRequest::ExportUserCredential { user_id }
        }
        Command::AppsList => LocalRequest::ListTAuthApps,
        Command::AppsShow { app_id } => LocalRequest::GetTAuthApp { app_id },
        Command::AppsCreate {
            owner_user_id,
            domain,
            name,
            redirects,
            connection,
            output,
            manifest_output,
        } => {
            if output == manifest_output {
                return Err(StartupError::InvalidCommand(
                    ".ta and manifest outputs must use different paths.".into(),
                ));
            }
            for path in [&output, &manifest_output] {
                if path.exists() {
                    return Err(StartupError::InvalidCommand(format!(
                        "Refusing to overwrite {}.",
                        path.display()
                    )));
                }
            }
            tauth_credential_output = Some(output);
            tauth_manifest_output = Some(manifest_output);
            LocalRequest::CreateTAuthApp {
                owner_user_id,
                domain,
                name,
                redirects,
                connection,
            }
        }
        Command::AppsExport { app_id, output } => {
            if output.exists() {
                return Err(StartupError::InvalidCommand(format!(
                    "Refusing to overwrite {}.",
                    output.display()
                )));
            }
            tauth_credential_output = Some(output);
            LocalRequest::ExportTAuthApp { app_id }
        }
        Command::AppsDelete {
            app_id,
            confirmed: true,
        } => LocalRequest::DeleteTAuthApp { app_id },
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
        Command::Health => LocalRequest::ListComponents,
        Command::Components => LocalRequest::ListComponents,
        Command::Logs { limit } => LocalRequest::GetLogs { limit },
        Command::UpdateCheck => LocalRequest::CheckUpdate,
        Command::UpdateApply | Command::UpdateChannel { .. } => unreachable!(),
        Command::CommunityList => LocalRequest::ListCommunities,
        Command::UsersRelease {
            confirmed: false, ..
        }
        | Command::UsersPurgeData {
            confirmed: false, ..
        }
        | Command::UsersCompleteDelete {
            confirmed: false, ..
        }
        | Command::UsersForceDetach {
            confirmed: false, ..
        }
        | Command::UsersForget {
            confirmed: false, ..
        }
        | Command::UsersRevokeApp {
            confirmed: false, ..
        }
        | Command::UsersRevokeAllApps {
            confirmed: false, ..
        }
        | Command::AppsDelete {
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
        Command::Dashboard
        | Command::Help
        | Command::Version
        | Command::Completions { .. }
        | Command::ManPage
        | Command::Install { .. }
        | Command::Bootstrap { .. }
        | Command::TermsStatus { .. }
        | Command::TermsShow { .. }
        | Command::TermsAccept { .. }
        | Command::DaemonEnable { .. }
        | Command::DaemonDisableStartup
        | Command::DaemonStartupStatus
        | Command::DaemonStart
        | Command::DaemonRestartService
        | Command::DaemonStopService => {
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
            if let ResponsePayload::UserCredentialExport {
                user_id,
                username,
                credential,
            } = &payload
            {
                let path = credential_output.as_deref().ok_or_else(|| {
                    StartupError::Other(
                        "Refusing to render a credential without an export destination.".into(),
                    )
                })?;
                iota_util::atomic_file::create_private(path, credential.0.as_bytes()).map_err(
                    |error| {
                        StartupError::Other(format!(
                            "Cannot export credential to {}: {error}",
                            path.display()
                        ))
                    },
                )?;
                println!(
                    "Exported credential for {} ({}) to {}.",
                    username,
                    user_id,
                    path.display()
                );
                return Ok(());
            }
            if let ResponsePayload::TAuthAppCreated {
                app,
                credential,
                txt_record,
                manifest_template,
            } = &payload
            {
                let credential_path = tauth_credential_output.as_deref().ok_or_else(|| {
                    StartupError::Other("Missing TAuth credential export destination.".into())
                })?;
                let manifest_path = tauth_manifest_output.as_deref().ok_or_else(|| {
                    StartupError::Other("Missing TAuth manifest export destination.".into())
                })?;
                let bytes = STANDARD.decode(&credential.0).map_err(|error| {
                    StartupError::Other(format!("Daemon returned invalid .ta data: {error}"))
                })?;
                iota_util::atomic_file::create_private(credential_path, &bytes).map_err(
                    |error| {
                        StartupError::Other(format!(
                            "Cannot export credential to {}: {error}",
                            credential_path.display()
                        ))
                    },
                )?;
                if let Err(error) = iota_util::atomic_file::create_private(
                    manifest_path,
                    manifest_template.as_bytes(),
                ) {
                    let _ = std::fs::remove_file(credential_path);
                    return Err(StartupError::Other(format!(
                        "Cannot export manifest template to {}: {error}",
                        manifest_path.display()
                    )));
                }
                println!("Created TAuth app {} for {}.", app.app_id, app.domain);
                println!(".ta: {}", credential_path.display());
                println!("TXT _tauth.{}: {}", app.domain, txt_record);
                println!("Manifest: {}", manifest_path.display());
                return Ok(());
            }
            if let ResponsePayload::TAuthAppCredentialExport { app_id, credential } = &payload {
                let path = tauth_credential_output.as_deref().ok_or_else(|| {
                    StartupError::Other("Missing TAuth credential export destination.".into())
                })?;
                let bytes = STANDARD.decode(&credential.0).map_err(|error| {
                    StartupError::Other(format!("Daemon returned invalid .ta data: {error}"))
                })?;
                iota_util::atomic_file::create_private(path, &bytes).map_err(|error| {
                    StartupError::Other(format!(
                        "Cannot export credential to {}: {error}",
                        path.display()
                    ))
                })?;
                println!("Exported TAuth app {app_id} to {}.", path.display());
                return Ok(());
            }
            if credential_output.is_some() || tauth_credential_output.is_some() {
                return Err(StartupError::Other(
                    "The daemon returned an unexpected credential export response.".into(),
                ));
            }
            if !matches!(output, OutputFormat::Text) {
                return render_structured(&payload, output);
            }
            match payload {
                ResponsePayload::Status(status) => {
                    let phase_color = if status.degraded_reason.is_some() {
                        cli_color::WARNING
                    } else {
                        cli_color::SUCCESS
                    };
                    print!(
                        "{} {}",
                        cli_color::info(&color, "Phase:"),
                        color.colorize(&status.phase, phase_color)
                    );
                    if !status.tasks.is_empty() {
                        print!(
                            ", {} {}",
                            cli_color::info(&color, "Tasks:"),
                            status.tasks.join(", ")
                        );
                    }
                    if let Some(reason) = status.degraded_reason {
                        print!(", {}: {}", cli_color::warning(&color, "Degraded"), reason);
                    }
                    println!();
                }
                ResponsePayload::Tasks(tasks) => {
                    if tasks.is_empty() {
                        println!("{}", cli_color::muted(&color, "No active tasks."));
                    } else {
                        for task in &tasks {
                            println!("{}", task.name);
                        }
                    }
                }
                ResponsePayload::Users(users) => {
                    if users.is_empty() {
                        println!("{}", cli_color::muted(&color, "No users."));
                    } else {
                        println!(
                            "{:<12} {:<18} {:<10} {:<9} {:<12} PENDING",
                            "ID", "USERNAME", "STATE", "DATA", "CREDENTIAL"
                        );
                        for user in &users {
                            println!(
                                "{:<12} {:<18} {:<10} {:<9} {:<12} {}",
                                user.user_id,
                                cli_color::heading(&color, &user.username),
                                match user.state {
                                    iota_ipc::LocalUserState::Managed => "managed",
                                    iota_ipc::LocalUserState::Released => "released",
                                },
                                if user.data_present {
                                    "present"
                                } else {
                                    "empty"
                                },
                                match user.credential_status {
                                    iota_ipc::CredentialStatus::LocalPresent => "local",
                                    iota_ipc::CredentialStatus::External => "external",
                                    iota_ipc::CredentialStatus::Missing => "missing",
                                    iota_ipc::CredentialStatus::None => "none",
                                },
                                user.pending_operation
                                    .as_ref()
                                    .map(format_pending_operation)
                                    .unwrap_or_else(|| "-".into())
                            );
                        }
                    }
                }
                ResponsePayload::TAuthApps(apps) => {
                    if apps.is_empty() {
                        println!("{}", cli_color::muted(&color, "No TAuth apps."));
                    } else {
                        for app in apps {
                            println!("{} {} {}", app.app_id, app.domain, app.connection_mode);
                        }
                    }
                }
                ResponsePayload::TAuthApp(app) => {
                    println!("App ID: {}", app.app_id);
                    println!("Domain: {}", app.domain);
                    println!("Owner user: {}", app.owner_user_id);
                    println!("Mode: {}", app.connection_mode);
                    println!("Endpoint: {}", app.endpoint_url);
                }
                ResponsePayload::TAuthAppCreated { .. }
                | ResponsePayload::TAuthAppCredentialExport { .. } => {
                    return Err(StartupError::Other(
                        "Refusing to display TAuth credential material.".into(),
                    ));
                }
                ResponsePayload::InvitationCreated(invitation) => {
                    println!("Invitation: {}", invitation.invitation_id);
                    println!("Token: {}", invitation.raw_token.0);
                    if let Some(url) = invitation.short_url {
                        println!("Link: {url}");
                    }
                    println!("Expires: {}", invitation.expires_at);
                    if !invitation.mirror_synced {
                        println!("Warning: local invitation metadata is still synchronizing.");
                    }
                }
                ResponsePayload::Invitations(invitations) => {
                    if invitations.is_empty() {
                        println!("No invitations.");
                    } else {
                        for invitation in invitations {
                            println!(
                                "{} ({:?}, {:?})",
                                invitation.invitation_id, invitation.authority, invitation.state
                            );
                        }
                    }
                }
                ResponsePayload::InvitationUpdated(invitation) => {
                    println!(
                        "Invitation {} is {:?}",
                        invitation.invitation_id, invitation.state
                    );
                }
                ResponsePayload::UserCreated { user_id, username } => {
                    println!(
                        "{} {} ({})",
                        cli_color::success(&color, "Created user"),
                        cli_color::heading(&color, &username),
                        user_id
                    );
                }
                ResponsePayload::UserRemoved { user_id } => {
                    println!("{} {}", cli_color::warning(&color, "Removed user"), user_id);
                }
                ResponsePayload::UserDataPurged { user_id } => {
                    println!(
                        "{} hosted data for {}. Account remains managed by this Iota.",
                        cli_color::success(&color, "Purged"),
                        user_id
                    );
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
                    println!(
                        "{}: {}",
                        cli_color::info(&color, "Connected"),
                        status.connected
                    );
                    if let Some(id) = status.iota_id {
                        println!("{}: {}", cli_color::info(&color, "Iota ID"), id);
                    }
                }
                ResponsePayload::Components(components) => {
                    if components.is_empty() {
                        println!(
                            "{}",
                            cli_color::muted(&color, "No component health data available.")
                        );
                    } else {
                        for comp in &components {
                            let (status_str, style) = match comp.status {
                                iota_ipc::HealthStatus::Healthy => ("healthy", cli_color::SUCCESS),
                                iota_ipc::HealthStatus::Degraded => {
                                    ("degraded", cli_color::WARNING)
                                }
                                iota_ipc::HealthStatus::Failed => ("failed", cli_color::ERROR),
                            };
                            let suffix = comp
                                .message
                                .as_deref()
                                .map(|m| format!(" ({m})"))
                                .unwrap_or_default();
                            println!(
                                "{:?}: {}{}",
                                comp.id,
                                color.colorize(status_str, style),
                                suffix
                            );
                        }
                    }
                }
                ResponsePayload::UserDetail(user) => {
                    println!(
                        "{}: {} ({})",
                        cli_color::info(&color, "User"),
                        cli_color::heading(&color, &user.username),
                        user.user_id
                    );
                    if let Some(ref name) = user.display_name {
                        println!("Display Name: {name}");
                    }
                    println!("Created At: {}", user.created_at);
                    if !user.tauth_grants.is_empty() {
                        println!("TAuth grants: {}", user.tauth_grants.join(", "));
                    }
                }
                ResponsePayload::TuCredentialPreview(preview) => {
                    println!("User: {} ({})", preview.username, preview.user_id);
                    println!(
                        "Current Iota: {}",
                        preview
                            .assigned_iota_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "Unassigned".into())
                    );
                }
                ResponsePayload::UserReconciled(result) => {
                    println!("Reconciled user {}: {:?}", result.user_id, result.action);
                }
                ResponsePayload::UserDiagnostics(diagnostics) => {
                    println!("User: {} ({})", diagnostics.username, diagnostics.user_id);
                    println!("Local state: {:?}", diagnostics.local_state);
                    println!("Hosted data: {}", diagnostics.data_present);
                    println!("Credential: {:?}", diagnostics.credential_status);
                    println!("TAuth grants: {}", diagnostics.tauth_grant_count);
                    if let Some(operation) = &diagnostics.pending_operation {
                        println!("Pending operation: {operation}");
                    }
                }
                ResponsePayload::UserCredentialExport { .. } => {
                    return Err(StartupError::Other(
                        "Refusing to display credential material.".into(),
                    ));
                }
                ResponsePayload::LogEntries(logs) => {
                    for entry in &logs.entries {
                        let ts = entry.timestamp_ms;
                        let (level, style) = if entry.is_error {
                            ("ERR", cli_color::ERROR)
                        } else {
                            ("INF", cli_color::INFO)
                        };
                        println!(
                            "[{ts}] {} {}: {}",
                            color.colorize(level, style),
                            entry.sender,
                            entry.message
                        );
                    }
                }
                ResponsePayload::UpdateStatus(status) => {
                    if status.available {
                        println!("{}", cli_color::success(&color, "Update available."));
                    } else {
                        println!("{}", cli_color::info(&color, "Up to date."));
                    }
                }
                ResponsePayload::Communities(communities) => {
                    if communities.is_empty() {
                        println!("{}", cli_color::muted(&color, "No communities."));
                    } else {
                        for c in &communities {
                            println!("{} ({})", cli_color::heading(&color, &c.title), c.name);
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
    if matches!(
        payload,
        ResponsePayload::UserCredentialExport { .. }
            | ResponsePayload::TAuthAppCreated { .. }
            | ResponsePayload::TAuthAppCredentialExport { .. }
    ) {
        return Err(StartupError::Other(
            "Refusing to encode credential material as ordinary output.".into(),
        ));
    }
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
        OutputFormat::Table => render_table(payload),
        OutputFormat::Text => unreachable!(),
    }
    Ok(())
}

fn render_table(payload: &ResponsePayload) {
    match payload {
        ResponsePayload::InvitationCreated(invitation) => {
            println!("{:<15} {}", "Invitation ID", invitation.invitation_id);
            println!(
                "{:<15} {}",
                "Authority",
                format!("{:?}", invitation.authority)
            );
            println!("{:<15} {}", "Token", invitation.raw_token.0);
            println!("{:<15} {}", "Expires", invitation.expires_at);
            if let Some(url) = &invitation.short_url {
                println!("{:<15} {}", "Link", url);
            }
        }
        ResponsePayload::Invitations(invitations) => {
            println!("{:<16} {:<10} {:<14} LABEL", "ID", "AUTHORITY", "STATE");
            for invitation in invitations {
                println!(
                    "{:<16} {:<10} {:<14} {}",
                    invitation.invitation_id,
                    format!("{:?}", invitation.authority),
                    format!("{:?}", invitation.state),
                    invitation.label.as_deref().unwrap_or("-")
                );
            }
        }
        ResponsePayload::InvitationUpdated(invitation) => {
            println!("{:<15} {}", "Invitation ID", invitation.invitation_id);
            println!("{:<15} {:?}", "State", invitation.state);
        }
        ResponsePayload::Users(users) => {
            if users.is_empty() {
                println!("No users.");
                return;
            }
            println!(
                "{:<12} {:<18} {:<10} {:<9} {:<12} PENDING",
                "ID", "USERNAME", "STATE", "DATA", "CREDENTIAL"
            );
            for user in users {
                println!(
                    "{:<12} {:<18} {:<10} {:<9} {:<12} {}",
                    user.user_id,
                    user.username,
                    match user.state {
                        iota_ipc::LocalUserState::Managed => "managed",
                        iota_ipc::LocalUserState::Released => "released",
                    },
                    if user.data_present {
                        "present"
                    } else {
                        "empty"
                    },
                    match user.credential_status {
                        iota_ipc::CredentialStatus::LocalPresent => "local",
                        iota_ipc::CredentialStatus::External => "external",
                        iota_ipc::CredentialStatus::Missing => "missing",
                        iota_ipc::CredentialStatus::None => "none",
                    },
                    user.pending_operation
                        .as_ref()
                        .map(format_pending_operation)
                        .unwrap_or_else(|| "-".into())
                );
            }
        }
        ResponsePayload::TAuthApps(apps) => {
            if apps.is_empty() {
                println!("No TAuth apps.");
                return;
            }
            println!("{:<66} {:<28} MODE", "APP ID", "DOMAIN");
            for app in apps {
                println!(
                    "{:<66} {:<28} {}",
                    app.app_id, app.domain, app.connection_mode
                );
            }
        }
        ResponsePayload::TAuthApp(app) => {
            println!("{:<18} {}", "App ID", app.app_id);
            println!("{:<18} {}", "Domain", app.domain);
            println!("{:<18} {}", "Owner user", app.owner_user_id);
            println!("{:<18} {}", "Public key", app.public_key);
            println!("{:<18} {}", "Mode", app.connection_mode);
            println!("{:<18} {}", "Endpoint", app.endpoint_url);
        }
        ResponsePayload::TAuthAppCreated { .. }
        | ResponsePayload::TAuthAppCredentialExport { .. } => {
            println!("TAuth credential material withheld.");
        }
        ResponsePayload::Tasks(tasks) => {
            if tasks.is_empty() {
                println!("No active tasks.");
                return;
            }
            println!("{}", "NAME");
            println!("{}", "--------");
            for task in tasks {
                println!("{}", task.name);
            }
        }
        ResponsePayload::Components(components) => {
            if components.is_empty() {
                println!("No component health data available.");
                return;
            }
            println!("{:<20} {:<10} {}", "COMPONENT", "STATUS", "MESSAGE");
            println!("{:<20} {:<10} {}", "--------", "--------", "--------");
            for comp in components {
                let status_str = match comp.status {
                    iota_ipc::HealthStatus::Healthy => "healthy",
                    iota_ipc::HealthStatus::Degraded => "degraded",
                    iota_ipc::HealthStatus::Failed => "failed",
                };
                let message = comp.message.as_deref().unwrap_or("-");
                println!(
                    "{:<20} {:<10} {}",
                    format!("{:?}", comp.id),
                    status_str,
                    message
                );
            }
        }
        ResponsePayload::Communities(communities) => {
            if communities.is_empty() {
                println!("No communities.");
                return;
            }
            println!("{:<20} {}", "NAME", "TITLE");
            println!("{:<20} {}", "--------", "--------");
            for c in communities {
                println!("{:<20} {}", c.name, c.title);
            }
        }
        ResponsePayload::LogEntries(logs) => {
            if logs.entries.is_empty() {
                println!("No log entries.");
                return;
            }
            println!(
                "{:<20} {:<6} {:<12} {}",
                "TIMESTAMP", "LEVEL", "SENDER", "MESSAGE"
            );
            println!(
                "{:<20} {:<6} {:<12} {}",
                "--------", "--------", "--------", "--------"
            );
            for entry in &logs.entries {
                let level = if entry.is_error { "ERR" } else { "INF" };
                println!(
                    "{:<20} {:<6} {:<12} {}",
                    entry.timestamp_ms, level, entry.sender, entry.message
                );
            }
        }
        ResponsePayload::Status(status) => {
            println!("{:<15} {}", "Field", "Value");
            println!("{:<15} {}", "--------", "--------");
            println!("{:<15} {}", "Phase", status.phase);
            if !status.tasks.is_empty() {
                println!("{:<15} {}", "Tasks", status.tasks.join(", "));
            }
            if let Some(reason) = &status.degraded_reason {
                println!("{:<15} {}", "Degraded", reason);
            }
        }
        ResponsePayload::DaemonStatus(status) => {
            println!("{}", status.formatted);
        }
        ResponsePayload::Config(config) => {
            println!("{}", config.yaml);
        }
        ResponsePayload::OmikronStatus(status) => {
            println!("{:<15} {}", "Field", "Value");
            println!("{:<15} {}", "--------", "--------");
            println!("{:<15} {}", "Connected", status.connected);
            if let Some(id) = &status.iota_id {
                println!("{:<15} {}", "Iota ID", id);
            }
        }
        ResponsePayload::UpdateStatus(status) => {
            println!("{:<15} {}", "Field", "Value");
            println!("{:<15} {}", "--------", "--------");
            println!("{:<15} {}", "Available", status.available);
        }
        ResponsePayload::UserCreated { user_id, username } => {
            println!("Created user {} ({})", username, user_id);
        }
        ResponsePayload::TuCredentialPreview(preview) => {
            println!("{:<15} {}", "Username", preview.username);
            println!("{:<15} {}", "User ID", preview.user_id);
            println!(
                "{:<15} {}",
                "Current Iota",
                preview
                    .assigned_iota_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "Unassigned".into())
            );
        }
        ResponsePayload::UserReconciled(result) => {
            println!("{:<15} {}", "User ID", result.user_id);
            println!("{:<15} {:?}", "Action", result.action);
        }
        ResponsePayload::UserDiagnostics(diagnostics) => {
            println!("{:<15} {}", "Username", diagnostics.username);
            println!("{:<15} {}", "User ID", diagnostics.user_id);
            println!("{:<15} {:?}", "Local state", diagnostics.local_state);
            println!("{:<15} {}", "Hosted data", diagnostics.data_present);
            println!("{:<15} {:?}", "Credential", diagnostics.credential_status);
            println!("{:<15} {}", "TAuth grants", diagnostics.tauth_grant_count);
        }
        ResponsePayload::UserCredentialExport { .. } => {
            println!("Credential export payload withheld.");
        }
        ResponsePayload::UserRemoved { user_id } => {
            println!("Removed user {}", user_id);
        }
        ResponsePayload::UserDataPurged { user_id } => {
            println!("Purged hosted data for {}", user_id);
        }
        ResponsePayload::Acknowledged { message } => {
            println!("{}", message);
        }
        ResponsePayload::UserDetail(user) => {
            println!("{:<15} {}", "Field", "Value");
            println!("{:<15} {}", "--------", "--------");
            println!("{:<15} {}", "Username", user.username);
            println!("{:<15} {}", "User ID", user.user_id);
            if let Some(ref name) = user.display_name {
                println!("{:<15} {}", "Display Name", name);
            }
            println!("{:<15} {}", "Created At", user.created_at);
            if !user.tauth_grants.is_empty() {
                println!("{:<15} {}", "TAuth grants", user.tauth_grants.join(", "));
            }
        }
    }
}

fn format_pending_operation(operation: &iota_ipc::UserOperationSummary) -> String {
    let kind = match operation.operation {
        iota_ipc::UserOperationKind::Create => "create",
        iota_ipc::UserOperationKind::Attach => "attach",
        iota_ipc::UserOperationKind::Release => "release",
        iota_ipc::UserOperationKind::Purge => "purge",
    };
    format!("{kind}/{}", operation.phase)
}
