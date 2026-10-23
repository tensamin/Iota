mod startup;
use startup::run_startup_command;
mod dashboard;
use dashboard::{connect_available, run_dashboard};
mod help;
use help::{print_completions, print_help, print_man_page};
mod commands;
use commands::run_command;
mod output;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_cli::{
    ipc_client::IpcClient, screens::main_screen::MainScreen, theme,
    ui::start_bootstrap_tui_with_config,
};
use iota_ipc::{LocalRequest, ResponsePayload, ResponseResult};
use iota_process_manager::detect;
use output::{format_pending_operation, render_structured};
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
