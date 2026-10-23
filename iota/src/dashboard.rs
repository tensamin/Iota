use super::*;

pub(super) async fn connect_available(
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

pub(super) async fn run_dashboard(
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

pub(super) fn persist_dashboard_consent(
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

pub(super) fn map_process_manager_error(
    error: iota_process_manager::ProcessManagerError,
) -> StartupError {
    use iota_process_manager::ProcessManagerErrorKind::*;
    match error.kind() {
        PermissionDenied => StartupError::SystemPermissionDenied(error.to_string()),
        TimedOut => StartupError::SystemCommandTimedOut(error.to_string()),
        _ => StartupError::Other(error.to_string()),
    }
}

pub(super) fn daemon_executable() -> Result<std::path::PathBuf, StartupError> {
    let candidate = iota_paths::daemon_executable();
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(StartupError::DaemonExecutableMissing(candidate))
    }
}

pub(super) fn writable_socket_path(path: &Path) -> Result<(), StartupError> {
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
