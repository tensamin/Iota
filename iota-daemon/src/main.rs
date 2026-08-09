use iota_daemon_lib::{
    DaemonRuntime, DaemonServices, IpcServer, ShutdownReason, StartupPhase, log_broadcaster,
    log_buffer::LogBuffer,
};
use iota_logger::{self as logger, log};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::CONFIG;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, watch};
#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let scope = match std::env::var("IOTA_DEPLOYMENT_MODE").ok().as_deref() {
        Some("system_socket_activated") | Some("system_always_on") => iota_paths::Scope::System,
        _ => iota_paths::Scope::User,
    };
    let paths = match iota_paths::IotaPaths::resolve(scope) {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("Cannot resolve Iota paths: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Bind a deliberately dormant IPC daemon before terms are accepted.  This
    // makes socket activation and `iota terms accept --system` usable, while
    // the router exposes status only and the inactive service cannot connect.
    if !iota_terms::consent::load(&paths.state_dir).has_all_required() {
        let socket = match &paths.ipc_endpoint {
            iota_paths::IpcEndpoint::UnixSocket(path) => path.clone(),
            iota_paths::IpcEndpoint::WindowsPipe(_) => {
                eprintln!("Windows named-pipe daemon transport is not implemented yet");
                return ExitCode::FAILURE;
            }
        };
        let runtime = Arc::new(DaemonRuntime::new());
        let (log_tx, _) = broadcast::channel(64);
        let log_buffer = Arc::new(Mutex::new(LogBuffer::new(64)));
        let (_, state_rx) = watch::channel(runtime.snapshot());
        let server = match IpcServer::bind(
            socket,
            runtime.clone(),
            DaemonServices::inactive(),
            log_tx,
            log_buffer,
            state_rx,
        )
        .await
        {
            Ok(server) => server,
            Err(error) => {
                eprintln!("Cannot bind dormant daemon IPC socket: {error}");
                return ExitCode::FAILURE;
            }
        };
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        eprintln!(
            "Iota daemon is awaiting terms acceptance. Run `iota terms accept{}` in an interactive terminal.",
            if paths.scope == iota_paths::Scope::System {
                " --system"
            } else {
                ""
            }
        );
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if iota_terms::consent::load(&paths.state_dir).has_all_required() {
                        // systemd restarts this daemon; a locally-launched daemon can
                        // simply be started again after accepting the documents.
                        return ExitCode::from(75);
                    }
                }
                _ = tokio::signal::ctrl_c() => return ExitCode::SUCCESS,
            }
        }
    }
    if let Err(error) = paths.migrate_legacy_layout() {
        eprintln!("Cannot migrate legacy Iota layout: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = paths.prepare_writable_directories() {
        eprintln!("Cannot prepare Iota directories: {error}");
        return ExitCode::FAILURE;
    }
    iota_util::file_util::configure_storage_directory(paths.storage_dir.clone());
    iota_storage::util::config_util::configure_config_path(paths.config_file.clone());
    iota_storage::util::config_util::load_config_from(&paths.config_file);
    omikron_connector::omikron_connection::configure_identity_path(paths.keyring_file());
    match paths.scope {
        iota_paths::Scope::User => logger::startup_with_log_dir(Some(paths.log_dir.clone())),
        iota_paths::Scope::System => logger::startup_with_log_dir(None),
    }

    let runtime = Arc::new(DaemonRuntime::new());
    // --- IPC infrastructure ---
    let (log_tx, _) = broadcast::channel(512);
    let log_buffer = Arc::new(Mutex::new(LogBuffer::new(1024)));
    log_broadcaster::spawn(log_tx.clone(), log_buffer.clone());
    let (state_tx, state_rx) = watch::channel(runtime.snapshot());

    runtime.set_startup_phase(StartupPhase::LoadingUsers);
    if tokio::task::spawn_blocking(user_manager::load_users_sync)
        .await
        .ok()
        .and_then(Result::ok)
        .is_none()
    {
        runtime.set_component_failed(
            iota_ipc::ComponentId::Storage,
            "user storage failed to load".into(),
        );
    } else {
        runtime.set_component_healthy(iota_ipc::ComponentId::Storage, None);
    }

    // Bind before migration and service startup: a successful bind is the
    // readiness boundary visible to clients and socket activation.
    let socket = match &paths.ipc_endpoint {
        iota_paths::IpcEndpoint::UnixSocket(path) => path.clone(),
        iota_paths::IpcEndpoint::WindowsPipe(_) => {
            eprintln!("Windows named-pipe daemon transport is not implemented yet");
            return ExitCode::FAILURE;
        }
    };
    let omikron = match omikron_connector::omikron_connection::connect_initial(
        runtime.cancellation.clone(),
        runtime.state.active_tasks.clone(),
        runtime.state.app.clone(),
    )
    .await
    {
        Ok(connection) => connection,
        Err(omikron_connector::OmikronStartupError::InitialConnectionTimeout { connection }) => {
            runtime.set_component_degraded(
                iota_ipc::ComponentId::Omikron,
                "Omikron connection unavailable; retrying".into(),
            );
            connection
        }
        Err(omikron_connector::OmikronStartupError::Authentication { connection }) => {
            runtime.set_component_failed(
                iota_ipc::ComponentId::Omikron,
                "Omikron authentication failed; regenerate the Iota identity to register again"
                    .into(),
            );
            // Keep IPC alive: identity rotation is the supported recovery
            // action and must remain available after authentication fails.
            connection
        }
        Err(omikron_connector::OmikronStartupError::Construction(error)) => {
            eprintln!("Cannot construct Omikron connection: {error}");
            return ExitCode::FAILURE;
        }
    };
    let omikron_health = omikron.clone();
    let omikron_reconcile = omikron.clone();
    let services = DaemonServices::new(omikron);
    let health_runtime = runtime.clone();
    runtime
        .tasks
        .spawn_tracked("omikron-health", async move {
            let mut states = omikron_health.connection_state();
            loop {
                let state = *states.borrow();
                match state {
                    omikron_connector::omikron_connection::ConnectionState::Connected {
                        ..
                    } => {
                        let ping_ms = *omikron_health.last_ping.lock().await;
                        let message = if ping_ms >= 0 {
                            format!("connected (RTT: {ping_ms} ms)")
                        } else {
                            "connected (waiting for RTT sample)".into()
                        };
                        health_runtime
                            .set_component_healthy(iota_ipc::ComponentId::Omikron, Some(message));
                    }
                    omikron_connector::omikron_connection::ConnectionState::Connecting => {
                        health_runtime.set_component_degraded(
                            iota_ipc::ComponentId::Omikron,
                            "connecting to Omikron".into(),
                        );
                    }
                    omikron_connector::omikron_connection::ConnectionState::Disconnected => {
                        let message = omikron_health
                            .get_auth_failure()
                            .await
                            .unwrap_or_else(|| "disconnected; retrying".into());
                        if omikron_health.has_auth_failure().await {
                            health_runtime
                                .set_component_failed(iota_ipc::ComponentId::Omikron, message);
                        } else {
                            health_runtime
                                .set_component_degraded(iota_ipc::ComponentId::Omikron, message);
                        }
                    }
                }
                tokio::select! {
                    changed = states.changed() => if changed.is_err() { break },
                    // RTT is updated by MTP's heartbeat independently of a
                    // connection-state transition, so periodically refresh
                    // the component detail while connected.
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                    _ = health_runtime.cancellation.cancelled() => break,
                }
            }
            Ok(())
        })
        .await;
    runtime
        .tasks
        .spawn_tracked("user-lifecycle-reconciliation", async move {
            let mut states = omikron_reconcile.connection_state();
            loop {
                if matches!(*states.borrow(), omikron_connector::omikron_connection::ConnectionState::Connected { .. }) {
                    omikron_connector::user_ops::reconcile_managed_users(omikron_reconcile.as_ref()).await;
                }
                tokio::select! {
                    changed = states.changed() => if changed.is_err() { break },
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                }
            }
            Ok(())
        })
        .await;
    let ipc_server = match IpcServer::bind(
        socket.clone(),
        runtime.clone(),
        services,
        log_tx.clone(),
        log_buffer.clone(),
        state_rx,
    )
    .await
    {
        Ok(server) => server,
        Err(error) => {
            eprintln!("Cannot bind daemon IPC socket: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("iota-daemon IPC listener ready at {}", socket.display());
    runtime.set_component_healthy(iota_ipc::ComponentId::Ipc, None);
    let listener_runtime = runtime.clone();
    runtime
        .tasks
        .spawn_tracked("ipc-server", async move {
            if let Err(error) = ipc_server.serve().await {
                eprintln!("iota-daemon IPC server failed: {error}");
                listener_runtime.shutdown(ShutdownReason::Fatal(format!(
                    "IPC listener stopped: {error}"
                )));
            }
            Ok(())
        })
        .await;
    log!("iota-daemon IPC server ready");

    log!(
        "iota-daemon paths (scope={:?}): config={} state={} storage={} identity={} cache={} log={} asset={} ipc={}",
        paths.scope,
        paths.config_file.display(),
        paths.state_dir.display(),
        paths.storage_dir.display(),
        paths.identity_dir.display(),
        paths.cache_dir.display(),
        paths.log_dir.display(),
        paths.asset_dir.display(),
        match &paths.ipc_endpoint {
            iota_paths::IpcEndpoint::UnixSocket(p) => p.display().to_string(),
            iota_paths::IpcEndpoint::WindowsPipe(n) => n.clone(),
        },
    );
    runtime.set_startup_phase(StartupPhase::StartingServices);

    // --- System monitor ---
    runtime.spawn_system_monitor().await;

    // --- State update publisher (watch-based, no full broadcast per tick) ---
    let state_publisher = runtime.clone();
    runtime
        .tasks
        .spawn_tracked("state-publisher", async move {
            loop {
                if state_publisher.is_shutting_down() {
                    break;
                }
                let snapshot = state_publisher.snapshot();
                let _ = state_tx.send(snapshot);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(())
        })
        .await;

    // --- Web server ---
    let web = CONFIG.load().web.clone();
    let web_config = web_server::WebConfig {
        mode: match web.mode {
            iota_storage::util::config_util::WebMode::Disabled => web_server::WebMode::Disabled,
            iota_storage::util::config_util::WebMode::Loopback => web_server::WebMode::Loopback,
            iota_storage::util::config_util::WebMode::Network => web_server::WebMode::Network,
        },
        bind: web
            .bind
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        port: web.port,
        asset_dir: resolve_config_path(&paths.config_file, &web.asset_dir, &paths.asset_dir),
        tls: web
            .certificate
            .zip(web.key)
            .map(|(certificate, key)| web_server::TlsConfig {
                certificate: resolve_config_path(
                    &paths.config_file,
                    &certificate,
                    &paths.config_dir,
                ),
                key: resolve_config_path(&paths.config_file, &key, &paths.config_dir),
            }),
        required: web.required,
    };
    match web_server::start(web_config, runtime.cancellation.clone()).await {
        Ok(None) => {
            runtime.set_component_healthy(iota_ipc::ComponentId::Web, Some("disabled".into()))
        }
        Ok(Some(handle)) => {
            runtime.set_component_healthy(iota_ipc::ComponentId::Web, None);
            runtime
                .tasks
                .spawn_tracked("web-server", async move {
                    handle.join().await;
                    Ok(())
                })
                .await;
        }
        Err(error) if web.required => {
            runtime.set_component_failed(iota_ipc::ComponentId::Web, error.to_string());
        }
        Err(error) => {
            runtime.set_component_degraded(iota_ipc::ComponentId::Web, error.to_string());
        }
    }

    runtime.set_startup_phase(StartupPhase::Ready);
    log!("iota-daemon started (phase: Ready)");

    // --- Main lifecycle loop ---
    let signal = async {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => ShutdownReason::Stop, _ = term.recv() => ShutdownReason::Stop }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            ShutdownReason::Stop
        }
    };
    tokio::select! {
        _ = runtime.cancellation.cancelled() => {},
        reason = signal => runtime.shutdown(reason),
    }

    let reason = runtime.shutdown_reason().unwrap_or(ShutdownReason::Stop);
    log!("iota-daemon shutting down (reason: {:?})", reason);
    runtime.set_startup_phase(StartupPhase::Stopping);

    let _ = runtime
        .tasks
        .join_with_timeout(Duration::from_secs(5))
        .await;

    let exit_code = reason.exit_code();
    log!("iota-daemon exited (code: {})", exit_code);
    ExitCode::from(exit_code as u8)
}

fn resolve_config_path(
    config_file: &std::path::Path,
    value: &str,
    default: &std::path::Path,
) -> std::path::PathBuf {
    if value.is_empty() {
        return default.to_path_buf();
    }
    let path = std::path::PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        config_file
            .parent()
            .expect("absolute configuration file has a parent")
            .join(path)
    }
}
