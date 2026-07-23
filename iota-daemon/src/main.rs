use iota_daemon_lib::{
    DaemonRuntime, DaemonServices, IpcServer, ShutdownReason, StartupPhase, log_broadcaster,
};
use iota_logger::{self as logger, log};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::CONFIG;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    logger::startup();
    iota_storage::util::config_util::load_config();

    let runtime = Arc::new(DaemonRuntime::new());
    // --- IPC infrastructure ---
    let (log_tx, _) = broadcast::channel(512);
    log_broadcaster::spawn(log_tx.clone());
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
    let socket = iota_paths::socket_path(iota_paths::SocketScope::User);
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
        Err(omikron_connector::OmikronStartupError::Authentication) => {
            runtime.set_component_failed(
                iota_ipc::ComponentId::Omikron,
                "Omikron authentication failed".into(),
            );
            return ExitCode::FAILURE;
        }
        Err(omikron_connector::OmikronStartupError::Construction(error)) => {
            eprintln!("Cannot construct Omikron connection: {error}");
            return ExitCode::FAILURE;
        }
    };
    let services = DaemonServices::new(omikron);
    let ipc_server =
        match IpcServer::bind(socket, runtime.clone(), services, log_tx.clone(), state_rx).await {
            Ok(server) => server,
            Err(error) => {
                eprintln!("Cannot bind daemon IPC socket: {error}");
                return ExitCode::FAILURE;
            }
        };
    eprintln!(
        "iota-daemon IPC listener ready at {}",
        iota_paths::socket_path(iota_paths::SocketScope::User).display()
    );
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
        asset_dir: std::path::PathBuf::from(web.asset_dir),
        tls: web
            .certificate
            .zip(web.key)
            .map(|(certificate, key)| web_server::TlsConfig {
                certificate: certificate.into(),
                key: key.into(),
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
