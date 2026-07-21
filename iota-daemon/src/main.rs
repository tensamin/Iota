use iota_daemon_lib::{DaemonRuntime, IpcServer, ShutdownReason, StartupPhase, log_broadcaster};
use iota_logger::{self as logger, log, log_t};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::CONFIG;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
fn socket_path() -> PathBuf {
    std::env::var_os("IOTA_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/iota/iota.sock"))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    logger::startup();
    iota_storage::util::config_util::load_config();

    let runtime = Arc::new(DaemonRuntime::new());
    runtime.set_startup_phase(StartupPhase::LoadingUsers);

    if user_manager::load_users().await.is_err() {
        log_t!("user_load_failed");
    }

    // --- IPC infrastructure ---
    let (log_tx, _) = broadcast::channel(512);
    log_broadcaster::spawn(log_tx.clone());
    let (state_tx, _state_rx) = watch::channel(iota_ipc::StateSnapshot::default());

    // --- Start IPC server early (before services) so clients can see startup phases ---
    runtime.set_startup_phase(StartupPhase::StartingServices);
    let ipc_server = IpcServer::new(
        socket_path(),
        runtime.clone(),
        log_tx.clone(),
        state_tx.clone(),
    );
    tokio::spawn(async move {
        if let Err(error) = ipc_server.run().await {
            eprintln!("iota-daemon IPC server failed: {error}");
        }
    });
    log!("iota-daemon IPC server started");

    // --- System monitor ---
    runtime.spawn_system_monitor();

    // --- State update publisher (watch-based, no full broadcast per tick) ---
    let state_publisher = runtime.clone();
    tokio::spawn(async move {
        loop {
            if state_publisher.is_shutting_down() {
                break;
            }
            let snapshot = state_publisher.snapshot();
            let _ = state_tx.send(snapshot);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    // --- Web server ---
    let port = CONFIG.load().port;
    if !web_server::start(port, runtime.cancellation.clone()).await {
        log!("Failed to start the MTP web server on port {}", port);
        runtime.mark_degraded("MTP web server failed to start".into());
    }

    // --- Omikron connection ---
    let omikron_result =
        omikron_connector::omikron_connection::get_omikron_connection(runtime.cancellation.clone())
            .await;
    if omikron_result.is_none() {
        runtime.mark_degraded("Omikron connection unavailable".into());
    }

    runtime.set_startup_phase(StartupPhase::Ready);
    log!("iota-daemon started (phase: Ready)");

    // --- Main lifecycle loop ---
    runtime.cancellation.cancelled().await;

    let reason = runtime.shutdown_reason().unwrap_or(ShutdownReason::Stop);
    log!("iota-daemon shutting down (reason: {:?})", reason);
    runtime.set_startup_phase(StartupPhase::Stopping);

    // Wait a moment for in-flight operations to complete
    tokio::time::sleep(Duration::from_millis(500)).await;

    let exit_code = reason.exit_code();
    log!("iota-daemon exited (code: {})", exit_code);
    std::process::exit(exit_code);
}
