use iota_daemon_lib::{DaemonRuntime, IpcServer, log_broadcaster};
use iota_logger::{self as logger, log, log_t};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::CONFIG;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

fn socket_path() -> PathBuf {
    std::env::var_os("IOTA_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/iota/iota.sock"))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    logger::startup();
    iota_storage::util::config_util::load_config();
    if user_manager::load_users().await.is_err() {
        log_t!("user_load_failed");
    }
    let runtime = Arc::new(DaemonRuntime::new());
    runtime.spawn_system_monitor();
    let (messages, _) = broadcast::channel(512);
    log_broadcaster::spawn(messages.clone());
    let state_updates = runtime.clone();
    let state_messages = messages.clone();
    tokio::spawn(async move {
        loop {
            if *state_updates.state.shutdown.read().await {
                break;
            }
            let _ = state_messages.send(iota_ipc::DaemonMessage::StateUpdate(
                state_updates.snapshot(),
            ));
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let port = CONFIG.load().port;
    if !web_server::start(port).await {
        log!("Failed to start the MTP web server on port {}", port);
    }
    let _ = omikron_connector::omikron_connection::get_omikron_connection().await;

    let server = IpcServer::new(socket_path(), runtime.clone(), messages);
    tokio::spawn(async move {
        if let Err(error) = server.run().await {
            eprintln!("iota-daemon IPC server failed: {error}");
        }
    });
    log!("iota-daemon started");
    while !*runtime.state.shutdown.read().await {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    log!("iota-daemon stopping");
}
