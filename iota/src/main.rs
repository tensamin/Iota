use iota_cli::{ipc_client::IpcClient, screens::main_screen::MainScreen, ui::start_tui};
use std::path::PathBuf;

fn socket_path() -> PathBuf {
    std::env::var_os("IOTA_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/iota/iota.sock"))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let path = socket_path();
    let ipc = match IpcClient::connect(&path).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!(
                "Cannot connect to iota-daemon at {}: {error}",
                path.display()
            );
            std::process::exit(1);
        }
    };
    let ui = start_tui(ipc);
    ui.set_screen(Box::new(MainScreen::new(ui.clone()).await))
        .await;
    while !ui.is_shutdown() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
