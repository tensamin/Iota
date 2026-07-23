use crate::startup_error::StartupError;
use iota_cli::{ipc_client::IpcClient, ui::UI};
use std::process::Stdio;
use std::{
    collections::VecDeque,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::Instant,
};

struct LocalDaemonGuard {
    child: Option<Child>,
    committed: bool,
}
impl LocalDaemonGuard {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            committed: false,
        }
    }
    fn commit(mut self) -> Child {
        self.committed = true;
        self.child.take().expect("local daemon child")
    }
}
impl Drop for LocalDaemonGuard {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(mut child) = self.child.take() {
                let _ = child.start_kill();
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
    }
}

pub async fn launch(
    ui: Arc<UI>,
    executable: &Path,
    socket: &Path,
) -> Result<Arc<IpcClient>, StartupError> {
    let mut child = Command::new(executable)
        .env("IOTA_SOCKET", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(false)
        .spawn()
        .map_err(|e| StartupError::DaemonExited {
            message: format!("Could not start daemon: {e}"),
        })?;
    let diagnostics = Arc::new(Mutex::new(VecDeque::<String>::with_capacity(64)));
    if let Some(stderr) = child.stderr.take() {
        let diagnostics = diagnostics.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let mut recent = diagnostics.lock().unwrap();
                if recent.len() == 64 {
                    recent.pop_front();
                }
                recent.push_back(line);
            }
        });
    }
    let mut guard = LocalDaemonGuard::new(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    let cancellation = ui.cancellation_token();
    loop {
        let result = tokio::select! {
            status = guard.child.as_mut().expect("child").wait() => {
                let status = match status { Ok(status) => status.to_string(), Err(error) => format!("wait failed: {error}") };
                return Err(StartupError::DaemonExited { message: format_diagnostic(format!("daemon exited with {status}"), &diagnostics) });
            }
            connection = IpcClient::connect(socket) => connection,
            _ = cancellation.cancelled() => return Err(StartupError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(StartupError::DaemonExited { message: format_diagnostic("timed out waiting for IPC handshake".into(), &diagnostics) }),
        };
        match result {
            Ok(client) => {
                // The daemon was launched with kill_on_drop(false) so it
                // survives after we release the child handle.  Let it run
                // independently; future CLI instances reconnect via IPC.
                let _child = guard.commit();
                return Ok(client);
            }
            Err(_error) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            Err(error) => {
                return Err(StartupError::DaemonExited {
                    message: format_diagnostic(
                        format!("timed out waiting for IPC handshake: {error}"),
                        &diagnostics,
                    ),
                });
            }
        }
    }
}

fn format_diagnostic(message: String, diagnostics: &Arc<Mutex<VecDeque<String>>>) -> String {
    let lines = diagnostics.lock().unwrap();
    if lines.is_empty() {
        message
    } else {
        format!(
            "{message}; daemon stderr: {}",
            lines.iter().cloned().collect::<Vec<_>>().join(" | ")
        )
    }
}
