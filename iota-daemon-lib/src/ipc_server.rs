use crate::{CommandRouter, DaemonRuntime};
use iota_ipc::{ClientMessage, DaemonMessage, read_msg, write_msg};
use std::io::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, os::fd::FromRawFd};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

pub struct IpcServer {
    path: PathBuf,
    runtime: Arc<DaemonRuntime>,
    messages: broadcast::Sender<DaemonMessage>,
}

impl IpcServer {
    pub fn new(
        path: impl Into<PathBuf>,
        runtime: Arc<DaemonRuntime>,
        messages: broadcast::Sender<DaemonMessage>,
    ) -> Self {
        Self {
            path: path.into(),
            runtime,
            messages,
        }
    }

    pub async fn run(self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let listener = match activated_listener()? {
            Some(listener) => listener,
            None => {
                remove_stale_socket(&self.path).await?;
                UnixListener::bind(&self.path)?
            }
        };
        loop {
            let (stream, _) = listener.accept().await?;
            let runtime = self.runtime.clone();
            let messages = self.messages.clone();
            tokio::spawn(async move {
                let _ = handle_client(stream, runtime, messages).await;
            });
        }
    }
}

/* systemd hands the first socket-activated file descriptor to the service as
 * descriptor 3. Manual launches continue to bind the configured socket path. */
fn activated_listener() -> Result<Option<UnixListener>> {
    let listen_fds = env::var("LISTEN_FDS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let listen_pid = env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    if listen_fds != Some(1) || listen_pid != Some(std::process::id()) {
        return Ok(None);
    }
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    UnixListener::from_std(listener).map(Some)
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => tokio::fs::remove_file(path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn handle_client(
    stream: UnixStream,
    runtime: Arc<DaemonRuntime>,
    messages: broadcast::Sender<DaemonMessage>,
) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let mut outgoing = messages.subscribe();
    let initial = DaemonMessage::StateUpdate(runtime.snapshot());
    write_msg(&mut writer, &initial).await?;
    let writer_task = tokio::spawn(async move {
        while let Ok(message) = outgoing.recv().await {
            if write_msg(&mut writer, &message).await.is_err() {
                break;
            }
        }
    });
    let router = CommandRouter::new(runtime.clone());
    loop {
        match read_msg::<_, ClientMessage>(&mut reader).await {
            Ok(ClientMessage::Command { seq, line }) => {
                let result = router.route(seq, line).await;
                let _ = messages.send(result);
            }
            Ok(ClientMessage::Subscribe) => {
                let _ = messages.send(DaemonMessage::StateUpdate(runtime.snapshot()));
            }
            Ok(ClientMessage::Ping { seq }) => {
                let _ = messages.send(DaemonMessage::Pong { seq });
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                writer_task.abort();
                return Err(error);
            }
        }
    }
    writer_task.abort();
    Ok(())
}
