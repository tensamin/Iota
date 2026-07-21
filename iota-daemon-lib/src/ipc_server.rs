use crate::{CommandRouter, DaemonRuntime};
use iota_ipc::{
    ClientMessage, DaemonMessage, HelloAck, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, read_msg,
    write_msg,
};
use iota_logger::log;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, os::fd::FromRawFd};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, watch};
use uuid::Uuid;

/// Per-client outbound queue capacity.
const CLIENT_CHANNEL_SIZE: usize = 256;

/// Maximum handshake retries before giving up.
const MAX_HANDSHAKE_RETRIES: u32 = 10;

pub struct IpcServer {
    path: PathBuf,
    runtime: Arc<DaemonRuntime>,
    log_tx: broadcast::Sender<DaemonMessage>,
    state_rx: watch::Sender<iota_ipc::StateSnapshot>,
}

impl IpcServer {
    pub fn new(
        path: impl Into<PathBuf>,
        runtime: Arc<DaemonRuntime>,
        log_tx: broadcast::Sender<DaemonMessage>,
        state_rx: watch::Sender<iota_ipc::StateSnapshot>,
    ) -> Self {
        Self {
            path: path.into(),
            runtime,
            log_tx,
            state_rx,
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
            let (stream, _addr) = listener.accept().await?;
            let runtime = self.runtime.clone();
            let log_tx = self.log_tx.clone();
            let state_rx = self.state_rx.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_client(stream, runtime, log_tx, state_rx).await {
                    eprintln!("IPC client error: {error}");
                }
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

#[derive(Clone, Debug)]
struct PeerIdentity {
    pid: i32,
    uid: u32,
    gid: u32,
}

fn peer_credentials(stream: &UnixStream) -> PeerIdentity {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let fd = stream.as_raw_fd();
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            );
            PeerIdentity {
                pid: cred.pid,
                uid: cred.uid,
                gid: cred.gid,
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        PeerIdentity {
            pid: 0,
            uid: 0,
            gid: 0,
        }
    }
}

async fn handle_client(
    stream: UnixStream,
    runtime: Arc<DaemonRuntime>,
    log_tx: broadcast::Sender<DaemonMessage>,
    _state_rx: watch::Sender<iota_ipc::StateSnapshot>,
) -> Result<()> {
    let peer = peer_credentials(&stream);
    let (mut reader, mut writer) = stream.into_split();
    let (directed_tx, directed_rx) = mpsc::channel::<DaemonMessage>(CLIENT_CHANNEL_SIZE);

    // --- Handshake ---
    let mut negotiated_version: Option<u16> = None;
    for _ in 0..MAX_HANDSHAKE_RETRIES {
        match read_msg::<_, ClientMessage>(&mut reader).await {
            Ok(ClientMessage::Hello { supported_versions }) => {
                let version = supported_versions
                    .iter()
                    .copied()
                    .find(|v| *v >= MIN_PROTOCOL_VERSION && *v <= PROTOCOL_VERSION)
                    .unwrap_or(PROTOCOL_VERSION);
                negotiated_version = Some(version);
                let instance_id = Uuid::new_v4().to_string();
                let ack = DaemonMessage::HelloAck(HelloAck {
                    protocol_version: version,
                    daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                    instance_id,
                    startup_phase: runtime.current_startup_phase().into(),
                    capabilities: vec!["commands".into(), "metrics".into(), "logs".into()],
                });
                write_msg(&mut writer, &ack).await?;
                break;
            }
            Ok(_) => {
                // Unexpected first message — send error and close.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected Hello as first message",
                ));
            }
            Err(e) => return Err(e),
        }
    }
    let _version = negotiated_version.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "Handshake failed after retries")
    })?;

    log!("IPC client connected (pid={}, uid={})", peer.pid, peer.uid);

    // --- Send initial state snapshot ---
    let initial = DaemonMessage::StateUpdate(runtime.snapshot());
    let _ = directed_tx.send(initial).await;

    // --- Writer task: merge directed responses + shared log events ---
    let mut log_rx = log_tx.subscribe();
    let directed_for_writer = directed_tx.clone();
    let writer_task = {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            let mut directed_rx = directed_rx;
            loop {
                tokio::select! {
                    // Directed messages (responses to this client's requests)
                    msg = directed_rx.recv() => {
                        match msg {
                            Some(message) => {
                                if write_msg(&mut writer, &message).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    // Shared log events
                    result = log_rx.recv() => {
                        match result {
                            Ok(message) => {
                                if write_msg(&mut writer, &message).await.is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                let _ = directed_for_writer.send(DaemonMessage::Gap { skipped }).await;
                                // Then send current snapshot for resync
                                let _ = directed_for_writer.send(
                                    DaemonMessage::StateUpdate(runtime.snapshot())
                                ).await;
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        })
    };

    // --- Reader loop ---
    let router = CommandRouter::new(runtime.clone());
    loop {
        match read_msg::<_, ClientMessage>(&mut reader).await {
            Ok(ClientMessage::Request(envelope)) => {
                let response = router.route(envelope.request_id, envelope.request).await;
                let _ = directed_tx.send(DaemonMessage::Response(response)).await;
            }
            Ok(ClientMessage::Subscribe { .. }) => {
                let snapshot = DaemonMessage::StateUpdate(runtime.snapshot());
                let _ = directed_tx.send(snapshot).await;
            }
            Ok(ClientMessage::Ping { seq }) => {
                let _ = directed_tx.send(DaemonMessage::Pong { seq }).await;
            }
            Ok(ClientMessage::Hello { .. }) => {
                // Re-handshake on existing connection: treat as resubscribe
                let snapshot = DaemonMessage::StateUpdate(runtime.snapshot());
                let _ = directed_tx.send(snapshot).await;
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                writer_task.abort();
                return Err(error);
            }
        }
    }
    writer_task.abort();
    log!(
        "IPC client disconnected (pid={}, uid={})",
        peer.pid,
        peer.uid
    );
    Ok(())
}
