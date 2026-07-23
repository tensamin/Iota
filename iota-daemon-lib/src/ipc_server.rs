use crate::deployment::from_environment;
use crate::{CommandRouter, DaemonRuntime, DaemonServices};
use iota_ipc::{
    ClientMessage, DaemonMessage, HelloAck, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, read_msg,
    write_msg,
};
use iota_logger::log;
use std::io::Result;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, fs::File, os::fd::FromRawFd, os::unix::net::UnixListener as StdUnixListener};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::timeout;
use uuid::Uuid;

/// Per-client outbound queue capacity.
const CLIENT_CHANNEL_SIZE: usize = 256;

/// Maximum handshake retries before giving up.
const MAX_HANDSHAKE_RETRIES: u32 = 1;
const CLIENT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub struct IpcServer {
    listener: UnixListener,
    runtime: Arc<DaemonRuntime>,
    services: Arc<DaemonServices>,
    log_tx: broadcast::Sender<DaemonMessage>,
    state_rx: watch::Receiver<iota_ipc::StateSnapshot>,
    instance_id: String,
    _instance_lock: File,
}

impl IpcServer {
    pub async fn bind(
        path: impl Into<PathBuf>,
        runtime: Arc<DaemonRuntime>,
        services: Arc<DaemonServices>,
        log_tx: broadcast::Sender<DaemonMessage>,
        state_rx: watch::Receiver<iota_ipc::StateSnapshot>,
    ) -> Result<Self> {
        let path = path.into();
        let listener = match activated_listener()? {
            Some(listener) => listener,
            None => {
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let lock_path = path.with_extension("sock.lock");
                let lock = File::options()
                    .create(true)
                    .mode(0o600)
                    .read(true)
                    .write(true)
                    .open(lock_path)?;
                let locked = unsafe {
                    libc::flock(
                        std::os::fd::AsRawFd::as_raw_fd(&lock),
                        libc::LOCK_EX | libc::LOCK_NB,
                    )
                } == 0;
                if !locked {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "another daemon instance is already running",
                    ));
                }
                remove_stale_socket(&path).await?;
                let listener = UnixListener::bind(&path)?;
                let _ = tokio::fs::set_permissions(
                    &path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                )
                .await;
                return Ok(Self {
                    listener,
                    runtime,
                    services,
                    log_tx,
                    state_rx,
                    instance_id: Uuid::new_v4().to_string(),
                    _instance_lock: lock,
                });
            }
        };
        Ok(Self {
            listener,
            runtime,
            services,
            log_tx,
            state_rx,
            instance_id: Uuid::new_v4().to_string(),
            _instance_lock: File::options().read(true).open("/dev/null")?,
        })
    }

    pub async fn serve(self) -> Result<()> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            eprintln!("IPC client accepted");
            let runtime = self.runtime.clone();
            let services = self.services.clone();
            let log_tx = self.log_tx.clone();
            let state_rx = self.state_rx.clone();
            let instance_id = self.instance_id.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    handle_client(stream, runtime, services, log_tx, state_rx, instance_id).await
                {
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
    // SAFETY: systemd transfers ownership of the activated descriptor to us.
    let listener = unsafe { StdUnixListener::from_raw_fd(3) };
    into_tokio_listener(listener).map(Some)
}

fn into_tokio_listener(listener: StdUnixListener) -> Result<UnixListener> {
    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener)
}

async fn write_client_message<W>(writer: &mut W, message: &DaemonMessage) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    timeout(CLIENT_IO_TIMEOUT, write_msg(writer, message))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "IPC client write timed out")
        })?
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "IPC path exists but is not an owned Unix socket",
                ));
            }
            if metadata.uid() != unsafe { libc::geteuid() } as u32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "existing IPC socket is not owned by the current user",
                ));
            }
            match timeout(
                std::time::Duration::from_millis(250),
                UnixStream::connect(path),
            )
            .await
            {
                Ok(Ok(_)) => Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "an IPC daemon is already listening",
                )),
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    tokio::fs::remove_file(path).await
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "could not determine whether the existing IPC socket is active",
                )),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Debug)]
struct PeerIdentity {
    pid: i32,
    uid: u32,
    _gid: u32,
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerIdentity> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let fd = stream.as_raw_fd();
            if libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(PeerIdentity {
                pid: cred.pid,
                uid: cred.uid,
                _gid: cred.gid,
            })
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(PeerIdentity {
            pid: 0,
            uid: 0,
            _gid: 0,
        })
    }
}

async fn handle_client(
    stream: UnixStream,
    runtime: Arc<DaemonRuntime>,
    services: Arc<DaemonServices>,
    log_tx: broadcast::Sender<DaemonMessage>,
    mut state_rx: watch::Receiver<iota_ipc::StateSnapshot>,
    instance_id: String,
) -> Result<()> {
    let peer = peer_credentials(&stream)?;
    // Access control belongs to the Unix socket.  The systemd socket grants
    // iota-operators group access (0660); rejecting every UID other than the
    // service account here would make that authorization ineffective.  Manual
    // sockets remain owner-only (0600) at bind time.
    let (mut reader, mut writer) = stream.into_split();
    // A failed writer must stop the reader and any subsequent command work
    // for this client; otherwise the reader can remain parked forever.
    let session_cancellation = runtime.cancellation.child_token();
    let (directed_tx, directed_rx) = mpsc::channel::<DaemonMessage>(CLIENT_CHANNEL_SIZE);
    eprintln!("IPC handshake started (pid={}, uid={})", peer.pid, peer.uid);

    // --- Handshake ---
    let mut negotiated_version: Option<u16> = None;
    for _ in 0..MAX_HANDSHAKE_RETRIES {
        match timeout(
            std::time::Duration::from_secs(15),
            read_msg::<_, ClientMessage>(&mut reader),
        )
        .await
        {
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "IPC Hello timed out",
                ));
            }
            Ok(result) => match result {
                Ok(ClientMessage::Hello { supported_versions }) => {
                    let version = supported_versions
                        .iter()
                        .copied()
                        .filter(|v| *v >= MIN_PROTOCOL_VERSION && *v <= PROTOCOL_VERSION)
                        .max()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "No compatible IPC protocol version",
                            )
                        })?;
                    negotiated_version = Some(version);
                    let ack = DaemonMessage::HelloAck(HelloAck {
                        protocol_version: version,
                        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                        instance_id: instance_id.clone(),
                        startup_phase: runtime.current_startup_phase().into(),
                        capabilities: vec!["commands".into(), "metrics".into(), "logs".into()],
                        lifecycle: *runtime.lifecycle.borrow(),
                        health: runtime.overall_health(),
                        deployment_mode: from_environment().mode,
                        supervisor: from_environment().supervisor,
                    });
                    write_client_message(&mut writer, &ack).await?;
                    eprintln!(
                        "IPC handshake acknowledged (pid={}, uid={})",
                        peer.pid, peer.uid
                    );
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
            },
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
    let writer_task = {
        let runtime = runtime.clone();
        let session_cancellation = session_cancellation.clone();
        tokio::spawn(async move {
            let mut directed_rx = directed_rx;
            loop {
                tokio::select! {
                    // Directed messages (responses to this client's requests)
                    msg = directed_rx.recv() => {
                        match msg {
                            Some(message) => {
                                if let Err(error) = write_client_message(&mut writer, &message).await {
                                    eprintln!("IPC client writer stopped while sending directed message: {error}");
                                    session_cancellation.cancel();
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
                                if let Err(error) = write_client_message(&mut writer, &message).await {
                                    eprintln!("IPC client writer stopped while sending log message: {error}");
                                    session_cancellation.cancel();
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                if write_client_message(&mut writer, &DaemonMessage::Gap { skipped }).await.is_err()
                                    || write_client_message(&mut writer, &DaemonMessage::StateUpdate(runtime.snapshot())).await.is_err()
                                {
                                    session_cancellation.cancel();
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let snapshot = state_rx.borrow().clone();
                        if let Err(error) = write_client_message(&mut writer, &DaemonMessage::StateUpdate(snapshot)).await {
                            eprintln!("IPC client writer stopped while sending state update: {error}");
                            session_cancellation.cancel();
                            break;
                        }
                    }
                }
            }
        })
    };

    // --- Reader loop ---
    let router = CommandRouter::new(runtime.clone(), services);
    loop {
        let message = tokio::select! {
            _ = session_cancellation.cancelled() => break,
            result = read_msg::<_, ClientMessage>(&mut reader) => result,
        };
        match message {
            Ok(ClientMessage::Request(envelope)) => {
                let shutdown_reason = match &envelope.request {
                    iota_ipc::LocalRequest::RequestProcessExit {
                        intent: iota_ipc::ExitIntent::Restart,
                    }
                    | iota_ipc::LocalRequest::RestartDaemon => Some("restart requested"),
                    iota_ipc::LocalRequest::RequestProcessExit {
                        intent: iota_ipc::ExitIntent::Stop,
                    } => Some("shutdown requested"),
                    iota_ipc::LocalRequest::StopDaemon => Some("shutdown requested"),
                    _ => None,
                };
                let response = if envelope.protocol_version < MIN_PROTOCOL_VERSION
                    || envelope.protocol_version > PROTOCOL_VERSION
                {
                    iota_ipc::ResponseEnvelope {
                        request_id: envelope.request_id,
                        result: iota_ipc::ResponseResult::Error(
                            iota_ipc::IpcErrorCode::UnsupportedVersion,
                        ),
                    }
                } else {
                    router.route(envelope.request_id, envelope.request).await
                };
                let _ = directed_tx.send(DaemonMessage::Response(response)).await;
                if let Some(reason) = shutdown_reason {
                    let _ = directed_tx
                        .send(DaemonMessage::LifecycleEvent(
                            iota_ipc::LifecycleEvent::Shutdown {
                                reason: reason.into(),
                            },
                        ))
                        .await;
                    // The request itself initiates daemon cancellation. Give
                    // the dedicated writer a chance to flush the response
                    // and lifecycle event before this session is torn down.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    break;
                }
            }
            Ok(ClientMessage::Subscribe { .. }) => {
                let snapshot = DaemonMessage::StateUpdate(runtime.snapshot());
                let _ = directed_tx.send(snapshot).await;
                let _ = directed_tx.send(DaemonMessage::Subscribed).await;
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
    session_cancellation.cancel();
    writer_task.abort();
    log!(
        "IPC client disconnected (pid={}, uid={})",
        peer.pid,
        peer.uid
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn converted_listener_does_not_block_the_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ipc.sock");
        let listener = match StdUnixListener::bind(path) {
            Ok(listener) => into_tokio_listener(listener).unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not create test socket: {error}"),
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}
