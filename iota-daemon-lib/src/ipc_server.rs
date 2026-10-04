use crate::deployment::from_environment;
use crate::log_buffer::LogBuffer;
use crate::{CommandRouter, DaemonRuntime, DaemonServices, IpcRole, PeerContext};
use iota_ipc::{
    ClientMessage, DaemonMessage, HelloAck, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, read_msg,
    write_msg,
};
use iota_logger::log;
use iota_storage::util::config_util;
use std::io::Result;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{env, fs::File, os::fd::FromRawFd, os::unix::net::UnixListener as StdUnixListener};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, broadcast, mpsc, watch};
use tokio::time::timeout;
use uuid::Uuid;

/// Per-client outbound queue capacity.
const CLIENT_CHANNEL_SIZE: usize = 256;
const MAX_CONFIGURED_IPC_CLIENTS: usize = 4096;

const CLIENT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Minimum metric subscription interval to prevent excessive update rates.
const MIN_METRIC_INTERVAL_MS: u64 = 100;
/// Maximum metric subscription interval.
const MAX_METRIC_INTERVAL_MS: u64 = 60_000;
/// Default metric interval if the client does not specify one.
const DEFAULT_METRIC_INTERVAL_MS: u64 = 500;

/// Per-client subscription state.
struct ClientSubscription {
    log_classes: Vec<String>,
    metric_interval_ms: u64,
}

#[expect(clippy::large_enum_variant, reason = "keep queued IPC messages inline")]
enum WriterCommand {
    Message(DaemonMessage),
    Flush {
        complete: tokio::sync::oneshot::Sender<()>,
    },
}

fn configured_client_limit() -> usize {
    config_util::CONFIG
        .load()
        .max_ipc_clients
        .clamp(1, MAX_CONFIGURED_IPC_CLIENTS)
}

pub struct IpcServer {
    listener: UnixListener,
    runtime: Arc<DaemonRuntime>,
    services: Arc<DaemonServices>,
    log_tx: broadcast::Sender<DaemonMessage>,
    log_buffer: Arc<Mutex<LogBuffer>>,
    state_rx: watch::Receiver<iota_ipc::StateSnapshot>,
    instance_id: String,
    _instance_lock: File,
    client_limit: Arc<Semaphore>,
}

impl IpcServer {
    pub async fn bind(
        path: impl Into<PathBuf>,
        runtime: Arc<DaemonRuntime>,
        services: Arc<DaemonServices>,
        log_tx: broadcast::Sender<DaemonMessage>,
        log_buffer: Arc<Mutex<LogBuffer>>,
        state_rx: watch::Receiver<iota_ipc::StateSnapshot>,
    ) -> Result<Self> {
        let path = path.into();
        let listener = match activated_listener()? {
            Some(listener) => listener,
            None => {
                let parent = path.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "IPC socket has no parent directory",
                    )
                })?;
                if !parent.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("IPC runtime directory does not exist: {}", parent.display()),
                    ));
                }
                let lock_path = path
                    .parent()
                    .unwrap_or_else(|| Path::new("/tmp"))
                    .join("daemon.lock");
                let lock = File::options()
                    .create(true)
                    .truncate(false)
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
                if let Err(error) =
                    tokio::fs::set_permissions(&path, PermissionsExt::from_mode(0o600)).await
                {
                    drop(listener);
                    let _ = tokio::fs::remove_file(&path).await;
                    return Err(error);
                }
                if let Err(error) = validate_manual_socket(&path).await {
                    drop(listener);
                    let _ = tokio::fs::remove_file(&path).await;
                    return Err(error);
                }
                return Ok(Self {
                    listener,
                    runtime,
                    services,
                    log_tx,
                    log_buffer,
                    state_rx,
                    instance_id: Uuid::new_v4().to_string(),
                    _instance_lock: lock,
                    client_limit: Arc::new(Semaphore::new(configured_client_limit())),
                });
            }
        };
        Ok(Self {
            listener,
            runtime,
            services,
            log_tx,
            log_buffer,
            state_rx,
            instance_id: Uuid::new_v4().to_string(),
            _instance_lock: File::options().read(true).open("/dev/null")?,
            client_limit: Arc::new(Semaphore::new(configured_client_limit())),
        })
    }

    pub async fn serve(self) -> Result<()> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            let permit = match self.client_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    eprintln!("IPC connection rejected: active client limit reached");
                    drop(stream);
                    continue;
                }
            };
            eprintln!("IPC client accepted");
            let runtime = self.runtime.clone();
            let services = self.services.clone();
            let log_tx = self.log_tx.clone();
            let log_buffer = self.log_buffer.clone();
            let state_rx = self.state_rx.clone();
            let instance_id = self.instance_id.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = handle_client(
                    stream,
                    runtime,
                    services,
                    log_tx,
                    log_buffer,
                    state_rx,
                    instance_id,
                )
                .await
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

async fn validate_manual_socket(path: &Path) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bound IPC path is no longer a Unix socket",
        ));
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("IPC socket has unexpected mode {mode:o}"),
        ));
    }

    let expected_uid = unsafe { libc::geteuid() } as u32;
    if metadata.uid() != expected_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "IPC socket ownership changed after bind",
        ));
    }
    Ok(())
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
        let _ = stream;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "IPC peer credentials are unsupported on this platform",
        ))
    }
}

fn role_for_peer(_peer: &PeerIdentity) -> IpcRole {
    // This deployment has one IPC listener. Its Unix socket permissions are
    // the admission boundary: systemd grants access to root, the daemon, and
    // members of iota-operators. Once a peer has passed that boundary, it is
    // an administrator for the operator console protocol.
    IpcRole::Admin
}

async fn handle_client(
    stream: UnixStream,
    runtime: Arc<DaemonRuntime>,
    services: Arc<DaemonServices>,
    log_tx: broadcast::Sender<DaemonMessage>,
    log_buffer: Arc<Mutex<LogBuffer>>,
    mut state_rx: watch::Receiver<iota_ipc::StateSnapshot>,
    instance_id: String,
) -> Result<()> {
    let peer_identity = peer_credentials(&stream)?;
    let peer = PeerContext {
        pid: peer_identity.pid,
        uid: peer_identity.uid,
        role: role_for_peer(&peer_identity),
    };
    let (mut reader, mut writer) = stream.into_split();
    // A failed writer must stop the reader and any subsequent command work
    // for this client; otherwise the reader can remain parked forever.
    let session_cancellation = runtime.cancellation.child_token();
    let (directed_tx, directed_rx) = mpsc::channel::<WriterCommand>(CLIENT_CHANNEL_SIZE);
    eprintln!("IPC handshake started (pid={}, uid={})", peer.pid, peer.uid);

    // --- Handshake ---
    let negotiated_version = match timeout(
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
                let ack = DaemonMessage::HelloAck(HelloAck {
                    protocol_version: version,
                    daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                    instance_id: instance_id.clone(),
                    startup_phase: runtime.current_startup_phase().into(),
                    capabilities: vec![
                        "commands".into(),
                        "metrics".into(),
                        "logs".into(),
                        "user_management_v2".into(),
                        "tu_inspection_v1".into(),
                        "credential_export_v1".into(),
                        "user_invitations_v1".into(),
                    ],
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
                version
            }
            Ok(_) => {
                // Unexpected first message, send an error and close.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected Hello as first message",
                ));
            }
            Err(e) => return Err(e),
        },
    };

    log!("IPC client connected (pid={}, uid={})", peer.pid, peer.uid);

    // --- Send initial state snapshot ---
    let initial = DaemonMessage::StateUpdate(runtime.snapshot());
    let _ = directed_tx.send(WriterCommand::Message(initial)).await;

    // --- Writer task: merge directed responses + shared log events ---
    let mut log_rx = log_tx.subscribe();
    let (sub_tx, mut sub_rx) = tokio::sync::watch::channel(ClientSubscription {
        log_classes: Vec::new(),
        metric_interval_ms: DEFAULT_METRIC_INTERVAL_MS,
    });
    let writer_task = {
        let runtime = runtime.clone();
        let session_cancellation = session_cancellation.clone();
        tokio::spawn(async move {
            let mut directed_rx = directed_rx;
            let mut last_metric_sent = tokio::time::Instant::now();
            let mut state_updates_open = true;
            loop {
                let metric_interval = sub_rx.borrow().metric_interval_ms;
                tokio::select! {
                    _ = session_cancellation.cancelled() => break,
                    // Directed messages (responses to this client's requests)
                    command = directed_rx.recv() => {
                        match command {
                            Some(WriterCommand::Message(message)) => {
                                if let Err(error) = write_client_message(&mut writer, &message).await {
                                    eprintln!("IPC client writer stopped while sending directed message: {error}");
                                    session_cancellation.cancel();
                                    break;
                                }
                            }
                            Some(WriterCommand::Flush { complete }) => {
                                if let Err(error) = writer.flush().await {
                                    eprintln!("IPC client writer stopped while flushing: {error}");
                                    session_cancellation.cancel();
                                    break;
                                }
                                let _ = complete.send(());
                            }
                            None => break,
                        }
                    }
                    // Shared log events
                    result = log_rx.recv() => {
                        match result {
                            Ok(DaemonMessage::LogEntry(entry)) => {
                                // Filter by subscribed log classes
                                let log_classes = sub_rx.borrow().log_classes.clone();
                                if (log_classes.is_empty()
                                    || log_classes.contains(&entry.sender))
                                    && let Err(error) = write_client_message(&mut writer, &DaemonMessage::LogEntry(entry)).await {
                                        eprintln!("IPC client writer stopped while sending log message: {error}");
                                        session_cancellation.cancel();
                                        break;
                                    }
                            }
                            Ok(DaemonMessage::MetricSample(sample)) => {
                                // Rate-limit metric samples based on subscription interval
                                let now = tokio::time::Instant::now();
                                if now.duration_since(last_metric_sent) >= std::time::Duration::from_millis(metric_interval) {
                                    last_metric_sent = now;
                                    if let Err(error) = write_client_message(&mut writer, &DaemonMessage::MetricSample(sample)).await {
                                        eprintln!("IPC client writer stopped while sending metric sample: {error}");
                                        session_cancellation.cancel();
                                        break;
                                    }
                                }
                            }
                            Ok(message) => {
                                // Forward other broadcast messages as-is
                                if let Err(error) = write_client_message(&mut writer, &message).await {
                                    eprintln!("IPC client writer stopped while sending broadcast message: {error}");
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
                            Err(broadcast::error::RecvError::Closed) => {
                                session_cancellation.cancel();
                                break;
                            }
                        }
                    }
                    changed = state_rx.changed(), if state_updates_open => {
                        if changed.is_err() {
                            state_updates_open = false;
                            continue;
                        }
                        let snapshot = state_rx.borrow().clone();
                        if let Err(error) = write_client_message(&mut writer, &DaemonMessage::StateUpdate(snapshot)).await {
                            eprintln!("IPC client writer stopped while sending state update: {error}");
                            session_cancellation.cancel();
                            break;
                        }
                    }
                    _ = sub_rx.changed() => {}
                }
            }
        })
    };

    // --- Reader loop ---
    let router = CommandRouter::new(runtime.clone(), services, log_buffer);
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
                let response = if envelope.protocol_version != negotiated_version {
                    log!(
                        "IPC protocol mismatch: pid={}, uid={}, negotiated={}, request={}",
                        peer.pid,
                        peer.uid,
                        negotiated_version,
                        envelope.protocol_version
                    );
                    iota_ipc::ResponseEnvelope {
                        request_id: envelope.request_id,
                        result: iota_ipc::ResponseResult::Error(
                            iota_ipc::IpcErrorCode::UnsupportedVersion,
                        ),
                    }
                } else {
                    router
                        .route(&peer, envelope.request_id, envelope.request)
                        .await
                };
                let should_shutdown = shutdown_reason.is_some()
                    && matches!(&response.result, iota_ipc::ResponseResult::Ok(_));
                let _ = directed_tx
                    .send(WriterCommand::Message(DaemonMessage::Response(response)))
                    .await;
                if let Some(reason) = shutdown_reason.filter(|_| should_shutdown) {
                    let _ = directed_tx
                        .send(WriterCommand::Message(DaemonMessage::LifecycleEvent(
                            iota_ipc::LifecycleEvent::Shutdown {
                                reason: reason.into(),
                            },
                        )))
                        .await;
                    let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
                    let _ = directed_tx
                        .send(WriterCommand::Flush { complete: flush_tx })
                        .await;
                    timeout(CLIENT_IO_TIMEOUT, flush_rx)
                        .await
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "IPC shutdown response flush timed out",
                            )
                        })?
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "IPC writer stopped before shutdown flush",
                            )
                        })?;
                    runtime.begin_shutdown();
                    break;
                }
            }
            Ok(ClientMessage::Subscribe {
                log_classes,
                metric_interval_ms,
            }) => {
                let interval = metric_interval_ms
                    .unwrap_or(DEFAULT_METRIC_INTERVAL_MS)
                    .clamp(MIN_METRIC_INTERVAL_MS, MAX_METRIC_INTERVAL_MS);
                let _ = sub_tx.send(ClientSubscription {
                    log_classes,
                    metric_interval_ms: interval,
                });
                let snapshot = DaemonMessage::StateUpdate(runtime.snapshot());
                let _ = directed_tx.send(WriterCommand::Message(snapshot)).await;
                let _ = directed_tx
                    .send(WriterCommand::Message(DaemonMessage::Subscribed))
                    .await;
            }
            Ok(ClientMessage::Ping { seq }) => {
                let _ = directed_tx
                    .send(WriterCommand::Message(DaemonMessage::Pong { seq }))
                    .await;
            }
            Ok(ClientMessage::Hello { .. }) => {
                // Re-handshake on existing connection: treat as resubscribe
                let snapshot = DaemonMessage::StateUpdate(runtime.snapshot());
                let _ = directed_tx.send(WriterCommand::Message(snapshot)).await;
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                session_cancellation.cancel();
                drop(directed_tx);
                let mut writer_task = writer_task;
                match timeout(CLIENT_IO_TIMEOUT, &mut writer_task).await {
                    Ok(_) => {}
                    Err(_) => {
                        writer_task.abort();
                        let _ = writer_task.await;
                    }
                }
                return Err(error);
            }
        }
    }
    drop(directed_tx);
    session_cancellation.cancel();
    let mut writer_task = writer_task;
    match timeout(CLIENT_IO_TIMEOUT, &mut writer_task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("IPC client writer task failed: {error}");
        }
        Err(_) => {
            eprintln!("IPC client writer did not stop before timeout");
            writer_task.abort();
            let _ = writer_task.await;
        }
    }
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

    #[tokio::test]
    async fn manual_socket_validation_requires_owner_only_mode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ipc.sock");
        let listener = StdUnixListener::bind(&path).expect("test socket binds");
        tokio::fs::set_permissions(&path, PermissionsExt::from_mode(0o600))
            .await
            .expect("test socket permissions apply");

        validate_manual_socket(&path)
            .await
            .expect("manual socket validation succeeds");
        drop(listener);
    }

    #[tokio::test]
    async fn manual_socket_validation_rejects_unexpected_mode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ipc.sock");
        let listener = StdUnixListener::bind(&path).expect("test socket binds");
        tokio::fs::set_permissions(&path, PermissionsExt::from_mode(0o660))
            .await
            .expect("test socket permissions apply");

        let error = validate_manual_socket(&path)
            .await
            .expect_err("group-accessible manual socket must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        drop(listener);
    }

    #[test]
    fn an_admitted_operator_peer_receives_administrator_role() {
        let peer = PeerIdentity {
            pid: 123,
            uid: 1000,
            _gid: 1000,
        };

        assert_eq!(role_for_peer(&peer), IpcRole::Admin);
    }
}
