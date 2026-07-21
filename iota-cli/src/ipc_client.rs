use iota_ipc::{
    ClientMessage, DaemonMessage, LocalRequest, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
    RequestEnvelope, ResponseResult, read_msg, write_msg,
};
use iota_state::{ClientState, UiLogEntry};
use std::collections::HashMap;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, oneshot, watch};

const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
const MAX_RECONNECT_ATTEMPTS: u32 = 50;

/// Connection state exposed to the UI.
#[derive(Clone, Debug)]
pub enum IpcConnectionState {
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    Incompatible { message: String },
    Disconnected,
}

/// Pending request awaiting a response.
struct PendingRequest {
    response_tx: oneshot::Sender<ResponseResult>,
}

/* The TUI owns this cache. IPC updates replace daemon snapshots and append
 * logs, so rendering never reaches into daemon-owned storage or connections. */
pub struct IpcClient {
    state: ClientState,
    writer: Mutex<OwnedWriteHalf>,
    next_request_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingRequest>>,
    connection_state: watch::Sender<IpcConnectionState>,
    path: PathBuf,
}

impl IpcClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let stream = Self::try_connect(&path).await?;
        let (mut reader, writer) = stream.into_split();

        let (conn_state_tx, _) = watch::channel(IpcConnectionState::Connecting);
        let client = Arc::new(Self {
            state: ClientState::new(),
            writer: Mutex::new(writer),
            next_request_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            connection_state: conn_state_tx,
            path: path.clone(),
        });

        // --- Handshake: send Hello, read HelloAck ---
        {
            let mut w = client.writer.lock().await;
            write_msg(
                &mut *w,
                &ClientMessage::Hello {
                    supported_versions: vec![MIN_PROTOCOL_VERSION, PROTOCOL_VERSION],
                },
            )
            .await?;
        }
        match read_msg::<_, DaemonMessage>(&mut reader).await {
            Ok(DaemonMessage::HelloAck(ack)) => {
                if ack.protocol_version < MIN_PROTOCOL_VERSION {
                    let _ = client
                        .connection_state
                        .send(IpcConnectionState::Incompatible {
                            message: format!(
                                "Daemon protocol {} < required {}",
                                ack.protocol_version, MIN_PROTOCOL_VERSION
                            ),
                        });
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!(
                            "Protocol version mismatch: daemon={}, minimum={}",
                            ack.protocol_version, MIN_PROTOCOL_VERSION
                        ),
                    ));
                }
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected HelloAck from daemon",
                ));
            }
            Err(e) => return Err(e),
        }

        let _ = client.connection_state.send(IpcConnectionState::Connected);

        // Start reader task (continues reading after handshake)
        let reader_client = client.clone();
        tokio::spawn(async move {
            reader_client.read_loop(reader).await;
        });

        // Subscribe to events
        client
            .send(ClientMessage::Subscribe {
                log_classes: vec![],
                metric_interval_ms: Some(500),
            })
            .await?;

        Ok(client)
    }

    /// Try to connect with retries for socket activation.
    pub async fn connect_or_activate(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let max_attempts = 30;
        for attempt in 0..max_attempts {
            match Self::connect(&path).await {
                Ok(client) => return Ok(client),
                Err(error) => {
                    if attempt < max_attempts - 1 {
                        let delay = Duration::from_millis(100 + attempt as u64 * 100);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        unreachable!()
    }

    async fn try_connect(path: &Path) -> Result<UnixStream> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(path).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(error);
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// Start the reconnection actor.
    pub fn spawn_reconnector(self: &Arc<Self>) {
        let client = self.clone();
        tokio::spawn(async move {
            client.reconnection_loop().await;
        });
    }

    async fn reconnection_loop(self: Arc<Self>) {
        let mut rx = self.connection_status();

        loop {
            // Wait until the connection enters the Disconnected state.
            loop {
                let disconnected = matches!(*rx.borrow(), IpcConnectionState::Disconnected);
                if disconnected {
                    break;
                }
                if rx.changed().await.is_err() {
                    return; // sender dropped
                }
            }

            let mut backoff = INITIAL_BACKOFF;
            let mut attempt: u32 = 0;

            // Attempt reconnection until success or max attempts.
            loop {
                tokio::time::sleep(backoff).await;
                attempt += 1;

                if attempt > MAX_RECONNECT_ATTEMPTS {
                    let _ = self
                        .connection_state
                        .send(IpcConnectionState::Incompatible {
                            message: "Max reconnection attempts exceeded".into(),
                        });
                    return;
                }

                let _ = self
                    .connection_state
                    .send(IpcConnectionState::Reconnecting { attempt });

                match Self::try_connect(&self.path).await {
                    Ok(stream) => {
                        let (mut reader, writer) = stream.into_split();
                        *self.writer.lock().await = writer;

                        // Re-handshake
                        {
                            let mut w = self.writer.lock().await;
                            if write_msg(
                                &mut *w,
                                &ClientMessage::Hello {
                                    supported_versions: vec![
                                        MIN_PROTOCOL_VERSION,
                                        PROTOCOL_VERSION,
                                    ],
                                },
                            )
                            .await
                            .is_err()
                            {
                                let _ = self
                                    .connection_state
                                    .send(IpcConnectionState::Disconnected);
                                break;
                            }
                        }

                        // Read HelloAck
                        match read_msg::<_, DaemonMessage>(&mut reader).await {
                            Ok(DaemonMessage::HelloAck(ack)) => {
                                if ack.protocol_version < MIN_PROTOCOL_VERSION {
                                    let _ = self.connection_state.send(
                                        IpcConnectionState::Incompatible {
                                            message: format!(
                                                "Daemon protocol {} < required {}",
                                                ack.protocol_version, MIN_PROTOCOL_VERSION
                                            ),
                                        },
                                    );
                                    return;
                                }
                            }
                            _ => {
                                let _ = self
                                    .connection_state
                                    .send(IpcConnectionState::Disconnected);
                                break;
                            }
                        }

                        // Clear pending requests with connection-lost errors
                        {
                            let mut pending = self.pending.lock().await;
                            for (_, request) in pending.drain() {
                                let _ = request.response_tx.send(
                                    ResponseResult::Error(
                                        iota_ipc::IpcErrorCode::Disconnected,
                                    ),
                                );
                            }
                        }

                        let _ = self.connection_state.send(IpcConnectionState::Connected);

                        // Start new reader loop
                        let reader_client = self.clone();
                        tokio::spawn(async move {
                            reader_client.read_loop(reader).await;
                        });

                        // Resubscribe
                        let _ = self
                            .send(ClientMessage::Subscribe {
                                log_classes: vec![],
                                metric_interval_ms: Some(500),
                            })
                            .await;

                        // Successfully reconnected; go back to waiting for
                        // the next disconnect.
                        break;
                    }
                    Err(_) => {
                        backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                    }
                }
            }
        }
    }

    async fn read_loop(self: Arc<Self>, mut reader: OwnedReadHalf) {
        loop {
            match read_msg::<_, DaemonMessage>(&mut reader).await {
                Ok(message) => self.apply(message).await,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    let _ = self.connection_state.send(IpcConnectionState::Disconnected);
                    break;
                }
                Err(_) => {
                    let _ = self.connection_state.send(IpcConnectionState::Disconnected);
                    break;
                }
            }
        }
    }

    pub fn state(&self) -> ClientState {
        self.state.clone()
    }

    pub fn connection_status(&self) -> watch::Receiver<IpcConnectionState> {
        self.connection_state.subscribe()
    }

    pub fn connection_status_snapshot(&self) -> IpcConnectionState {
        self.connection_state.borrow().clone()
    }

    pub async fn send_request(&self, request: LocalRequest) -> Result<ResponseResult> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (response_tx, response_rx) = oneshot::channel();

        {
            let mut pending = self.pending.lock().await;
            pending.insert(request_id, PendingRequest { response_tx });
        }

        let envelope = RequestEnvelope {
            request_id,
            protocol_version: PROTOCOL_VERSION,
            request,
        };
        self.send(ClientMessage::Request(envelope)).await?;

        match tokio::time::timeout(Duration::from_secs(30), response_rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Ok(ResponseResult::Error(iota_ipc::IpcErrorCode::Disconnected)),
            Err(_) => {
                self.pending.lock().await.remove(&request_id);
                Ok(ResponseResult::Error(iota_ipc::IpcErrorCode::Disconnected))
            }
        }
    }

    /// Parse a legacy console command string into a typed request.
    pub fn parse_console_command(line: &str) -> Option<LocalRequest> {
        let parts: Vec<&str> = line.trim_start_matches('/').split_whitespace().collect();
        match parts.as_slice() {
            ["help"] => None,
            ["tasks"] => Some(LocalRequest::ListTasks),
            ["user", "add", username] => Some(LocalRequest::CreateUser {
                username: username.to_string(),
            }),
            ["user", "remove", user_id_str] => {
                let user_id = user_id_str.parse::<i64>().ok()?;
                Some(LocalRequest::RemoveUser { user_id })
            }
            ["user", "list"] => Some(LocalRequest::ListUsers),
            ["reconnect"] => Some(LocalRequest::ReconnectOmikron),
            ["regenerate", "keys"] => Some(LocalRequest::RotateIotaIdentity),
            ["reload"] | ["restart"] => Some(LocalRequest::RestartDaemon),
            ["shutdown"] | ["stop"] => Some(LocalRequest::StopDaemon),
            _ => None,
        }
    }

    /// Legacy command interface: parse text command, send as typed request.
    pub async fn send_command(&self, _seq: u64, line: String) -> Result<()> {
        let trimmed = line.trim_start_matches('/').trim();

        // Handle ping as a direct Ping message (not a LocalRequest).
        if trimmed == "ping" || trimmed.starts_with("ping ") {
            let seq = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = self.send(ClientMessage::Ping { seq }).await {
                let mut state = self
                    .state
                    .app
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                state.push_log(UiLogEntry {
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis(),
                    sender: "Console".into(),
                    message: format!("Failed to send ping: {}", e),
                    is_error: true,
                });
                return Err(e);
            }
            let mut state = self
                .state
                .app
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.push_log(UiLogEntry {
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                sender: "Console".into(),
                message: "Ping sent".into(),
                is_error: false,
            });
            return Ok(());
        }

        if let Some(request) = Self::parse_console_command(&line) {
            match self.send_request(request).await {
                Ok(result) => {
                    let mut state = self
                        .state
                        .app
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let message = match &result {
                        ResponseResult::Ok(msg) => msg.clone(),
                        ResponseResult::Error(code) => format!("Error: {:?}", code),
                    };
                    state.push_log(UiLogEntry {
                        timestamp_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis(),
                        sender: "Command".into(),
                        message,
                        is_error: matches!(&result, ResponseResult::Error(_)),
                    });
                    Ok(())
                }
                Err(e) => {
                    let mut state = self
                        .state
                        .app
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    state.push_log(UiLogEntry {
                        timestamp_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis(),
                        sender: "Console".into(),
                        message: format!("Failed to send: {}", e),
                        is_error: true,
                    });
                    Err(e)
                }
            }
        } else {
            let mut state = self
                .state
                .app
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.push_log(UiLogEntry {
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                sender: "Console".into(),
                message: if line.trim() == "help" {
                    "Available commands: tasks, ping, user, reconnect, regenerate, restart, stop"
                        .into()
                } else {
                    format!("Unknown command: {}", line)
                },
                is_error: false,
            });
            Ok(())
        }
    }

    async fn send(&self, message: ClientMessage) -> Result<()> {
        let mut writer = self.writer.lock().await;
        write_msg(&mut *writer, &message).await
    }

    async fn apply(&self, message: DaemonMessage) {
        match message {
            DaemonMessage::LogEntry(entry) => {
                let mut state = self
                    .state
                    .app
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                state.push_log(UiLogEntry {
                    timestamp_ms: entry.timestamp_ms,
                    sender: entry.sender,
                    message: entry.message,
                    is_error: entry.is_error,
                });
            }
            DaemonMessage::StateUpdate(snapshot) => {
                let mut state = self
                    .state
                    .app
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                state.cpu = snapshot.cpu;
                state.ram = snapshot.ram;
                state.ping = snapshot.ping;
                state.net_up = snapshot.net_up;
                state.net_down = snapshot.net_down;
                state.sys_info = snapshot.sys_info;
            }
            DaemonMessage::MetricSample(sample) => {
                let mut state = self
                    .state
                    .app
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(cpu) = sample.cpu {
                    let idx = state.cpu.len() as f64;
                    state.cpu.push((idx, cpu));
                    if state.cpu.len() > iota_state::MAX_POINTS {
                        state.cpu.remove(0);
                    }
                }
                if let Some(ram) = sample.ram {
                    let idx = state.ram.len() as f64;
                    state.ram.push((idx, ram));
                    if state.ram.len() > iota_state::MAX_POINTS {
                        state.ram.remove(0);
                    }
                }
                if let Some(ping) = sample.ping {
                    state.push_ping_val(ping);
                }
                if let Some(net_up) = sample.net_up {
                    let idx = state.net_up.len() as f64;
                    state.net_up.push((idx, net_up));
                    if state.net_up.len() > iota_state::MAX_POINTS {
                        state.net_up.remove(0);
                    }
                }
                if let Some(net_down) = sample.net_down {
                    let idx = state.net_down.len() as f64;
                    state.net_down.push((idx, net_down));
                    if state.net_down.len() > iota_state::MAX_POINTS {
                        state.net_down.remove(0);
                    }
                }
            }
            DaemonMessage::Response(response) => {
                let mut pending = self.pending.lock().await;
                if let Some(request) = pending.remove(&response.request_id) {
                    let _ = request.response_tx.send(response.result);
                } else {
                    let mut state = self
                        .state
                        .app
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let message = match &response.result {
                        ResponseResult::Ok(msg) => msg.clone(),
                        ResponseResult::Error(code) => format!("Error: {:?}", code),
                    };
                    state.push_log(UiLogEntry {
                        timestamp_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis(),
                        sender: "Command".into(),
                        message,
                        is_error: matches!(&response.result, ResponseResult::Error(_)),
                    });
                }
            }
            DaemonMessage::HelloAck(_) => {}
            DaemonMessage::Pong { .. } => {}
            DaemonMessage::LifecycleEvent(event) => match event {
                iota_ipc::LifecycleEvent::Shutdown { reason } => {
                    let mut state = self
                        .state
                        .app
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    state.push_log(UiLogEntry {
                        timestamp_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis(),
                        sender: "Daemon".into(),
                        message: format!("Daemon shutting down: {}", reason),
                        is_error: true,
                    });
                }
                _ => {}
            },
            DaemonMessage::Gap { skipped } => {
                let mut state = self
                    .state
                    .app
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                state.push_log(UiLogEntry {
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis(),
                    sender: "System".into(),
                    message: format!("Skipped {} messages, resynchronizing", skipped),
                    is_error: false,
                });
            }
        }
    }
}
