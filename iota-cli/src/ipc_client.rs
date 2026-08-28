use iota_ipc::{
    ClientMessage, DaemonMessage, HelloAck, LocalRequest, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
    RequestEnvelope, ResponsePayload, ResponseResult, read_msg, write_msg,
};
use iota_state::{ClientState, UiLogEntry};
use std::collections::HashMap;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
const MAX_RECONNECT_ATTEMPTS: u32 = 50;
const STARTUP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Connection state exposed to the UI.
#[derive(Clone, Debug)]
pub enum IpcConnectionState {
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    Incompatible { message: String },
    Failed { message: String },
    Disconnected,
}

/// Daemon information shown by the UI. This is separate from socket connectivity:
/// a connected daemon may still be starting or degraded.
#[derive(Clone, Debug, Default)]
pub struct DaemonStatus {
    pub version: String,
    pub instance_id: String,
    pub startup_phase: Option<iota_ipc::StartupPhase>,
    pub degraded_reason: Option<String>,
    pub lifecycle: Option<iota_ipc::LifecyclePhase>,
    pub health: iota_ipc::HealthStatus,
    pub deployment_mode: Option<iota_ipc::DeploymentMode>,
    pub supervisor: Option<iota_ipc::SupervisorKind>,
    pub components: std::collections::BTreeMap<iota_ipc::ComponentId, iota_ipc::ComponentHealth>,
}

/// Pending request awaiting a response.
struct PendingRequest {
    response_tx: oneshot::Sender<ResponseResult>,
}

struct ActiveWriter {
    generation: u64,
    writer: OwnedWriteHalf,
}

struct NegotiatedConnection {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    ack: HelloAck,
    buffered_messages: Vec<DaemonMessage>,
}

/* The TUI owns this cache. IPC updates replace daemon snapshots and append
 * logs, so rendering never reaches into daemon-owned storage or connections. */
pub struct IpcClient {
    state: ClientState,
    writer: Mutex<Option<ActiveWriter>>,
    next_generation: AtomicU64,
    next_request_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingRequest>>,
    connection_state: watch::Sender<IpcConnectionState>,
    daemon_status: watch::Sender<DaemonStatus>,
    path: PathBuf,
    reconnector_started: AtomicBool,
    cancellation: CancellationToken,
    background_tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl IpcClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let deadline = tokio::time::Instant::now() + STARTUP_CONNECT_TIMEOUT;
        Self::connect_until(&path, deadline).await
    }

    async fn connect_until(path: &Path, deadline: tokio::time::Instant) -> Result<Arc<Self>> {
        let path = path.to_path_buf();
        let stream = Self::connect_stream(&path, deadline).await?;
        let negotiated = Self::negotiate_stream(stream, deadline).await?;

        // These values are visible before MainScreen subscribes.  Do not
        // publish the handshake into a channel with no retained receiver.
        let initial_status = DaemonStatus {
            version: negotiated.ack.daemon_version.clone(),
            instance_id: negotiated.ack.instance_id.clone(),
            startup_phase: Some(negotiated.ack.startup_phase),
            degraded_reason: None,
            lifecycle: Some(negotiated.ack.lifecycle),
            health: negotiated.ack.health,
            deployment_mode: Some(negotiated.ack.deployment_mode),
            supervisor: Some(negotiated.ack.supervisor),
            components: std::collections::BTreeMap::new(),
        };
        let (conn_state_tx, _) = watch::channel(IpcConnectionState::Connected);
        let (daemon_status_tx, _) = watch::channel(initial_status);
        let client = Arc::new(Self {
            state: ClientState::new(),
            writer: Mutex::new(Some(ActiveWriter {
                generation: 1,
                writer: negotiated.writer,
            })),
            next_generation: AtomicU64::new(2),
            next_request_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            connection_state: conn_state_tx,
            daemon_status: daemon_status_tx,
            path: path.clone(),
            reconnector_started: AtomicBool::new(false),
            cancellation: CancellationToken::new(),
            background_tasks: StdMutex::new(Vec::new()),
        });

        // Apply messages received while waiting for subscription confirmation
        // before exposing the connection to the UI.
        for message in negotiated.buffered_messages {
            client.apply(message).await;
        }

        // Start reader task (continues reading after handshake)
        let reader_client = client.clone();
        let task = tokio::spawn(async move {
            reader_client.read_loop(negotiated.reader, 1).await;
        });
        client.background_tasks.lock().unwrap().push(task);

        Ok(client)
    }

    /// Try to connect with retries for socket activation.
    pub async fn connect_or_activate(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let deadline = tokio::time::Instant::now() + STARTUP_CONNECT_TIMEOUT;
        let mut last_error = None;
        while tokio::time::Instant::now() < deadline {
            match Self::connect_until(&path, deadline).await {
                Ok(client) => return Ok(client),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out waiting for daemon")
        }))
    }

    async fn connect_stream(path: &Path, deadline: tokio::time::Instant) -> Result<UnixStream> {
        tokio::time::timeout_at(deadline, UnixStream::connect(path))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out connecting to daemon",
                )
            })?
    }

    async fn negotiate_stream(
        stream: UnixStream,
        deadline: tokio::time::Instant,
    ) -> Result<NegotiatedConnection> {
        let (mut reader, mut writer) = stream.into_split();
        tokio::time::timeout_at(
            deadline,
            write_msg(
                &mut writer,
                &ClientMessage::Hello {
                    supported_versions: vec![MIN_PROTOCOL_VERSION, PROTOCOL_VERSION],
                },
            ),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out sending IPC Hello")
        })??;
        let ack = match tokio::time::timeout_at(deadline, read_msg::<_, DaemonMessage>(&mut reader))
            .await
        {
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out waiting for IPC HelloAck",
                ));
            }
            Ok(Ok(DaemonMessage::HelloAck(ack))) => ack,
            Ok(Ok(_)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected HelloAck as the first daemon message",
                ));
            }
            Ok(Err(error)) => return Err(error),
        };
        if !Self::is_compatible_version(ack.protocol_version) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "Unsupported daemon protocol version {}",
                    ack.protocol_version
                ),
            ));
        }
        tokio::time::timeout_at(
            deadline,
            write_msg(
                &mut writer,
                &ClientMessage::Subscribe {
                    log_classes: vec![],
                    metric_interval_ms: Some(500),
                },
            ),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timed out sending IPC subscription",
            )
        })??;

        // The daemon may send its initial StateUpdate before the acknowledgement.
        // Keep draining until the subscription itself is confirmed, otherwise a
        // UI can report Connected while no state stream exists yet.
        let mut buffered_messages = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, read_msg::<_, DaemonMessage>(&mut reader)).await
            {
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Timed out waiting for IPC subscription acknowledgement",
                    ));
                }
                Ok(Ok(DaemonMessage::Subscribed)) => break,
                Ok(Ok(message)) => buffered_messages.push(message),
                Ok(Err(error)) => return Err(error),
            }
        }

        Ok(NegotiatedConnection {
            reader,
            writer,
            ack,
            buffered_messages,
        })
    }

    /// Start the reconnection actor.
    pub fn spawn_reconnector(self: &Arc<Self>) {
        if self.reconnector_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let client = self.clone();
        let task = tokio::spawn(async move {
            client.reconnection_loop().await;
        });
        self.background_tasks.lock().unwrap().push(task);
    }

    async fn reconnection_loop(self: Arc<Self>) {
        let mut rx = self.connection_status();

        loop {
            while !matches!(*rx.borrow(), IpcConnectionState::Disconnected) {
                if tokio::select! {
                    changed = rx.changed() => changed.is_err(),
                    _ = self.cancellation.cancelled() => true,
                } {
                    return;
                }
            }

            let mut backoff = INITIAL_BACKOFF;
            for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
                if self.cancellation.is_cancelled() {
                    return;
                }
                let _ = self
                    .connection_state
                    .send(IpcConnectionState::Reconnecting { attempt });
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {},
                    _ = self.cancellation.cancelled() => return,
                }
                let deadline = tokio::time::Instant::now() + CONNECT_ATTEMPT_TIMEOUT;
                let result = async {
                    let stream = Self::connect_stream(&self.path, deadline).await?;
                    Self::negotiate_stream(stream, deadline).await
                }
                .await;
                match result {
                    Ok(connection) => {
                        self.install_connection(connection).await;
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                        let _ = self
                            .connection_state
                            .send(IpcConnectionState::Incompatible {
                                message: error.to_string(),
                            });
                        return;
                    }
                    Err(error) if attempt == MAX_RECONNECT_ATTEMPTS => {
                        let _ = self.connection_state.send(IpcConnectionState::Failed {
                            message: format!("Reconnect failed after {attempt} attempts: {error}"),
                        });
                        return;
                    }
                    Err(error) => {
                        eprintln!(
                            "IPC reconnect attempt {attempt} to {} failed: kind={:?}, error={error}",
                            self.path.display(),
                            error.kind()
                        );
                        backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                    }
                }
            }
        }
    }

    async fn install_connection(self: &Arc<Self>, connection: NegotiatedConnection) {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        *self.writer.lock().await = Some(ActiveWriter {
            generation,
            writer: connection.writer,
        });
        self.update_hello_ack(connection.ack);
        for message in connection.buffered_messages {
            self.apply(message).await;
        }
        let _ = self.connection_state.send(IpcConnectionState::Connected);
        let client = self.clone();
        let task = tokio::spawn(async move {
            client.read_loop(connection.reader, generation).await;
        });
        self.background_tasks.lock().unwrap().push(task);
    }

    async fn fail_pending_requests(&self) {
        let mut pending = self.pending.lock().await;
        for (_, request) in pending.drain() {
            let _ = request
                .response_tx
                .send(ResponseResult::Error(iota_ipc::IpcErrorCode::Disconnected));
        }
    }

    async fn mark_disconnected(&self, generation: u64) {
        let removed = {
            let mut writer = self.writer.lock().await;
            match writer.as_ref() {
                Some(active) if active.generation == generation => {
                    writer.take();
                    true
                }
                _ => false,
            }
        };
        if removed {
            let _ = self.connection_state.send(IpcConnectionState::Disconnected);
            self.fail_pending_requests().await;
        }
    }

    async fn read_loop(self: Arc<Self>, mut reader: OwnedReadHalf, generation: u64) {
        loop {
            let result = tokio::select! {
                result = read_msg::<_, DaemonMessage>(&mut reader) => result,
                _ = self.cancellation.cancelled() => break,
            };
            match result {
                Ok(message) => self.apply(message).await,
                Err(_) => {
                    self.mark_disconnected(generation).await;
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

    pub fn daemon_status(&self) -> watch::Receiver<DaemonStatus> {
        self.daemon_status.subscribe()
    }

    /// Stop the IPC reader/reconnector and release the socket writer.  This
    /// is deliberately bounded so UI shutdown cannot hang on a peer.
    pub async fn shutdown(&self) {
        self.cancellation.cancel();
        self.writer.lock().await.take();
        let tasks = std::mem::take(&mut *self.background_tasks.lock().unwrap());
        for mut task in tasks {
            if tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
    }

    fn is_compatible_version(version: u16) -> bool {
        (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version)
    }

    fn update_hello_ack(&self, ack: HelloAck) {
        self.daemon_status.send_modify(|status| {
            status.version = ack.daemon_version;
            status.instance_id = ack.instance_id;
            status.startup_phase = Some(ack.startup_phase);
            status.lifecycle = Some(ack.lifecycle);
            status.health = ack.health;
            status.deployment_mode = Some(ack.deployment_mode);
            status.supervisor = Some(ack.supervisor);
        });
    }

    fn format_payload(payload: &ResponsePayload) -> String {
        match payload {
            ResponsePayload::Status(status) => {
                let mut msg = format!("Phase: {}", status.phase);
                if !status.tasks.is_empty() {
                    msg.push_str(&format!(", Tasks: {}", status.tasks.join(", ")));
                }
                if let Some(reason) = &status.degraded_reason {
                    msg.push_str(&format!(", Degraded: {reason}"));
                }
                msg
            }
            ResponsePayload::Tasks(tasks) => {
                if tasks.is_empty() {
                    "No active tasks.".into()
                } else {
                    tasks
                        .iter()
                        .map(|t| t.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            }
            ResponsePayload::Users(users) => {
                if users.is_empty() {
                    "No users.".into()
                } else {
                    users
                        .iter()
                        .map(|u| format!("{} ({})", u.username, u.user_id))
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            ResponsePayload::UserCreated { user_id, username } => {
                format!("Created user {} ({})", username, user_id)
            }
            ResponsePayload::UserRemoved { user_id } => {
                format!("Removed user {}", user_id)
            }
            ResponsePayload::UserDataPurged { user_id } => {
                format!("Purged hosted data for {}", user_id)
            }
            ResponsePayload::Acknowledged { message } => message.clone(),
            ResponsePayload::DaemonStatus(status) => status.formatted.clone(),
            ResponsePayload::Config(config) => config.yaml.clone(),
            ResponsePayload::OmikronStatus(status) => {
                let mut msg = format!("Connected: {}", status.connected);
                if let Some(id) = status.iota_id {
                    msg.push_str(&format!("\nIota ID: {}", id));
                }
                msg
            }
            ResponsePayload::Components(components) => {
                if components.is_empty() {
                    "No component health data available.".into()
                } else {
                    components
                        .iter()
                        .map(|c| {
                            let status_str = match c.status {
                                iota_ipc::HealthStatus::Healthy => "healthy",
                                iota_ipc::HealthStatus::Degraded => "degraded",
                                iota_ipc::HealthStatus::Failed => "failed",
                            };
                            format!("{:?}: {}", c.id, status_str)
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            ResponsePayload::UserDetail(user) => {
                let mut msg = format!("User: {} ({})", user.username, user.user_id);
                if let Some(ref name) = user.display_name {
                    msg.push_str(&format!("\nDisplay Name: {name}"));
                }
                msg.push_str(&format!("\nCreated At: {}", user.created_at));
                if !user.trusted_apps.is_empty() {
                    msg.push_str(&format!("\nTrusted Apps: {}", user.trusted_apps.join(", ")));
                }
                msg
            }
            ResponsePayload::LogEntries(logs) => logs
                .entries
                .iter()
                .map(|e| {
                    let level = if e.is_error { "ERR" } else { "INF" };
                    format!("[{}] {level} {}: {}", e.timestamp_ms, e.sender, e.message)
                })
                .collect::<Vec<_>>()
                .join("\n"),
            ResponsePayload::UpdateStatus(status) => {
                if status.available {
                    "Update available.".into()
                } else {
                    "Up to date.".into()
                }
            }
            ResponsePayload::Communities(communities) => {
                if communities.is_empty() {
                    "No communities.".into()
                } else {
                    communities
                        .iter()
                        .map(|c| format!("{} ({})", c.title, c.name))
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
        }
    }

    fn format_error(code: &iota_ipc::IpcErrorCode) -> &'static str {
        match code {
            iota_ipc::IpcErrorCode::InvalidRequest => "The command is not valid.",
            iota_ipc::IpcErrorCode::NotFound => "The requested user or resource was not found.",
            iota_ipc::IpcErrorCode::Conflict => "The request conflicts with existing state.",
            iota_ipc::IpcErrorCode::StorageFailure => "The daemon could not update its storage.",
            iota_ipc::IpcErrorCode::OmikronUnavailable => {
                "Omikron is unavailable; try reconnecting."
            }
            iota_ipc::IpcErrorCode::UnsupportedVersion => {
                "CLI and daemon versions are incompatible."
            }
            iota_ipc::IpcErrorCode::NotReady => "The daemon is still starting; try again shortly.",
            iota_ipc::IpcErrorCode::Disconnected => "The daemon connection was lost.",
            iota_ipc::IpcErrorCode::Timeout => "The daemon request timed out.",
            iota_ipc::IpcErrorCode::Cancelled => "The daemon request was cancelled.",
            iota_ipc::IpcErrorCode::Unauthorized => {
                "The daemon rejected this operation: the connected IPC account lacks the required role. Use the configured operator socket or ask an administrator to grant access."
            }
            iota_ipc::IpcErrorCode::InternalFailure => "The daemon reported an internal failure.",
        }
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
        if let Err(error) = self.send(ClientMessage::Request(envelope)).await {
            self.pending.lock().await.remove(&request_id);
            return Err(error);
        }

        match tokio::time::timeout(Duration::from_secs(45), response_rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Ok(ResponseResult::Error(iota_ipc::IpcErrorCode::Disconnected)),
            Err(_) => {
                self.pending.lock().await.remove(&request_id);
                Ok(ResponseResult::Error(iota_ipc::IpcErrorCode::Timeout))
            }
        }
    }

    /// Parse a legacy console command string into a typed request.
    /// Delegates to the shared parser in iota-ipc.
    pub fn parse_console_command(line: &str) -> Option<LocalRequest> {
        iota_ipc::text_commands::parse(line)
    }

    /// Legacy command interface: parse text command, send as typed request.
    pub async fn send_command(&self, _seq: u64, line: String) -> Result<()> {
        let trimmed = line.trim_start_matches('/').trim();

        // Handle ping as a direct Ping message (not a LocalRequest).
        if trimmed == "ping" || trimmed.starts_with("ping ") {
            let seq = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = self.send(ClientMessage::Ping { seq }).await {
                let mut state = self.state.app.lock().await;
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
            let mut state = self.state.app.lock().await;
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
                    let mut state = self.state.app.lock().await;
                    let message = match &result {
                        ResponseResult::Ok(payload) => Self::format_payload(payload),
                        ResponseResult::Error(code) => Self::format_error(code).into(),
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
                    let mut state = self.state.app.lock().await;
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
            let mut state = self.state.app.lock().await;
            state.push_log(UiLogEntry {
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                sender: "Console".into(),
                message:                 if trimmed == "help" {
                    "Commands: status, tasks, ping, user add <name>, user remove <id>, user list, users, reconnect, regenerate keys, restart, stop, config get, config reload, omikron status, components"
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
        let deadline = tokio::time::Instant::now() + CONNECT_ATTEMPT_TIMEOUT;
        let mut writer_guard = tokio::time::timeout_at(deadline, self.writer.lock())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out acquiring IPC writer",
                )
            })?;
        let active = writer_guard.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "IPC connection is not active",
            )
        })?;
        let generation = active.generation;
        let write_result =
            tokio::time::timeout_at(deadline, write_msg(&mut active.writer, &message))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Timed out writing IPC message",
                    )
                })
                .and_then(|result| result);
        drop(writer_guard);
        if write_result.is_err() {
            self.mark_disconnected(generation).await;
        }
        write_result
    }

    async fn apply(&self, message: DaemonMessage) {
        match message {
            DaemonMessage::LogEntry(entry) => {
                let mut state = self.state.app.lock().await;
                state.push_log(UiLogEntry {
                    timestamp_ms: entry.timestamp_ms,
                    sender: entry.sender,
                    message: entry.message,
                    is_error: entry.is_error,
                });
            }
            DaemonMessage::StateUpdate(snapshot) => {
                // Never hold a watch borrow while sending to that same
                // channel: send waits for outstanding Ref guards.
                self.daemon_status.send_modify(|status| {
                    status.startup_phase = Some(snapshot.startup_phase);
                    status.degraded_reason = snapshot.degraded_reason.clone();
                    status.lifecycle = Some(snapshot.lifecycle);
                    status.health = snapshot.overall_health;
                    status.components = snapshot.components.clone();
                });
                let mut state = self.state.app.lock().await;
                state.cpu = snapshot.cpu;
                state.ram = snapshot.ram;
                state.ping = snapshot.ping;
                state.net_up = snapshot.net_up;
                state.net_down = snapshot.net_down;
                state.sys_info = snapshot.sys_info;
            }
            DaemonMessage::MetricSample(sample) => {
                let mut state = self.state.app.lock().await;
                if let Some(cpu) = sample.cpu {
                    state.push_cpu((0.0, cpu));
                }
                if let Some(ram) = sample.ram {
                    state.push_ram((0.0, ram));
                }
                if let Some(ping) = sample.ping {
                    state.push_ping_val(ping);
                }
                if let Some(net_up) = sample.net_up {
                    state.push_net_up((0.0, net_up));
                }
                if let Some(net_down) = sample.net_down {
                    state.push_net_down((0.0, net_down));
                }
            }
            DaemonMessage::Response(response) => {
                let mut pending = self.pending.lock().await;
                if let Some(request) = pending.remove(&response.request_id) {
                    let _ = request.response_tx.send(response.result);
                } else {
                    let mut state = self.state.app.lock().await;
                    let message = match &response.result {
                        ResponseResult::Ok(payload) => Self::format_payload(payload),
                        ResponseResult::Error(code) => Self::format_error(code).into(),
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
            DaemonMessage::HelloAck(ack) => self.update_hello_ack(ack),
            DaemonMessage::Subscribed => {}
            DaemonMessage::Pong { .. } => {}
            DaemonMessage::LifecycleEvent(event) => match event {
                iota_ipc::LifecycleEvent::Shutdown { reason } => {
                    let mut state = self.state.app.lock().await;
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
                iota_ipc::LifecycleEvent::StateChanged(status) => {
                    self.daemon_status.send_modify(|daemon_status| {
                        daemon_status.degraded_reason = match status {
                            iota_ipc::ConnectionStatus::Degraded => {
                                Some("A daemon dependency is degraded".into())
                            }
                            _ => None,
                        };
                    });
                }
            },
            DaemonMessage::Gap { skipped } => {
                let mut state = self.state.app.lock().await;
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
