use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Client → Daemon
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        supported_versions: Vec<u16>,
    },
    Subscribe {
        log_classes: Vec<String>,
        metric_interval_ms: Option<u64>,
    },
    Request(RequestEnvelope),
    Ping {
        seq: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestEnvelope {
    pub request_id: u64,
    pub protocol_version: u16,
    pub request: LocalRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum LocalRequest {
    GetStatus,
    ListTasks,
    ListUsers,
    CreateUser {
        username: String,
    },
    RemoveUser {
        user_id: i64,
    },
    ReconnectOmikron,
    RotateIotaIdentity,
    RequestProcessExit {
        intent: ExitIntent,
    },
    GetDaemonStatus,
    #[serde(skip)]
    RestartDaemon,
    #[serde(skip)]
    StopDaemon,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitIntent {
    Stop,
    Restart,
}

// ---------------------------------------------------------------------------
// Daemon → Client
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum DaemonMessage {
    HelloAck(HelloAck),
    /// Confirms that the server has installed this connection's subscription.
    Subscribed,
    LogEntry(LogEntry),
    StateUpdate(StateSnapshot),
    MetricSample(MetricSample),
    Response(ResponseEnvelope),
    Pong {
        seq: u64,
    },
    LifecycleEvent(LifecycleEvent),
    Gap {
        skipped: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HelloAck {
    pub protocol_version: u16,
    pub daemon_version: String,
    pub instance_id: String,
    pub startup_phase: StartupPhase,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub lifecycle: LifecyclePhase,
    #[serde(default)]
    pub health: HealthStatus,
    #[serde(default)]
    pub deployment_mode: DeploymentMode,
    #[serde(default)]
    pub supervisor: SupervisorKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseEnvelope {
    pub request_id: u64,
    pub result: ResponseResult,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ResponseResult {
    Ok(String),
    Error(IpcErrorCode),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcErrorCode {
    InvalidRequest,
    NotFound,
    Conflict,
    StorageFailure,
    OmikronUnavailable,
    UnsupportedVersion,
    NotReady,
    Disconnected,
    Timeout,
    Cancelled,
    Unauthorized,
    InternalFailure,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum LifecycleEvent {
    StateChanged(ConnectionStatus),
    Shutdown { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Connected,
    Reconnecting,
    Degraded,
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupPhase {
    Starting,
    MigratingStorage,
    LoadingUsers,
    StartingServices,
    Ready,
    Degraded,
    Stopping,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    #[default]
    Starting,
    Ready,
    Stopping,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    #[default]
    Healthy,
    Degraded,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentId {
    Storage,
    Ipc,
    Omikron,
    Web,
    Updater,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    SessionChild,
    UiAutoStart,
    UserService,
    SystemSocketActivated,
    SystemAlwaysOn,
    #[default]
    External,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorKind {
    #[default]
    None,
    IotaUi,
    Systemd,
    External,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: HealthStatus,
    pub message: Option<String>,
    pub changed_at_ms: u128,
}

impl Default for StartupPhase {
    fn default() -> Self {
        Self::Starting
    }
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogEntry {
    pub timestamp_ms: u128,
    pub sender: String,
    pub message: String,
    pub is_error: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateSnapshot {
    pub cpu: Vec<(f64, f64)>,
    pub ram: Vec<(f64, f64)>,
    pub ping: Vec<(f64, f64)>,
    pub net_up: Vec<(f64, f64)>,
    pub net_down: Vec<(f64, f64)>,
    pub sys_info: String,
    #[serde(default)]
    pub startup_phase: StartupPhase,
    #[serde(default)]
    pub degraded_reason: Option<String>,
    #[serde(default)]
    pub lifecycle: LifecyclePhase,
    #[serde(default)]
    pub startup_step: Option<String>,
    #[serde(default)]
    pub overall_health: HealthStatus,
    #[serde(default)]
    pub components: std::collections::BTreeMap<ComponentId, ComponentHealth>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MetricSample {
    pub cpu: Option<f64>,
    pub ram: Option<f64>,
    pub ping: Option<f64>,
    pub net_up: Option<f64>,
    pub net_down: Option<f64>,
}
