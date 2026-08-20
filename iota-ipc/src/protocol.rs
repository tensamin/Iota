use serde::{Deserialize, Serialize};

/// IPC credentials are supplied by the interactive CLI, never a daemon-side
/// path lookup.  Debug is deliberately redacted because command routing logs
/// the request value.
#[derive(Clone, Deserialize, Serialize)]
pub struct SecretString(pub String);

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

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
    AttachUserFromTu {
        credential: SecretString,
    },
    PurgeUserData {
        user_id: i64,
    },
    ReleaseUser {
        user_id: i64,
    },
    CompleteDeleteUser {
        user_id: i64,
        credential: Option<SecretString>,
    },
    /// Retained only to return an actionable deprecation error to old IPC
    /// clients. It must never select lifecycle semantics implicitly.
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
    GetConfig,
    SetConfig {
        key: String,
        value: String,
    },
    ReloadConfig,
    GetOmikronStatus,
    ListComponents,
    GetUser {
        user_id: i64,
    },
    ImportUser {
        username: String,
    },
    GetLogs {
        limit: usize,
    },
    CheckUpdate,
    ListCommunities,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcRole {
    Read,
    Operate,
    Admin,
}

impl IpcRole {
    pub fn allows(self, required: IpcRole) -> bool {
        matches!(
            (self, required),
            (IpcRole::Admin, _)
                | (IpcRole::Operate, IpcRole::Operate | IpcRole::Read)
                | (IpcRole::Read, IpcRole::Read)
        )
    }
}

impl LocalRequest {
    /// Return the minimum authenticated local role required to execute a
    /// request. New request variants must be assigned explicitly here.
    pub fn required_role(&self) -> IpcRole {
        match self {
            Self::GetStatus
            | Self::ListTasks
            | Self::ListUsers
            | Self::GetDaemonStatus
            | Self::GetOmikronStatus
            | Self::ListComponents
            | Self::GetUser { .. }
            | Self::GetLogs { .. }
            | Self::CheckUpdate
            | Self::ListCommunities => IpcRole::Read,

            Self::ReconnectOmikron | Self::ReloadConfig => IpcRole::Operate,

            Self::CreateUser { .. }
            | Self::AttachUserFromTu { .. }
            | Self::PurgeUserData { .. }
            | Self::ReleaseUser { .. }
            | Self::CompleteDeleteUser { .. }
            | Self::RemoveUser { .. }
            | Self::RotateIotaIdentity
            | Self::RequestProcessExit { .. }
            | Self::RestartDaemon
            | Self::StopDaemon
            | Self::GetConfig
            | Self::SetConfig { .. }
            | Self::ImportUser { .. } => IpcRole::Admin,
        }
    }
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
    Ok(ResponsePayload),
    Error(IpcErrorCode),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ResponsePayload {
    Status(StatusResponse),
    Tasks(Vec<TaskSummary>),
    Users(Vec<UserSummary>),
    UserCreated {
        user_id: i64,
        username: String,
    },
    /// Retained only for wire compatibility. New lifecycle code never emits it.
    UserRemoved {
        user_id: i64,
    },
    UserDataPurged {
        user_id: i64,
    },
    Acknowledged {
        message: String,
    },
    DaemonStatus(DaemonStatusResponse),
    Config(ConfigResponse),
    OmikronStatus(OmikronStatusResponse),
    Components(Vec<ComponentStatusResponse>),
    UserDetail(UserDetailResponse),
    LogEntries(LogEntriesResponse),
    UpdateStatus(UpdateStatusResponse),
    Communities(Vec<CommunitySummary>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigResponse {
    pub yaml: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OmikronStatusResponse {
    pub connected: bool,
    pub iota_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComponentStatusResponse {
    pub id: ComponentId,
    pub status: HealthStatus,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserDetailResponse {
    pub user_id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub created_at: i64,
    pub trusted_apps: Vec<String>,
    pub state: LocalUserState,
    pub data_present: bool,
    pub credential_present: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogEntriesResponse {
    pub entries: Vec<LogEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateStatusResponse {
    pub available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommunitySummary {
    pub name: String,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusResponse {
    pub phase: String,
    pub tasks: Vec<String>,
    pub degraded_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TaskSummary {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserSummary {
    pub user_id: i64,
    pub username: String,
    pub state: LocalUserState,
    pub data_present: bool,
    pub credential_present: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalUserState {
    Managed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DaemonStatusResponse {
    pub formatted: String,
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

impl std::fmt::Display for IpcErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "the daemon rejected the request",
            Self::NotFound => "the requested resource was not found",
            Self::Conflict => "the request conflicts with current daemon state",
            Self::StorageFailure => "the daemon could not access local storage",
            Self::OmikronUnavailable => "Omikron is unavailable",
            Self::UnsupportedVersion => "the client and daemon protocol versions are incompatible",
            Self::NotReady => "the daemon is not ready yet",
            Self::Disconnected => "the daemon connection was lost",
            Self::Timeout => "the daemon did not respond in time",
            Self::Cancelled => "the daemon cancelled the request",
            Self::Unauthorized => {
                "the daemon denied this operation because the IPC account lacks the required role"
            }
            Self::InternalFailure => "the daemon encountered an internal failure",
        })
    }
}

#[cfg(test)]
mod error_tests {
    use super::IpcErrorCode;

    #[test]
    fn error_codes_have_operator_facing_messages() {
        assert_eq!(
            IpcErrorCode::NotReady.to_string(),
            "the daemon is not ready yet"
        );
        assert!(
            !IpcErrorCode::InternalFailure
                .to_string()
                .contains("InternalFailure")
        );
        assert!(
            IpcErrorCode::Unauthorized
                .to_string()
                .contains("required role")
        );
    }
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
