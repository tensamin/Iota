pub mod protocol;
pub mod text_commands;
pub mod transport;

pub use protocol::{
    ClientMessage, CommunitySummary, ComponentHealth, ComponentId, ComponentStatusResponse,
    ConfigResponse, ConnectionStatus, DaemonMessage, DaemonStatusResponse, DeploymentMode,
    ExitIntent, HealthStatus, HelloAck, IpcErrorCode, LifecycleEvent, LifecyclePhase, LocalRequest,
    LocalUserState, LogEntriesResponse, LogEntry, MetricSample, OmikronStatusResponse,
    RequestEnvelope, ResponseEnvelope, ResponsePayload, ResponseResult, SecretString, StartupPhase,
    StateSnapshot, StatusResponse, SupervisorKind, TaskSummary, UpdateStatusResponse,
    UserDetailResponse, UserSummary,
};
pub use transport::{read_msg, write_msg};

/// Current IPC protocol version.
pub const PROTOCOL_VERSION: u16 = 2;
/// Minimum protocol version this daemon understands.
pub const MIN_PROTOCOL_VERSION: u16 = 2;
