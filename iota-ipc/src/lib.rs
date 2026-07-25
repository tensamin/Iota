pub mod protocol;
pub mod text_commands;
pub mod transport;

pub use protocol::{
    ClientMessage, ComponentHealth, ComponentId, ComponentStatusResponse, ConfigResponse,
    ConnectionStatus, DaemonMessage, DaemonStatusResponse, DeploymentMode, ExitIntent,
    HealthStatus, HelloAck, IpcErrorCode, LifecycleEvent, LifecyclePhase, LocalRequest, LogEntry,
    LogEntriesResponse, MetricSample, OmikronStatusResponse, RequestEnvelope, ResponseEnvelope,
    ResponsePayload, ResponseResult, StartupPhase, StateSnapshot, StatusResponse, SupervisorKind,
    TaskSummary, UpdateStatusResponse, UserDetailResponse, UserSummary, CommunitySummary,
};
pub use transport::{read_msg, write_msg};

/// Current IPC protocol version.
pub const PROTOCOL_VERSION: u16 = 2;
/// Minimum protocol version this daemon understands.
pub const MIN_PROTOCOL_VERSION: u16 = 2;
