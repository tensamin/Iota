pub mod protocol;
pub mod transport;

pub use protocol::{
    ClientMessage, ComponentHealth, ComponentId, ConnectionStatus, DaemonMessage, DeploymentMode,
    ExitIntent, HealthStatus, HelloAck, IpcErrorCode, LifecycleEvent, LifecyclePhase, LocalRequest,
    LogEntry, MetricSample, RequestEnvelope, ResponseEnvelope, ResponseResult, StartupPhase,
    StateSnapshot, SupervisorKind,
};
pub use transport::{read_msg, write_msg};

/// Current IPC protocol version.
pub const PROTOCOL_VERSION: u16 = 2;
/// Minimum protocol version this daemon understands.
pub const MIN_PROTOCOL_VERSION: u16 = 2;
