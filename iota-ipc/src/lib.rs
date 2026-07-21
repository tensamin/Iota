pub mod protocol;
pub mod transport;

pub use protocol::{
    ClientMessage, DaemonMessage, HelloAck, LogEntry, StateSnapshot, MetricSample,
    RequestEnvelope, ResponseEnvelope, ResponseResult, LocalRequest, IpcErrorCode,
    ConnectionStatus, StartupPhase, LifecycleEvent,
};
pub use transport::{read_msg, write_msg};

/// Current IPC protocol version.
pub const PROTOCOL_VERSION: u16 = 2;
/// Minimum protocol version this daemon understands.
pub const MIN_PROTOCOL_VERSION: u16 = 2;
