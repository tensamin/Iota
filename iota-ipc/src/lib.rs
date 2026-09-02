pub mod protocol;
pub mod text_commands;
pub mod transport;

pub use protocol::{
    ClientMessage, CommunitySummary, ComponentHealth, ComponentId, ComponentStatusResponse,
    ConfigResponse, ConnectionStatus, CredentialStatus, DaemonMessage, DaemonStatusResponse,
    DeploymentMode, ExitIntent, HealthStatus, HelloAck, IpcErrorCode, IpcRole, LifecycleEvent,
    LifecyclePhase, LocalRequest, LocalUserState, LogEntriesResponse, LogEntry, MetricSample,
    OmikronStatusResponse, ReconcileAction, RequestEnvelope, ResponseEnvelope, ResponsePayload,
    ResponseResult, SecretString, StartupPhase, StateSnapshot, StatusResponse, SupervisorKind,
    TaskSummary, TuCredentialPreview, UpdateStatusResponse, UserDetailResponse, UserDiagnostics,
    UserOperationKind, UserOperationSummary, UserReconcileResult, UserSummary,
};
pub use transport::{MAX_MESSAGE_SIZE, read_msg, write_msg};

/// Current IPC protocol version.
pub const PROTOCOL_VERSION: u16 = 4;
/// Minimum protocol version this daemon understands.
pub const MIN_PROTOCOL_VERSION: u16 = 2;
