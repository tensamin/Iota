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
    ListTAuthApps,
    GetTAuthApp {
        app_id: String,
    },
    CreateTAuthApp {
        owner_user_id: i64,
        domain: String,
        name: String,
        redirects: Vec<String>,
        connection: TAuthConnectionInput,
    },
    ExportTAuthApp {
        app_id: String,
    },
    DeleteTAuthApp {
        app_id: String,
    },
    CreateInvitation {
        authority: InvitationAuthority,
        lifetime_seconds: u64,
        password: Option<SecretString>,
        label: Option<String>,
    },
    ListInvitations {
        authority: Option<InvitationAuthority>,
    },
    RevokeInvitation {
        authority: InvitationAuthority,
        invitation_id: i64,
    },
    CreateUser {
        username: String,
    },
    InspectTuCredential {
        credential: SecretString,
    },
    AttachUserFromTu {
        credential: SecretString,
    },
    ReconcileUser {
        user_id: i64,
    },
    ForceDetachUser {
        user_id: i64,
    },
    ForgetReleasedUser {
        user_id: i64,
    },
    GetUserDiagnostics {
        user_id: i64,
    },
    RevokeTAuthGrant {
        user_id: i64,
        app_id: String,
    },
    RevokeAllTAuthGrants {
        user_id: i64,
    },
    ExportUserCredential {
        user_id: i64,
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
    pub const fn log_name(&self) -> &'static str {
        match self {
            Self::GetStatus => "get_status",
            Self::ListTasks => "list_tasks",
            Self::ListUsers => "list_users",
            Self::ListTAuthApps => "list_tauth_apps",
            Self::GetTAuthApp { .. } => "get_tauth_app",
            Self::CreateTAuthApp { .. } => "create_tauth_app",
            Self::ExportTAuthApp { .. } => "export_tauth_app",
            Self::DeleteTAuthApp { .. } => "delete_tauth_app",
            Self::CreateInvitation { .. } => "create_invitation",
            Self::ListInvitations { .. } => "list_invitations",
            Self::RevokeInvitation { .. } => "revoke_invitation",
            Self::CreateUser { .. } => "create_user",
            Self::InspectTuCredential { .. } => "inspect_tu_credential",
            Self::AttachUserFromTu { .. } => "attach_user_from_tu",
            Self::ReconcileUser { .. } => "reconcile_user",
            Self::ForceDetachUser { .. } => "force_detach_user",
            Self::ForgetReleasedUser { .. } => "forget_released_user",
            Self::GetUserDiagnostics { .. } => "get_user_diagnostics",
            Self::RevokeTAuthGrant { .. } => "revoke_tauth_grant",
            Self::RevokeAllTAuthGrants { .. } => "revoke_all_tauth_grants",
            Self::ExportUserCredential { .. } => "export_user_credential",
            Self::PurgeUserData { .. } => "purge_user_data",
            Self::ReleaseUser { .. } => "release_user",
            Self::CompleteDeleteUser { .. } => "complete_delete_user",
            Self::RemoveUser { .. } => "remove_user",
            Self::ReconnectOmikron => "reconnect_omikron",
            Self::RotateIotaIdentity => "rotate_iota_identity",
            Self::RequestProcessExit { .. } => "request_process_exit",
            Self::GetDaemonStatus => "get_daemon_status",
            Self::RestartDaemon => "restart_daemon",
            Self::StopDaemon => "stop_daemon",
            Self::GetConfig => "get_config",
            Self::SetConfig { .. } => "set_config",
            Self::ReloadConfig => "reload_config",
            Self::GetOmikronStatus => "get_omikron_status",
            Self::ListComponents => "list_components",
            Self::GetUser { .. } => "get_user",
            Self::ImportUser { .. } => "import_user",
            Self::GetLogs { .. } => "get_logs",
            Self::CheckUpdate => "check_update",
            Self::ListCommunities => "list_communities",
        }
    }

    /// Return the minimum authenticated local role required to execute a
    /// request. New request variants must be assigned explicitly here.
    pub fn required_role(&self) -> IpcRole {
        match self {
            Self::GetStatus
            | Self::ListTasks
            | Self::ListUsers
            | Self::ListTAuthApps
            | Self::GetTAuthApp { .. }
            | Self::ListInvitations { .. }
            | Self::GetDaemonStatus
            | Self::GetOmikronStatus
            | Self::ListComponents
            | Self::GetUser { .. }
            | Self::GetUserDiagnostics { .. }
            | Self::GetLogs { .. }
            | Self::CheckUpdate
            | Self::ListCommunities => IpcRole::Read,

            Self::ReconnectOmikron | Self::ReloadConfig => IpcRole::Operate,

            Self::CreateUser { .. }
            | Self::CreateTAuthApp { .. }
            | Self::ExportTAuthApp { .. }
            | Self::DeleteTAuthApp { .. }
            | Self::CreateInvitation { .. }
            | Self::RevokeInvitation { .. }
            | Self::InspectTuCredential { .. }
            | Self::AttachUserFromTu { .. }
            | Self::ReconcileUser { .. }
            | Self::ForceDetachUser { .. }
            | Self::ForgetReleasedUser { .. }
            | Self::RevokeTAuthGrant { .. }
            | Self::RevokeAllTAuthGrants { .. }
            | Self::ExportUserCredential { .. }
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
#[expect(
    clippy::large_enum_variant,
    reason = "keep IPC response payloads inline"
)]
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
    TAuthApps(Vec<TAuthAppSummary>),
    TAuthApp(TAuthAppSummary),
    TAuthAppCreated {
        app: TAuthAppSummary,
        credential: SecretString,
        txt_record: String,
        manifest_template: String,
    },
    TAuthAppCredentialExport {
        app_id: String,
        credential: SecretString,
    },
    InvitationCreated(InvitationCreated),
    Invitations(Vec<InvitationSummary>),
    InvitationUpdated(InvitationSummary),
    UserCreated {
        user_id: i64,
        username: String,
    },
    TuCredentialPreview(TuCredentialPreview),
    UserReconciled(UserReconcileResult),
    UserDiagnostics(UserDiagnostics),
    UserCredentialExport {
        user_id: i64,
        username: String,
        credential: SecretString,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TAuthConnectionInput {
    Hosted {
        omega_url: String,
    },
    ForcedOmikron {
        omikron_url: String,
        omikron_public_key: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TAuthAppSummary {
    pub app_id: String,
    pub owner_user_id: i64,
    pub domain: String,
    pub public_key: String,
    pub connection_mode: String,
    pub endpoint_url: String,
    pub created_at: i64,
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
    pub tauth_grants: Vec<String>,
    pub state: LocalUserState,
    pub data_present: bool,
    pub credential_status: CredentialStatus,
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvitationAuthority {
    Omega,
    Iota,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvitationState {
    Pending,
    RevocationPending,
    Provisioning,
    Redeemed,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvitationCreated {
    pub authority: InvitationAuthority,
    pub invitation_id: i64,
    pub raw_token: SecretString,
    pub expires_at: i64,
    pub short_url: Option<String>,
    #[serde(default)]
    pub mirror_synced: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvitationSummary {
    pub authority: InvitationAuthority,
    pub invitation_id: i64,
    pub label: Option<String>,
    pub password_protected: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub state: InvitationState,
    pub redeemed_user_id: Option<i64>,
    #[serde(default)]
    pub local_provisioned_user_id: Option<i64>,
    #[serde(default)]
    pub local_provisioned_at: Option<i64>,
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
    pub credential_status: CredentialStatus,
    #[serde(default)]
    pub pending_operation: Option<UserOperationSummary>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserOperationKind {
    Create,
    Attach,
    Release,
    Purge,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserOperationSummary {
    pub operation: UserOperationKind,
    pub phase: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    LocalPresent,
    External,
    Missing,
    None,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TuCredentialPreview {
    pub user_id: i64,
    pub username: String,
    pub assigned_iota_id: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserReconcileResult {
    pub user_id: i64,
    pub local_state: LocalUserState,
    pub omega_iota_id: Option<i64>,
    pub action: ReconcileAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileAction {
    None,
    ReleasedLocally,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserDiagnostics {
    pub user_id: i64,
    pub username: String,
    pub local_state: LocalUserState,
    pub data_present: bool,
    pub credential_status: CredentialStatus,
    pub tauth_grant_count: usize,
    pub pending_operation: Option<String>,
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
    Unsupported,
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
            Self::Unsupported => "the requested operation is not implemented",
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
    use super::{
        CredentialStatus, LocalUserState, ResponsePayload, SecretString, UserOperationKind,
        UserOperationSummary, UserSummary,
    };

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

    #[test]
    fn credential_export_debug_output_is_redacted() {
        let payload = ResponsePayload::UserCredentialExport {
            user_id: 42,
            username: "alice".into(),
            credential: SecretString("private-tu-contents".into()),
        };
        let output = format!("{payload:?}");

        assert!(!output.contains("private-tu-contents"));
        assert!(output.contains("<redacted>"));
    }

    #[test]
    fn request_log_name_does_not_include_config_value() {
        let request = super::LocalRequest::SetConfig {
            key: "omikron_host".into(),
            value: "private-config-value".into(),
        };
        assert_eq!(request.log_name(), "set_config");
        assert!(!request.log_name().contains("private-config-value"));
    }

    #[test]
    fn user_summary_serializes_pending_operation_without_lifecycle_secrets() {
        let summary = UserSummary {
            user_id: 42,
            username: "alice".into(),
            state: LocalUserState::Managed,
            data_present: true,
            credential_status: CredentialStatus::LocalPresent,
            pending_operation: Some(UserOperationSummary {
                operation: UserOperationKind::Purge,
                phase: "database_purged".into(),
            }),
        };
        let encoded = serde_json::to_string(&summary).unwrap();

        assert!(encoded.contains("purge"));
        assert!(encoded.contains("database_purged"));
        assert!(!encoded.contains("private_key"));
        assert!(!encoded.contains("reset_token"));
    }

    #[test]
    fn user_summary_accepts_older_payload_without_pending_operation() {
        let summary: UserSummary = serde_json::from_str(
            r#"{"user_id":42,"username":"alice","state":"managed","data_present":true,"credential_status":"local_present"}"#,
        )
        .unwrap();

        assert!(summary.pending_operation.is_none());
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupPhase {
    #[default]
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
