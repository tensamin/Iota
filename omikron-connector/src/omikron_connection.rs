#![allow(
    clippy::result_large_err,
    reason = "return protocol error frames directly to the sender"
)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dashmap::DashSet;
use iota_logger::{LogLevel, log, log_cv_in, log_cv_out, log_t};
use iota_state::AppState;
use iota_storage::util::config_util::{CONFIG, modify_config};
use iota_storage::util::relay_replay;
use iota_storage::util::{chat_files, client_relay_delivery, relay_queue};
use iota_util::crypto_helper::{self, keyring_from_base64};
use mtp::client::{Client, ClientConfig, MTPConnection, Policy, SendMode, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue, TypeMap};
use mtp::crypto::{Ed25519Signer, Keyring, PublicKeyBundle, SignatureScheme};
use rand_core::RngCore;
use serde::Serialize;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod account;
mod diagnostics;
mod discovery;
mod dispatch;
mod invitations;
mod relay;
mod requests;
mod storage_handlers;
mod supervisor;
mod tauth_handlers;
mod workers;

use crate::client::{OmikronClient, OmikronError};
use crate::omega_discovery;
use crate::password::PasswordAuthRuntime;

use iota_connection::message_common::*;
use iota_connection::message_handlers;
use iota_identity::{AuthorityLocator, LocalUserStore};

// ============================================================================
// Configuration
// ============================================================================

const IOTA_KEYRING_PATH: &str = "iota.mk";
static ASSET_IO_PERMITS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    Arc::new(Semaphore::new(
        CONFIG.load().storage_limits.max_asset_io_workers,
    ))
});

async fn run_asset_handler<T: Send + 'static>(
    cv: &CommunicationValue,
    handler: fn(&CommunicationValue) -> T,
) -> Result<T, CommunicationValue> {
    let permit = ASSET_IO_PERMITS
        .clone()
        .try_acquire_owned()
        .map_err(|_| error_response(cv, CommunicationType::ErrorInternal))?;
    let frame = cv.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        handler(&frame)
    })
    .await
    .map_err(|error| {
        log!("Asset I/O worker failed: {error}");
        error_response(cv, CommunicationType::ErrorInternal)
    })
}
static IDENTITY_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
static OMIKRON_TRUST_DIRECTORY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/*
 * Keeps identity and pinned Omikron key files independent from the process
 * working directory, so restarts use the same trusted material.
 */
pub fn configure_identity_path(path: PathBuf) {
    let trust_directory = path.parent().map(|parent| parent.join("omikrons"));
    let _ = IDENTITY_PATH.set(path);
    if let Some(trust_directory) = trust_directory {
        let _ = OMIKRON_TRUST_DIRECTORY.set(trust_directory);
    }
}
fn identity_path() -> &'static Path {
    IDENTITY_PATH
        .get()
        .map(PathBuf::as_path)
        .unwrap_or_else(|| Path::new(IOTA_KEYRING_PATH))
}
fn omikron_trust_directory() -> &'static Path {
    OMIKRON_TRUST_DIRECTORY
        .get()
        .map(PathBuf::as_path)
        .unwrap_or_else(|| Path::new("omikrons"))
}

fn omikron_public_key_path(id: i64) -> PathBuf {
    omikron_trust_directory().join(format!("{id}.mpkb"))
}

fn legacy_omikron_public_key_path() -> PathBuf {
    identity_path()
        .parent()
        .map(|parent| parent.join("omikron.mpkb"))
        .unwrap_or_else(|| PathBuf::from("omikron.mpkb"))
}

fn save_omikron_public_key(key: &PublicKeyBundle, path: &Path) -> Result<(), String> {
    let temporary = serialization_path(path)?;
    mtp::files::save_public_key_bundle(key, &temporary)
        .map_err(|error| format!("serialize Omikron public key: {error}"))?;
    let bytes = std::fs::read(&temporary)
        .map_err(|error| format!("read serialized Omikron public key: {error}"));
    let _ = std::fs::remove_file(&temporary);
    let bytes = bytes?;
    iota_util::atomic_file::replace(path, &bytes, 3)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

fn serialization_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} has no file name", path.display()))?;
    Ok(parent.join(format!(
        ".{}.serialize-{}",
        name.to_string_lossy(),
        Uuid::new_v4()
    )))
}

const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(45);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

fn container_value<'a>(
    fields: &'a [(DataTypeId, DataValue)],
    kind: DataType,
    type_map: &TypeMap,
) -> Option<&'a DataValue> {
    let id = kind.try_to_id(type_map)?;
    fields
        .iter()
        .find_map(|(field_id, value)| (*field_id == id).then_some(value))
}

fn container_signed_i64(
    fields: &[(DataTypeId, DataValue)],
    kind: DataType,
    type_map: &TypeMap,
) -> Option<i64> {
    container_value(fields, kind, type_map)
        .and_then(DataValue::as_signed_number)
        .and_then(|value| i64::try_from(value).ok())
}

fn targets_iota(value: &CommunicationValue, expected_iota_id: Option<u64>) -> bool {
    let target = value
        .get_data(DataType::IotaId)
        .as_signed_number()
        .and_then(|id| u64::try_from(id).ok())
        .filter(|id| *id > 0);
    target.is_some() && target == expected_iota_id
}

fn parse_omega_invitation(
    fields: &[(DataTypeId, DataValue)],
    type_map: &TypeMap,
    expected_iota_id: i64,
    synced_at: i64,
) -> Result<iota_storage::users::invitations::InvitationSummary, OmikronError> {
    use iota_storage::users::invitations::{InvitationState, InvitationSummary};

    let invitation_id = container_signed_i64(fields, DataType::InvitationId, type_map)
        .filter(|value| *value > 0)
        .ok_or_else(|| OmikronError::Internal("invalid Omega invitation ID".into()))?;
    if container_value(fields, DataType::InvitationAuthority, type_map).and_then(DataValue::as_str)
        != Some("omega")
    {
        return Err(OmikronError::Internal(
            "invalid Omega invitation authority".into(),
        ));
    }
    if container_signed_i64(fields, DataType::IotaId, type_map) != Some(expected_iota_id) {
        return Err(OmikronError::Internal(
            "Omega invitation snapshot contained the wrong Iota ID".into(),
        ));
    }
    let remote_revision = container_signed_i64(fields, DataType::InvitationRevision, type_map)
        .filter(|value| *value > 0)
        .ok_or_else(|| OmikronError::Internal("invalid Omega invitation revision".into()))?;
    let state = match container_value(fields, DataType::InvitationState, type_map)
        .and_then(DataValue::as_str)
    {
        Some("pending") => InvitationState::Pending,
        Some("provisioning") => InvitationState::Provisioning,
        Some("redeemed") => InvitationState::Redeemed,
        Some("revoked") => InvitationState::Revoked,
        Some("expired") => InvitationState::Expired,
        _ => {
            return Err(OmikronError::Internal(
                "invalid Omega invitation state".into(),
            ));
        }
    };
    let label = match container_value(fields, DataType::InvitationLabel, type_map) {
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| OmikronError::Internal("invalid Omega invitation label".into()))?,
        ),
        None => None,
    };
    let password_protected =
        container_value(fields, DataType::InvitationPasswordProtected, type_map)
            .and_then(DataValue::as_bool)
            .ok_or_else(|| {
                OmikronError::Internal("invalid Omega invitation password protection flag".into())
            })?;
    let created_at = container_signed_i64(fields, DataType::InvitationCreatedAt, type_map)
        .filter(|value| *value > 0)
        .ok_or_else(|| OmikronError::Internal("invalid Omega invitation creation time".into()))?;
    let expires_at = container_signed_i64(fields, DataType::InvitationExpiresAt, type_map)
        .filter(|value| *value > 0)
        .ok_or_else(|| OmikronError::Internal("invalid Omega invitation expiry time".into()))?;
    let redeemed_user_id = match container_value(fields, DataType::UserId, type_map) {
        Some(value) => Some(
            value
                .as_signed_number()
                .and_then(|value| i64::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    OmikronError::Internal("invalid Omega invitation redeemed user ID".into())
                })?,
        ),
        None => None,
    };
    Ok(InvitationSummary {
        invitation_id,
        authority: iota_storage::users::invitations::InvitationAuthority::Omega,
        label: label.map(str::to_owned),
        password_protected,
        created_at,
        expires_at: Some(expires_at),
        state,
        remote_revision,
        redeemed_user_id,
        redeemed_at: None,
        revoked_at: None,
        pending_action: None,
        pending_action_at: None,
        last_synced_at: Some(synced_at),
        local_provisioned_user_id: None,
        local_provisioned_at: None,
    })
}
const MAX_CONCURRENT_HANDLERS: usize = 20;

type PendingDelivery = dyn Fn(
        relay_queue::PendingRelay,
        CommunicationValue,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CommunicationValue, String>> + Send>,
    > + Send
    + Sync;

struct ResolvedOmikronEndpoint {
    id: Option<i64>,
    host: String,
    port: u16,
    public_key: PublicKeyBundle,
}

struct InvitationSyncRuntime {
    flush_in_progress: AtomicBool,
    next_retry_at: Mutex<Option<Instant>>,
    retry_delay: Mutex<Duration>,
}

impl InvitationSyncRuntime {
    fn new() -> Self {
        Self {
            flush_in_progress: AtomicBool::new(false),
            next_retry_at: Mutex::new(None),
            retry_delay: Mutex::new(Duration::from_secs(5)),
        }
    }
}

fn next_invitation_retry_delay(current: Duration) -> Duration {
    (current * 2).min(Duration::from_secs(300))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionAttemptResult {
    became_healthy: bool,
}

fn jittered_reconnect_delay(delay: Duration) -> Duration {
    let ceiling_ms = u64::try_from(MAX_RECONNECT_DELAY.as_millis())
        .expect("reconnect ceiling must fit in milliseconds");
    let base_ms = u64::try_from(delay.as_millis().min(u128::from(ceiling_ms)))
        .expect("bounded reconnect delay must fit in milliseconds");
    let jitter_span = base_ms / 5;
    if jitter_span == 0 {
        return Duration::from_millis(base_ms);
    }

    let mut rng = rand_core::OsRng;
    let range = jitter_span.saturating_mul(2).saturating_add(1);
    let offset = (rng.next_u64() % range) as i128 - jitter_span as i128;
    let jittered = (base_ms as i128 + offset).clamp(0, i128::from(ceiling_ms));
    Duration::from_millis(u64::try_from(jittered).expect("bounded jitter must be non-negative"))
}

#[derive(Debug, thiserror::Error)]
enum ConnectorRequestError {
    #[error(transparent)]
    Request(#[from] tau::RequestError),
    #[error("request rejected: {kind:?}: {reason}")]
    Rejected {
        kind: CommunicationType,
        reason: String,
    },
    #[error("{0}")]
    Disconnected(String),
}

fn map_await_response_error(error: ConnectorRequestError) -> OmikronError {
    match error {
        ConnectorRequestError::Request(tau::RequestError::Timeout) => {
            OmikronError::Timeout("request timed out".into())
        }
        ConnectorRequestError::Rejected { kind, reason } => OmikronError::Rejected(kind, reason),
        error => OmikronError::Disconnected(error.to_string()),
    }
}

fn expected_response(expected: Option<CommunicationType>, response: &CommunicationValue) -> bool {
    let actual = response.get_comm_type_enum();
    actual.is_some_and(tau::is_protocol_error)
        || actual.is_some() && actual == expected
        || actual == Some(CommunicationType::Success)
            && matches!(
                expected,
                Some(
                    CommunicationType::Relay
                        | CommunicationType::CompleteRegisterUser
                        | CommunicationType::DeleteUser
                        | CommunicationType::AttachUserComplete
                        | CommunicationType::DeleteUserCredentialComplete
                        | CommunicationType::ReleaseUserFromIota
                        | CommunicationType::RevokeUserInvitation
                        | CommunicationType::EraseHostedUserDataAck
                        | CommunicationType::AcknowledgeIotaUserProvision
                        | CommunicationType::AccountStateApplied
                )
            )
        || matches!(
            (expected, actual),
            (
                Some(CommunicationType::AccountStateRequest),
                Some(CommunicationType::AccountStateSnapshot)
            ) | (
                Some(CommunicationType::GetChatSecret),
                Some(CommunicationType::ChatSecretResponse)
            ) | (
                Some(CommunicationType::TAuthAuthorize),
                Some(CommunicationType::TAuthAuthorizationResult)
            ) | (
                Some(CommunicationType::TAuthExchangeCode),
                Some(CommunicationType::TAuthExchangeCodeResponse)
            ) | (
                Some(CommunicationType::PasswordEnrollmentStart),
                Some(CommunicationType::PasswordEnrollmentResponse)
            ) | (
                Some(CommunicationType::PasswordProvisioningStart),
                Some(CommunicationType::PasswordProvisioningResponse)
            )
        )
}

fn wire_user_id(user_id: i64) -> u64 {
    u64::try_from(user_id).expect("validated user ID is non-negative")
}

fn load_or_migrate_keyring_at(
    path: &Path,
    legacy: Option<String>,
) -> Result<iota_identity::LocalNodeIdentity, iota_identity::LocalNodeIdentityError> {
    let legacy = legacy
        .map(|encoded| {
            keyring_from_base64(&encoded).ok_or_else(|| {
                iota_identity::LocalNodeIdentityError::InvalidIdentity(
                    iota_identity::IdentityError::InvalidIdentifier(
                        "legacy Iota keyring is invalid".into(),
                    ),
                )
            })
        })
        .transpose()?;
    iota_identity::LocalNodeIdentity::load_or_create(path, legacy)
}

// ============================================================================
// Waiting Task System
// ============================================================================

struct ConnectionAttempt {
    generation: u64,
    sender: Arc<Sender>,
    responses: tau::ResponseCorrelator,
    cancellation: CancellationToken,
}

impl ConnectionAttempt {
    fn close(&self) {
        self.cancellation.cancel();
        self.responses.close();
        self.sender.close_immediate();
    }
}

// ============================================================================
// Connection State
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { identified: bool },
}

/// Incomplete shutdown retains its supervisor and all mutation tasks. Calling
/// `stop` again waits for the same drain rather than detaching those tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    Complete,
    Incomplete { pending_operations: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectorShutdownError {
    #[error("connector supervisor failed: {0}")]
    Supervisor(#[from] tokio::task::JoinError),
    #[error("connector worker failed with unresolved work")]
    UnresolvedWorker,
}

pub(super) struct PendingOperation(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for PendingOperation {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Serialize)]
struct TAuthLocatorUnsigned<'a> {
    version: u16,
    principal: &'a str,
    omikron_url: &'a str,
    omikron_public_key: &'a str,
    target_iota_id: u64,
    iota_public_key: &'a str,
    issued_at: i64,
}

#[derive(Serialize)]
struct TAuthLocator<'a> {
    version: u16,
    principal: &'a str,
    omikron_url: &'a str,
    omikron_public_key: &'a str,
    target_iota_id: u64,
    iota_public_key: &'a str,
    issued_at: i64,
    signature: String,
}

fn string_array(values: &[String]) -> DataValue {
    DataValue::Array(values.iter().cloned().map(DataValue::Str).collect())
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }

    pub fn is_identified(&self) -> bool {
        matches!(self, ConnectionState::Connected { identified: true })
    }
}

// ============================================================================
// Omikron Connection (Client-side with auto-reconnect)
// ============================================================================

#[allow(dead_code)] // message_send_times is unused.
#[derive(Clone)]
pub struct OmikronConnection {
    state: Arc<RwLock<ConnectionState>>,
    state_watch_tx: watch::Sender<ConnectionState>,
    active_attempt: Arc<RwLock<Option<Arc<ConnectionAttempt>>>>,
    next_attempt: Arc<AtomicU64>,
    // Inbound handlers and maintenance retain their originating transport.
    bound_attempt: Option<Arc<ConnectionAttempt>>,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub last_ping: Arc<Mutex<i64>>,
    pending_operations: Arc<std::sync::atomic::AtomicUsize>,
    worker_failed: Arc<AtomicBool>,
    pub(super) preparation_tasks: Arc<Mutex<JoinSet<()>>>,
    draining_attempts: Arc<Mutex<JoinSet<()>>>,
    relay_flush: Arc<Mutex<()>>,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    reconnect_on_close: Arc<RwLock<bool>>,
    auth_failure: Arc<RwLock<Option<String>>>,
    pub(super) keyring: Arc<RwLock<Option<Arc<Keyring>>>>,
    pub(super) http_client: reqwest::Client,
    session_manager: Arc<iota_auth::SessionManager>,
    pub(super) password_auth: Arc<PasswordAuthRuntime>,
    handler_semaphore: Arc<Semaphore>,
    cancellation: CancellationToken,
    pub(crate) active_tasks: Arc<DashSet<String>>,
    pub(crate) app: Arc<std::sync::Mutex<AppState>>,
    invitation_sync: Arc<InvitationSyncRuntime>,
    relay_service: Arc<OnceLock<Arc<iota_connection::relay_service::RelayService>>>,
    local_deliveries: Arc<OnceLock<Arc<dyn other_iota::LocalDeliverySink>>>,
    pending_deliveries: Arc<OnceLock<Arc<PendingDelivery>>>,
}

impl OmikronConnection {
    pub fn new(active_tasks: Arc<DashSet<String>>, app: Arc<std::sync::Mutex<AppState>>) -> Self {
        Self::with_cancellation(CancellationToken::new(), active_tasks, app)
    }

    pub fn with_cancellation(
        cancellation: CancellationToken,
        active_tasks: Arc<DashSet<String>>,
        app: Arc<std::sync::Mutex<AppState>>,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let (state_watch_tx, _) = watch::channel(ConnectionState::Disconnected);

        OmikronConnection {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            state_watch_tx,
            active_attempt: Arc::new(RwLock::new(None)),
            next_attempt: Arc::new(AtomicU64::new(1)),
            bound_attempt: None,
            connection_loop_handle: Arc::new(Mutex::new(None)),
            last_ping: Arc::new(Mutex::new(-1)),
            pending_operations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            worker_failed: Arc::new(AtomicBool::new(false)),
            preparation_tasks: Arc::new(Mutex::new(JoinSet::new())),
            draining_attempts: Arc::new(Mutex::new(JoinSet::new())),
            relay_flush: Arc::new(Mutex::new(())),
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            reconnect_on_close: Arc::new(RwLock::new(true)),
            auth_failure: Arc::new(RwLock::new(None)),
            keyring: Arc::new(RwLock::new(None)),
            http_client: reqwest::Client::new(),
            session_manager: Arc::new(iota_auth::SessionManager::default()),
            password_auth: Arc::new(PasswordAuthRuntime::default()),
            handler_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDLERS)),
            cancellation,
            active_tasks,
            app,
            invitation_sync: Arc::new(InvitationSyncRuntime::new()),
            relay_service: Arc::new(OnceLock::new()),
            local_deliveries: Arc::new(OnceLock::new()),
            pending_deliveries: Arc::new(OnceLock::new()),
        }
    }

    pub fn install_relay_service(
        &self,
        relay: Arc<iota_connection::relay_service::RelayService>,
    ) -> Result<(), Arc<iota_connection::relay_service::RelayService>> {
        self.relay_service.set(relay)
    }

    pub fn relay_service(&self) -> Option<Arc<iota_connection::relay_service::RelayService>> {
        self.relay_service.get().cloned()
    }

    pub fn install_local_delivery_sink(
        &self,
        sink: Arc<dyn other_iota::LocalDeliverySink>,
    ) -> Result<(), Arc<dyn other_iota::LocalDeliverySink>> {
        self.local_deliveries.set(sink)
    }

    /// The client manager owns per-connection correlation and flush exclusion.
    /// Only a response to this exact queue snapshot can acknowledge delivery.
    pub fn install_pending_delivery_sink<F, Fut>(&self, sink: F) -> Result<(), String>
    where
        F: Fn(relay_queue::PendingRelay, CommunicationValue) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<CommunicationValue, String>> + Send + 'static,
    {
        self.pending_deliveries
            .set(Arc::new(move |record, frame| Box::pin(sink(record, frame))))
            .map_err(|_| "pending client delivery sink already installed".into())
    }

    pub fn session_manager(&self) -> Arc<iota_auth::SessionManager> {
        self.session_manager.clone()
    }

    pub(super) fn track_operation(&self) -> PendingOperation {
        self.pending_operations.fetch_add(1, Ordering::AcqRel);
        PendingOperation(self.pending_operations.clone())
    }

    pub(super) fn preparation_cancellation(&self) -> CancellationToken {
        self.bound_attempt
            .as_ref()
            .map(|attempt| attempt.cancellation.clone())
            .unwrap_or_else(|| self.cancellation.clone())
    }

    async fn set_state(&self, new_state: ConnectionState) {
        let mut state = self.state.write().await;
        if self.cancellation.is_cancelled() && new_state != ConnectionState::Disconnected {
            return;
        }
        if *state != new_state {
            self.lifecycle_event(
                LogLevel::Info,
                "connector.state.changed",
                self.bound_attempt
                    .as_ref()
                    .map(|attempt| attempt.generation),
                format_args!("from={state:?} to={new_state:?}"),
            );
        }
        *state = new_state;
        self.state_watch_tx.send_replace(new_state);
    }

    /// Subscribe to connection transitions for daemon health reporting.
    pub fn connection_state(&self) -> watch::Receiver<ConnectionState> {
        self.state_watch_tx.subscribe()
    }

    fn initialize_password_auth(&self, identity: &Path) {
        if let Err(error) = self.password_auth.initialize(identity) {
            log!("Password authentication unavailable: {}", error);
        }
    }

    // -------------------------------------------------------------------------
    // Identity (own Keyring, migrated from the legacy base64-in-config format)
    // -------------------------------------------------------------------------

    async fn load_or_migrate_keyring(
        &self,
    ) -> Result<iota_identity::LocalNodeIdentity, iota_identity::LocalNodeIdentityError> {
        load_or_migrate_keyring_at(identity_path(), CONFIG.load().keyring.clone())
    }
}

impl OmikronConnection {
    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    pub async fn has_auth_failure(&self) -> bool {
        self.auth_failure.read().await.is_some()
    }

    pub async fn get_auth_failure(&self) -> Option<String> {
        self.auth_failure.read().await.clone()
    }

    pub async fn clear_auth_failure(&self) {
        *self.auth_failure.write().await = None;
    }

    /// Create a new local keyring and register it as a new Iota identity.
    /// The existing keyring is retained as a timestamped backup so a failed
    /// recovery does not silently destroy the user's previous identity.
    pub async fn rotate_identity(self: &Arc<Self>) -> Result<(), OmikronError> {
        if self.cancellation.is_cancelled() {
            return Err(OmikronError::Disconnected("connector is stopped".into()));
        }
        log!("Iota identity rotation requested");
        match self
            .drain(Duration::from_secs(5), false)
            .await
            .map_err(|error| OmikronError::Internal(error.to_string()))?
        {
            ShutdownOutcome::Complete => {}
            ShutdownOutcome::Incomplete { .. } => {
                return Err(OmikronError::Internal(
                    "identity rotation requires a completed connector drain".into(),
                ));
            }
        }

        if self.cancellation.is_cancelled() {
            return Err(OmikronError::Disconnected(
                "connector stopped during identity drain".into(),
            ));
        }
        let path = identity_path();
        if path.exists() {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let backup = path.with_extension(format!("mk.backup-{stamp}"));
            std::fs::rename(path, &backup).map_err(|error| {
                OmikronError::Internal(format!(
                    "could not back up identity {}: {error}",
                    path.display()
                ))
            })?;
            log!("Existing Iota identity backed up to {}", backup.display());
        }

        let keyring = crypto_helper::generate_keyring();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                OmikronError::Internal(format!(
                    "could not create identity directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        iota_identity::LocalNodeIdentity::save_keyring_verified(&keyring, path).map_err(
            |error| {
                OmikronError::Internal(format!(
                    "could not save new identity {}: {error}",
                    path.display()
                ))
            },
        )?;
        modify_config(|config| {
            config.iota_id = None;
            config.keyring = None;
            config.public_key = None;
            config.private_key = None;
        });
        log!("New Iota identity generated; registration started");

        self.clear_auth_failure().await;
        self.connect().await;
        match self.await_connection(Some(CONNECTION_TIMEOUT)).await {
            Ok(()) => {
                let id = CONFIG.load().iota_id;
                log!(
                    "New Iota identity registered{}",
                    id.map(|v| format!(" (Iota-ID: {v})")).unwrap_or_default()
                );
                Ok(())
            }
            Err(timeout) => {
                if let Some(reason) = self.get_auth_failure().await {
                    log!("Iota identity registration failed: {}", reason);
                    Err(OmikronError::Authentication(reason))
                } else {
                    log!("Iota identity registration did not complete: {}", timeout);
                    Err(OmikronError::Timeout(timeout))
                }
            }
        }
    }
}

// ============================================================================
// Global Instance
// ============================================================================

pub async fn connect_initial(
    cancellation: CancellationToken,
    active_tasks: Arc<DashSet<String>>,
    app: Arc<std::sync::Mutex<AppState>>,
) -> Result<Arc<OmikronConnection>, crate::client::OmikronStartupError> {
    let conn = Arc::new(OmikronConnection::with_cancellation(
        cancellation,
        active_tasks,
        app,
    ));
    conn.connect().await;
    match conn.await_connection(Some(CONNECTION_TIMEOUT)).await {
        Ok(()) => Ok(conn),
        Err(_) if conn.has_auth_failure().await => {
            Err(crate::client::OmikronStartupError::Authentication { connection: conn })
        }
        Err(_) => {
            Err(crate::client::OmikronStartupError::InitialConnectionTimeout { connection: conn })
        }
    }
}

#[async_trait::async_trait]
impl iota_connection::connection_handler::ConnectionHandler for OmikronConnection {
    async fn send_message(
        &self,
        cv: &CommunicationValue,
    ) -> Result<(), iota_connection::connection_handler::ConnectionError> {
        OmikronConnection::send_message(self, cv)
            .await
            .map_err(iota_connection::connection_handler::ConnectionError::Disconnected)
    }

    async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout: Option<Duration>,
    ) -> Result<CommunicationValue, iota_connection::connection_handler::ConnectionError> {
        OmikronConnection::await_response(self, cv, timeout)
            .await
            .map_err(|error| {
                if error.contains("timed out") {
                    iota_connection::connection_handler::ConnectionError::Timeout(error)
                } else {
                    iota_connection::connection_handler::ConnectionError::Disconnected(error)
                }
            })
    }

    async fn is_connected(&self) -> bool {
        OmikronConnection::is_connected(self).await
    }

    async fn is_identified(&self) -> bool {
        OmikronConnection::is_identified(self).await
    }

    async fn stop(&self) {
        match OmikronConnection::stop(self).await {
            Ok(ShutdownOutcome::Complete) => {}
            outcome => log!("Omikron shutdown remains supervised: {outcome:?}"),
        }
    }
}

#[async_trait::async_trait]
impl iota_connection::relay_service::RelayNodeIdentity for OmikronConnection {
    async fn keyring(&self) -> Option<Arc<Keyring>> {
        self.keyring.read().await.as_ref().cloned()
    }

    fn node_id(&self) -> Option<iota_identity::IotaNodeId> {
        self.keyring
            .try_read()
            .ok()
            .and_then(|keyring| keyring.as_ref().cloned())
            .and_then(|keyring| {
                iota_identity::IotaNodeId::from_public_keys(&keyring.public_key_bundle()).ok()
            })
    }
}

#[async_trait::async_trait]
impl OmikronClient for OmikronConnection {
    async fn send_message(&self, value: &CommunicationValue) -> Result<(), OmikronError> {
        Self::send_message(self, value)
            .await
            .map_err(OmikronError::Disconnected)
    }

    async fn await_response(
        &self,
        value: &CommunicationValue,
        timeout: Duration,
    ) -> Result<CommunicationValue, OmikronError> {
        self.await_response_typed(value, Some(timeout))
            .await
            .map_err(map_await_response_error)
    }

    async fn sync_omega_invitations(&self) -> Result<(), OmikronError> {
        Self::sync_omega_invitations(self).await
    }

    async fn flush_pending_invitation_actions(&self) {
        Self::flush_pending_invitation_actions(self).await;
    }

    async fn reconnect(&self) -> Result<(), OmikronError> {
        let this = Arc::new(self.clone());
        Self::reconnect(&this).await;
        Ok(())
    }

    async fn rotate_identity(&self) -> Result<(), OmikronError> {
        let this = Arc::new(self.clone());
        Self::rotate_identity(&this).await
    }

    async fn is_connected(&self) -> bool {
        Self::is_connected(self).await
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "omikron_connection/tests.rs"]
mod tests;
