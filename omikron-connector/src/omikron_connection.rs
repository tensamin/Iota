use base64::{Engine as _, engine::general_purpose::STANDARD};
use dashmap::{DashMap, DashSet};
use iota_logger::{LogLevel, PrintType, log, log_cv_in, log_cv_out, log_event, log_t};
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, Semaphore, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::client::{OmikronClient, OmikronError};
use crate::omega_discovery;
use crate::password::PasswordAuthRuntime;

use iota_connection::message_common::*;
use iota_connection::message_handlers;
use iota_connection::relay::{
    RelayValidationError, forward_verified_relay, open_verified_relay_content,
    verify_relay_metadata,
};
use iota_identity::AuthorityLocator;

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
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const TASK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_HANDLERS: usize = 20;

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

fn map_await_response_error(error: String) -> OmikronError {
    if error.contains("timed out") {
        OmikronError::Timeout(error)
    } else if error.contains("kind=not_found") {
        OmikronError::Rejected(CommunicationType::ErrorNotFound, error)
    } else if error.starts_with("Request rejected") {
        OmikronError::Rejected(CommunicationType::Error, error)
    } else {
        OmikronError::Disconnected(error)
    }
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

pub struct WaitingTask {
    pub task: Box<dyn FnOnce(CommunicationValue) -> bool + Send + Sync>,
    pub inserted_at: Instant,
}

pub static WAITING_TASKS: LazyLock<DashMap<u32, WaitingTask>> = LazyLock::new(|| DashMap::new());

pub fn start_task_cleanup_loop() {
    tokio::spawn(async {
        loop {
            sleep(TASK_CLEANUP_INTERVAL).await;
            WAITING_TASKS.retain(|_, v| v.inserted_at.elapsed() < TASK_MAX_AGE);
        }
    });
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
pub struct OmikronConnection {
    state: Arc<RwLock<ConnectionState>>,
    state_watch_tx: watch::Sender<ConnectionState>,
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub last_ping: Arc<Mutex<i64>>,
    maintenance_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
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
            sender: Arc::new(RwLock::new(None)),
            connection_loop_handle: Arc::new(Mutex::new(None)),
            last_ping: Arc::new(Mutex::new(-1)),
            maintenance_handle: Arc::new(Mutex::new(None)),
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

    pub fn session_manager(&self) -> Arc<iota_auth::SessionManager> {
        self.session_manager.clone()
    }

    async fn dispatch_relay(self: Arc<Self>, frame: CommunicationValue) {
        let Some(relay) = self.relay_service() else {
            log!("Rejecting Omikron Relay because the daemon relay service is unavailable");
            return;
        };
        match relay
            .accept_relay(
                iota_connection::relay_service::IngressSource::Omikron {
                    connection_id: self.connection_id.to_string(),
                },
                frame,
            )
            .await
        {
            Ok(outcome) => {
                let (ingress_response, local_deliveries) = outcome.into_parts();
                for response in ingress_response
                    .into_iter()
                    .chain(local_deliveries.into_iter().map(|delivery| delivery.frame))
                {
                    if let Err(error) = self.send_message(&response).await {
                        log!("Relay outcome delivery failed: {error}");
                        break;
                    }
                }
            }
            Err(error) => log!("Relay service rejected Omikron ingress: {error:?}"),
        }
    }

    async fn set_state(&self, new_state: ConnectionState) {
        *self.state.write().await = new_state;
        let _ = self.state_watch_tx.send(new_state);
    }

    /// Subscribe to connection transitions for daemon health reporting.
    pub fn connection_state(&self) -> watch::Receiver<ConnectionState> {
        self.state_watch_tx.subscribe()
    }

    // -------------------------------------------------------------------------
    // Connection Management
    // -------------------------------------------------------------------------

    pub async fn connect(self: &Arc<Self>) {
        if self.connection_loop_handle.lock().await.is_none() {
            self.clone().start().await;
        }
    }

    pub async fn start(self: Arc<Self>) {
        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        if self.shutdown_tx.lock().await.is_none() {
            let (shutdown_tx, _) = watch::channel(false);
            *self.shutdown_tx.lock().await = Some(shutdown_tx);
        }

        *self.reconnect_on_close.write().await = true;

        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.connection_loop().await;
        });

        *self.connection_loop_handle.lock().await = Some(handle);
    }

    pub async fn stop(&self) {
        *self.reconnect_on_close.write().await = false;

        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        if let Some(handle) = self.maintenance_handle.lock().await.take() {
            handle.abort();
        }

        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close().await;
        }

        self.set_state(ConnectionState::Disconnected).await;
        *self.sender.write().await = None;
    }

    async fn connection_loop(self: Arc<Self>) {
        let mut reconnect_delay = RECONNECT_DELAY;
        let shutdown_rx = self.shutdown_tx.lock().await.as_ref().unwrap().subscribe();
        let mut shutdown_rx = shutdown_rx;

        loop {
            if *shutdown_rx.borrow() || self.cancellation.is_cancelled() {
                log_t!("omikron_connection_loop_shutdown");
                break;
            }

            if !*self.reconnect_on_close.read().await {
                break;
            }

            let retry_reason = match self.clone().connect_once().await {
                Ok(result) => {
                    if result.became_healthy {
                        reconnect_delay = RECONNECT_DELAY;
                    }
                    if !*self.reconnect_on_close.read().await {
                        break;
                    }
                    "Connection lost".to_string()
                }
                Err(e) => {
                    if self.auth_failure.read().await.is_some() {
                        log!("Authentication failed, stopping reconnection: {}", e);
                        break;
                    }
                    format!("Connection failed: {e}")
                }
            };

            let delay = jittered_reconnect_delay(reconnect_delay);
            log!("{}, retrying in {:?}...", retry_reason, delay);
            tokio::select! {
                _ = sleep(delay) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }

            reconnect_delay = std::cmp::min(reconnect_delay * 2, MAX_RECONNECT_DELAY);
        }
    }

    fn initialize_password_auth(&self, identity: &Path) {
        if let Err(error) = self.password_auth.initialize(identity) {
            log!("Password authentication unavailable: {}", error);
        }
    }

    async fn connect_once(self: Arc<Self>) -> Result<ConnectionAttemptResult, String> {
        self.set_state(ConnectionState::Connecting).await;
        log_t!("omikron_connecting");

        let identity = self
            .load_or_migrate_keyring()
            .await
            .map_err(|error| format!("Iota identity initialization failed: {error}"))?;
        let keyring = identity.keyring();
        *self.keyring.write().await = Some(keyring.clone());
        self.initialize_password_auth(identity_path());

        let existing_iota_id = CONFIG.load().iota_id;

        let endpoint = self.resolve_omikron_endpoint(existing_iota_id).await?;

        let addr_str = format!("https://{}:{}", endpoint.host, endpoint.port);

        log!("Connecting to Omikron at {}", addr_str);

        let policy = Policy::default()
            .with_send_mode(SendMode::PersistentStream)
            .with_timeouts(
                Duration::from_millis(2_000),
                Duration::from_millis(2_000),
                Duration::from_millis(30_000),
            )
            .with_keep_alive(Some(Duration::from_secs(6)))
            .with_receiver_queue_capacity(1000)
            .with_max_concurrent_stream_tasks(10)
            .with_persistent_stream_retries(5, Duration::from_secs(5));
        let client_config = ClientConfig::new(&addr_str)
            .with_description("iota")
            .with_policy(policy)
            .with_ping_interval(MAINTENANCE_INTERVAL);

        let connection = match Client::auth_connect_or_register(
            client_config,
            existing_iota_id,
            &keyring,
            &endpoint.public_key,
        )
        .await
        {
            Ok(connection) => connection,
            Err(mtp::common::CommunicationError::AuthenticationFailed(reason)) => {
                /* MTP currently combines invalid proofs with timeouts and backend
                 * failures in this variant. Retrying is safe; stopping here can
                 * strand an Iota during a temporary Omega outage. */
                return Err(format!("Authentication attempt failed: {reason}"));
            }
            Err(e) => return Err(format!("Connection failed: {}", e)),
        };

        log_t!("omikron_connection_success");

        self.persist_authenticated_omikron(&endpoint)?;

        if existing_iota_id.is_none() {
            modify_config(|cfg| cfg.iota_id = Some(connection.client_id));
            log!("Registered with Iota-ID: {}", connection.client_id);
        }

        let sender_arc = Arc::new(connection.sender.clone());
        *self.sender.write().await = Some(sender_arc.clone());
        self.set_state(ConnectionState::Connected { identified: true })
            .await;
        self.password_auth.prune();

        // Start read loop
        let connection = Arc::new(connection);
        let read_self = self.clone();
        let read_connection = connection.clone();
        let read_handle = tokio::spawn(async move {
            read_self.read_loop(read_connection).await;
        });

        log_t!("omikron_authenticated");

        self.classify_legacy_pending_relays().await;
        if let Err(error) = self.sync_omega_invitations().await {
            log!(
                "Omega invitation snapshot synchronization failed: {}",
                error
            );
        }
        self.flush_pending_invitation_actions().await;

        let maintenance_self = self.clone();
        let maintenance_handle = tokio::spawn(async move {
            maintenance_self.maintenance_loop(connection).await;
        });
        *self.maintenance_handle.lock().await = Some(maintenance_handle);

        {
            self.active_tasks.insert("Omikron Listener".to_string());
        }

        // Wait for read loop to complete
        let result = read_handle.await;
        *self.sender.write().await = None;
        self.set_state(ConnectionState::Disconnected).await;
        {
            self.active_tasks.remove("Omikron Listener");
        }

        if let Some(handle) = self.maintenance_handle.lock().await.take() {
            handle.abort();
        }

        match result {
            Ok(()) => Ok(ConnectionAttemptResult {
                became_healthy: true,
            }),
            Err(e) => Err(format!("Read loop error: {}", e)),
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

    async fn sync_pending_invitation_revocations(&self) -> Result<(), String> {
        let invitations = iota_storage::users::invitations::list()
            .map_err(|error| format!("failed to load pending invitation actions: {error}"))?;
        for invitation in invitations.into_iter().filter(|invitation| {
            invitation.authority == iota_storage::users::invitations::InvitationAuthority::Omega
                && invitation.pending_action
                    == Some(iota_storage::users::invitations::PendingAction::Revoke)
        }) {
            let request = CommunicationValue::new(CommunicationType::RevokeUserInvitation)
                .add_typed_default(
                    DataType::InvitationAuthority,
                    DataValue::Str("omega".into()),
                )
                .add_typed_default(
                    DataType::InvitationId,
                    DataValue::SignedNumber(invitation.invitation_id.into()),
                );
            let response = self
                .await_response(&request, Some(Duration::from_secs(20)))
                .await?;
            if response.is_type(CommunicationType::Success) {
                let Some(revision) = response
                    .get_data(DataType::InvitationRevision)
                    .as_signed_number()
                    .and_then(|value| i64::try_from(value).ok())
                else {
                    return Err("Omega revoke response omitted invitation revision".into());
                };
                let state = match response.get_data(DataType::InvitationState).as_str() {
                    Some("pending") => iota_storage::users::invitations::InvitationState::Pending,
                    Some("provisioning") => {
                        iota_storage::users::invitations::InvitationState::Provisioning
                    }
                    Some("redeemed") => iota_storage::users::invitations::InvitationState::Redeemed,
                    Some("revoked") => iota_storage::users::invitations::InvitationState::Revoked,
                    Some("expired") => iota_storage::users::invitations::InvitationState::Expired,
                    _ => return Err("Omega revoke response contained invalid state".into()),
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                iota_storage::users::invitations::apply_revoke_result(
                    invitation.invitation_id,
                    state,
                    revision,
                    (state == iota_storage::users::invitations::InvitationState::Revoked)
                        .then_some(now),
                    now,
                )
                .map_err(|error| format!("failed to apply invitation revoke result: {error}"))?;
            } else {
                return Err("Omega returned the wrong invitation revoke response type".into());
            }
        }
        Ok(())
    }

    pub async fn flush_pending_invitation_actions(&self) {
        if self
            .invitation_sync
            .flush_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let now = Instant::now();
        if self
            .invitation_sync
            .next_retry_at
            .lock()
            .await
            .is_some_and(|retry_at| retry_at > now)
        {
            self.invitation_sync
                .flush_in_progress
                .store(false, Ordering::Release);
            return;
        }
        match self.sync_pending_invitation_revocations().await {
            Ok(()) => {
                *self.invitation_sync.next_retry_at.lock().await = None;
                *self.invitation_sync.retry_delay.lock().await = Duration::from_secs(5);
            }
            Err(error) => {
                log!("Pending invitation action flush failed: {}", error);
                let mut delay = self.invitation_sync.retry_delay.lock().await;
                *self.invitation_sync.next_retry_at.lock().await = Some(now + *delay);
                *delay = next_invitation_retry_delay(*delay);
            }
        }
        self.invitation_sync
            .flush_in_progress
            .store(false, Ordering::Release);
    }

    pub async fn sync_omega_invitations(&self) -> Result<(), OmikronError> {
        let request = CommunicationValue::new(CommunicationType::ListUserInvitations)
            .add_typed_default(
                DataType::InvitationAuthority,
                DataValue::Str("omega".into()),
            );
        let response = self
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(map_await_response_error)?;
        if !response.is_type(CommunicationType::ListUserInvitations) {
            return Err(OmikronError::Internal(
                "Omega returned the wrong invitation snapshot response type".into(),
            ));
        }
        let Some(DataValue::Array(remote)) = response.get_data(DataType::Invitations) else {
            return Err(OmikronError::Internal(
                "Omega invitation snapshot omitted Invitations".into(),
            ));
        };
        let type_map = TypeMap::latest();
        let synced_at = now_millis_i64();
        let expected_iota_id = CONFIG
            .load()
            .iota_id
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| OmikronError::Internal("Iota identity is not configured".into()))?;
        let mut invitations = Vec::with_capacity(remote.len());
        for invitation in remote {
            let DataValue::Container(fields) = invitation else {
                return Err(OmikronError::Internal(
                    "Omega invitation snapshot contained a non-container record".into(),
                ));
            };
            invitations.push(parse_omega_invitation(
                fields,
                &type_map,
                expected_iota_id,
                synced_at,
            )?);
        }
        iota_storage::users::invitations::merge_omega_snapshot(&invitations, synced_at).map_err(
            |error| {
                OmikronError::Storage(format!(
                    "failed to persist Omega invitation snapshot: {error}"
                ))
            },
        )?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Omikron discovery (via Omega's HTTP API, replacing the static
    // host/port/public-key-file model)
    // -------------------------------------------------------------------------

    /*
     * Discovery runs fresh on every `connect_once()` attempt rather than once
     * at construction, since a fixed `OmikronConnection` may need to move to
     * a different Omikron across reconnects (e.g. after the sticky/primary
     * Omikron dies). `OMIKRON_HOST`/`OMIKRON_PORT` remain as a manual
     * override for local dev/testing against a hand-run Omikron without a
     * live Omega.
     *
     * Keys are pinned per Omikron ID. A different relay can therefore be used
     * after failover, while an unexpected key change for one relay remains a
     * security error. Discovery data becomes durable only after MTP
     * authentication has completed.
     */
    async fn resolve_omikron_endpoint(
        &self,
        existing_iota_id: Option<u64>,
    ) -> Result<ResolvedOmikronEndpoint, String> {
        if let (Ok(host), Ok(port_str)) = (env::var("OMIKRON_HOST"), env::var("OMIKRON_PORT")) {
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("Invalid OMIKRON_PORT: {}", port_str))?;
            let key_path = Path::new("omikron.mpkb");
            let public_key = mtp::files::load_public_key_bundle(key_path)
                .map_err(|e| {
                    format!(
                        "Failed to load Omikron public key bundle from {}: {}. Obtain {} from the Omikron operator and place it at that path.",
                        key_path.display(), e, key_path.display()
                    )
                })?;
            return Ok(ResolvedOmikronEndpoint {
                id: None,
                host,
                port,
                public_key,
            });
        }

        let cached_endpoint = {
            let conf = CONFIG.load();
            match (&conf.omikron_id, &conf.omikron_host, conf.omikron_port) {
                (Some(id), Some(host), Some(port)) if !host.trim().is_empty() && port != 0 => {
                    mtp::files::load_public_key_bundle(&omikron_public_key_path(*id))
                        .ok()
                        .map(|public_key| ResolvedOmikronEndpoint {
                            id: Some(*id),
                            host: host.clone(),
                            port,
                            public_key,
                        })
                }
                (Some(_), Some(_), Some(_)) => {
                    log!("Ignoring invalid cached Omikron endpoint in Iota configuration");
                    None
                }
                (None, Some(host), Some(port)) if !host.trim().is_empty() && port != 0 => {
                    mtp::files::load_public_key_bundle(legacy_omikron_public_key_path())
                        .ok()
                        .map(|public_key| ResolvedOmikronEndpoint {
                            id: None,
                            host: host.clone(),
                            port,
                            public_key,
                        })
                }
                _ => None,
            }
        };

        let discovered = match existing_iota_id {
            Some(id) => match omega_discovery::discover_primary(id).await {
                Ok(endpoint) => Some(endpoint),
                Err(e) => {
                    log!(
                        "Sticky Omikron discovery failed ({}), falling back to a random Omikron",
                        e
                    );
                    omega_discovery::discover_random().await.ok()
                }
            },
            None => omega_discovery::discover_random().await.ok(),
        };

        let endpoint = if let Some(endpoint) = discovered {
            let key_path = omikron_public_key_path(endpoint.id);
            match mtp::files::load_public_key_bundle(&key_path).ok() {
                Some(cached) => {
                    let keys_match =
                        match (cached.try_as_bytes(), endpoint.public_key.try_as_bytes()) {
                            (Ok(cached_bytes), Ok(discovered_bytes)) => {
                                cached_bytes == discovered_bytes
                            }
                            _ => false,
                        };
                    if !keys_match {
                        log!(
                            "Fetched Omikron public key differs from the trusted {}. \
                             Omikron key rotation requires an explicit trust refresh.",
                            key_path.display(),
                        );
                        return Err(format!(
                            "Omega returned a changed public key for Omikron {}",
                            endpoint.id
                        ));
                    } else {
                        ResolvedOmikronEndpoint {
                            id: Some(endpoint.id),
                            host: endpoint.host,
                            port: endpoint.port,
                            public_key: cached,
                        }
                    }
                }
                None => ResolvedOmikronEndpoint {
                    id: Some(endpoint.id),
                    host: endpoint.host,
                    port: endpoint.port,
                    public_key: endpoint.public_key,
                },
            }
        } else if let Some(cached) = cached_endpoint {
            log!(
                "Omega discovery unreachable, falling back to last-known Omikron {}:{}",
                cached.host,
                cached.port
            );
            cached
        } else {
            return Err(
                "Omega discovery failed and no cached Omikron address/key is available".to_string(),
            );
        };

        Ok(endpoint)
    }

    fn persist_authenticated_omikron(
        &self,
        endpoint: &ResolvedOmikronEndpoint,
    ) -> Result<(), String> {
        let Some(id) = endpoint.id else {
            return Ok(());
        };
        let key_path = omikron_public_key_path(id);
        std::fs::create_dir_all(omikron_trust_directory())
            .map_err(|error| format!("create Omikron trust directory: {error}"))?;
        save_omikron_public_key(&endpoint.public_key, &key_path)?;
        modify_config(|cfg| {
            cfg.omikron_id = Some(id);
            cfg.omikron_host = Some(endpoint.host.clone());
            cfg.omikron_port = Some(endpoint.port);
        });
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Read Loop & Maintenance
    // -------------------------------------------------------------------------

    async fn read_loop(self: Arc<Self>, connection: Arc<MTPConnection>) {
        loop {
            let result = connection.receive().await;
            match result {
                Ok(cv) => {
                    if cv.is_type(CommunicationType::Relay) {
                        let permit = self.handler_semaphore.clone().acquire_owned().await;
                        let self_clone = self.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            self_clone.dispatch_relay(cv).await;
                        });
                        continue;
                    }
                    let Some(msg_id) = cv.id() else {
                        let permit = self.handler_semaphore.clone().acquire_owned().await;
                        let self_clone = self.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            self_clone.handle_message_impl(cv).await;
                        });
                        continue;
                    };
                    if let Some((_, task)) = WAITING_TASKS.remove(&msg_id) {
                        if (task.task)(cv.clone()) {
                            continue;
                        }
                    }
                    let permit = self.handler_semaphore.clone().acquire_owned().await;
                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        self_clone.handle_message_impl(cv).await;
                    });
                }
                Err(e) => {
                    self.fail_all_waiting_tasks(format!(
                        "Connection receive error: {} (connection_id={})",
                        e, self.connection_id
                    ))
                    .await;
                    break;
                }
            }
            if !connection.receiver.is_open() {
                self.fail_all_waiting_tasks(format!(
                    "Connection closed (connection_id={}, receiver_open=false)",
                    self.connection_id
                ))
                .await;
                break;
            }
        }
    }

    async fn maintenance_loop(self: Arc<Self>, connection: Arc<MTPConnection>) {
        loop {
            sleep(MAINTENANCE_INTERVAL).await;

            if !self.state.read().await.is_connected() {
                break;
            }

            if let Some(sender) = self.sender.read().await.as_ref() {
                if !sender.is_open() {
                    break;
                }
            } else {
                break;
            }

            if let Some(ping) = connection.get_ping() {
                let ping_ms = i64::try_from(ping.as_millis()).unwrap_or(i64::MAX);
                *self.last_ping.lock().await = ping_ms;
                self.app.lock().unwrap().push_ping_val(ping_ms as f64);
            }

            self.classify_legacy_pending_relays().await;
            self.flush_pending_relays().await;
            let invitation_self = self.clone();
            tokio::spawn(async move {
                invitation_self.flush_pending_invitation_actions().await;
            });
            if let Err(error) = relay_replay::prune_completed(
                now_millis_i64().saturating_sub(relay_replay::RELAY_RETENTION_MILLIS),
            ) {
                log!("Relay replay cleanup failed: {}", error);
            }
            self.password_auth.prune();
            if let Err(error) = iota_storage::util::protected_replay::prune(
                now_millis_i64().saturating_sub(7 * 24 * 60 * 60 * 1000),
            ) {
                log!("Password command replay cleanup failed: {error}");
            }
        }
    }

    async fn resolve_relay_signing_keys(
        &self,
        signer_id: u64,
    ) -> Result<Vec<PublicKeyBundle>, RelayValidationError> {
        self.resolve_relay_principal(signer_id)
            .await
            .map(|principal| principal.public_keys)
    }

    async fn resolve_relay_principal(
        &self,
        signer_id: u64,
    ) -> Result<iota_identity::ResolvedPrincipal, RelayValidationError> {
        use iota_identity::{
            AuthorityId, AuthorityLocator, IdentityResolver, PrincipalId, UserSelector,
        };
        let authority = AuthorityId::omega_legacy(&omega_discovery::omega_host())
            .map_err(|error| RelayValidationError::KeyLookup(error.to_string()))?;
        let locator = AuthorityLocator::new(omega_discovery::omega_host())
            .map_err(|error| RelayValidationError::KeyLookup(error.to_string()))?;
        let principals = Arc::new(iota_storage::identity::SqlitePrincipalStore);
        let local_users = Arc::new(iota_storage::identity::SqliteLocalUserStore);
        let local = iota_storage::identity::LocalIdentityResolver::new(
            authority.clone(),
            iota_identity::AuthorityKind::Omega,
            iota_identity::PrincipalHome::Omega(locator.clone()),
            local_users,
            principals.clone(),
        );
        let principal = PrincipalId {
            authority: authority.clone(),
            user_id: signer_id,
        };
        match local
            .signing_keys(&principal, &iota_identity::ResolutionContext::default())
            .await
        {
            Ok(_) => local
                .resolve_principal(&principal)
                .await
                .map_err(|error| RelayValidationError::KeyLookup(error.to_string())),
            Err(iota_identity::IdentityError::NotFound) => {
                crate::identity::resolve_omega_principal(
                    self,
                    principals.as_ref(),
                    &authority,
                    &locator,
                    &UserSelector::UserId(signer_id),
                )
                .await
                .map_err(|error| RelayValidationError::KeyLookup(error.to_string()))
            }
            Err(error) => Err(RelayValidationError::KeyLookup(error.to_string())),
        }
    }
}

impl OmikronConnection {
    async fn classify_legacy_pending_relays(&self) {
        let mut after_id = 0;
        loop {
            let records = match relay_queue::list_without_relay_identity_after(after_id, 100) {
                Ok(records) => records,
                Err(error) => {
                    log!("Pending relay ownership query failed: {}", error);
                    return;
                }
            };
            if records.is_empty() {
                return;
            }
            for record in records {
                after_id = record.id;
                let Some(version) = mtp::type_map::Version::parse(&record.type_map_version) else {
                    log!(
                        "Deleting pending Relay {} with invalid type-map version",
                        record.id
                    );
                    let _ = relay_queue::delete(record.id);
                    continue;
                };
                let type_map = mtp::codec::TypeMap::new(version);
                let Ok(frame) = CommunicationValue::from_bytes_with(&record.frame, &type_map)
                else {
                    log!("Deleting pending Relay {} with invalid frame", record.id);
                    let _ = relay_queue::delete(record.id);
                    continue;
                };
                let Some(local_iota_id) = CONFIG.load().iota_id else {
                    return;
                };
                let Some(keyring) = self.keyring.read().await.as_ref().cloned() else {
                    return;
                };
                let verified = verify_relay_metadata(
                    &frame,
                    local_iota_id,
                    &keyring,
                    |signer_id| async move { self.resolve_relay_signing_keys(signer_id).await },
                )
                .await;
                let verified = match verified {
                    Ok(verified) => verified,
                    Err(RelayValidationError::KeyLookup(error)) => {
                        log!(
                            "Deferring pending Relay {} ownership lookup: {}",
                            record.id,
                            error
                        );
                        continue;
                    }
                    Err(RelayValidationError::MissingSigningKeys(signer_id)) => {
                        log!(
                            "Deferring pending Relay {} until signer {} keys are available",
                            record.id,
                            signer_id
                        );
                        continue;
                    }
                    Err(error) => {
                        log!(
                            "Deleting structurally invalid pending Relay {}: {}",
                            record.id,
                            error
                        );
                        let _ = relay_queue::delete(record.id);
                        continue;
                    }
                };
                let identity = match (
                    i64::try_from(verified.context.signer_id),
                    i64::try_from(verified.context.final_recipient_id),
                ) {
                    (Ok(signer_id), Ok(destination_user_id)) => {
                        let Ok(signer) = self
                            .resolve_relay_principal(verified.context.signer_id)
                            .await
                        else {
                            continue;
                        };
                        let Ok(recipient) = self
                            .resolve_relay_principal(verified.context.final_recipient_id)
                            .await
                        else {
                            continue;
                        };
                        relay_queue::RelayIdentity {
                            signer: signer.handle,
                            recipient: recipient.handle,
                            message_id: verified.context.message_id,
                            legacy_signer_id: Some(signer_id),
                            legacy_recipient_id: Some(destination_user_id),
                        }
                    }
                    _ => {
                        let _ = relay_queue::delete(record.id);
                        continue;
                    }
                };
                if matches!(record.target, relay_queue::RelayTarget::User(destination) if i64::try_from(destination).ok() != identity.legacy_recipient_id)
                {
                    log!(
                        "Quarantining pending Relay {} with a target-recipient mismatch",
                        record.id
                    );
                    let _ = relay_queue::quarantine_target_mismatch(record.id);
                    continue;
                }
                if let Err(error) = relay_queue::set_relay_identity(record.id, &identity) {
                    log!(
                        "Pending Relay {} ownership backfill failed: {}",
                        record.id,
                        error
                    );
                }
            }
        }
    }

    async fn flush_pending_relays(&self) {
        self.flush_pending_relays_for_user(None).await;
    }

    async fn flush_pending_relays_for_user(&self, destination_user_id: Option<i64>) {
        let Ok(records) = relay_queue::list_active(100) else {
            return;
        };
        for record in records.into_iter().filter(|record| {
            destination_user_id.is_none_or(|user_id| {
                matches!(record.target, relay_queue::RelayTarget::User(destination) if i64::try_from(destination).ok() == Some(user_id))
            })
        }) {
            if record.relay_signer_id.is_none()
                || record.relay_destination_user_id.is_none()
                || record.relay_message_id.is_none()
                || record.signer_principal.is_none()
                || record.destination_principal.is_none()
            {
                log!(
                    "Skipping pending Relay {} until ownership is classified",
                    record.id
                );
                continue;
            }
            let Some(signer_principal) = record.signer_principal else {
                continue;
            };
            let Some(version) = mtp::type_map::Version::parse(&record.type_map_version) else {
                log!(
                    "Retaining pending Relay {} with invalid type-map version {}",
                    record.id,
                    record.type_map_version
                );
                continue;
            };
            let type_map = mtp::codec::TypeMap::new(version);
            let Ok(frame) = CommunicationValue::from_bytes_with(&record.frame, &type_map) else {
                log!("Retaining pending Relay {} with invalid frame", record.id);
                continue;
            };
            if record.relay_signer_id.is_none()
                || record.relay_destination_user_id.is_none()
                || record.relay_message_id.is_none()
            {
                let Some(local_iota_id) = CONFIG.load().iota_id else {
                    log!(
                        "Retaining pending Relay {} until the Iota identity is available",
                        record.id
                    );
                    continue;
                };
                let Some(keyring) = self.keyring.read().await.as_ref().cloned() else {
                    log!(
                        "Retaining pending Relay {} until the Iota keyring is available",
                        record.id
                    );
                    continue;
                };
                let resolver_connection = self;
                let verified = verify_relay_metadata(
                    &frame,
                    local_iota_id,
                    &keyring,
                    move |signer_id| async move {
                        resolver_connection
                            .resolve_relay_signing_keys(signer_id)
                            .await
                    },
                )
                .await;
                let Ok(verified) = verified else {
                    log!("Deleting unverifiable pending Relay {}", record.id);
                    if let Err(error) = relay_queue::delete(record.id) {
                        log!("Pending Relay {} cleanup failed: {}", record.id, error);
                    }
                    continue;
                };
                let relay_identity = match (
                    i64::try_from(verified.context.signer_id),
                    i64::try_from(verified.context.final_recipient_id),
                ) {
                    (Ok(signer_id), Ok(destination_user_id)) => {
                        let Ok(signer) = self.resolve_relay_principal(verified.context.signer_id).await else {
                            continue;
                        };
                        let Ok(recipient) = self.resolve_relay_principal(verified.context.final_recipient_id).await else {
                            continue;
                        };
                        relay_queue::RelayIdentity {
                            signer: signer.handle,
                            recipient: recipient.handle,
                            message_id: verified.context.message_id,
                            legacy_signer_id: Some(signer_id),
                            legacy_recipient_id: Some(destination_user_id),
                        }
                    }
                    _ => {
                        log!(
                            "Deleting pending Relay {} with an out-of-range identity",
                            record.id
                        );
                        if let Err(error) = relay_queue::delete(record.id) {
                            log!("Pending Relay {} cleanup failed: {}", record.id, error);
                        }
                        continue;
                    }
                };
                if let Err(error) = relay_queue::set_relay_identity(record.id, &relay_identity) {
                    log!(
                        "Pending Relay {} ownership backfill failed: {}",
                        record.id,
                        error
                    );
                    continue;
                }
            }
            let Some(wire_target) = record.target.legacy_wire_target() else {
                continue;
            };
            let Ok(forwarded) = forward_verified_relay(&frame, wire_target) else {
                log!(
                    "Retaining pending Relay {} with invalid route target",
                    record.id
                );
                continue;
            };
            match record.target {
                relay_queue::RelayTarget::LegacyOmegaIota { iota_id: destination_iota, .. } => {
                    match self
                        .await_relay_response(&forwarded, Duration::from_secs(20))
                        .await
                    {
                        Ok(response) if response.is_type(CommunicationType::Success) => {
                            let accepted_at = response
                                .get_data(DataType::RelayAcceptedAt)
                                .as_number()
                                .and_then(|value| i64::try_from(value).ok());
                            let relay_id = response.get_data(DataType::RelayMessageId).as_str();
                            if let (Some(accepted_at), Some(message_id), Some(signer_id)) = (
                                accepted_at,
                                record.relay_message_id.as_deref(),
                                record.relay_signer_id,
                            ) && relay_id == Some(message_id)
                            {
                                if frame.is_type(CommunicationType::SetChatSecret) {
                                    let Some(keyring) = self.keyring.read().await.as_ref().cloned()
                                    else {
                                        log!(
                                            "Retaining pending chat-secret Relay {} until the Iota keyring is available",
                                            record.id
                                        );
                                        continue;
                                    };
                                    let resolver_connection = self;
                                    let verified = match verify_relay_metadata(
                                        &frame,
                                        destination_iota,
                                        &keyring,
                                        move |signer_id| async move {
                                            resolver_connection
                                                .resolve_relay_signing_keys(signer_id)
                                                .await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(value) => value,
                                        Err(error) => {
                                            log!(
                                                "Retaining pending chat-secret Relay {} after verification failure: {}",
                                                record.id,
                                                error
                                            );
                                            continue;
                                        }
                                    };
                                    let content = match open_verified_relay_content(
                                        &verified,
                                        &[&keyring],
                                    ) {
                                        Ok(value) => value,
                                        Err(error) => {
                                            log!(
                                                "Retaining pending chat-secret Relay {} after content verification failure: {}",
                                                record.id,
                                                error
                                            );
                                            continue;
                                        }
                                    };
                                    let recipient_principal = match record.destination_principal {
                                        Some(principal) => principal,
                                        None => match self
                                            .resolve_relay_principal(
                                                verified.context.final_recipient_id,
                                            )
                                            .await
                                        {
                                            Ok(principal) => principal.handle,
                                            Err(error) => {
                                                log!(
                                                    "Retaining pending chat-secret Relay {} after recipient resolution failure: {}",
                                                    record.id,
                                                    error
                                                );
                                                continue;
                                            }
                                        },
                                    };
                                    if let Err(error) =
                                        message_handlers::apply_verified_relay_content(
                                            &verified.context,
                                            &content,
                                            signer_principal,
                                            recipient_principal,
                                            now_millis_i64(),
                                            signer_id,
                                            true,
                                        )
                                    {
                                        log!(
                                            "Retaining pending chat-secret Relay {} after origin application failure: {}",
                                            record.id,
                                            error
                                        );
                                        continue;
                                    }
                                }
                                if let Err(error) =
                                    iota_storage::util::downstream_relay::acknowledge_iota_delivery(
                                        record.frame_id,
                                        signer_principal,
                                        Some(signer_id),
                                        message_id,
                                        accepted_at,
                                    )
                                {
                                    log!(
                                        "Pending Relay {} acknowledgement failed: {}",
                                        record.id,
                                        error
                                    );
                                }
                            } else {
                                log!("Pending Relay {} returned malformed Success", record.id);
                            }
                        }
                        Ok(response) if !response.is_type(CommunicationType::ErrorInternal) => {
                            if let (Some(message_id), Some(signer_id)) =
                                (record.relay_message_id.as_deref(), record.relay_signer_id)
                            {
                                if let Err(error) =
                                    iota_storage::util::downstream_relay::reject_iota_delivery(
                                        record.frame_id,
                                        signer_principal,
                                        Some(signer_id),
                                        message_id,
                                        "destination_rejected",
                                    )
                                {
                                    log!(
                                        "Pending Relay {} rejection cleanup failed: {}",
                                        record.id,
                                        error
                                    );
                                }
                            }
                        }
                        Ok(response) => log!(
                            "Pending Relay {} route returned retryable {}",
                            record.id,
                            response.get_type()
                        ),
                        Err(error) => {
                            log!("Pending Relay {} delivery failed: {}", record.id, error)
                        }
                    }
                }
                relay_queue::RelayTarget::User(_) => {
                    if let Err(error) = self.send_message(&forwarded).await {
                        log!("Pending Relay {} delivery failed: {}", record.id, error);
                    }
                }
                relay_queue::RelayTarget::Iota(_) => {}
            }
        }
    }

    // -------------------------------------------------------------------------
    // Message Handling - Dispatch
    // -------------------------------------------------------------------------

    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if !matches!(
            cv.get_comm_type_enum(),
            Some(
                CommunicationType::PasswordEnrollmentStart
                    | CommunicationType::PasswordEnrollmentFinish
                    | CommunicationType::PasswordEnrollmentStatus
                    | CommunicationType::PasswordEnrollmentDisable
                    | CommunicationType::PasswordProvisioningStart
                    | CommunicationType::PasswordProvisioningFinish
            )
        ) {
            log_cv_in!(&cv);
        }

        if cv.is_type(CommunicationType::Success)
            && let Some(frame_id) = cv.id()
            && let Some(destination_id) = cv
                .get_data(DataType::UserId)
                .as_number()
                .and_then(|value| u64::try_from(value).ok())
        {
            let Ok(destination_id) = i64::try_from(destination_id) else {
                log!("Relay destination ID exceeds storage range");
                return;
            };
            match client_relay_delivery::acknowledge_client_delivery(destination_id, frame_id) {
                Ok(client_relay_delivery::ClientRelayDeliveryResult::Acknowledged) => {
                    return;
                }
                Ok(client_relay_delivery::ClientRelayDeliveryResult::NotFound) => {}
                Err(error) => log!("Relay delivery acknowledgement failed: {}", error),
            }
        }

        if cv.is_type(CommunicationType::ErrorNoIota)
            && cv.get_data(DataType::ErrorType).as_str() == Some("client_offline")
            && let (Some(frame_id), Some(destination_id)) = (
                cv.id(),
                cv.get_data(DataType::UserId)
                    .as_number()
                    .and_then(|id| i64::try_from(id).ok()),
            )
        {
            if let Err(error) = relay_queue::mark_client_offline(destination_id, frame_id) {
                log!("Pending Relay offline state update failed: {}", error);
            }
            return;
        }

        let Some(msg_id) = cv.id() else {
            self.handle_message_impl(cv).await;
            return;
        };

        if let Some((_, task)) = WAITING_TASKS.remove(&msg_id) {
            if (task.task)(cv.clone()) {
                return;
            }
        }

        self.clone().handle_message_impl(cv).await;
    }

    async fn handle_message_impl(self: Arc<Self>, cv: CommunicationValue) {
        if cv.is_type(CommunicationType::Relay) {
            self.dispatch_relay(cv).await;
            return;
        }
        if cv.require_id().is_err() {
            let _ = self
                .send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        if matches!(
            iota_connection::relay::message_security_class(&cv),
            iota_connection::relay::MessageSecurityClass::RelayOnly
        ) {
            log!("Rejecting sender-based application mutation outside Relay");
            let _ = self
                .send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        macro_rules! dispatch {
            ($ty:ident, $method:ident) => {
                if cv.is_type(CommunicationType::$ty) {
                    self.clone().$method(&cv).await;
                    return;
                }
            };
        }

        dispatch!(GetChatSecret, handle_get_chat_secret);
        dispatch!(TAuthAuthorize, handle_tauth_authorize);
        dispatch!(PasswordEnrollmentStart, handle_password_enrollment_start);
        dispatch!(PasswordEnrollmentFinish, handle_password_enrollment_finish);
        dispatch!(PasswordEnrollmentStatus, handle_password_enrollment_status);
        dispatch!(
            PasswordEnrollmentDisable,
            handle_password_enrollment_disable
        );
        dispatch!(
            PasswordProvisioningStart,
            handle_password_provisioning_start
        );
        dispatch!(
            PasswordProvisioningFinish,
            handle_password_provisioning_finish
        );
        dispatch!(TAuthExchangeCode, handle_tauth_exchange_code);
        dispatch!(TAuthUser, handle_tauth_user);
        dispatch!(TAuthContacts, handle_tauth_contacts);
        dispatch!(TAuthPublicLookup, handle_tauth_public_lookup);
        dispatch!(TAuthMetadataGet, handle_tauth_metadata_get);
        dispatch!(TAuthMetadataSet, handle_tauth_metadata_set);
        dispatch!(TAuthMetadataDelete, handle_tauth_metadata_delete);
        dispatch!(TAuthDisconnectDelete, handle_tauth_disconnect_delete);
        dispatch!(TAuthGrantList, handle_tauth_grant_list);
        dispatch!(TAuthGrantRevoke, handle_tauth_grant_revoke);
        dispatch!(TAuthGrantMetadataSet, handle_tauth_grant_metadata_set);
        dispatch!(AccountStateRequest, handle_account_state_request);
        dispatch!(AccountStateApplied, handle_account_state_applied);
        dispatch!(ReadNotification, handle_read_notification);
        dispatch!(MessageEdit, handle_message_edit);
        dispatch!(MessageEditLive, handle_message_edit_live);
        dispatch!(MessageReactionAdd, handle_message_reaction_add);
        dispatch!(MessageReactionRemove, handle_message_reaction_remove);
        dispatch!(MessageReactionLive, handle_message_reaction_live);
        dispatch!(MessageDeleteLive, handle_message_delete_live);
        dispatch!(MessageGet, handle_message_get);
        dispatch!(MessagesGet, handle_messages_get);
        dispatch!(GetChats, handle_get_chats);
        dispatch!(AddCommunity, handle_add_community);
        dispatch!(GetCommunities, handle_get_communities);
        dispatch!(RemoveCommunity, handle_remove_community);
        dispatch!(GlobalSettingsSave, handle_global_settings_save);
        dispatch!(GlobalSettingsLoad, handle_global_settings_load);
        dispatch!(SettingsSave, handle_settings_save);
        dispatch!(SettingsLoad, handle_settings_load);
        dispatch!(SettingsList, handle_settings_list);
        dispatch!(SyncedSettingSet, handle_synced_setting_set);
        dispatch!(SyncedSettingGet, handle_synced_setting_get);
        dispatch!(SyncedSettingDelete, handle_synced_setting_delete);
        dispatch!(SyncedSettingsList, handle_synced_settings_list);
        dispatch!(UserBlobPut, handle_user_blob_put);
        dispatch!(UserBlobGet, handle_user_blob_get);
        dispatch!(UserBlobDelete, handle_user_blob_delete);
        dispatch!(UserBlobList, handle_user_blob_list);
        dispatch!(UserAssetUploadStart, handle_user_asset_upload_start);
        dispatch!(UserAssetUploadChunk, handle_user_asset_upload_chunk);
        dispatch!(UserAssetUploadStatus, handle_user_asset_upload_status);
        dispatch!(UserAssetUploadCommit, handle_user_asset_upload_commit);
        dispatch!(UserAssetUploadAbort, handle_user_asset_upload_abort);
        dispatch!(UserAssetGetChunk, handle_user_asset_get_chunk);
        dispatch!(UserAssetList, handle_user_asset_list);
        dispatch!(UserAssetDelete, handle_user_asset_delete);
        dispatch!(UserBlock, handle_user_block);
        dispatch!(UserUnblock, handle_user_unblock);
        dispatch!(BlockedUsersGet, handle_blocked_users_get);
        dispatch!(ReceiptPolicyGet, handle_receipt_policy_get);
        dispatch!(ReceiptPolicySet, handle_receipt_policy_set);
        dispatch!(MessageStoragePolicyGet, handle_message_storage_policy_get);
        dispatch!(MessageStoragePolicySet, handle_message_storage_policy_set);
        dispatch!(UserBlockCheck, handle_user_block_check);
        dispatch!(CallContactCheck, handle_call_contact_check);
        dispatch!(CallEnvelopeStore, handle_call_envelope_store);
        dispatch!(CallEnvelopeGet, handle_call_envelope_get);
        dispatch!(CallContactAccept, handle_call_contact_accept);
        dispatch!(EraseHostedUserData, handle_erase_hosted_user_data);
        dispatch!(ProvisionIotaUser, handle_iota_user_provisioning);
    }

    // -------------------------------------------------------------------------
    // Message Handlers
    // -------------------------------------------------------------------------

    /// Omega-authorized account cleanup. The storage operation is idempotent;
    /// acknowledgement is therefore safe to retry after a reconnect.
    async fn handle_erase_hosted_user_data(self: Arc<Self>, cv: &CommunicationValue) {
        if !targets_iota(cv, CONFIG.load().iota_id) {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }
        let Some(user_id) = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0)
        else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };

        if iota_storage::users::user_manager::erase_user_locally(user_id).is_err() {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                .await;
            return;
        }

        let acknowledgement = CommunicationValue::new(CommunicationType::EraseHostedUserDataAck)
            .with_request_id(cv)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
        let _ = self.send_message(&acknowledgement).await;
    }

    /* Omega sends only public account metadata here. The locally created
     * profile records an external credential origin and never receives a TU. */
    async fn handle_iota_user_provisioning(self: Arc<Self>, cv: &CommunicationValue) {
        if !targets_iota(cv, CONFIG.load().iota_id) {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0);
        let username = cv.get_data(DataType::Username).as_str().map(str::to_owned);
        let public_key = cv.get_data(DataType::PublicKey).as_str().map(str::to_owned);
        let invitation_id = cv
            .get_data(DataType::InvitationId)
            .as_signed_number()
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value > 0);
        let invitation_revision = cv
            .get_data(DataType::InvitationRevision)
            .as_signed_number()
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value > 0);
        let Some((user_id, username, public_key, invitation_id, invitation_revision)) = user_id
            .zip(username)
            .zip(public_key)
            .zip(invitation_id)
            .zip(invitation_revision)
            .map(|((((id, username), key), invitation_id), revision)| {
                (id, username, key, invitation_id, revision)
            })
        else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let profile = iota_storage::users::user_profile::UserProfile::new(
            user_id, username, None, public_key, None, None,
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let mut result = iota_storage::users::invitations::apply_external_invitation_provisioning(
            invitation_id,
            invitation_revision,
            &profile,
            now,
        );
        if matches!(
            result,
            Ok(iota_storage::users::invitations::ProvisioningResult::MissingInvitation)
        ) {
            if self.sync_omega_invitations().await.is_ok() {
                result = iota_storage::users::invitations::apply_external_invitation_provisioning(
                    invitation_id,
                    invitation_revision,
                    &profile,
                    now,
                );
            }
        }
        match result {
            Ok(
                iota_storage::users::invitations::ProvisioningResult::Created
                | iota_storage::users::invitations::ProvisioningResult::AlreadyApplied,
            ) => {}
            Ok(iota_storage::users::invitations::ProvisioningResult::RevocationPending) => {
                self.flush_pending_invitation_actions().await;
                return;
            }
            Ok(iota_storage::users::invitations::ProvisioningResult::Conflict) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
            Ok(iota_storage::users::invitations::ProvisioningResult::MissingInvitation) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                    .await;
                return;
            }
        }
        let acknowledgement =
            CommunicationValue::new(CommunicationType::AcknowledgeIotaUserProvision)
                .with_request_id(cv)
                .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
                .add_typed_default(
                    DataType::InvitationId,
                    DataValue::SignedNumber(invitation_id.into()),
                );
        let _ = self.send_message(&acknowledgement).await;
    }

    async fn handle_get_chat_secret(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_chat_secret(cv))
            .await;
    }

    async fn handle_tauth_authorize(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(user_id) = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok())
        else {
            self.send_tauth_error(cv, "missing authenticated user")
                .await;
            return;
        };
        let Some(request_json) = cv.get_data(DataType::AuthorizationRequest).as_str() else {
            self.send_tauth_error(cv, "missing authorization request")
                .await;
            return;
        };
        let verified =
            match crate::tauth::verify_authorization(&self.http_client, request_json).await {
                Ok(verified) => verified,
                Err(error) => {
                    self.send_tauth_error(cv, &error.to_string()).await;
                    return;
                }
            };
        let existing = iota_storage::tauth::get_grant(user_id, &verified.request.app_id)
            .ok()
            .flatten();
        let reusable = existing.as_ref().is_some_and(|grant| {
            grant.domain == verified.request.domain
                && grant.app_public_key == verified.manifest.public_key
                && iota_storage::tauth::grant_covers(grant, &verified.request.scopes)
                    .unwrap_or(false)
        });
        let approved = cv.get_data(DataType::Enabled) == Some(&DataValue::BoolTrue);
        let locator = match self.signed_tauth_locator(user_id).await {
            Ok(locator) => locator,
            Err(error) => {
                self.send_tauth_error(cv, &error).await;
                return;
            }
        };
        let mut response = CommunicationValue::new(CommunicationType::TAuthAuthorizationResult)
            .with_request_id(cv)
            .with_receiver(user_id as u64)
            .add_typed_default(
                DataType::AppId,
                DataValue::Str(verified.request.app_id.clone()),
            )
            .add_typed_default(
                DataType::AppName,
                DataValue::Str(verified.manifest.name.clone()),
            )
            .add_typed_default(
                DataType::Domain,
                DataValue::Str(verified.request.domain.clone()),
            )
            .add_typed_default(
                DataType::RedirectUri,
                DataValue::Str(verified.request.redirect_uri.clone()),
            )
            .add_typed_default(
                DataType::State,
                DataValue::Str(verified.request.state.clone()),
            )
            .add_typed_default(DataType::Scopes, string_array(&verified.request.scopes))
            .add_typed_default(DataType::Locator, DataValue::Str(locator.clone()));
        if approved || reusable {
            match iota_storage::tauth::issue_code(iota_storage::tauth::AuthorizationGrant {
                local_user_id: user_id,
                app_id: &verified.request.app_id,
                app_name: &verified.manifest.name,
                domain: &verified.request.domain,
                redirect_uri: &verified.request.redirect_uri,
                scopes: &verified.request.scopes,
                app_public_key: &verified.manifest.public_key,
                manifest_hash: &verified.manifest_hash,
                pkce_challenge: &verified.request.pkce_challenge,
                authorization_request: request_json,
                locator: &locator,
            }) {
                Ok(code) => {
                    response = response
                        .add_typed_default(DataType::AuthorizationCode, DataValue::Str(code))
                }
                Err(error) => {
                    self.send_tauth_error(cv, &error.to_string()).await;
                    return;
                }
            }
        }
        let _ = self.send_message(&response).await;
    }

    async fn handle_tauth_exchange_code(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(code) = cv.get_data(DataType::AuthorizationCode).as_str() else {
            self.send_tauth_error(cv, "missing authorization code")
                .await;
            return;
        };
        let Some(app_id) = cv.get_data(DataType::AppId).as_str() else {
            self.send_tauth_error(cv, "missing app ID").await;
            return;
        };
        let Some(redirect) = cv.get_data(DataType::RedirectUri).as_str() else {
            self.send_tauth_error(cv, "missing redirect URI").await;
            return;
        };
        let Some(verifier) = cv.get_data(DataType::CodeVerifier).as_str() else {
            self.send_tauth_error(cv, "missing PKCE verifier").await;
            return;
        };
        let request_json = match iota_storage::tauth::authorization_request_for_code(code) {
            Ok(Some(request)) => request,
            _ => {
                self.send_tauth_error(cv, "authorization code is invalid, expired, or used")
                    .await;
                return;
            }
        };
        let verified =
            match crate::tauth::verify_authorization(&self.http_client, &request_json).await {
                Ok(verified)
                    if verified.request.app_id == app_id
                        && verified.request.redirect_uri == redirect =>
                {
                    verified
                }
                Ok(_) => {
                    self.send_tauth_error(cv, "authorization code binding mismatch")
                        .await;
                    return;
                }
                Err(error) => {
                    self.send_tauth_error(cv, &error.to_string()).await;
                    return;
                }
            };
        let session = match iota_storage::tauth::exchange_code(code, app_id, redirect, verifier) {
            Ok(session) => session,
            Err(error) => {
                self.send_tauth_error(cv, &error.to_string()).await;
                return;
            }
        };
        let principal = iota_storage::tauth::canonical_principal(session.local_user_id)
            .ok()
            .flatten()
            .unwrap_or_default();
        let response = CommunicationValue::new(CommunicationType::TAuthExchangeCodeResponse)
            .with_request_id(cv)
            .add_typed_default(DataType::SessionToken, DataValue::Str(session.token))
            .add_typed_default(DataType::AppId, DataValue::Str(verified.request.app_id))
            .add_typed_default(DataType::Principal, DataValue::Str(principal))
            .add_typed_default(DataType::Scopes, string_array(&session.scopes))
            .add_typed_default(DataType::Locator, DataValue::Str(session.locator));
        let _ = self.send_message(&response).await;
    }

    async fn handle_tauth_user(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(session) = self
            .tauth_session(cv, iota_storage::tauth::Scope::IdentityRead)
            .await
        else {
            return;
        };
        let principal = iota_storage::tauth::canonical_principal(session.local_user_id)
            .ok()
            .flatten()
            .unwrap_or_default();
        match iota_storage::tauth::public_profile(&principal) {
            Ok(Some(mut profile)) => {
                match self.signed_tauth_home_node().await {
                    Ok(descriptor) => profile["home_node"] = descriptor,
                    Err(error) => {
                        self.send_tauth_error(cv, &error).await;
                        return;
                    }
                }
                self.send_tauth_json(cv, CommunicationType::TAuthUser, profile.to_string())
                    .await
            }
            _ => {
                self.send_tauth_error(cv, "user profile is unavailable")
                    .await
            }
        }
    }

    async fn handle_tauth_contacts(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(session) = self
            .tauth_session(cv, iota_storage::tauth::Scope::ContactsRead)
            .await
        else {
            return;
        };
        match iota_storage::tauth::canonical_contact_ids(session.local_user_id) {
            Ok(contacts) => {
                self.send_tauth_json(
                    cv,
                    CommunicationType::TAuthContacts,
                    serde_json::to_string(&contacts).unwrap(),
                )
                .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    async fn handle_tauth_public_lookup(self: Arc<Self>, cv: &CommunicationValue) {
        if self
            .tauth_session(cv, iota_storage::tauth::Scope::IdentityRead)
            .await
            .is_none()
        {
            return;
        }
        let Some(principal) = cv.get_data(DataType::Principal).as_str() else {
            self.send_tauth_error(cv, "missing principal").await;
            return;
        };
        match iota_storage::tauth::public_profile(principal) {
            Ok(Some(mut profile)) => {
                if iota_storage::tauth::is_local_principal(principal).unwrap_or(false) {
                    match self.signed_tauth_home_node().await {
                        Ok(descriptor) => profile["home_node"] = descriptor,
                        Err(error) => {
                            self.send_tauth_error(cv, &error).await;
                            return;
                        }
                    }
                }
                self.send_tauth_json(
                    cv,
                    CommunicationType::TAuthPublicLookup,
                    profile.to_string(),
                )
                .await
            }
            Ok(None) => self.send_tauth_error(cv, "principal was not found").await,
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    async fn handle_tauth_metadata_get(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(token) = cv.get_data(DataType::SessionToken).as_str() else {
            self.send_tauth_error(cv, "missing session token").await;
            return;
        };
        match iota_storage::tauth::get_metadata(token) {
            Ok(value) => {
                let mut response = CommunicationValue::new(CommunicationType::TAuthMetadataGet)
                    .with_request_id(cv);
                if let Some(value) = value {
                    response = response.add_typed_default(DataType::Json, DataValue::Str(value));
                }
                let _ = self.send_message(&response).await;
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    async fn handle_tauth_metadata_set(self: Arc<Self>, cv: &CommunicationValue) {
        let token = cv.get_data(DataType::SessionToken).as_str();
        let json = cv.get_data(DataType::Json).as_str();
        match token.zip(json) {
            Some((token, json)) => match iota_storage::tauth::set_metadata(token, json) {
                Ok(()) => {
                    self.send_tauth_empty(cv, CommunicationType::TAuthMetadataSet)
                        .await
                }
                Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
            },
            None => {
                self.send_tauth_error(cv, "missing session token or JSON")
                    .await
            }
        }
    }

    async fn handle_tauth_metadata_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(token) = cv.get_data(DataType::SessionToken).as_str() else {
            self.send_tauth_error(cv, "missing session token").await;
            return;
        };
        match iota_storage::tauth::delete_metadata(token) {
            Ok(()) => {
                self.send_tauth_empty(cv, CommunicationType::TAuthMetadataDelete)
                    .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    async fn handle_tauth_disconnect_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(token) = cv.get_data(DataType::SessionToken).as_str() else {
            self.send_tauth_error(cv, "missing session token").await;
            return;
        };
        match iota_storage::tauth::disconnect_and_delete(token) {
            Ok(()) => {
                self.send_tauth_empty(cv, CommunicationType::TAuthDisconnectDelete)
                    .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    async fn handle_tauth_grant_list(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(user_id) = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok())
        else {
            self.send_tauth_error(cv, "missing authenticated user")
                .await;
            return;
        };
        match iota_storage::tauth::list_grants(user_id) {
            Ok(grants) => {
                self.send_tauth_json(
                    cv,
                    CommunicationType::TAuthGrantResponse,
                    serde_json::to_string(&grants).unwrap(),
                )
                .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    async fn handle_tauth_grant_revoke(self: Arc<Self>, cv: &CommunicationValue) {
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok());
        let app_id = cv.get_data(DataType::AppId).as_str();
        match user_id.zip(app_id) {
            Some((user_id, app_id)) => match iota_storage::tauth::revoke_grant(user_id, app_id) {
                Ok(_) => {
                    self.send_tauth_empty(cv, CommunicationType::TAuthGrantResponse)
                        .await
                }
                Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
            },
            None => self.send_tauth_error(cv, "missing user or app ID").await,
        }
    }

    async fn handle_tauth_grant_metadata_set(self: Arc<Self>, cv: &CommunicationValue) {
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok());
        let app_id = cv.get_data(DataType::AppId).as_str();
        let json = cv.get_data(DataType::Json).as_str();
        match user_id.zip(app_id).zip(json) {
            Some(((user_id, app_id), json)) => {
                match iota_storage::tauth::set_metadata_for_user(user_id, app_id, json) {
                    Ok(()) => {
                        self.send_tauth_empty(cv, CommunicationType::TAuthGrantResponse)
                            .await
                    }
                    Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
                }
            }
            None => {
                self.send_tauth_error(cv, "missing user, app ID, or JSON")
                    .await
            }
        }
    }

    async fn tauth_session(
        self: &Arc<Self>,
        cv: &CommunicationValue,
        scope: iota_storage::tauth::Scope,
    ) -> Option<iota_storage::tauth::Session> {
        let token = cv.get_data(DataType::SessionToken).as_str();
        match token.map(|token| iota_storage::tauth::authorize_session(token, scope)) {
            Some(Ok(session)) => Some(session),
            Some(Err(error)) => {
                self.clone().send_tauth_error(cv, &error.to_string()).await;
                None
            }
            None => {
                self.clone()
                    .send_tauth_error(cv, "missing session token")
                    .await;
                None
            }
        }
    }

    async fn signed_tauth_locator(&self, user_id: i64) -> Result<String, String> {
        let config = CONFIG.load();
        let target_iota_id = config
            .iota_id
            .ok_or_else(|| "Iota ID is unavailable".to_string())?;
        let omikron_id = config
            .omikron_id
            .ok_or_else(|| "Omikron ID is unavailable".to_string())?;
        let host = config
            .omikron_host
            .as_deref()
            .ok_or_else(|| "Omikron host is unavailable".to_string())?;
        let port = config
            .omikron_port
            .ok_or_else(|| "Omikron port is unavailable".to_string())?;
        let omikron_key = mtp::files::load_public_key_bundle(&omikron_public_key_path(omikron_id))
            .map_err(|error| error.to_string())?;
        let omikron_public_key = omikron_key
            .try_to_base64()
            .map_err(|error| error.to_string())?;
        let keyring = self
            .keyring
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| "Iota keyring is unavailable".to_string())?;
        let iota_public_key = keyring
            .public_key_bundle()
            .try_to_base64()
            .map_err(|error| error.to_string())?;
        let principal = iota_storage::tauth::canonical_principal(user_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "canonical principal is unavailable".to_string())?;
        let omikron_url = format!("https://{host}:{port}");
        let issued_at = iota_storage::tauth::now_seconds();
        let unsigned = TAuthLocatorUnsigned {
            version: 1,
            principal: &principal,
            omikron_url: &omikron_url,
            omikron_public_key: &omikron_public_key,
            target_iota_id,
            iota_public_key: &iota_public_key,
            issued_at,
        };
        let signer =
            Ed25519Signer::new(&keyring.sig_cl_secret_key).map_err(|error| error.to_string())?;
        let signature = STANDARD.encode(
            signer
                .sign(&serde_json::to_vec(&unsigned).unwrap())
                .map_err(|error| error.to_string())?,
        );
        serde_json::to_string(&TAuthLocator {
            version: 1,
            principal: &principal,
            omikron_url: &omikron_url,
            omikron_public_key: &omikron_public_key,
            target_iota_id,
            iota_public_key: &iota_public_key,
            issued_at,
            signature,
        })
        .map_err(|error| error.to_string())
    }

    async fn signed_tauth_home_node(&self) -> Result<serde_json::Value, String> {
        let config = CONFIG.load();
        let host = config
            .omikron_host
            .as_deref()
            .ok_or_else(|| "Omikron host is unavailable".to_string())?;
        let port = config
            .omikron_port
            .ok_or_else(|| "Omikron port is unavailable".to_string())?;
        let relay =
            AuthorityLocator::new(format!("{host}:{port}")).map_err(|error| error.to_string())?;
        let identity = self
            .load_or_migrate_keyring()
            .await
            .map_err(|error| error.to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let descriptor = iota_storage::node_directory::SqliteNodeDirectory
            .ensure_local_descriptor(&identity, Vec::new(), vec![relay], now)
            .map_err(|error| error.to_string())?
            .to_wire_v1()
            .map_err(|error| error.to_string())?;
        serde_json::to_value(descriptor).map_err(|error| error.to_string())
    }

    async fn send_tauth_empty(self: Arc<Self>, cv: &CommunicationValue, kind: CommunicationType) {
        let _ = self
            .send_message(&CommunicationValue::new(kind).with_request_id(cv))
            .await;
    }

    async fn send_tauth_json(
        self: Arc<Self>,
        cv: &CommunicationValue,
        kind: CommunicationType,
        json: String,
    ) {
        let response = CommunicationValue::new(kind)
            .with_request_id(cv)
            .add_typed_default(DataType::Json, DataValue::Str(json));
        let _ = self.send_message(&response).await;
    }

    async fn send_tauth_error(self: Arc<Self>, cv: &CommunicationValue, message: &str) {
        let response = error_response(cv, CommunicationType::ErrorInvalidData)
            .add_typed_default(DataType::Message, DataValue::Str(message.to_owned()));
        let _ = self.send_message(&response).await;
    }

    async fn handle_account_state_request(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_account_state_request(cv);
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok());
        if response.is_type(CommunicationType::AccountStateSnapshot) {
            log!("AccountStateSnapshot user={:?} stage=generated", user_id);
            if let Some(user_id) = user_id
                && let Err(error) = relay_queue::pause_client_deliveries(user_id)
            {
                log!("Pending Relay state-sync pause failed: {}", error);
            }

            if let Err(error) = self.send_message(&response).await {
                log!(
                    "Initial AccountStateSnapshot delivery failed for user {:?}: {}",
                    user_id,
                    error
                );
            } else {
                log!(
                    "AccountStateSnapshot user={:?} stage=sent_to_omikron",
                    user_id
                );
            }
            return;
        }

        if let Err(error) = self.send_message(&response).await {
            log!("AccountStateRequest response delivery failed: {}", error);
        }
    }

    async fn handle_account_state_applied(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_account_state_applied(cv);
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok());
        if self.send_message(&response).await.is_ok()
            && response.is_type(CommunicationType::Success)
            && let Some(user_id) = user_id
        {
            if let Err(error) = relay_queue::resume_client_deliveries(user_id) {
                log!("Pending Relay client resume failed: {}", error);
            } else {
                self.flush_pending_relays_for_user(Some(user_id)).await;
            }
        }
    }

    async fn handle_read_notification(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_read_notification(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    fn mutation_live_message(
        ty: CommunicationType,
        request: &CommunicationValue,
        mutation: &message_handlers::MessageMutation,
        extra: Vec<(DataType, DataValue)>,
    ) -> CommunicationValue {
        let mut message = CommunicationValue::new(ty)
            .with_request_id(request)
            .with_sender(wire_user_id(mutation.sender_id))
            .with_receiver(wire_user_id(mutation.partner_id))
            .add_typed_default(
                DataType::ChatPartnerId,
                DataValue::SignedNumber(mutation.sender_id as i128),
            )
            .add_typed_default(
                DataType::SendTime,
                DataValue::SignedNumber(mutation.send_time as i128),
            );
        for (data_type, value) in extra {
            message = message.add_typed_default(data_type, value);
        }
        message
    }

    async fn persist_and_deliver_remote_edit(&self, cv: &CommunicationValue) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let receiver_id = match cv
            .require_receiver()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(receiver_id) if receiver_id > 0 => receiver_id,
            _ => return,
        };
        let Some(send_time) = data_i64(cv, DataType::SendTime).filter(|time| *time > 0) else {
            return;
        };
        let Some(content) = cv.get_data(DataType::Content).as_str() else {
            return;
        };
        if chat_files::apply_remote_edit(receiver_id, sender_id, send_time, sender_id, content)
            .is_ok()
        {
            let _ = self.send_message(cv).await;
        }
    }

    async fn persist_and_deliver_remote_reaction(&self, cv: &CommunicationValue, add: bool) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let receiver_id = match cv
            .require_receiver()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(receiver_id) if receiver_id > 0 => receiver_id,
            _ => return,
        };
        let Some(send_time) = data_i64(cv, DataType::SendTime).filter(|time| *time > 0) else {
            return;
        };
        let Some(reaction) = cv.get_data(DataType::Reaction).as_str() else {
            return;
        };
        if reaction.is_empty() || reaction.len() > 64 {
            return;
        }
        let result = if add {
            chat_files::add_reaction(receiver_id, sender_id, send_time, sender_id, reaction)
        } else {
            chat_files::remove_reaction(receiver_id, sender_id, send_time, sender_id, reaction)
        };
        if result.is_ok() {
            let _ = self.send_message(cv).await;
        }
    }

    async fn persist_and_deliver_remote_delete(&self, cv: &CommunicationValue) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let receiver_id = match cv
            .require_receiver()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(receiver_id) if receiver_id > 0 => receiver_id,
            _ => return,
        };
        let Some(send_time) = data_i64(cv, DataType::SendTime).filter(|time| *time > 0) else {
            return;
        };
        if chat_files::apply_remote_delete(receiver_id, sender_id, send_time, sender_id).is_ok() {
            let _ = self.send_message(cv).await;
        }
    }

    async fn handle_message_edit(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_message_edit(cv);
        if !response.is_type(CommunicationType::Success) {
            let _ = self.send_message(&response).await;
            return;
        }
        let Ok(mutation) = message_handlers::message_mutation(cv) else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let Some(content) = cv.get_data(DataType::Content).as_str() else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let live = Self::mutation_live_message(
            CommunicationType::MessageEditLive,
            cv,
            &mutation,
            vec![(DataType::Content, DataValue::Str(content.to_string()))],
        );
        let partner_is_local =
            match iota_storage::users::user_manager::get_user(mutation.partner_id) {
                Ok(user) => user.is_some(),
                Err(_) => {
                    let _ = self
                        .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                        .await;
                    return;
                }
            };
        if partner_is_local
            && chat_files::apply_remote_edit(
                mutation.partner_id,
                mutation.sender_id,
                mutation.send_time,
                mutation.sender_id,
                content,
            )
            .is_err()
        {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorNotFound))
                .await;
            return;
        }
        let _ = self.send_message(&response).await;
        let _ = self.send_message(&live).await;
    }

    async fn handle_message_edit_live(self: Arc<Self>, cv: &CommunicationValue) {
        self.persist_and_deliver_remote_edit(cv).await;
    }

    async fn handle_message_reaction_add(self: Arc<Self>, cv: &CommunicationValue) {
        self.handle_message_reaction(cv, true).await;
    }

    async fn handle_message_reaction_remove(self: Arc<Self>, cv: &CommunicationValue) {
        self.handle_message_reaction(cv, false).await;
    }

    async fn handle_message_reaction(self: Arc<Self>, cv: &CommunicationValue, add: bool) {
        let response = message_handlers::handle_message_reaction(cv, add);
        if !response.is_type(CommunicationType::Success) {
            let _ = self.send_message(&response).await;
            return;
        }
        let Ok(mutation) = message_handlers::message_mutation(cv) else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let Some(reaction) = cv.get_data(DataType::Reaction).as_str() else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let live = Self::mutation_live_message(
            CommunicationType::MessageReactionLive,
            cv,
            &mutation,
            vec![
                (DataType::Reaction, DataValue::Str(reaction.to_string())),
                (
                    DataType::SenderId,
                    DataValue::SignedNumber(mutation.sender_id as i128),
                ),
                (DataType::Accepted, DataValue::Bool(add)),
            ],
        );
        let partner_is_local =
            match iota_storage::users::user_manager::get_user(mutation.partner_id) {
                Ok(user) => user.is_some(),
                Err(_) => {
                    let _ = self
                        .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                        .await;
                    return;
                }
            };
        if partner_is_local {
            let result = if add {
                chat_files::add_reaction(
                    mutation.partner_id,
                    mutation.sender_id,
                    mutation.send_time,
                    mutation.sender_id,
                    reaction,
                )
            } else {
                chat_files::remove_reaction(
                    mutation.partner_id,
                    mutation.sender_id,
                    mutation.send_time,
                    mutation.sender_id,
                    reaction,
                )
            };
            if result.is_err() {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorNotFound))
                    .await;
                return;
            }
        }
        let _ = self.send_message(&response).await;
        let _ = self.send_message(&live).await;
    }

    async fn handle_message_reaction_live(self: Arc<Self>, cv: &CommunicationValue) {
        let add = cv.get_data(DataType::Accepted).as_bool().unwrap_or(true);
        self.persist_and_deliver_remote_reaction(cv, add).await;
    }

    async fn handle_message_delete_live(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let sender_is_local = match iota_storage::users::user_manager::get_user(sender_id) {
            Ok(user) => user.is_some(),
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                    .await;
                return;
            }
        };
        if !sender_is_local {
            self.persist_and_deliver_remote_delete(cv).await;
            return;
        }

        let response = message_handlers::handle_message_delete(cv);
        if !response.is_type(CommunicationType::Success) {
            let _ = self.send_message(&response).await;
            return;
        }
        let Ok(mutation) = message_handlers::message_mutation(cv) else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let live = Self::mutation_live_message(
            CommunicationType::MessageDeleteLive,
            cv,
            &mutation,
            Vec::new(),
        );
        let partner_is_local =
            match iota_storage::users::user_manager::get_user(mutation.partner_id) {
                Ok(user) => user.is_some(),
                Err(_) => {
                    let _ = self
                        .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                        .await;
                    return;
                }
            };
        if partner_is_local
            && chat_files::apply_remote_delete(
                mutation.partner_id,
                mutation.sender_id,
                mutation.send_time,
                mutation.sender_id,
            )
            .is_err()
        {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorNotFound))
                .await;
            return;
        }
        let _ = self.send_message(&response).await;
        let _ = self.send_message(&live).await;
    }

    async fn handle_messages_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_messages_get(cv))
            .await;
    }

    async fn handle_message_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_message_get(cv))
            .await;
    }

    async fn handle_get_chats(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_chats(cv))
            .await;
    }

    async fn handle_add_community(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_add_community(cv))
            .await;
    }

    async fn handle_get_communities(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_communities(cv))
            .await;
    }

    async fn handle_remove_community(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_remove_community(cv))
            .await;
    }

    async fn handle_global_settings_save(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_global_settings_save(cv))
            .await;
    }

    async fn handle_global_settings_load(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_global_settings_load(cv))
            .await;
    }

    async fn handle_settings_save(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_settings_save(cv, 0))
            .await;
    }

    async fn handle_settings_load(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_settings_load(cv, 0))
            .await;
    }

    async fn handle_settings_list(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_settings_list(cv, 0))
            .await;
    }

    async fn handle_synced_setting_set(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_synced_setting_set(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_synced_setting_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_synced_setting_get(cv))
            .await;
    }

    async fn handle_synced_setting_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_synced_setting_delete(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_synced_settings_list(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_synced_settings_list(cv))
            .await;
    }

    async fn handle_user_blob_put(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_blob_put(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_user_blob_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_user_blob_get(cv))
            .await;
    }

    async fn handle_user_blob_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_blob_delete(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_user_blob_list(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_user_blob_list(cv))
            .await;
    }

    async fn handle_user_asset_upload_start(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_start).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    async fn handle_user_asset_upload_chunk(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_chunk).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    async fn handle_user_asset_upload_status(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_status).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    async fn handle_user_asset_upload_commit(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_commit).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let mutation = result;
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_user_asset_upload_abort(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_abort).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    async fn handle_user_asset_get_chunk(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_get_chunk).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    async fn handle_user_asset_list(self: Arc<Self>, cv: &CommunicationValue) {
        let result = match run_asset_handler(cv, message_handlers::handle_user_asset_list).await {
            Ok(result) => result,
            Err(response) => {
                let _ = self.send_message(&response).await;
                return;
            }
        };
        let _ = self.send_message(&result).await;
    }

    async fn handle_user_asset_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let result = match run_asset_handler(cv, message_handlers::handle_user_asset_delete).await {
            Ok(result) => result,
            Err(response) => {
                let _ = self.send_message(&response).await;
                return;
            }
        };
        let mutation = result;
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_user_block(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_block(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_user_unblock(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_unblock(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_blocked_users_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_blocked_users_get(cv))
            .await;
    }

    async fn handle_receipt_policy_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_receipt_policy_get(cv))
            .await;
    }

    async fn handle_receipt_policy_set(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_receipt_policy_set(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_message_storage_policy_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_message_storage_policy_get(cv))
            .await;
    }

    async fn handle_message_storage_policy_set(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_message_storage_policy_set(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    async fn handle_user_block_check(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_user_block_check(cv))
            .await;
    }

    async fn handle_call_contact_check(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_call_contact_check(cv))
            .await;
    }

    async fn handle_call_envelope_store(self: Arc<Self>, cv: &CommunicationValue) {
        let response = match CONFIG
            .load()
            .omikron_id
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(owner) => message_handlers::handle_call_envelope_store(cv, owner),
            None => error_response(cv, CommunicationType::ErrorInternal),
        };
        let _ = self.send_message(&response).await;
    }

    async fn handle_call_envelope_get(self: Arc<Self>, cv: &CommunicationValue) {
        let response = match CONFIG
            .load()
            .omikron_id
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(owner) => message_handlers::handle_call_envelope_get(cv, owner),
            None => error_response(cv, CommunicationType::ErrorInternal),
        };
        let _ = self.send_message(&response).await;
    }

    async fn handle_call_contact_accept(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_call_contact_accept(cv))
            .await;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    pub async fn send_message(&self, cv: &CommunicationValue) -> Result<(), String> {
        let sender_guard = self.sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
            if !sender.is_open() {
                log_event!(
                    PrintType::Omikron,
                    LogLevel::Warn,
                    "omikron.send_failed",
                    "connection_id={} message_id={:?} message_type={} reason=connection_closed",
                    self.connection_id,
                    cv.id(),
                    cv.get_type_name().unwrap_or("unknown")
                );
                drop(sender_guard);
                if let Some(sender) = self.sender.write().await.take() {
                    sender.close().await;
                }
                self.fail_all_waiting_tasks(format!(
                    "Send failed: connection closed (connection_id={})",
                    self.connection_id
                ))
                .await;
                return Err("connection closed".to_string());
            }

            let sender_clone = Arc::clone(sender);
            drop(sender_guard);

            log_cv_out!(cv);

            if let Err(e) = sender_clone.send(cv).await {
                log_event!(
                    PrintType::Omikron,
                    LogLevel::Error,
                    "omikron.send_failed",
                    "connection_id={} message_id={:?} message_type={} error={}",
                    self.connection_id,
                    cv.id(),
                    cv.get_type_name().unwrap_or("unknown"),
                    e
                );
                self.fail_all_waiting_tasks(format!(
                    "Send failed: {} (connection_id={})",
                    e, self.connection_id
                ))
                .await;
                return Err(e.to_string());
            }

            Ok(())
        } else {
            log_event!(
                PrintType::Omikron,
                LogLevel::Debug,
                "omikron.send_skipped",
                "connection_id={} message_id={:?} message_type={} reason=not_connected",
                self.connection_id,
                cv.id(),
                cv.get_type_name().unwrap_or("unknown")
            );
            Err("not connected".to_string())
        }
    }

    async fn fail_all_waiting_tasks(&self, reason: String) {
        let keys: Vec<u32> = WAITING_TASKS.iter().map(|entry| *entry.key()).collect();

        for key in keys {
            if let Some((_, waiting_task)) = WAITING_TASKS.remove(&key) {
                let response = CommunicationValue::new(CommunicationType::ErrorInternal)
                    .with_id(key)
                    .add_typed_default(DataType::Message, DataValue::Str(reason.clone()));
                let _ = (waiting_task.task)(response);
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.state.read().await.is_connected()
    }

    pub async fn is_identified(&self) -> bool {
        self.state.read().await.is_identified()
    }

    pub async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let (tx, rx) = oneshot::channel();
        let msg_id = cv
            .require_id()
            .map_err(|error| format!("cannot await response without a message id: {error}"))?;

        WAITING_TASKS.insert(
            msg_id,
            WaitingTask {
                task: Box::new(move |response_cv| {
                    let _ = tx.send(response_cv);
                    true
                }),
                inserted_at: Instant::now(),
            },
        );

        if let Err(send_err) = self.send_message(cv).await {
            WAITING_TASKS.remove(&msg_id);
            return Err(format!(
                "Request send failed (msg_id={}, reason={})",
                msg_id, send_err
            ));
        }

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response_cv)) => {
                let is_error = response_cv.is_type(CommunicationType::Error)
                    || response_cv.is_type(CommunicationType::ErrorInternal)
                    || response_cv.is_type(CommunicationType::ErrorNotFound)
                    || response_cv.is_type(CommunicationType::ErrorInvalidData)
                    || response_cv.is_type(CommunicationType::ErrorInvalidChallenge)
                    || response_cv.is_type(CommunicationType::ErrorNotAuthenticated);
                if is_error {
                    let reason = response_cv
                        .get_data(DataType::Message)
                        .as_str()
                        .or_else(|| response_cv.get_data(DataType::ErrorType).as_str())
                        .unwrap_or("connection error")
                        .to_string();
                    let rejection_kind = if response_cv.is_type(CommunicationType::ErrorNotFound) {
                        "not_found"
                    } else {
                        "other"
                    };
                    Err(format!(
                        "Request rejected (kind={rejection_kind}, msg_id={msg_id}, reason={reason})"
                    ))
                } else {
                    Ok(response_cv)
                }
            }
            Ok(Err(_)) => {
                WAITING_TASKS.remove(&msg_id);
                Err("Channel closed while awaiting response".to_string())
            }
            Err(_) => {
                let waiting_tasks_len = WAITING_TASKS.len();
                WAITING_TASKS.remove(&msg_id);
                Err(format!(
                    "Request timed out (msg_id={}, timeout={}s, connected={}, waiting_tasks={})",
                    msg_id,
                    timeout.as_secs(),
                    self.is_connected().await,
                    waiting_tasks_len
                ))
            }
        }
    }

    async fn await_relay_response(
        &self,
        cv: &CommunicationValue,
        timeout: Duration,
    ) -> Result<CommunicationValue, String> {
        let (tx, rx) = oneshot::channel();
        let msg_id = cv.require_id().map_err(|error| error.to_string())?;
        WAITING_TASKS.insert(
            msg_id,
            WaitingTask {
                task: Box::new(move |response| {
                    let _ = tx.send(response);
                    true
                }),
                inserted_at: Instant::now(),
            },
        );
        if let Err(error) = self.send_message(cv).await {
            WAITING_TASKS.remove(&msg_id);
            return Err(format!("Relay send failed: {error}"));
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                WAITING_TASKS.remove(&msg_id);
                Err("Relay response channel closed".into())
            }
            Err(_) => {
                WAITING_TASKS.remove(&msg_id);
                Err("Relay response timed out".into())
            }
        }
    }

    pub async fn await_connection(&self, timeout_duration: Option<Duration>) -> Result<(), String> {
        let mut rx = self.state_watch_tx.subscribe();
        if rx.borrow().is_connected() {
            return Ok(());
        }

        let timeout = timeout_duration.unwrap_or(CONNECTION_TIMEOUT);

        let result: Result<(), String> = tokio::time::timeout(timeout, async {
            loop {
                rx.changed()
                    .await
                    .map_err(|_| "State watch channel closed".to_string())?;
                if rx.borrow().is_connected() {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| {
            format!(
                "Connection not established within {} seconds",
                timeout.as_secs()
            )
        })?;

        result
    }

    pub async fn has_auth_failure(&self) -> bool {
        self.auth_failure.read().await.is_some()
    }

    pub async fn get_auth_failure(&self) -> Option<String> {
        self.auth_failure.read().await.clone()
    }

    pub async fn clear_auth_failure(&self) {
        *self.auth_failure.write().await = None;
    }

    pub async fn reconnect(self: &Arc<Self>) {
        self.clear_auth_failure().await;
        *self.reconnect_on_close.write().await = true;
        self.stop().await;
        self.connect().await;
    }

    /// Create a new local keyring and register it as a new Iota identity.
    /// The existing keyring is retained as a timestamped backup so a failed
    /// recovery does not silently destroy the user's previous identity.
    pub async fn rotate_identity(self: &Arc<Self>) -> Result<(), OmikronError> {
        log!("Iota identity rotation requested");
        self.stop().await;

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
        OmikronConnection::stop(self).await
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

impl iota_connection::relay_service::LegacyRelayIdentity for OmikronConnection {
    fn legacy_iota_id(&self) -> Option<u64> {
        CONFIG.load().iota_id
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
        Self::await_response(self, value, Some(timeout))
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
        let this = Arc::new(Self {
            state: self.state.clone(),
            state_watch_tx: self.state_watch_tx.clone(),
            sender: self.sender.clone(),
            connection_loop_handle: self.connection_loop_handle.clone(),
            last_ping: self.last_ping.clone(),
            maintenance_handle: self.maintenance_handle.clone(),
            connection_id: self.connection_id,
            shutdown_tx: self.shutdown_tx.clone(),
            reconnect_on_close: self.reconnect_on_close.clone(),
            auth_failure: self.auth_failure.clone(),
            keyring: self.keyring.clone(),
            http_client: self.http_client.clone(),
            session_manager: self.session_manager.clone(),
            password_auth: self.password_auth.clone(),
            handler_semaphore: self.handler_semaphore.clone(),
            cancellation: self.cancellation.clone(),
            active_tasks: self.active_tasks.clone(),
            app: self.app.clone(),
            invitation_sync: self.invitation_sync.clone(),
            relay_service: self.relay_service.clone(),
        });
        Self::reconnect(&this).await;
        Ok(())
    }

    async fn rotate_identity(&self) -> Result<(), OmikronError> {
        let this = Arc::new(Self {
            state: self.state.clone(),
            state_watch_tx: self.state_watch_tx.clone(),
            sender: self.sender.clone(),
            connection_loop_handle: self.connection_loop_handle.clone(),
            last_ping: self.last_ping.clone(),
            maintenance_handle: self.maintenance_handle.clone(),
            connection_id: self.connection_id,
            shutdown_tx: self.shutdown_tx.clone(),
            reconnect_on_close: self.reconnect_on_close.clone(),
            auth_failure: self.auth_failure.clone(),
            keyring: self.keyring.clone(),
            http_client: self.http_client.clone(),
            session_manager: self.session_manager.clone(),
            password_auth: self.password_auth.clone(),
            handler_semaphore: self.handler_semaphore.clone(),
            cancellation: self.cancellation.clone(),
            active_tasks: self.active_tasks.clone(),
            app: self.app.clone(),
            invitation_sync: self.invitation_sync.clone(),
            relay_service: self.relay_service.clone(),
        });
        Self::rotate_identity(&this).await
    }

    async fn is_connected(&self) -> bool {
        Self::is_connected(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn damaged_password_setup_does_not_invalidate_iota_identity() {
        let directory = test_path("password-isolation");
        fs::create_dir(&directory).unwrap();
        let identity_path = directory.join("identity.keyring");
        let identity = load_or_migrate_keyring_at(&identity_path, None).unwrap();
        fs::write(
            identity_path.with_file_name("password-auth.setup"),
            b"corrupt setup",
        )
        .unwrap();
        let connection = OmikronConnection::new(
            Arc::new(DashSet::new()),
            Arc::new(std::sync::Mutex::new(AppState::new())),
        );
        *connection.keyring.write().await = Some(identity.keyring());
        connection.initialize_password_auth(&identity_path);
        assert!(connection.keyring.read().await.is_some());
        assert!(connection.password_auth.setup().is_err());
        assert_eq!(
            fs::read(identity_path.with_file_name("password-auth.setup")).unwrap(),
            b"corrupt setup"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    fn test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "iota-identity-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ))
    }

    #[test]
    fn generated_identity_is_unprotected_and_survives_reload() {
        let path = test_path("reload");
        let identity = load_or_migrate_keyring_at(&path, None).expect("identity saves");
        let reloaded = load_or_migrate_keyring_at(&path, None).expect("identity loads");
        assert_eq!(
            identity
                .keyring()
                .try_to_bytes()
                .expect("keyring serializes"),
            reloaded
                .keyring()
                .try_to_bytes()
                .expect("keyring serializes")
        );
        assert!(mtp::files::load_keyring_raw(&path).is_ok());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn corrupt_existing_identity_does_not_generate_a_replacement() {
        let path = test_path("corrupt");
        fs::write(&path, b"not a keyring").expect("corrupt fixture writes");
        let error =
            load_or_migrate_keyring_at(&path, None).expect_err("corrupt identity must fail");
        assert!(matches!(
            error,
            iota_identity::LocalNodeIdentityError::Storage { .. }
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn legacy_raw_identity_is_loaded_only_when_the_raw_format_is_valid() {
        let path = test_path("legacy");
        let keyring = crypto_helper::generate_keyring();
        let mut raw = b"MTMK".to_vec();
        raw.push(1);
        raw.extend_from_slice(&keyring.try_to_bytes().expect("keyring serializes"));
        fs::write(&path, raw).expect("legacy fixture writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("legacy fixture is owner-only");
        }

        let migrated = load_or_migrate_keyring_at(&path, None).expect("legacy identity loads");
        assert_eq!(
            migrated
                .keyring()
                .try_to_bytes()
                .expect("keyring serializes"),
            keyring.try_to_bytes().expect("keyring serializes")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identity_directory_failure_is_returned() {
        let parent = test_path("parent-file");
        fs::write(&parent, b"not a directory").expect("parent fixture writes");
        let path = parent.join("iota.mk");
        let error = load_or_migrate_keyring_at(&path, None)
            .expect_err("directory failure must be returned");
        assert!(matches!(
            error,
            iota_identity::LocalNodeIdentityError::Directory { .. }
        ));
        let _ = fs::remove_file(parent);
    }

    #[test]
    fn reconnect_jitter_stays_bounded_by_the_exponential_delay_ceiling() {
        for _ in 0..32 {
            let delay = jittered_reconnect_delay(Duration::from_secs(5));
            assert!(delay >= Duration::from_secs(4));
            assert!(delay <= Duration::from_secs(6));
        }

        assert!(jittered_reconnect_delay(Duration::from_secs(600)) <= MAX_RECONNECT_DELAY);
    }

    #[test]
    fn per_omikron_trust_paths_do_not_collide() {
        assert_ne!(omikron_public_key_path(1), omikron_public_key_path(2));
    }

    #[test]
    fn not_found_response_is_preserved_for_callers() {
        let error = map_await_response_error(
            "Request rejected (kind=not_found, msg_id=1, reason=connection error)".into(),
        );

        assert!(matches!(
            error,
            OmikronError::Rejected(CommunicationType::ErrorNotFound, _)
        ));
    }

    #[test]
    fn omega_invitation_snapshot_parser_requires_authoritative_fields() {
        let type_map = TypeMap::latest();
        let mut fields = Vec::new();
        for (kind, value) in [
            (
                DataType::InvitationAuthority,
                DataValue::Str("omega".into()),
            ),
            (DataType::InvitationId, DataValue::SignedNumber(7)),
            (DataType::IotaId, DataValue::SignedNumber(42)),
            (DataType::InvitationRevision, DataValue::SignedNumber(3)),
            (
                DataType::InvitationState,
                DataValue::Str("provisioning".into()),
            ),
            (DataType::InvitationCreatedAt, DataValue::SignedNumber(10)),
            (DataType::InvitationExpiresAt, DataValue::SignedNumber(20)),
            (
                DataType::InvitationPasswordProtected,
                DataValue::Bool(false),
            ),
        ] {
            fields.push((kind.try_to_id(&type_map).expect("type is mapped"), value));
        }
        let parsed = parse_omega_invitation(&fields, &type_map, 42, 20).expect("snapshot parses");
        assert_eq!(parsed.invitation_id, 7);
        assert_eq!(parsed.remote_revision, 3);
        assert_eq!(
            parsed.authority,
            iota_storage::users::invitations::InvitationAuthority::Omega
        );

        fields.retain(|(id, _)| Some(*id) != DataType::InvitationRevision.try_to_id(&type_map));
        assert!(parse_omega_invitation(&fields, &type_map, 42, 20).is_err());
    }

    #[test]
    fn omega_control_target_requires_signed_local_iota_id() {
        let matching = CommunicationValue::new(CommunicationType::ProvisionIotaUser)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(42));
        let wrong = CommunicationValue::new(CommunicationType::EraseHostedUserData)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(43));
        let unsigned = CommunicationValue::new(CommunicationType::EraseHostedUserData)
            .add_typed_default(DataType::IotaId, DataValue::UnsignedNumber(42));
        assert!(targets_iota(&matching, Some(42)));
        assert!(!targets_iota(&wrong, Some(42)));
        assert!(!targets_iota(&unsigned, Some(42)));
        assert!(!targets_iota(&matching, None));
    }

    #[test]
    fn omega_invitation_snapshot_parser_rejects_wrong_authority_or_iota() {
        let type_map = TypeMap::latest();
        let fields = [
            (DataType::InvitationAuthority, DataValue::Str("iota".into())),
            (DataType::InvitationId, DataValue::SignedNumber(7)),
            (DataType::IotaId, DataValue::SignedNumber(42)),
            (DataType::InvitationRevision, DataValue::SignedNumber(3)),
            (DataType::InvitationState, DataValue::Str("pending".into())),
            (DataType::InvitationCreatedAt, DataValue::SignedNumber(10)),
            (DataType::InvitationExpiresAt, DataValue::SignedNumber(20)),
            (
                DataType::InvitationPasswordProtected,
                DataValue::Bool(false),
            ),
        ]
        .into_iter()
        .map(|(kind, value)| (kind.try_to_id(&type_map).expect("type is mapped"), value))
        .collect::<Vec<_>>();

        assert!(parse_omega_invitation(&fields, &type_map, 42, 20).is_err());

        let mut fields = fields;
        let authority_id = DataType::InvitationAuthority
            .try_to_id(&type_map)
            .expect("type is mapped");
        let authority = fields
            .iter_mut()
            .find(|(id, _)| *id == authority_id)
            .expect("authority field exists");
        authority.1 = DataValue::Str("omega".into());
        assert!(parse_omega_invitation(&fields, &type_map, 43, 20).is_err());
    }

    #[test]
    fn invitation_action_retry_delay_backs_off_and_caps() {
        assert_eq!(
            next_invitation_retry_delay(Duration::from_secs(5)),
            Duration::from_secs(10)
        );
        assert_eq!(
            next_invitation_retry_delay(Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }
}
