use dashmap::{DashMap, DashSet};
use iota_logger::{log, log_cv_in, log_cv_out, log_t};
use iota_state::AppState;
use iota_storage::util::config_util::{CONFIG, modify_config};
use iota_storage::util::relay_replay;
use iota_storage::util::{
    chat_files, chats_util, client_relay_delivery, outgoing_relay, relay_queue,
};
use iota_util::crypto_helper::{self, keyring_from_base64};
use iota_util::crypto_util::{self};
use mtp::client::{Client, ClientConfig, MTPConnection, Policy, SendMode, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::{Keyring, PublicKeyBundle};
use rand_core::RngCore;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, Semaphore, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::client::{OmikronClient, OmikronError};
use crate::omega_discovery;

use iota_connection::message_common::*;
use iota_connection::message_handlers;
use iota_connection::relay::{
    RelayValidationError, forward_verified_relay, open_verified_relay_content,
    verify_relay_metadata,
};
use iota_util::route_target::RouteTarget;

// ============================================================================
// Configuration
// ============================================================================

const IOTA_KEYRING_PATH: &str = "iota.mk";
static IDENTITY_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
static OMIKRON_TRUST_DIRECTORY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
static NEXT_CLIENT_EVENT_ID: AtomicU32 = AtomicU32::new(1);

fn next_client_event_id() -> u32 {
    NEXT_CLIENT_EVENT_ID.fetch_add(1, Ordering::Relaxed).max(1)
}

fn record_origin_delivery_failure(signer_id: u64, relay_message_id: &str, failure: &str) {
    let Ok(storage_owner) = i64::try_from(signer_id) else {
        return;
    };
    if let Err(error) = chat_files::record_delivery_failure(
        storage_owner,
        storage_owner,
        relay_message_id,
        failure,
        now_millis_i64(),
    ) {
        log!("Relay delivery failure storage failed: {error}");
    }
}

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
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const TASK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_HANDLERS: usize = 20;
const RELAY_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;

struct ResolvedOmikronEndpoint {
    id: Option<i64>,
    host: String,
    port: u16,
    public_key: PublicKeyBundle,
}

#[derive(Debug)]
pub enum IdentityError {
    Storage(mtp::files::FileError),
    Directory(std::io::Error),
    InvalidLegacyIdentity,
    Verification(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "identity storage error: {error}"),
            Self::Directory(error) => write!(f, "unable to create identity directory: {error}"),
            Self::InvalidLegacyIdentity => f.write_str("legacy identity is invalid"),
            Self::Verification(error) => {
                write!(f, "persisted identity could not be verified: {error}")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

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

/*
 * The identity is stored in the Iota state directory as raw keyring bytes so
 * daemon restarts do not depend on a separately managed passphrase.
 */
fn save_keyring_verified(keyring: &Keyring, path: &Path) -> Result<(), IdentityError> {
    mtp::files::save_keyring_raw(keyring, path).map_err(IdentityError::Storage)?;
    let persisted = mtp::files::load_keyring_raw(path).map_err(IdentityError::Storage)?;
    let expected = keyring
        .try_to_bytes()
        .map_err(|error| IdentityError::Verification(error.to_string()))?;
    let actual = persisted
        .try_to_bytes()
        .map_err(|error| IdentityError::Verification(error.to_string()))?;
    if expected != actual {
        return Err(IdentityError::Verification(
            "persisted keyring differs from the requested identity".into(),
        ));
    }
    Ok(())
}

fn load_or_migrate_keyring_at(
    path: &Path,
    legacy: Option<String>,
) -> Result<Keyring, IdentityError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(IdentityError::Directory)?;
    }

    match mtp::files::load_keyring_raw(path) {
        Ok(keyring) => return Ok(keyring),
        Err(mtp::files::FileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(IdentityError::Storage(error)),
    }

    let keyring = match legacy {
        Some(encoded) => {
            keyring_from_base64(&encoded).ok_or(IdentityError::InvalidLegacyIdentity)?
        }
        None => {
            log!(
                "No existing Iota identity found at {}; generating a new identity",
                path.display()
            );
            crypto_helper::generate_keyring()
        }
    };

    save_keyring_verified(&keyring, path)?;
    Ok(keyring)
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
    keyring: Arc<RwLock<Option<Arc<Keyring>>>>,
    pub app_challenges: Arc<DashMap<u64, String>>,
    pub app_sessions: Arc<DashMap<u64, (i64, String)>>,
    handler_semaphore: Arc<Semaphore>,
    cancellation: CancellationToken,
    pub(crate) active_tasks: Arc<DashSet<String>>,
    pub(crate) app: Arc<std::sync::Mutex<AppState>>,
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
            app_challenges: Arc::new(DashMap::new()),
            app_sessions: Arc::new(DashMap::new()),
            handler_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDLERS)),
            cancellation,
            active_tasks,
            app,
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

    async fn connect_once(self: Arc<Self>) -> Result<ConnectionAttemptResult, String> {
        self.set_state(ConnectionState::Connecting).await;
        log_t!("omikron_connecting");

        let keyring = Arc::new(
            self.load_or_migrate_keyring()
                .await
                .map_err(|error| format!("Iota identity initialization failed: {error}"))?,
        );
        *self.keyring.write().await = Some(keyring.clone());

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

        // Start read loop
        let connection = Arc::new(connection);
        let read_self = self.clone();
        let read_connection = connection.clone();
        let read_handle = tokio::spawn(async move {
            read_self.read_loop(read_connection).await;
        });

        log_t!("omikron_authenticated");

        self.classify_legacy_pending_relays().await;

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

    async fn load_or_migrate_keyring(&self) -> Result<Keyring, IdentityError> {
        load_or_migrate_keyring_at(identity_path(), CONFIG.load().keyring.clone())
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
                            self_clone.handle_relay(cv).await;
                        });
                        continue;
                    }
                    let Some(msg_id) = cv.id() else {
                        let self_clone = self.clone();
                        tokio::spawn(async move {
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
            if let Err(error) = relay_replay::prune_completed(
                now_millis_i64().saturating_sub(RELAY_RETENTION_MILLIS),
            ) {
                log!("Relay replay cleanup failed: {}", error);
            }
        }
    }

    async fn resolve_relay_signing_keys(
        &self,
        signer_id: u64,
    ) -> Result<Vec<PublicKeyBundle>, RelayValidationError> {
        let signer_id_i64 = i64::try_from(signer_id).map_err(|_| {
            RelayValidationError::KeyLookup("signer ID exceeds local storage range".into())
        })?;
        let local_user = iota_storage::users::user_manager::get_user(signer_id_i64)
            .map_err(|error| RelayValidationError::KeyLookup(error.to_string()))?;
        if let Some(user) = local_user {
            let key = iota_util::crypto_helper::public_key_bundle_from_base64(&user.public_key)
                .ok_or_else(|| {
                    RelayValidationError::KeyLookup("stored user key is invalid".into())
                })?;
            return Ok(vec![key]);
        }

        let request = CommunicationValue::new(CommunicationType::GetUserData).add_typed_default(
            DataType::UserId,
            DataValue::UnsignedNumber(u128::from(signer_id)),
        );
        let response = self
            .await_response(&request, Some(Duration::from_secs(10)))
            .await
            .map_err(RelayValidationError::KeyLookup)?;
        if !response.is_type(CommunicationType::GetUserData) {
            return Err(RelayValidationError::KeyLookup(
                "Omega returned an unexpected user lookup response".into(),
            ));
        }
        let public_key = response
            .get_data(DataType::PublicKey)
            .and_then(|value| value.as_str())
            .ok_or_else(|| RelayValidationError::KeyLookup("Omega returned no user key".into()))?;
        let key = iota_util::crypto_helper::public_key_bundle_from_base64(public_key).ok_or_else(
            || RelayValidationError::KeyLookup("Omega returned an invalid user key".into()),
        )?;
        Ok(vec![key])
    }

    pub async fn hosting_iota_for_user(&self, user_id: u64) -> Result<u64, String> {
        let user_id_i64 = i64::try_from(user_id)
            .map_err(|_| "user ID exceeds local storage range".to_string())?;
        if iota_storage::users::user_manager::get_user(user_id_i64)
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return CONFIG
                .load()
                .iota_id
                .ok_or_else(|| "Iota identity is not configured".into());
        }

        let request = CommunicationValue::new(CommunicationType::GetUserData).add_typed_default(
            DataType::UserId,
            DataValue::UnsignedNumber(u128::from(user_id)),
        );
        let response = self
            .await_response(&request, Some(Duration::from_secs(10)))
            .await?;
        response
            .get_data(DataType::IotaId)
            .and_then(|value| value.as_number())
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| "Omega returned no hosting Iota for the user".into())
    }

    async fn send_relay_response(&self, frame_id: Option<u32>, response_type: CommunicationType) {
        if let Some(frame_id) = frame_id {
            let response = CommunicationValue::new(response_type).with_id(frame_id);
            if let Err(error) = self.send_message(&response).await {
                log!("Relay response could not be sent: {}", error);
            }
        }
    }

    async fn send_relay_success(
        &self,
        frame_id: Option<u32>,
        iota_id: u64,
        relay_message_id: &str,
        accepted_at: i64,
        include_origin_timestamp: bool,
    ) {
        let Some(frame_id) = frame_id else { return };
        let response = CommunicationValue::new(CommunicationType::Success)
            .with_id(frame_id)
            .add_typed_default(DataType::IotaId, DataValue::UnsignedNumber(iota_id.into()))
            .add_typed_default(
                DataType::RelayMessageId,
                DataValue::Str(relay_message_id.to_string()),
            )
            .add_typed_default(
                DataType::RelayAcceptedAt,
                DataValue::SignedNumber(accepted_at.into()),
            );
        let response = if include_origin_timestamp {
            response
                .add_typed_default(
                    DataType::OriginIotaReceivedAt,
                    DataValue::SignedNumber(accepted_at.into()),
                )
                .add_typed_default(
                    DataType::DestinationIotaReceivedAt,
                    DataValue::SignedNumber(accepted_at.into()),
                )
        } else {
            response
        };
        if let Err(error) = self.send_message(&response).await {
            log!("Relay response could not be sent: {}", error);
        }
    }

    fn client_event_from_relay(
        message_type: CommunicationType,
        payload: &DataValue,
        signer_id: u64,
        recipient_id: u64,
        relay_message_id: &str,
        accepted_at: i64,
    ) -> Option<CommunicationValue> {
        let sender = DataValue::UnsignedNumber(u128::from(signer_id));
        let receiver = recipient_id;
        let event_id = next_client_event_id();

        match message_type {
            CommunicationType::MessageSend => {
                let frame = CommunicationValue::new(CommunicationType::MessageSend)
                    .with_payload(payload.clone());
                let content = frame.get_data(DataType::Content)?.clone();
                let send_time = frame.get_data(DataType::SendTime)?.clone();
                let version = frame.get_data(DataType::VersionNumber)?.clone();
                let mut message = vec![
                    (DataType::Content, content),
                    (DataType::SendTime, send_time),
                    (DataType::VersionNumber, version),
                    (
                        DataType::RelayMessageId,
                        DataValue::Str(relay_message_id.to_string()),
                    ),
                    (DataType::MessageState, DataValue::Str("sent".to_string())),
                ];
                if let Some(reply_id) = frame.get_data(DataType::ReplyId) {
                    message.push((DataType::ReplyId, reply_id.clone()));
                }
                let mut event = CommunicationValue::new(CommunicationType::MessageLive)
                    .with_id(event_id)
                    .with_sender(signer_id)
                    .with_receiver(receiver)
                    .add_typed_default(DataType::SenderId, sender)
                    .add_typed_default(DataType::Message, typed_container(message))
                    .add_typed_default(
                        DataType::LastMessageAt,
                        DataValue::SignedNumber(accepted_at.into()),
                    );
                if let (Ok(owner), Ok(partner)) =
                    (i64::try_from(recipient_id), i64::try_from(signer_id))
                    && let Ok(Some(contact)) = chats_util::get_user(owner, partner)
                {
                    event = event.add_typed_default(
                        DataType::Notifications,
                        DataValue::SignedNumber(contact.notifications.into()),
                    );
                    if let Some(last_message_at) = contact.last_message_at {
                        event = event.add_typed_default(
                            DataType::LastMessageAt,
                            DataValue::SignedNumber(last_message_at.into()),
                        );
                    }
                }
                Some(event)
            }
            CommunicationType::SetChatSecret => {
                let frame = CommunicationValue::new(CommunicationType::SetChatSecret)
                    .with_payload(payload.clone());
                let chat_id = frame.get_data(DataType::ChatId)?.clone();
                let secret_id = frame.get_data(DataType::SecretId)?.clone();
                let version = frame.get_data(DataType::VersionNumber)?.clone();
                Some(
                    CommunicationValue::new(CommunicationType::ChatSecretForward)
                        .with_id(event_id)
                        .with_sender(signer_id)
                        .with_receiver(receiver)
                        .add_typed_default(DataType::ChatId, chat_id)
                        .add_typed_default(
                            DataType::SenderUserId,
                            DataValue::Str(signer_id.to_string()),
                        )
                        .add_typed_default(
                            DataType::RecipientUserId,
                            DataValue::Str(recipient_id.to_string()),
                        )
                        .add_typed_default(DataType::SecretId, secret_id)
                        .add_typed_default(DataType::VersionNumber, version)
                        .add_typed_default(
                            DataType::Payload,
                            DataValue::Str("available".to_string()),
                        ),
                )
            }
            CommunicationType::MessageEdit => {
                let frame = CommunicationValue::new(CommunicationType::MessageEdit)
                    .with_payload(payload.clone());
                Some(
                    CommunicationValue::new(CommunicationType::MessageEditLive)
                        .with_id(event_id)
                        .with_sender(signer_id)
                        .with_receiver(receiver)
                        .add_typed_default(
                            DataType::Content,
                            frame.get_data(DataType::Content)?.clone(),
                        )
                        .add_typed_default(
                            DataType::SendTime,
                            frame.get_data(DataType::SendTime)?.clone(),
                        )
                        .add_typed_default(
                            DataType::VersionNumber,
                            frame.get_data(DataType::VersionNumber)?.clone(),
                        )
                        .add_typed_default(DataType::ChatPartnerId, sender.clone()),
                )
            }
            CommunicationType::MessageReactionAdd | CommunicationType::MessageReactionRemove => {
                let frame = CommunicationValue::new(message_type).with_payload(payload.clone());
                Some(
                    CommunicationValue::new(CommunicationType::MessageReactionLive)
                        .with_id(event_id)
                        .with_sender(signer_id)
                        .with_receiver(receiver)
                        .add_typed_default(
                            DataType::Reaction,
                            frame.get_data(DataType::Reaction)?.clone(),
                        )
                        .add_typed_default(
                            DataType::SendTime,
                            frame.get_data(DataType::SendTime)?.clone(),
                        )
                        .add_typed_default(DataType::ChatPartnerId, sender.clone())
                        .add_typed_default(DataType::SenderId, sender)
                        .add_typed_default(
                            DataType::Accepted,
                            DataValue::Bool(message_type == CommunicationType::MessageReactionAdd),
                        ),
                )
            }
            CommunicationType::MessageDelete | CommunicationType::MessageDeleteLive => {
                let frame = CommunicationValue::new(CommunicationType::MessageDelete)
                    .with_payload(payload.clone());
                Some(
                    CommunicationValue::new(CommunicationType::MessageDeleteLive)
                        .with_id(event_id)
                        .with_sender(signer_id)
                        .with_receiver(receiver)
                        .add_typed_default(
                            DataType::SendTime,
                            frame.get_data(DataType::SendTime)?.clone(),
                        )
                        .add_typed_default(DataType::ChatPartnerId, sender),
                )
            }
            CommunicationType::AddConversation if recipient_id < signer_id => {
                let chat_id = format!("{recipient_id}:{signer_id}");
                Some(
                    CommunicationValue::new(CommunicationType::ChatSecretForward)
                        .with_id(event_id)
                        .with_sender(signer_id)
                        .with_receiver(receiver)
                        .add_typed_default(DataType::ChatId, DataValue::Str(chat_id.clone()))
                        .add_typed_default(
                            DataType::SenderUserId,
                            DataValue::Str(signer_id.to_string()),
                        )
                        .add_typed_default(
                            DataType::RecipientUserId,
                            DataValue::Str(recipient_id.to_string()),
                        )
                        .add_typed_default(
                            DataType::SecretId,
                            DataValue::Str(format!("chat:{chat_id}:main")),
                        )
                        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1))
                        .add_typed_default(DataType::Payload, DataValue::Str("init".to_string())),
                )
            }
            _ => None,
        }
    }

    async fn handle_relay(self: Arc<Self>, frame: CommunicationValue) {
        let Some(incoming_frame_id) = frame.id() else {
            log!("Rejecting Relay without a message id");
            return;
        };
        let Some(local_iota_id) = CONFIG.load().iota_id else {
            log!("Rejecting Relay because this Iota has no registered identity");
            self.send_relay_response(Some(incoming_frame_id), CommunicationType::ErrorInvalidData)
                .await;
            return;
        };
        let Some(keyring) = self.keyring.read().await.as_ref().cloned() else {
            log!("Rejecting Relay because the Iota keyring is unavailable");
            self.send_relay_response(Some(incoming_frame_id), CommunicationType::ErrorInternal)
                .await;
            return;
        };

        let resolver_connection = self.clone();
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

        let verified = match verified {
            Ok(value) => value,
            Err(error) => {
                log!("Relay metadata verification failed: {}", error);
                self.send_relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInvalidData,
                )
                .await;
                return;
            }
        };
        let accepted_at = now_millis_i64();
        let signer_id = match i64::try_from(verified.context.signer_id) {
            Ok(id) => id,
            Err(_) => {
                self.send_relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInvalidData,
                )
                .await;
                return;
            }
        };
        let recipient_id = match i64::try_from(verified.context.final_recipient_id) {
            Ok(id) => id,
            Err(_) => {
                self.send_relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInvalidData,
                )
                .await;
                return;
            }
        };
        let signer_is_local = match iota_storage::users::user_manager::get_user(signer_id) {
            Ok(user) => user.is_some(),
            Err(error) => {
                log!(
                    "Relay locality lookup failed for signer {}: {}",
                    signer_id,
                    error
                );
                self.send_relay_response(Some(incoming_frame_id), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        };
        let recipient_is_local = match iota_storage::users::user_manager::get_user(recipient_id) {
            Ok(user) => user.is_some(),
            Err(error) => {
                log!(
                    "Relay locality lookup failed for recipient {}: {}",
                    recipient_id,
                    error
                );
                self.send_relay_response(Some(incoming_frame_id), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        };
        if !signer_is_local && !recipient_is_local {
            log!(
                "Rejecting Relay with no local origin or destination: signer {}, recipient {}",
                verified.context.signer_id,
                verified.context.final_recipient_id,
            );
            self.send_relay_response(Some(incoming_frame_id), CommunicationType::ErrorInvalidData)
                .await;
            return;
        }

        /* Evaluate recipient policy before reserving relay replay state or
         * persisting the frame, so blocked traffic leaves no durable trace. */
        if recipient_block_policy_applies(recipient_is_local, recipient_id, signer_id) {
            match iota_storage::util::blocked_users::is_blocked(recipient_id, signer_id) {
                Ok(true) => {
                    log!(
                        "Rejecting Relay from blocked signer {} to recipient {}",
                        signer_id,
                        recipient_id
                    );
                    self.send_relay_response(
                        Some(incoming_frame_id),
                        CommunicationType::ErrorNotAuthenticated,
                    )
                    .await;
                    return;
                }
                Ok(false) => {}
                Err(error) => {
                    log!(
                        "Relay block policy lookup failed for recipient {}: {}",
                        recipient_id,
                        error
                    );
                    self.send_relay_response(
                        Some(incoming_frame_id),
                        CommunicationType::ErrorInternal,
                    )
                    .await;
                    return;
                }
            }
        }

        /* An origin Iota is authoritative for receipt disclosure. Inspect
         * local-origin relay content before reserving or queuing the frame. */
        if signer_is_local {
            let content = match open_verified_relay_content(&verified, &[&keyring]) {
                Ok(content) => content,
                Err(error) => {
                    log!("Relay origin content verification failed: {}", error);
                    self.send_relay_response(
                        Some(incoming_frame_id),
                        CommunicationType::ErrorInvalidData,
                    )
                    .await;
                    return;
                }
            };
            if let Err(error) = message_handlers::validate_outgoing_receipt_policy(
                signer_id,
                &verified.context,
                &content,
            ) {
                log!("Rejecting local receipt relay: {}", error);
                self.send_relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInvalidData,
                )
                .await;
                return;
            }
        }

        let frame_bytes = match frame.clone().without_id().to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                log!(
                    "Relay could not be serialized for durable acceptance: {}",
                    error
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        };
        let type_map_version = verified.context.type_map.version.to_string();
        let frame_id = incoming_frame_id;
        let reservation = match relay_replay::reserve(
            verified.context.signer_id,
            &verified.context.message_id,
            verified.context.created_at,
            accepted_at,
            verified.context.final_recipient_id,
            &frame_bytes,
            frame_id,
            &type_map_version,
        ) {
            Ok(value) => value,
            Err(error) => {
                log!("Relay durable acceptance failed: {}", error);
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        };
        let already_applied = match reservation {
            relay_replay::RelayReservation::New => false,
            relay_replay::RelayReservation::Existing {
                frame_matches: false,
                ..
            } => {
                log!(
                    "Rejecting Relay identity collision for signer {} and message {}",
                    verified.context.signer_id,
                    verified.context.message_id
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
            relay_replay::RelayReservation::Existing { ref state, .. } if state == "delivered" => {
                self.send_relay_response(frame.id(), CommunicationType::Success)
                    .await;
                return;
            }
            relay_replay::RelayReservation::Existing { ref state, .. }
                if state == "applied" || state == "queued" =>
            {
                true
            }
            relay_replay::RelayReservation::Existing { ref state, .. } if state == "rejected" => {
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
            relay_replay::RelayReservation::Existing { .. } => false,
        };

        /* A shared Iota owns both independent replicas before delivering to its
         * local recipient. The destination path below writes the recipient copy. */
        if signer_is_local && recipient_is_local && !already_applied {
            let content = match open_verified_relay_content(&verified, &[&keyring]) {
                Ok(value) => value,
                Err(error) => {
                    log!(
                        "Relay shared-Iota origin content verification failed: {}",
                        error
                    );
                    let _ = relay_replay::mark_rejected(
                        verified.context.signer_id,
                        &verified.context.message_id,
                    );
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
            };
            let owner = match i64::try_from(verified.context.signer_id) {
                Ok(value) => value,
                Err(_) => {
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
            };
            if let Err(error) = message_handlers::apply_verified_relay_content(
                &verified.context,
                &content,
                accepted_at,
                owner,
                true,
            ) {
                log!("Relay shared-Iota origin application failed: {}", error);
                let _ = relay_replay::mark_rejected(
                    verified.context.signer_id,
                    &verified.context.message_id,
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
            if let Err(error) = chat_files::record_destination_iota_received(
                owner,
                owner,
                &verified.context.message_id,
                accepted_at,
            ) {
                log!(
                    "Relay shared-Iota destination timestamp storage failed: {}",
                    error
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        }

        if signer_is_local && !recipient_is_local {
            /* Chat-secret versions are immutable. Apply them locally only after
             * the peer has accepted the same relay, so a peer conflict cannot
             * leave a newly generated origin version behind. */
            let defer_chat_secret_commit = frame.is_type(CommunicationType::SetChatSecret);
            if !already_applied {
                if !defer_chat_secret_commit {
                    let content = match open_verified_relay_content(&verified, &[&keyring]) {
                        Ok(value) => value,
                        Err(error) => {
                            log!("Relay origin content verification failed: {}", error);
                            let _ = relay_replay::mark_rejected(
                                verified.context.signer_id,
                                &verified.context.message_id,
                            );
                            self.send_relay_response(
                                frame.id(),
                                CommunicationType::ErrorInvalidData,
                            )
                            .await;
                            return;
                        }
                    };
                    if let Err(error) = message_handlers::apply_verified_relay_content(
                        &verified.context,
                        &content,
                        accepted_at,
                        i64::try_from(verified.context.signer_id).unwrap_or_default(),
                        true,
                    ) {
                        log!("Relay origin application failed: {}", error);
                        let _ = relay_replay::mark_rejected(
                            verified.context.signer_id,
                            &verified.context.message_id,
                        );
                        self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                }
            }
            let router = match self
                .hosting_iota_for_user(verified.context.final_recipient_id)
                .await
            {
                Ok(destination_iota) => destination_iota,
                Err(error) => {
                    log!("Relay origin route lookup failed: {}", error);
                    record_origin_delivery_failure(
                        verified.context.signer_id,
                        &verified.context.message_id,
                        "destination_iota_not_found",
                    );
                    self.send_relay_response(frame.id(), CommunicationType::ErrorNoIota)
                        .await;
                    return;
                }
            };
            let forwarded = match forward_verified_relay(&frame, RouteTarget::Iota(router)) {
                Ok(value) => value,
                Err(error) => {
                    log!("Relay origin forwarding validation failed: {}", error);
                    record_origin_delivery_failure(
                        verified.context.signer_id,
                        &verified.context.message_id,
                        "forwarding_validation_failed",
                    );
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
            };
            let bytes = match forwarded.to_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    log!("Relay origin retry could not be serialized: {}", error);
                    record_origin_delivery_failure(
                        verified.context.signer_id,
                        &verified.context.message_id,
                        "serialization_failed",
                    );
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                        .await;
                    return;
                }
            };
            let relay_identity = match (
                i64::try_from(verified.context.signer_id),
                i64::try_from(verified.context.final_recipient_id),
            ) {
                (Ok(signer_id), Ok(destination_user_id)) => relay_queue::RelayIdentity {
                    signer_id,
                    destination_user_id,
                    message_id: verified.context.message_id.clone(),
                },
                _ => {
                    log!("Relay identity exceeds the storage range");
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
            };
            if let Err(error) =
                outgoing_relay::commit_outgoing_relay(outgoing_relay::OutgoingRelay {
                    target: RouteTarget::Iota(router),
                    identity: &relay_identity,
                    frame: &bytes,
                    created_at: now_millis_i64(),
                    frame_id,
                    type_map_version: &type_map_version,
                })
            {
                log!("Relay origin retry queue failed: {}", error);
                record_origin_delivery_failure(
                    verified.context.signer_id,
                    &verified.context.message_id,
                    "queue_failed",
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
            match self
                .await_relay_response(&forwarded, Duration::from_secs(20))
                .await
            {
                Ok(response) if response.is_type(CommunicationType::Success) => {
                    let returned_id = response.get_data(DataType::RelayMessageId).as_str();
                    let destination_accepted_at = response
                        .get_data(DataType::RelayAcceptedAt)
                        .as_number()
                        .and_then(|value| i64::try_from(value).ok());
                    if returned_id != Some(verified.context.message_id.as_str()) {
                        log!("Relay acknowledgement returned a different RelayMessageId");
                        self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                    let Some(destination_accepted_at) = destination_accepted_at else {
                        log!("Relay acknowledgement is missing RelayAcceptedAt");
                        self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    };
                    let Ok(signer_id) = i64::try_from(verified.context.signer_id) else {
                        self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    };
                    if defer_chat_secret_commit && !already_applied {
                        let content = match open_verified_relay_content(&verified, &[&keyring]) {
                            Ok(value) => value,
                            Err(error) => {
                                log!("Relay origin content verification failed: {}", error);
                                self.send_relay_response(
                                    frame.id(),
                                    CommunicationType::ErrorInvalidData,
                                )
                                .await;
                                return;
                            }
                        };
                        let Ok(origin_id) = i64::try_from(verified.context.signer_id) else {
                            self.send_relay_response(
                                frame.id(),
                                CommunicationType::ErrorInvalidData,
                            )
                            .await;
                            return;
                        };
                        if let Err(error) = message_handlers::apply_verified_relay_content(
                            &verified.context,
                            &content,
                            accepted_at,
                            origin_id,
                            true,
                        ) {
                            log!("Relay origin chat-secret application failed: {}", error);
                            self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                                .await;
                            return;
                        }
                    }
                    if let Err(error) =
                        iota_storage::util::downstream_relay::acknowledge_iota_delivery(
                            router,
                            frame_id,
                            signer_id,
                            &verified.context.message_id,
                            destination_accepted_at,
                        )
                    {
                        log!(
                            "Relay destination acknowledgement storage failed: {}",
                            error
                        );
                        self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                            .await;
                        return;
                    }
                    let response = response
                        .add_typed_default(
                            DataType::OriginIotaReceivedAt,
                            DataValue::SignedNumber(accepted_at.into()),
                        )
                        .add_typed_default(
                            DataType::DestinationIotaReceivedAt,
                            DataValue::SignedNumber(destination_accepted_at.into()),
                        )
                        .with_id(frame_id);
                    if let Err(error) = self.send_message(&response).await {
                        log!("Relay response could not be sent: {}", error);
                    }
                }
                Ok(response) => {
                    log!("Relay origin route returned {}", response.get_type());
                    if response.is_type(CommunicationType::ErrorInternal)
                        && !defer_chat_secret_commit
                    {
                        record_origin_delivery_failure(
                            verified.context.signer_id,
                            &verified.context.message_id,
                            "destination_internal_error",
                        );
                        self.send_relay_success(
                            frame.id(),
                            local_iota_id,
                            &verified.context.message_id,
                            accepted_at,
                            true,
                        )
                        .await;
                        return;
                    } else if let Ok(signer_id) = i64::try_from(verified.context.signer_id) {
                        if let Err(error) =
                            iota_storage::util::downstream_relay::reject_iota_delivery(
                                router,
                                frame_id,
                                signer_id,
                                &verified.context.message_id,
                                "destination_rejected",
                            )
                        {
                            log!("Relay rejection cleanup failed: {}", error);
                        }
                        record_origin_delivery_failure(
                            verified.context.signer_id,
                            &verified.context.message_id,
                            "destination_rejected",
                        );
                    }
                    self.send_relay_response(
                        frame.id(),
                        response
                            .get_comm_type_enum()
                            .unwrap_or(CommunicationType::ErrorInternal),
                    )
                    .await;
                }
                Err(error) => {
                    log!("Relay origin forwarding failed: {}", error);
                    record_origin_delivery_failure(
                        verified.context.signer_id,
                        &verified.context.message_id,
                        "destination_unreachable",
                    );
                    if defer_chat_secret_commit {
                        if let Ok(signer_id) = i64::try_from(verified.context.signer_id) {
                            if let Err(queue_error) =
                                iota_storage::util::downstream_relay::reject_iota_delivery(
                                    router,
                                    frame_id,
                                    signer_id,
                                    &verified.context.message_id,
                                    "destination_unreachable",
                                )
                            {
                                log!("Chat-secret relay retry cleanup failed: {}", queue_error);
                            }
                        }
                        self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                            .await;
                        return;
                    }
                    self.send_relay_success(
                        frame.id(),
                        local_iota_id,
                        &verified.context.message_id,
                        accepted_at,
                        true,
                    )
                    .await;
                }
            }
            return;
        }

        let destination = verified.context.final_recipient_id;
        let forwarded = match forward_verified_relay(&frame, RouteTarget::User(destination)) {
            Ok(value) => value,
            Err(error) => {
                log!("Relay forwarding validation failed: {}", error);
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
        };
        let bytes = match forwarded.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                log!(
                    "Relay could not be serialized for client delivery: {}",
                    error
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        };
        let relay_identity = match (
            i64::try_from(verified.context.signer_id),
            i64::try_from(verified.context.final_recipient_id),
        ) {
            (Ok(signer_id), Ok(destination_user_id)) => relay_queue::RelayIdentity {
                signer_id,
                destination_user_id,
                message_id: verified.context.message_id.clone(),
            },
            _ => {
                log!("Relay identity exceeds the storage range");
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
        };
        if let Err(error) = relay_queue::enqueue(
            RouteTarget::User(destination),
            &relay_identity,
            &bytes,
            now_millis_i64(),
            frame_id,
            &type_map_version,
        ) {
            log!("Relay could not be queued for client delivery: {}", error);
            self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                .await;
            return;
        }

        let mut client_event = None;
        if !already_applied {
            let content = match open_verified_relay_content(&verified, &[&keyring]) {
                Ok(value) => value,
                Err(error) => {
                    log!("Relay content verification failed: {}", error);
                    if let Err(queue_error) =
                        relay_queue::remove_for_frame(RouteTarget::User(destination), frame_id)
                    {
                        log!(
                            "Relay invalid-content queue cleanup failed: {}",
                            queue_error
                        );
                    }
                    let _ = relay_replay::mark_rejected(
                        verified.context.signer_id,
                        &verified.context.message_id,
                    );
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
            };
            if let Err(error) = message_handlers::apply_verified_relay_content(
                &verified.context,
                &content,
                accepted_at,
                match i64::try_from(destination) {
                    Ok(value) => value,
                    Err(_) => {
                        log!("Relay destination ID exceeds storage range");
                        self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                },
                false,
            ) {
                log!("Relay application dispatch failed: {}", error);
                if let Err(queue_error) =
                    relay_queue::remove_for_frame(RouteTarget::User(destination), frame_id)
                {
                    log!("Relay application queue cleanup failed: {}", queue_error);
                }
                let _ = relay_replay::mark_rejected(
                    verified.context.signer_id,
                    &verified.context.message_id,
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
            client_event = Self::client_event_from_relay(
                content.message_type,
                &content.content,
                verified.context.signer_id,
                destination,
                &verified.context.message_id,
                accepted_at,
            );
            if let Err(error) =
                relay_replay::mark_applied(verified.context.signer_id, &verified.context.message_id)
            {
                log!("Relay application state update failed: {}", error);
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        }

        if signer_is_local && recipient_is_local {
            let Ok(owner) = i64::try_from(verified.context.signer_id) else {
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            };
            if let Err(error) = outgoing_relay::apply_outgoing_history_policy(
                owner,
                owner,
                &verified.context.message_id,
            ) {
                log!("Shared-Iota outgoing history policy failed: {}", error);
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        }

        if let Err(error) =
            relay_replay::mark_queued(verified.context.signer_id, &verified.context.message_id)
        {
            log!("Relay queue state update failed: {}", error);
        }
        self.send_relay_success(
            frame.id(),
            local_iota_id,
            &verified.context.message_id,
            accepted_at,
            signer_is_local,
        )
        .await;
        if let Some(event) = client_event {
            if let Err(error) = self.send_message(&event).await {
                log!("Relay client event delivery failed: {}", error);
            }
        }
    }

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
                    (Ok(signer_id), Ok(destination_user_id)) => relay_queue::RelayIdentity {
                        signer_id,
                        destination_user_id,
                        message_id: verified.context.message_id,
                    },
                    _ => {
                        let _ = relay_queue::delete(record.id);
                        continue;
                    }
                };
                if matches!(record.target, RouteTarget::User(destination) if i64::try_from(destination).ok() != Some(identity.destination_user_id))
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
                matches!(record.target, RouteTarget::User(destination) if i64::try_from(destination).ok() == Some(user_id))
            })
        }) {
            if record.relay_signer_id.is_none()
                || record.relay_destination_user_id.is_none()
                || record.relay_message_id.is_none()
            {
                log!(
                    "Skipping pending Relay {} until ownership is classified",
                    record.id
                );
                continue;
            }
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
                    (Ok(signer_id), Ok(destination_user_id)) => relay_queue::RelayIdentity {
                        signer_id,
                        destination_user_id,
                        message_id: verified.context.message_id,
                    },
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
            let Ok(forwarded) = forward_verified_relay(&frame, record.target) else {
                log!(
                    "Retaining pending Relay {} with invalid route target",
                    record.id
                );
                continue;
            };
            match record.target {
                RouteTarget::Iota(destination_iota) => {
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
                                    if let Err(error) =
                                        message_handlers::apply_verified_relay_content(
                                            &verified.context,
                                            &content,
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
                                        destination_iota,
                                        record.frame_id,
                                        signer_id,
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
                                        destination_iota,
                                        record.frame_id,
                                        signer_id,
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
                RouteTarget::User(_) => {
                    if let Err(error) = self.send_message(&forwarded).await {
                        log!("Pending Relay {} delivery failed: {}", record.id, error);
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Message Handling - Dispatch
    // -------------------------------------------------------------------------

    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        log_cv_in!(&cv);

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
            self.handle_relay(cv).await;
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
        dispatch!(AppIdentification, handle_app_identification);
        dispatch!(AppChallengeResponse, handle_app_challenge_response);
        dispatch!(SaveAppData, handle_save_app_data);
        dispatch!(LoadAppData, handle_load_app_data);
        dispatch!(CreateApp, handle_create_app);
        dispatch!(DeleteApp, handle_delete_app);
        dispatch!(ClientConnected, handle_client_connected);
        dispatch!(ClientStateAck, handle_client_state_ack);
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
        dispatch!(UserBlock, handle_user_block);
        dispatch!(UserUnblock, handle_user_unblock);
        dispatch!(BlockedUsersGet, handle_blocked_users_get);
        dispatch!(ReceiptPolicyGet, handle_receipt_policy_get);
        dispatch!(ReceiptPolicySet, handle_receipt_policy_set);
        dispatch!(MessageStoragePolicyGet, handle_message_storage_policy_get);
        dispatch!(MessageStoragePolicySet, handle_message_storage_policy_set);
        dispatch!(UserBlockCheck, handle_user_block_check);
        dispatch!(EraseHostedUserData, handle_erase_hosted_user_data);
        dispatch!(ProvisionIotaUser, handle_iota_user_provisioning);
    }

    // -------------------------------------------------------------------------
    // Message Handlers
    // -------------------------------------------------------------------------

    /// Omega-authorized account cleanup. The storage operation is idempotent;
    /// acknowledgement is therefore safe to retry after a reconnect.
    async fn handle_erase_hosted_user_data(self: Arc<Self>, cv: &CommunicationValue) {
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
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0);
        let username = cv.get_data(DataType::Username).as_str().map(str::to_owned);
        let public_key = cv.get_data(DataType::PublicKey).as_str().map(str::to_owned);
        let invitation_id = cv
            .get_data(DataType::InvitationId)
            .as_str()
            .filter(|value| uuid::Uuid::parse_str(value).is_ok())
            .map(str::to_owned);
        let Some((user_id, username, public_key, invitation_id)) = user_id
            .zip(username)
            .zip(public_key)
            .zip(invitation_id)
            .map(|(((id, username), key), invitation_id)| (id, username, key, invitation_id))
        else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let profile = iota_storage::users::user_profile::UserProfile::new(
            user_id, username, None, public_key, None, None,
        );
        if iota_storage::users::user_manager::try_add_user_with_credential_origin(
            profile,
            iota_storage::users::user_manager::CredentialOrigin::External,
        )
        .is_err()
        {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                .await;
            return;
        }
        let acknowledgement =
            CommunicationValue::new(CommunicationType::AcknowledgeIotaUserProvision)
                .with_request_id(cv)
                .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
                .add_typed_default(DataType::InvitationId, DataValue::Str(invitation_id));
        let _ = self.send_message(&acknowledgement).await;
    }

    async fn handle_get_chat_secret(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_chat_secret(cv))
            .await;
    }

    async fn handle_app_identification(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = match cv.require_sender() {
            Ok(sender_id) => sender_id,
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
        };
        let app_identifier = cv
            .get_data(DataType::AppIdentifier)
            .as_str()
            .unwrap_or("")
            .to_string();
        let app_public_key = cv
            .get_data(DataType::AppPublicKey)
            .as_str()
            .unwrap_or("")
            .to_string();
        let Some(user_id) = data_i64(cv, DataType::UserId).filter(|id| *id > 0) else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };

        let mut trusted = false;
        let user = match iota_storage::users::user_manager::get_user(user_id) {
            Ok(user) => user,
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                    .await;
                return;
            }
        };
        if let Some(user) = user {
            if let Some(pub_k) = user.trusted_apps.get(&app_identifier) {
                if pub_k == &app_public_key {
                    trusted = true;
                }
            }
        }

        if trusted {
            let challenge = Uuid::new_v4().to_string();

            self.app_challenges.insert(sender_id, challenge.clone());
            self.app_sessions
                .insert(sender_id, (user_id, app_identifier.clone()));

            if let Some(app_pub_bundle) =
                iota_util::crypto_helper::public_key_bundle_from_base64(&app_public_key)
            {
                let keyring = self.keyring.read().await.as_ref().cloned();
                if let Some(keyring) = keyring {
                    if let Ok(encrypted_challenge) =
                        crypto_util::encrypt_challenge(&challenge, &app_pub_bundle)
                    {
                        let bundle = keyring.public_key_bundle();
                        let pub_k_b64 = crypto_helper::public_key_bundle_to_base64(&bundle);

                        let res = CommunicationValue::new(CommunicationType::AppChallenge)
                            .with_request_id(cv)
                            .with_receiver(sender_id)
                            .add_typed_default(DataType::PublicKey, DataValue::Str(pub_k_b64))
                            .add_typed_default(
                                DataType::Challenge,
                                DataValue::Str(encrypted_challenge),
                            );

                        let _ = self.send_message(&res).await;
                        return;
                    }
                }
            }
        }

        let res = CommunicationValue::new(CommunicationType::ErrorInvalidChallenge)
            .with_request_id(cv)
            .with_receiver(sender_id);
        let _ = self.send_message(&res).await;
    }

    async fn handle_app_challenge_response(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = match cv.require_sender() {
            Ok(sender_id) => sender_id,
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
        };
        if let Some((_, expected_challenge)) = self.app_challenges.remove(&sender_id) {
            if let Some(DataValue::Str(response)) = cv.get_data(DataType::Challenge) {
                if expected_challenge == *response {
                    let res = CommunicationValue::new(CommunicationType::AppIdentificationResponse)
                        .with_request_id(cv)
                        .with_receiver(sender_id);
                    let _ = self.send_message(&res).await;
                    return;
                }
            }
        }
        let res = CommunicationValue::new(CommunicationType::ErrorInvalidChallenge)
            .with_request_id(cv)
            .with_receiver(sender_id);
        let _ = self.send_message(&res).await;
    }

    async fn handle_save_app_data(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = match cv.require_sender() {
            Ok(sender_id) => sender_id,
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
        };
        let app_data = cv
            .get_data(DataType::AppData)
            .as_str()
            .unwrap_or("")
            .to_string();

        if let Some(session) = self.app_sessions.get(&sender_id) {
            let (user_id, app_identifier) = session.value();
            iota_storage::users::user_manager::save_app_data(*user_id, app_identifier, &app_data);
        }

        let res = CommunicationValue::new(CommunicationType::SaveAppData)
            .with_request_id(cv)
            .with_receiver(sender_id);
        let _ = self.send_message(&res).await;
    }

    async fn handle_load_app_data(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = match cv.require_sender() {
            Ok(sender_id) => sender_id,
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
        };
        let mut app_data = String::new();

        if let Some(session) = self.app_sessions.get(&sender_id) {
            let (user_id, app_identifier) = session.value();
            app_data = iota_storage::users::user_manager::load_app_data(*user_id, app_identifier);
        }

        let res = CommunicationValue::new(CommunicationType::LoadAppData)
            .with_request_id(cv)
            .with_receiver(sender_id)
            .add_typed_default(DataType::AppData, DataValue::Str(app_data));
        let _ = self.send_message(&res).await;
    }

    async fn handle_create_app(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_create_app(cv))
            .await;
    }

    async fn handle_delete_app(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_delete_app(cv))
            .await;
    }

    async fn handle_client_connected(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_client_connected(cv);
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok());
        let session_id = cv
            .get_data(DataType::SessionId)
            .as_number()
            .and_then(|id| i64::try_from(id).ok());

        if response.is_type(CommunicationType::ClientStateSync) {
            log!(
                "ClientStateSync user={:?} session={:?} stage=generated",
                user_id,
                session_id
            );
            if let Some(user_id) = user_id
                && let Err(error) = relay_queue::pause_client_deliveries(user_id)
            {
                log!("Pending Relay state-sync pause failed: {}", error);
            }

            if let Err(error) = self.send_message(&response).await {
                log!(
                    "Initial ClientStateSync delivery failed for user {:?}, session {:?}: {}",
                    user_id,
                    session_id,
                    error
                );
            } else {
                log!(
                    "ClientStateSync user={:?} session={:?} stage=sent_to_omikron",
                    user_id,
                    session_id
                );
            }
            return;
        }

        if let Err(error) = self.send_message(&response).await {
            log!("ClientConnected response delivery failed: {}", error);
        }
    }

    async fn handle_client_state_ack(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_client_state_ack(cv);
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

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    pub async fn send_message(&self, cv: &CommunicationValue) -> Result<(), String> {
        let sender_guard = self.sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
            if !sender.is_open() {
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
                self.fail_all_waiting_tasks(format!(
                    "Send failed: {} (connection_id={})",
                    e, self.connection_id
                ))
                .await;
                return Err(e.to_string());
            }

            Ok(())
        } else {
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
        save_keyring_verified(&keyring, path).map_err(|error| {
            OmikronError::Internal(format!(
                "could not save new identity {}: {error}",
                path.display()
            ))
        })?;
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

fn recipient_block_policy_applies(
    recipient_is_local: bool,
    recipient_id: i64,
    signer_id: i64,
) -> bool {
    recipient_is_local && recipient_id != signer_id
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

impl iota_connection::connection_handler::ConnectionHandler for OmikronConnection {
    async fn send_message(&self, cv: &CommunicationValue) -> Result<(), String> {
        OmikronConnection::send_message(self, cv).await
    }

    async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        OmikronConnection::await_response(self, cv, timeout).await
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
            app_challenges: self.app_challenges.clone(),
            app_sessions: self.app_sessions.clone(),
            handler_semaphore: self.handler_semaphore.clone(),
            cancellation: self.cancellation.clone(),
            active_tasks: self.active_tasks.clone(),
            app: self.app.clone(),
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
            app_challenges: self.app_challenges.clone(),
            app_sessions: self.app_sessions.clone(),
            handler_semaphore: self.handler_semaphore.clone(),
            cancellation: self.cancellation.clone(),
            active_tasks: self.active_tasks.clone(),
            app: self.app.clone(),
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
        let keyring = load_or_migrate_keyring_at(&path, None).expect("identity saves");
        let reloaded = load_or_migrate_keyring_at(&path, None).expect("identity loads");
        assert_eq!(
            keyring.try_to_bytes().expect("keyring serializes"),
            reloaded.try_to_bytes().expect("keyring serializes")
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
        assert!(matches!(error, IdentityError::Storage(_)));
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

        let migrated = load_or_migrate_keyring_at(&path, None).expect("legacy identity loads");
        assert_eq!(
            migrated.try_to_bytes().expect("keyring serializes"),
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
        assert!(matches!(error, IdentityError::Directory(_)));
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
    fn recipient_block_policy_skips_self_delivery() {
        assert!(!recipient_block_policy_applies(true, 42, 42));
        assert!(recipient_block_policy_applies(true, 42, 43));
        assert!(!recipient_block_policy_applies(false, 42, 43));
    }
}
