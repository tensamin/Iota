use dashmap::{DashMap, DashSet};
use iota_logger::{log, log_cv_in, log_cv_out, log_t};
use iota_state::AppState;
use iota_storage::util::chat_files;
use iota_storage::util::config_util::{CONFIG, modify_config};
use iota_storage::util::{relay_queue, relay_replay};
use iota_util::crypto_helper::{self, keyring_from_base64};
use iota_util::crypto_util::{self};
use mtp::client::{Client, ClientConfig, MTPConnection, Policy, SendMode, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::{Keyring, PublicKeyBundle};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicU32, Ordering},
};
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
static OMIKRON_PUBLIC_KEY_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/*
 * Keeps identity and pinned Omikron key files independent from the process
 * working directory, so restarts use the same trusted material.
 */
pub fn configure_identity_path(path: PathBuf) {
    let key_path = path.parent().map(|parent| parent.join("omikron.mpkb"));
    let _ = IDENTITY_PATH.set(path);
    if let Some(key_path) = key_path {
        let _ = OMIKRON_PUBLIC_KEY_PATH.set(key_path);
    }
}
fn identity_path() -> &'static Path {
    IDENTITY_PATH
        .get()
        .map(PathBuf::as_path)
        .unwrap_or_else(|| Path::new(IOTA_KEYRING_PATH))
}
fn omikron_public_key_path() -> &'static Path {
    OMIKRON_PUBLIC_KEY_PATH
        .get()
        .map(PathBuf::as_path)
        .unwrap_or_else(|| Path::new("omikron.mpkb"))
}

fn save_keyring(keyring: &Keyring, path: &Path) -> Result<(), String> {
    let temporary = serialization_path(path)?;
    mtp::files::save_keyring_raw(keyring, &temporary)
        .map_err(|error| format!("serialize keyring: {error}"))?;
    let bytes =
        std::fs::read(&temporary).map_err(|error| format!("read serialized keyring: {error}"));
    let _ = std::fs::remove_file(&temporary);
    let bytes = bytes?;
    iota_util::atomic_file::replace_private(path, &bytes, 3)
        .map_err(|error| format!("write {}: {error}", path.display()))
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
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const TASK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_HANDLERS: usize = 20;
const RELAY_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
static NEXT_RELAY_FRAME_ID: AtomicU32 = AtomicU32::new(1);

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

fn ensure_relay_frame_id(frame: CommunicationValue) -> CommunicationValue {
    if frame.id().is_some_and(|id| id != 0) {
        return frame;
    }
    let id = NEXT_RELAY_FRAME_ID.fetch_add(1, Ordering::Relaxed).max(1);
    frame.with_id(id)
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

            match self.clone().connect_once().await {
                Ok(()) => {
                    if *self.reconnect_on_close.read().await {
                        log!("Connection lost, reconnecting in {:?}...", reconnect_delay);
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    if self.auth_failure.read().await.is_some() {
                        log!("Authentication failed, stopping reconnection: {}", e);
                        break;
                    }
                    log!(
                        "Connection failed: {}, retrying in {:?}...",
                        e,
                        reconnect_delay
                    );
                }
            }

            tokio::select! {
                _ = sleep(reconnect_delay) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }

            reconnect_delay = std::cmp::min(reconnect_delay * 2, MAX_RECONNECT_DELAY);
        }
    }

    async fn connect_once(self: Arc<Self>) -> Result<(), String> {
        self.set_state(ConnectionState::Connecting).await;
        log_t!("omikron_connecting");

        let keyring = Arc::new(self.load_or_migrate_keyring().await);
        *self.keyring.write().await = Some(keyring.clone());

        let existing_iota_id = CONFIG.load().iota_id;

        let (host, port, omikron_public_key) =
            self.resolve_omikron_endpoint(existing_iota_id).await?;

        let addr_str = format!("https://{}:{}", host, port);

        log!("Connecting to Omikron at {}", addr_str);

        let client_config = ClientConfig::new(&addr_str)
            .with_description("iota")
            .with_policy(Policy {
                send_mode: SendMode::SingleStreamPerMessage,
                max_message_size: 1_000_000_000,
                handshake_max_message_size: 1_000_000_000,
                close_frame_len: u32::MAX,
                application_close_code: 0,
                open_stream_timeout: Duration::from_millis(2_000),
                write_timeout: Duration::from_millis(2_000),
                accept_stream_timeout: Duration::from_millis(10_000),
                read_timeout: Duration::from_millis(30_000),
                keep_alive_interval: Some(Duration::from_secs(6)),
                max_idle_timeout: None,
                force_close_delay: Duration::from_millis(300),
                receiver_queue_capacity: 1000,
                max_concurrent_stream_tasks: 10,
                persistent_stream_max_retries: 5,
                persistent_stream_retry_backoff: Duration::from_secs(5),
                max_frames_per_stream: None,
            })
            .with_ping_interval(MAINTENANCE_INTERVAL)
            .with_max_missed_pings(0);

        let connection = match Client::auth_connect_or_register(
            client_config,
            existing_iota_id,
            &keyring,
            &omikron_public_key,
        )
        .await
        {
            Ok(connection) => connection,
            Err(mtp::common::CommunicationError::AuthenticationFailed(reason)) => {
                let reason = format!(
                    "Authentication failed: {}. Your Iota keys may be invalid or the private key has changed on the server.",
                    reason
                );
                *self.reconnect_on_close.write().await = false;
                *self.auth_failure.write().await = Some(reason.clone());
                self.set_state(ConnectionState::Disconnected).await;
                return Err(reason);
            }
            Err(e) => return Err(format!("Connection failed: {}", e)),
        };

        log_t!("omikron_connection_success");

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
            Ok(()) => {
                if *self.reconnect_on_close.read().await {
                    Err("Connection closed, will reconnect".to_string())
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(format!("Read loop error: {}", e)),
        }
    }

    // -------------------------------------------------------------------------
    // Identity (own Keyring, migrated from the legacy base64-in-config format)
    // -------------------------------------------------------------------------

    /*
     * `iota.mk` is now the source of truth for this Iota's identity. A
     * pre-existing base64 keyring in config.json (from before the MTP auth
     * migration) is imported once so already-registered Iotas keep their
     * identity, and mirrored back into config.json for older code paths
     * that still read it directly.
     */
    async fn load_or_migrate_keyring(&self) -> Keyring {
        let path = identity_path();
        if let Ok(kr) = mtp::files::load_keyring_raw(path) {
            return kr;
        }

        let legacy = CONFIG.load().keyring.clone();
        let keyring = legacy
            .and_then(|b64| keyring_from_base64(&b64))
            .unwrap_or_else(|| {
                log!(
                    "WARNING: No existing keyring found. Neither {} nor config.json \
                     contain a keyring; generating a new identity. If you already had \
                     an Iota identity, restore {} from a backup to avoid losing access.",
                    path.display(),
                    path.display()
                );
                crypto_helper::generate_keyring()
            });

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = save_keyring(&keyring, path) {
            log!("Failed to persist {}: {}", path.display(), e);
        }

        keyring
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
     * The fetched Omikron public key is pinned to `omikron.mpkb` (trust on
     * first use): if a cached key exists and a fresh discovery response
     * disagrees with it, the mismatch is logged loudly and the cached key is
     * kept rather than silently trusting whatever Omega's HTTP API returned
     * this time - the same trust boundary the previous manual-file-drop
     * model had, just automated for the common case.
     */
    async fn resolve_omikron_endpoint(
        &self,
        existing_iota_id: Option<u64>,
    ) -> Result<(String, u16, PublicKeyBundle), String> {
        if let (Ok(host), Ok(port_str)) = (env::var("OMIKRON_HOST"), env::var("OMIKRON_PORT")) {
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("Invalid OMIKRON_PORT: {}", port_str))?;
            let key_path = omikron_public_key_path();
            let public_key = mtp::files::load_public_key_bundle(key_path)
                .map_err(|e| {
                    format!(
                        "Failed to load Omikron public key bundle from {}: {}. Obtain {} from the Omikron operator and place it at that path.",
                        key_path.display(), e, key_path.display()
                    )
                })?;
            return Ok((host, port, public_key));
        }

        let key_path = omikron_public_key_path();
        let cached_key = mtp::files::load_public_key_bundle(key_path).ok();
        let cached_host_port = {
            let conf = CONFIG.load();
            match (&conf.omikron_host, conf.omikron_port) {
                (Some(host), Some(port)) if !host.trim().is_empty() && port != 0 => {
                    Some((host.clone(), port))
                }
                (Some(_), Some(_)) => {
                    log!("Ignoring invalid cached Omikron endpoint in Iota configuration");
                    None
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

        let (host, port, public_key) = if let Some(endpoint) = discovered {
            match &cached_key {
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
                            "Fetched Omikron public key differs from the cached {} - keeping the \
                             cached key. Delete {} manually if this is an expected key rotation.",
                            key_path.display(),
                            key_path.display()
                        );
                        if let Some((cached_host, cached_port)) = &cached_host_port {
                            (cached_host.clone(), *cached_port, cached.clone())
                        } else {
                            return Err(format!(
                                "Omega returned an Omikron key that differs from {} and no validated cached endpoint is available",
                                key_path.display()
                            ));
                        }
                    } else {
                        (endpoint.host, endpoint.port, cached.clone())
                    }
                }
                None => {
                    if let Err(e) = save_omikron_public_key(&endpoint.public_key, key_path) {
                        log!("Failed to cache Omikron public key: {}", e);
                    }
                    (endpoint.host, endpoint.port, endpoint.public_key)
                }
            }
        } else if let (Some(cached), Some((host, port))) = (&cached_key, &cached_host_port) {
            log!(
                "Omega discovery unreachable, falling back to last-known Omikron {}:{}",
                host,
                port
            );
            (host.clone(), *port, cached.clone())
        } else {
            return Err(
                "Omega discovery failed and no cached Omikron address/key is available".to_string(),
            );
        };

        modify_config(|cfg| {
            cfg.omikron_host = Some(host.clone());
            cfg.omikron_port = Some(port);
        });

        Ok((host, port, public_key))
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
                    let msg_id = cv.get_id();
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
                let ping_ms = ping.as_millis() as i64;
                *self.last_ping.lock().await = ping_ms;
                self.app.lock().unwrap().push_ping_val(ping_ms as f64);
            }

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
        if let Some(user) = iota_storage::users::user_manager::get_user(signer_id as i64) {
            let key = iota_util::crypto_helper::public_key_bundle_from_base64(&user.public_key)
                .ok_or_else(|| {
                    RelayValidationError::KeyLookup("stored user key is invalid".into())
                })?;
            return Ok(vec![key]);
        }

        let request = CommunicationValue::new(CommunicationType::GetUserData).add_typed_default(
            DataType::UserId,
            DataValue::UnsignedNumber(signer_id as u128),
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
        if iota_storage::users::user_manager::get_user(user_id as i64).is_some() {
            return CONFIG
                .load()
                .iota_id
                .ok_or_else(|| "Iota identity is not configured".into());
        }

        let request = CommunicationValue::new(CommunicationType::GetUserData)
            .add_typed_default(DataType::UserId, DataValue::UnsignedNumber(user_id as u128));
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

    async fn handle_relay(self: Arc<Self>, frame: CommunicationValue) {
        let frame = ensure_relay_frame_id(frame);
        let incoming_frame_id = frame.id();
        let Some(local_iota_id) = CONFIG.load().iota_id else {
            log!("Rejecting Relay because this Iota has no registered identity");
            self.send_relay_response(incoming_frame_id, CommunicationType::ErrorInvalidData)
                .await;
            return;
        };
        let Some(keyring) = self.keyring.read().await.as_ref().cloned() else {
            log!("Rejecting Relay because the Iota keyring is unavailable");
            self.send_relay_response(incoming_frame_id, CommunicationType::ErrorInternal)
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
                self.send_relay_response(incoming_frame_id, CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
        };
        let signer_is_local =
            iota_storage::users::user_manager::get_user(verified.context.signer_id as i64)
                .is_some();
        let recipient_is_local =
            iota_storage::users::user_manager::get_user(verified.context.final_recipient_id as i64)
                .is_some();
        if !signer_is_local && !recipient_is_local {
            log!(
                "Rejecting Relay with no local origin or destination: signer {}, recipient {}",
                verified.context.signer_id,
                verified.context.final_recipient_id,
            );
            self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                .await;
            return;
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
        let frame_id = frame.id().unwrap_or_default();
        let reservation = match relay_replay::reserve(
            verified.context.signer_id,
            &verified.context.message_id,
            verified.context.created_at,
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

        if signer_is_local && !recipient_is_local {
            let router = match self
                .hosting_iota_for_user(verified.context.final_recipient_id)
                .await
            {
                Ok(destination_iota) => destination_iota,
                Err(error) => {
                    log!("Relay origin route lookup failed: {}", error);
                    self.send_relay_response(frame.id(), CommunicationType::ErrorNoIota)
                        .await;
                    return;
                }
            };
            let forwarded = match forward_verified_relay(&frame, RouteTarget::Iota(router)) {
                Ok(value) => value,
                Err(error) => {
                    log!("Relay origin forwarding validation failed: {}", error);
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
            };
            let bytes = match forwarded.to_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    log!("Relay origin retry could not be serialized: {}", error);
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                        .await;
                    return;
                }
            };
            if let Err(error) = relay_queue::enqueue(
                RouteTarget::Iota(router),
                &bytes,
                now_millis_i64(),
                frame_id,
                &type_map_version,
            ) {
                log!("Relay origin retry queue failed: {}", error);
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
            if let Err(error) = relay_replay::mark_state(
                verified.context.signer_id,
                &verified.context.message_id,
                "queued",
            ) {
                log!("Relay origin state update failed: {}", error);
            }
            match self
                .await_response(&forwarded, Some(Duration::from_secs(20)))
                .await
            {
                Ok(response) if response.is_type(CommunicationType::Success) => {
                    if let Err(error) = relay_queue::acknowledge_iota(router, frame_id) {
                        log!(
                            "Relay origin acknowledgement could not clear the queue: {}",
                            error
                        );
                    }
                    if let Err(error) = relay_replay::mark_state(
                        verified.context.signer_id,
                        &verified.context.message_id,
                        "delivered",
                    ) {
                        log!("Relay origin delivery state update failed: {}", error);
                    }
                    self.send_relay_response(frame.id(), CommunicationType::Success)
                        .await;
                }
                Ok(response) => {
                    log!("Relay origin route returned {}", response.get_type());
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
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
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
        if let Err(error) = relay_queue::enqueue(
            RouteTarget::User(destination),
            &bytes,
            now_millis_i64(),
            forwarded.id().unwrap_or_default(),
            &type_map_version,
        ) {
            log!("Relay could not be queued for client delivery: {}", error);
            self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                .await;
            return;
        }

        if !already_applied {
            let content = match open_verified_relay_content(
                &verified,
                &[&keyring],
                verified.context.final_recipient_id,
            ) {
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
                    let _ = relay_replay::mark_state(
                        verified.context.signer_id,
                        &verified.context.message_id,
                        "rejected",
                    );
                    self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
            };
            if let Err(error) =
                message_handlers::apply_verified_relay_content(&verified.context, &content)
            {
                log!("Relay application dispatch failed: {}", error);
                if let Err(queue_error) =
                    relay_queue::remove_for_frame(RouteTarget::User(destination), frame_id)
                {
                    log!("Relay application queue cleanup failed: {}", queue_error);
                }
                let _ = relay_replay::mark_state(
                    verified.context.signer_id,
                    &verified.context.message_id,
                    "rejected",
                );
                self.send_relay_response(frame.id(), CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }
            if let Err(error) = relay_replay::mark_state(
                verified.context.signer_id,
                &verified.context.message_id,
                "applied",
            ) {
                log!("Relay application state update failed: {}", error);
                self.send_relay_response(frame.id(), CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        }

        if let Err(error) = relay_replay::mark_state(
            verified.context.signer_id,
            &verified.context.message_id,
            "queued",
        ) {
            log!("Relay queue state update failed: {}", error);
        }
        self.send_relay_response(frame.id(), CommunicationType::Success)
            .await;
        if let Err(error) = self.send_message(&forwarded).await {
            log!("Relay delivery to local client failed: {}", error);
        }
    }

    async fn flush_pending_relays(&self) {
        let Ok(records) = relay_queue::list(100) else {
            return;
        };
        for record in records {
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
                        .await_response(&forwarded, Some(Duration::from_secs(20)))
                        .await
                    {
                        Ok(response) if response.is_type(CommunicationType::Success) => {
                            if let Err(error) =
                                relay_queue::acknowledge_iota(destination_iota, record.frame_id)
                            {
                                log!(
                                    "Pending Relay {} acknowledgement could not clear the queue: {}",
                                    record.id,
                                    error
                                );
                            }
                        }
                        Ok(response) => log!(
                            "Pending Relay {} route returned {}",
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
    // Message Handling — Dispatch
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
            match relay_queue::acknowledge(destination_id, frame_id) {
                Ok(true) => {
                    if let Err(error) =
                        relay_replay::mark_delivered_for_frame(destination_id, frame_id)
                    {
                        log!("Relay delivery state update failed: {}", error);
                    }
                    return;
                }
                Ok(false) => {}
                Err(error) => log!("Relay delivery acknowledgement failed: {}", error),
            }
        }

        let msg_id = cv.get_id();

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
        dispatch!(MessageState, handle_message_state);
        dispatch!(MessageEdit, handle_message_edit);
        dispatch!(MessageEditLive, handle_message_edit_live);
        dispatch!(MessageReactionAdd, handle_message_reaction_add);
        dispatch!(MessageReactionRemove, handle_message_reaction_remove);
        dispatch!(MessageReactionLive, handle_message_reaction_live);
        dispatch!(MessageDeleteLive, handle_message_delete_live);
        dispatch!(MessageGet, handle_message_get);
        dispatch!(MessagesGet, handle_messages_get);
        dispatch!(GetChats, handle_get_chats);
        dispatch!(AddConversation, handle_add_conversation);
        dispatch!(AddCommunity, handle_add_community);
        dispatch!(GetCommunities, handle_get_communities);
        dispatch!(RemoveCommunity, handle_remove_community);
        dispatch!(GlobalSettingsSave, handle_global_settings_save);
        dispatch!(GlobalSettingsLoad, handle_global_settings_load);
        dispatch!(SettingsSave, handle_settings_save);
        dispatch!(SettingsLoad, handle_settings_load);
        dispatch!(SettingsList, handle_settings_list);
        dispatch!(EraseHostedUserData, handle_erase_hosted_user_data);
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
            .with_id(cv.get_id())
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
        let _ = self.send_message(&acknowledgement).await;
    }

    async fn handle_get_chat_secret(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_chat_secret(cv))
            .await;
    }

    async fn handle_app_identification(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = cv.get_sender();
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
        let user_id = cv.get_data(DataType::UserId).as_number().unwrap_or(0) as i64;

        let mut trusted = false;
        if let Some(user) = iota_storage::users::user_manager::get_user(user_id) {
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
                if let Ok(keyring) = mtp::files::load_keyring_raw(identity_path()) {
                    if let Ok(encrypted_challenge) =
                        crypto_util::encrypt_challenge(&challenge, &app_pub_bundle)
                    {
                        let bundle = keyring.public_key_bundle();
                        let pub_k_b64 = crypto_helper::public_key_bundle_to_base64(&bundle);

                        let res = CommunicationValue::new(CommunicationType::AppChallenge)
                            .with_id(cv.get_id())
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
            .with_id(cv.get_id())
            .with_receiver(sender_id);
        let _ = self.send_message(&res).await;
    }

    async fn handle_app_challenge_response(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = cv.get_sender();
        if let Some((_, expected_challenge)) = self.app_challenges.remove(&sender_id) {
            if let Some(DataValue::Str(response)) = cv.get_data(DataType::Challenge) {
                if expected_challenge == *response {
                    let res = CommunicationValue::new(CommunicationType::AppIdentificationResponse)
                        .with_id(cv.get_id())
                        .with_receiver(sender_id);
                    let _ = self.send_message(&res).await;
                    return;
                }
            }
        }
        let res = CommunicationValue::new(CommunicationType::ErrorInvalidChallenge)
            .with_id(cv.get_id())
            .with_receiver(sender_id);
        let _ = self.send_message(&res).await;
    }

    async fn handle_save_app_data(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = cv.get_sender();
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
            .with_id(cv.get_id())
            .with_receiver(sender_id);
        let _ = self.send_message(&res).await;
    }

    async fn handle_load_app_data(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = cv.get_sender();
        let mut app_data = String::new();

        if let Some(session) = self.app_sessions.get(&sender_id) {
            let (user_id, app_identifier) = session.value();
            app_data = iota_storage::users::user_manager::load_app_data(*user_id, app_identifier);
        }

        let res = CommunicationValue::new(CommunicationType::LoadAppData)
            .with_id(cv.get_id())
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
        let _ = self
            .send_message(&message_handlers::handle_client_connected(cv))
            .await;
    }

    async fn handle_client_state_ack(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_client_state_ack(cv))
            .await;
    }

    async fn handle_message_state(self: Arc<Self>, cv: &CommunicationValue) {
        message_handlers::handle_message_state(cv);
    }

    fn mutation_live_message(
        ty: CommunicationType,
        request: &CommunicationValue,
        mutation: &message_handlers::MessageMutation,
        extra: Vec<(DataType, DataValue)>,
    ) -> CommunicationValue {
        let mut message = CommunicationValue::new(ty)
            .with_id(request.get_id())
            .with_sender(mutation.sender_id as u64)
            .with_receiver(mutation.partner_id as u64)
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
        let sender_id = match i64::try_from(cv.get_sender()) {
            Ok(sender_id) => sender_id,
            Err(_) => return,
        };
        let receiver_id = match i64::try_from(cv.get_receiver()) {
            Ok(receiver_id) if receiver_id > 0 => receiver_id,
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
        let sender_id = match i64::try_from(cv.get_sender()) {
            Ok(sender_id) => sender_id,
            Err(_) => return,
        };
        let receiver_id = match i64::try_from(cv.get_receiver()) {
            Ok(receiver_id) if receiver_id > 0 => receiver_id,
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
        let sender_id = match i64::try_from(cv.get_sender()) {
            Ok(sender_id) => sender_id,
            Err(_) => return,
        };
        let receiver_id = match i64::try_from(cv.get_receiver()) {
            Ok(receiver_id) if receiver_id > 0 => receiver_id,
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
        if iota_storage::users::user_manager::get_user(mutation.partner_id).is_some()
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
        if iota_storage::users::user_manager::get_user(mutation.partner_id).is_some() {
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
        let sender_id = match i64::try_from(cv.get_sender()) {
            Ok(sender_id) => sender_id,
            Err(_) => return,
        };
        if iota_storage::users::user_manager::get_user(sender_id).is_none() {
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
        if iota_storage::users::user_manager::get_user(mutation.partner_id).is_some()
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

    async fn handle_add_conversation(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_add_conversation(cv))
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

            log_cv_out!(&cv);

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
        let msg_id = cv.get_id();

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
                    Err(format!(
                        "Request rejected (msg_id={}, reason={})",
                        msg_id, reason
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                OmikronError::Internal(format!(
                    "could not create identity directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        save_keyring(&keyring, path).map_err(|error| {
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
            .map_err(|error| {
                if error.contains("timed out") {
                    OmikronError::Timeout(error)
                } else if error.starts_with("Request rejected") {
                    OmikronError::Internal(error)
                } else {
                    OmikronError::Disconnected(error)
                }
            })
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

    #[test]
    fn durable_keyring_save_preserves_mtp_format() {
        let directory = std::env::temp_dir().join(format!("iota-keyring-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(IOTA_KEYRING_PATH);
        let keyring = crypto_helper::generate_keyring();

        save_keyring(&keyring, &path).unwrap();

        let loaded = mtp::files::load_keyring_raw(&path).unwrap();
        assert_eq!(
            keyring.try_to_bytes().unwrap(),
            loaded.try_to_bytes().unwrap()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
