use dashmap::DashMap;
use iota_logger::{log, log_cv_in, log_cv_out, log_t};
use iota_state::{ACTIVE_TASKS, SHUTDOWN};
use iota_storage::users::contact::Contact;
use iota_storage::util::chat_files::{self, MessageState, change_message_state};
use iota_storage::util::chats_util::{self, get_user, mod_user};
use iota_storage::util::communities_util::CommunitiesUtil;
use iota_storage::util::config_util::{CONFIG, modify_config};
use iota_storage::util::e2ee_storage::{
    self, ChatSecretQuery, PendingChatSecretForward, StoredChatSecret,
};
use iota_util::crypto_helper::{self, keyring_from_base64};
use iota_util::crypto_util::{self};
use iota_util::file_util::{get_children, has_file, load_file, save_file};
use mtp::client::{Client, ClientConfig, Policy, Receiver, SendMode, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::{Keyring, PublicKeyBundle};
use mtp::type_map::TypeMap;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use uuid::Uuid;

use crate::omega_discovery;

fn typed_container(items: Vec<(DataType, DataValue)>) -> DataValue {
    use mtp::type_map::{DataTypeId, TypeMap};
    let tm = TypeMap::latest();
    DataValue::Container(
        items
            .into_iter()
            .filter_map(|(dt, dv)| tm.data_id_enum(dt).map(|id| (DataTypeId(id), dv)))
            .collect(),
    )
}

fn data_string(cv: &CommunicationValue, dt: DataType) -> Option<String> {
    cv.get_data(dt)
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| cv.get_data(dt).as_number().map(|n| n.to_string()))
        .or_else(|| cv.get_data(dt).as_signed_number().map(|n| n.to_string()))
}

fn data_i64(cv: &CommunicationValue, dt: DataType) -> Option<i64> {
    cv.get_data(dt)
        .as_number()
        .and_then(|n| i64::try_from(n).ok())
        .or_else(|| {
            cv.get_data(dt)
                .as_signed_number()
                .and_then(|n| i64::try_from(n).ok())
        })
        .or_else(|| cv.get_data(dt).as_str().and_then(|s| s.parse::<i64>().ok()))
}

#[derive(Debug, Clone)]
struct ChatSecretRecipient {
    user_id: String,
    encrypted_secret: Vec<u8>,
    kem_ciphertext: Vec<u8>,
}

fn recipient_from_value(value: &DataValue) -> Option<ChatSecretRecipient> {
    let tm = TypeMap::latest();
    let user_id = value
        .get_field(DataType::UserId.to_id(&tm))?
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .get_field(DataType::UserId.to_id(&tm))?
                .as_number()
                .map(|n| n.to_string())
        })?;
    let encrypted_secret = value
        .get_field(DataType::EncryptedSecret.to_id(&tm))?
        .as_bytes()?;
    let kem_ciphertext = value
        .get_field(DataType::KemCiphertext.to_id(&tm))?
        .as_bytes()?;

    Some(ChatSecretRecipient {
        user_id,
        encrypted_secret,
        kem_ciphertext,
    })
}

fn chat_secret_recipients(cv: &CommunicationValue) -> Option<Vec<ChatSecretRecipient>> {
    let recipients = cv.get_data(DataType::Recipients).as_array()?;
    let parsed = recipients
        .iter()
        .map(recipient_from_value)
        .collect::<Option<Vec<_>>>()?;

    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

fn set_chat_secret_cv_for_recipient(
    source: &CommunicationValue,
    recipient: &ChatSecretRecipient,
) -> CommunicationValue {
    let recipient_value = typed_container(vec![
        (DataType::UserId, DataValue::Str(recipient.user_id.clone())),
        (
            DataType::EncryptedSecret,
            DataValue::Bytes(recipient.encrypted_secret.clone()),
        ),
        (
            DataType::KemCiphertext,
            DataValue::Bytes(recipient.kem_ciphertext.clone()),
        ),
    ]);

    CommunicationValue::new(CommunicationType::SetChatSecret)
        .with_id(source.get_id())
        .with_sender(source.get_sender())
        .with_receiver(recipient.user_id.parse::<u64>().unwrap_or(0))
        .add_typed_default(DataType::ChatId, source.get_data(DataType::ChatId).clone())
        .add_typed_default(
            DataType::SecretId,
            source.get_data(DataType::SecretId).clone(),
        )
        .add_typed_default(
            DataType::VersionNumber,
            source.get_data(DataType::VersionNumber).clone(),
        )
        .add_typed_default(
            DataType::WrappingScheme,
            source.get_data(DataType::WrappingScheme).clone(),
        )
        .add_typed_default(
            DataType::CreatedAt,
            source.get_data(DataType::CreatedAt).clone(),
        )
        .add_typed_default(
            DataType::Recipients,
            DataValue::Array(vec![recipient_value]),
        )
}

fn now_millis_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn pending_chat_secret_forward_from_cv(
    cv: &CommunicationValue,
) -> Option<PendingChatSecretForward> {
    let recipient = chat_secret_recipients(cv)?.into_iter().next()?;
    Some(PendingChatSecretForward {
        recipient_user_id: recipient.user_id,
        chat_id: data_string(cv, DataType::ChatId)?,
        sender_user_id: cv.get_sender().to_string(),
        secret_id: data_string(cv, DataType::SecretId)?,
        version: data_i64(cv, DataType::VersionNumber)?,
        encrypted_secret: recipient.encrypted_secret,
        kem_ciphertext: recipient.kem_ciphertext,
        wrapping_scheme: data_string(cv, DataType::WrappingScheme)?,
        created_at: data_i64(cv, DataType::CreatedAt).unwrap_or_else(now_millis_i64),
    })
}

fn chat_secret_forward_cv(record: &PendingChatSecretForward) -> CommunicationValue {
    let recipient = typed_container(vec![
        (
            DataType::UserId,
            DataValue::Str(record.recipient_user_id.clone()),
        ),
        (
            DataType::EncryptedSecret,
            DataValue::Bytes(record.encrypted_secret.clone()),
        ),
        (
            DataType::KemCiphertext,
            DataValue::Bytes(record.kem_ciphertext.clone()),
        ),
    ]);

    CommunicationValue::new(CommunicationType::SetChatSecret)
        .with_sender(record.sender_user_id.parse::<u64>().unwrap_or(0))
        .with_receiver(record.recipient_user_id.parse::<u64>().unwrap_or(0))
        .add_typed_default(DataType::ChatId, DataValue::Str(record.chat_id.clone()))
        .add_typed_default(
            DataType::SenderUserId,
            DataValue::Str(record.sender_user_id.clone()),
        )
        .add_typed_default(DataType::SecretId, DataValue::Str(record.secret_id.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(record.version as i128),
        )
        .add_typed_default(
            DataType::WrappingScheme,
            DataValue::Str(record.wrapping_scheme.clone()),
        )
        .add_typed_default(
            DataType::CreatedAt,
            DataValue::SignedNumber(record.created_at as i128),
        )
        .add_typed_default(DataType::Recipients, DataValue::Array(vec![recipient]))
}

fn error_response(request: &CommunicationValue, ty: CommunicationType) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_id(request.get_id())
        .with_receiver(request.get_sender())
}

// Helper function to check if read receipts are enabled globally
async fn is_read_receipts_enabled() -> bool {
    CONFIG.load().read_receipts_enabled
}

// ============================================================================
// Configuration
// ============================================================================

const IOTA_KEYRING_PATH: &str = "iota.mk";
const OMIKRON_PUBLIC_KEY_PATH: &str = "omikron.mpkb";
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const TASK_MAX_AGE: Duration = Duration::from_secs(60);

// ============================================================================
// Waiting Task System
// ============================================================================

pub struct WaitingTask {
    pub task: Box<dyn Fn(Arc<OmikronConnection>, CommunicationValue) -> bool + Send + Sync>,
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
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub last_ping: Arc<Mutex<i64>>,
    heartbeat_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    reconnect_on_close: Arc<RwLock<bool>>,
    auth_failure: Arc<RwLock<Option<String>>>,
    pub app_challenges: Arc<RwLock<HashMap<u64, String>>>,
    pub app_sessions: Arc<RwLock<HashMap<u64, (i64, String)>>>,
}

impl OmikronConnection {
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);

        OmikronConnection {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sender: Arc::new(RwLock::new(None)),
            connection_loop_handle: Arc::new(Mutex::new(None)),
            last_ping: Arc::new(Mutex::new(-1)),
            heartbeat_handle: Arc::new(Mutex::new(None)),
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            reconnect_on_close: Arc::new(RwLock::new(true)),
            auth_failure: Arc::new(RwLock::new(None)),
            app_challenges: Arc::new(RwLock::new(HashMap::new())),
            app_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
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

        if let Some(handle) = self.heartbeat_handle.lock().await.take() {
            handle.abort();
        }

        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close();
        }

        *self.state.write().await = ConnectionState::Disconnected;
        *self.sender.write().await = None;
    }

    async fn connection_loop(self: Arc<Self>) {
        let mut reconnect_delay = RECONNECT_DELAY;
        let shutdown_rx = self.shutdown_tx.lock().await.as_ref().unwrap().subscribe();
        let mut shutdown_rx = shutdown_rx;

        loop {
            if *shutdown_rx.borrow() || *SHUTDOWN.read().await {
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
        *self.state.write().await = ConnectionState::Connecting;
        log_t!("omikron_connecting");

        let keyring = self.load_or_migrate_keyring().await;

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
                close_frame_len: u32::MAX,
                application_close_code: 0,
                open_stream_timeout: Duration::from_millis(2_000),
                write_timeout: Duration::from_millis(2_000),
                accept_stream_timeout: Duration::from_millis(10_000),
                read_timeout: Duration::from_millis(30_000),
                keep_alive_interval: Some(Duration::from_secs(6)),
                max_idle_timeout: Some(Duration::from_secs(30)),
                force_close_delay: Duration::from_millis(300),
                max_transient_recv_errors: 20,
                transient_recv_backoff: Duration::from_millis(100),
                receiver_queue_capacity: 1000,
            });

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
                *self.state.write().await = ConnectionState::Disconnected;
                return Err(reason);
            }
            Err(e) => return Err(format!("Connection failed: {}", e)),
        };

        log_t!("omikron_connection_success");

        if existing_iota_id.is_none() {
            modify_config(|cfg| cfg.iota_id = Some(connection.client_id));
            log!("Registered with Iota-ID: {}", connection.client_id);
        }

        let sender_arc = Arc::new(connection.sender);
        *self.sender.write().await = Some(sender_arc.clone());
        *self.state.write().await = ConnectionState::Connected { identified: true };

        // Start read loop
        let mut receiver = connection.receiver;
        let read_self = self.clone();
        let read_handle = tokio::spawn(async move {
            read_self.read_loop(&mut receiver).await;
        });

        log_t!("omikron_authenticated");

        // Start heartbeat
        let heartbeat_self = self.clone();
        let heartbeat_handle = tokio::spawn(async move {
            heartbeat_self.heartbeat_loop().await;
        });
        *self.heartbeat_handle.lock().await = Some(heartbeat_handle);

        {
            ACTIVE_TASKS.insert("Omikron Listener".to_string());
        }

        // Wait for read loop to complete
        let result = read_handle.await;
        *self.sender.write().await = None;
        *self.state.write().await = ConnectionState::Disconnected;
        {
            ACTIVE_TASKS.remove("Omikron Listener");
        }

        if let Some(handle) = self.heartbeat_handle.lock().await.take() {
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
        if let Ok(kr) = mtp::files::load_keyring(IOTA_KEYRING_PATH) {
            return kr;
        }

        let legacy = CONFIG.load().keyring.clone();
        let keyring = legacy
            .and_then(|b64| keyring_from_base64(&b64))
            .unwrap_or_else(crypto_helper::generate_keyring);

        if let Err(e) = mtp::files::save_keyring(&keyring, IOTA_KEYRING_PATH) {
            log!("Failed to persist {}: {}", IOTA_KEYRING_PATH, e);
        }

        let b64 = crypto_helper::keyring_to_base64(&keyring);
        modify_config(|cfg| cfg.keyring = Some(b64));

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
            let public_key = mtp::files::load_public_key_bundle(OMIKRON_PUBLIC_KEY_PATH)
                .map_err(|e| {
                    format!(
                        "Failed to load Omikron public key bundle from {}: {}. Obtain {} from the Omikron operator and place it in the working directory.",
                        OMIKRON_PUBLIC_KEY_PATH, e, OMIKRON_PUBLIC_KEY_PATH
                    )
                })?;
            return Ok((host, port, public_key));
        }

        let cached_key = mtp::files::load_public_key_bundle(OMIKRON_PUBLIC_KEY_PATH).ok();
        let cached_host_port = {
            let conf = CONFIG.load();
            match (&conf.omikron_host, conf.omikron_port) {
                (Some(host), Some(port)) => Some((host.clone(), port)),
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
                Some(cached) if cached.as_bytes() != endpoint.public_key.as_bytes() => {
                    log!(
                        "Fetched Omikron public key differs from the cached {} - keeping the \
                         cached key. Delete {} manually if this is an expected key rotation.",
                        OMIKRON_PUBLIC_KEY_PATH,
                        OMIKRON_PUBLIC_KEY_PATH
                    );
                    (endpoint.host, endpoint.port, cached.clone())
                }
                Some(cached) => (endpoint.host, endpoint.port, cached.clone()),
                None => {
                    if let Err(e) = mtp::files::save_public_key_bundle(
                        &endpoint.public_key,
                        OMIKRON_PUBLIC_KEY_PATH,
                    ) {
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
    // Read Loop & Heartbeat
    // -------------------------------------------------------------------------

    async fn read_loop(self: Arc<Self>, receiver: &mut Receiver) {
        loop {
            let result = receiver.receive().await;
            match result {
                Ok(cv) => {
                    self.clone().handle_message(cv).await;
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
            if !receiver.is_open() {
                self.fail_all_waiting_tasks(format!(
                    "Connection closed (connection_id={}, receiver_open=false)",
                    self.connection_id
                ))
                .await;
                break;
            }
        }
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        loop {
            sleep(HEARTBEAT_INTERVAL).await;

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

            self.flush_pending_chat_secret_forwards().await;
            self.send_ping().await;
        }
    }

    async fn forward_chat_secret(&self, cv: &CommunicationValue) -> bool {
        self.await_response(cv, Some(Duration::from_secs(10)))
            .await
            .is_ok()
    }

    async fn store_pending_chat_secret_forward(&self, cv: &CommunicationValue) {
        let Some(record) = pending_chat_secret_forward_from_cv(cv) else {
            return;
        };
        let _ = e2ee_storage::put_pending_chat_secret_forward(record);
    }

    async fn flush_pending_chat_secret_forwards(&self) {
        let Ok(records) = e2ee_storage::get_pending_chat_secret_forwards(100) else {
            return;
        };

        for record in records {
            let Ok(recipient) = record.recipient_user_id.parse::<u64>() else {
                let _ = e2ee_storage::delete_pending_chat_secret_forward(
                    &record.recipient_user_id,
                    &record.chat_id,
                    &record.secret_id,
                );
                continue;
            };

            let message = chat_secret_forward_cv(&record).with_receiver(recipient);
            if self.forward_chat_secret(&message).await {
                let _ = e2ee_storage::delete_pending_chat_secret_forward(
                    &record.recipient_user_id,
                    &record.chat_id,
                    &record.secret_id,
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // Message Handling (Preserved from original)
    // -------------------------------------------------------------------------

    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if !cv.is_type(CommunicationType::Ping) && !cv.is_type(CommunicationType::Pong) {
            log_cv_in!(&cv);
        }

        let msg_id = cv.get_id();

        // Dispatch waiting task for this message id
        if let Some((_, task)) = WAITING_TASKS.remove(&msg_id) {
            if (task.task)(self.clone(), cv.clone()) {
                return;
            }
        }

        if cv.is_type(CommunicationType::Pong) {
            self.handle_pong(&cv).await;
            return;
        }

        if cv.is_type(CommunicationType::SetChatSecret) {
            let sender_id = cv.get_sender().to_string();
            let recipients = match chat_secret_recipients(&cv) {
                Some(recipients) => recipients,
                None => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                        .await;
                    return;
                }
            };
            let now = now_millis_i64();
            let chat_id = data_string(&cv, DataType::ChatId);
            let secret_id = data_string(&cv, DataType::SecretId);
            let version = data_i64(&cv, DataType::VersionNumber);
            let wrapping_scheme = data_string(&cv, DataType::WrappingScheme);
            let created_at = data_i64(&cv, DataType::CreatedAt).unwrap_or(now);

            let Some((((chat_id, secret_id), version), wrapping_scheme)) =
                chat_id.zip(secret_id).zip(version).zip(wrapping_scheme)
            else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };

            for recipient in &recipients {
                let recipient_id = recipient.user_id.parse::<i64>().unwrap_or(0);
                let is_local = iota_storage::users::user_manager::get_user(recipient_id).is_some();

                if is_local {
                    if e2ee_storage::put_chat_secret(StoredChatSecret {
                        user_id: recipient.user_id.clone(),
                        chat_id: chat_id.clone(),
                        secret_id: secret_id.clone(),
                        version,
                        encrypted_secret: recipient.encrypted_secret.clone(),
                        kem_ciphertext: recipient.kem_ciphertext.clone(),
                        wrapping_scheme: wrapping_scheme.clone(),
                        created_at,
                        updated_at: now,
                    })
                    .is_err()
                    {
                        self.send_message(&error_response(
                            &cv,
                            CommunicationType::ErrorInvalidData,
                        ))
                        .await;
                        return;
                    }
                    continue;
                }

                if recipient.user_id != sender_id {
                    let forward = set_chat_secret_cv_for_recipient(&cv, recipient);
                    if !self.forward_chat_secret(&forward).await {
                        self.store_pending_chat_secret_forward(&forward).await;
                    }
                }
            }

            self.send_message(&error_response(&cv, CommunicationType::Success))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::GetChatSecret) {
            let Some(user_id) = data_string(&cv, DataType::UserId) else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };
            if user_id != cv.get_sender().to_string() {
                self.send_message(&error_response(&cv, CommunicationType::ErrorNotFound))
                    .await;
                return;
            }
            let Some(chat_id) = data_string(&cv, DataType::ChatId) else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };

            match e2ee_storage::get_chat_secret(ChatSecretQuery {
                user_id,
                chat_id,
                secret_id: data_string(&cv, DataType::SecretId),
            }) {
                Ok(Some(record)) => {
                    let response = CommunicationValue::new(CommunicationType::ChatSecretResponse)
                        .with_id(cv.get_id())
                        .with_receiver(cv.get_sender())
                        .add_typed_default(DataType::UserId, DataValue::Str(record.user_id))
                        .add_typed_default(DataType::ChatId, DataValue::Str(record.chat_id))
                        .add_typed_default(DataType::SecretId, DataValue::Str(record.secret_id))
                        .add_typed_default(
                            DataType::VersionNumber,
                            DataValue::SignedNumber(record.version as i128),
                        )
                        .add_typed_default(
                            DataType::EncryptedSecret,
                            DataValue::Bytes(record.encrypted_secret),
                        )
                        .add_typed_default(
                            DataType::KemCiphertext,
                            DataValue::Bytes(record.kem_ciphertext),
                        )
                        .add_typed_default(
                            DataType::WrappingScheme,
                            DataValue::Str(record.wrapping_scheme),
                        )
                        .add_typed_default(
                            DataType::CreatedAt,
                            DataValue::SignedNumber(record.created_at as i128),
                        )
                        .add_typed_default(
                            DataType::UpdatedAt,
                            DataValue::SignedNumber(record.updated_at as i128),
                        );
                    self.send_message(&response).await;
                }
                Ok(None) => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorNotSet))
                        .await
                }
                Err(_) => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                        .await
                }
            }
            return;
        }

        if cv.is_type(CommunicationType::ChatSecretForward) {
            let sender_id = cv.get_sender().to_string();
            let recipient_user_id = data_string(&cv, DataType::RecipientUserId).unwrap_or_default();
            if data_string(&cv, DataType::SenderUserId).as_deref() != Some(sender_id.as_str())
                || recipient_user_id.is_empty()
                || pending_chat_secret_forward_from_cv(&cv).is_none()
            {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }

            let forward = cv
                .clone()
                .with_receiver(recipient_user_id.parse::<u64>().unwrap_or(0));
            if self.forward_chat_secret(&forward).await {
                self.send_message(&error_response(&cv, CommunicationType::Success))
                    .await;
            } else {
                self.store_pending_chat_secret_forward(&cv).await;
                self.send_message(&error_response(&cv, CommunicationType::Success))
                    .await;
            }
            return;
        }

        if cv.is_type(CommunicationType::AppIdentification) {
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

                self.app_challenges
                    .write()
                    .await
                    .insert(sender_id, challenge.clone());
                self.app_sessions
                    .write()
                    .await
                    .insert(sender_id, (user_id, app_identifier.clone()));

                if let Some(app_pub_bundle) =
                    iota_util::crypto_helper::public_key_bundle_from_base64(&app_public_key)
                {
                    let kr_str = CONFIG.load().keyring.clone().unwrap_or_default();

                    if let Some(keyring) = keyring_from_base64(&kr_str) {
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

                            self.send_message(&res).await;
                            return;
                        }
                    }
                }
            }

            let res = CommunicationValue::new(CommunicationType::ErrorInvalidChallenge)
                .with_id(cv.get_id())
                .with_receiver(sender_id);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::AppChallengeResponse) {
            let sender_id = cv.get_sender();
            let mut challenges = self.app_challenges.write().await;
            if let Some(expected) = challenges.remove(&sender_id) {
                if let DataValue::Str(response) = cv.get_data(DataType::Challenge) {
                    if expected == *response {
                        let res =
                            CommunicationValue::new(CommunicationType::AppIdentificationResponse)
                                .with_id(cv.get_id())
                                .with_receiver(sender_id);
                        self.send_message(&res).await;
                        return;
                    }
                }
            }
            let res = CommunicationValue::new(CommunicationType::ErrorInvalidChallenge)
                .with_id(cv.get_id())
                .with_receiver(sender_id);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::SaveAppData) {
            let sender_id = cv.get_sender();
            let app_data = cv
                .get_data(DataType::AppData)
                .as_str()
                .unwrap_or("")
                .to_string();

            let sessions = self.app_sessions.read().await;
            if let Some((user_id, app_identifier)) = sessions.get(&sender_id) {
                iota_storage::users::user_manager::save_app_data(
                    *user_id,
                    app_identifier,
                    &app_data,
                );
            }

            let res = CommunicationValue::new(CommunicationType::SaveAppData)
                .with_id(cv.get_id())
                .with_receiver(sender_id);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::LoadAppData) {
            let sender_id = cv.get_sender();
            let mut app_data = String::new();

            let sessions = self.app_sessions.read().await;
            if let Some((user_id, app_identifier)) = sessions.get(&sender_id) {
                app_data =
                    iota_storage::users::user_manager::load_app_data(*user_id, app_identifier);
            }

            let res = CommunicationValue::new(CommunicationType::LoadAppData)
                .with_id(cv.get_id())
                .with_receiver(sender_id)
                .add_typed_default(DataType::AppData, DataValue::Str(app_data));
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::CreateApp) {
            let sender_id = cv.get_sender() as i64;
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

            if !app_identifier.is_empty() && !app_public_key.is_empty() {
                if let Some(mut user) = iota_storage::users::user_manager::get_user(sender_id) {
                    if !user.trusted_apps.contains_key(&app_identifier) {
                        user.trusted_apps.insert(app_identifier, app_public_key);
                        iota_storage::users::user_manager::update_user(user);
                    }
                }
            }

            let res = CommunicationValue::new(CommunicationType::CreateApp)
                .with_id(cv.get_id())
                .with_receiver(sender_id as u64);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::DeleteApp) {
            let sender_id = cv.get_sender() as i64;
            let app_identifier = cv
                .get_data(DataType::AppIdentifier)
                .as_str()
                .unwrap_or("")
                .to_string();

            if !app_identifier.is_empty() {
                if let Some(mut user) = iota_storage::users::user_manager::get_user(sender_id) {
                    if user.trusted_apps.contains_key(&app_identifier) {
                        user.trusted_apps.remove(&app_identifier);
                        iota_storage::users::user_manager::update_user(user);
                    }
                }
            }

            let res = CommunicationValue::new(CommunicationType::DeleteApp)
                .with_id(cv.get_id())
                .with_receiver(sender_id as u64);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::ClientConnected) {
            let user_id = cv.get_data(DataType::UserId).as_number().unwrap_or(0) as i64;
            let _session_id = cv.get_data(DataType::SessionId).as_number().unwrap_or(0) as i64;

            let contacts = chats_util::get_users(user_id);
            let mut contacts_array = Vec::new();

            for (i, contact) in contacts.iter().enumerate() {
                let mut contact_container = Vec::new();
                contact_container.push((
                    DataType::UserId,
                    DataValue::SignedNumber(contact.user_id as i128),
                ));
                contact_container.push((
                    DataType::LastMessageAt,
                    DataValue::SignedNumber(contact.last_message_at.unwrap_or(0) as i128),
                ));

                if let Some(ref name) = contact.user_name {
                    contact_container.push((DataType::Username, DataValue::Str(name.clone())));
                }

                let amount = if i < 10 { 20 } else { 1 };
                let messages = chat_files::get_messages(user_id, contact.user_id, 0, amount);

                let mut msg_array = Vec::new();
                for m in messages.members() {
                    let message_time = m["message_time"].as_i64().unwrap_or(0);
                    let content = m["content"].as_str().unwrap_or("").to_string();
                    let sent_by_self = m["sent_by_self"].as_bool().unwrap_or(false);
                    let height = m["height"].as_i64().unwrap_or(0);
                    let message_state = m["message_state"].as_str().unwrap_or("").to_string();

                    let mut msg_container = Vec::new();
                    msg_container.push((
                        DataType::SendTime,
                        DataValue::SignedNumber(message_time as i128),
                    ));
                    msg_container.push((DataType::Content, DataValue::Str(content.clone())));
                    msg_container.push((DataType::MessageState, DataValue::Str(message_state)));
                    msg_container.push((DataType::Height, DataValue::SignedNumber(height as i128)));
                    msg_container.push((DataType::SentBySelf, DataValue::Bool(sent_by_self)));
                    msg_array.push(typed_container(msg_container));

                    if msg_array.len() == 1 {
                        let sender_id = if sent_by_self {
                            user_id
                        } else {
                            contact.user_id
                        };
                        let mut last_msg = Vec::new();
                        last_msg.push((DataType::Content, DataValue::Str(content)));
                        last_msg.push((
                            DataType::SenderId,
                            DataValue::SignedNumber(sender_id as i128),
                        ));
                        contact_container.push((DataType::LastMessage, typed_container(last_msg)));
                    }
                }
                contact_container.push((DataType::Messages, DataValue::Array(msg_array)));
                contacts_array.push(typed_container(contact_container));
            }

            let resp = CommunicationValue::new(CommunicationType::ClientConnected)
                .with_id(cv.get_id())
                .add_typed_default(DataType::Contacts, DataValue::Array(contacts_array));
            self.send_message(&resp).await;
            return;
        }

        // ************************************************ //
        // Direct messages                                  //
        // ************************************************ //

        if cv.is_type(CommunicationType::MessageState) {
            let sender_id = &cv.get_sender();
            let receiver_id = match cv.get_data(DataType::ChatPartnerId).as_number() {
                Some(id) => id,
                _ => return,
            };

            // Parse send_time robustly: accept numeric or string, fallback to current time
            let send_time_val = cv.get_data(DataType::SendTime);
            let now_i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let timestamp_i64 = if let Some(n) = send_time_val.as_number() {
                n as i64
            } else if let Some(s) = send_time_val.as_str() {
                s.parse::<i64>().unwrap_or(now_i64)
            } else {
                now_i64
            };

            let _ = chat_files::change_message_state(
                timestamp_i64,
                receiver_id as i64,
                *sender_id as i64,
                MessageState::from_str(cv.get_data(DataType::MessageState).as_str().unwrap_or("")),
            );
        }

        // Incoming storsed message: store for the recipient, attempt local delivery, notify sender.
        if cv.is_type(CommunicationType::MessageSend) {
            let sender_id: u64 = cv.get_sender();

            // parse receiver_id (the storage owner for this incoming message)
            let receiver_id: i64 = if let Some(n) = cv.get_data(DataType::ReceiverId).as_number() {
                n as i64
            } else if let Some(s) = cv.get_data(DataType::ReceiverId).as_str() {
                s.parse::<i64>().unwrap_or(0)
            } else {
                0
            };

            // parse send_time robustly (number or string), fallback to now
            let send_time_val = cv.get_data(DataType::SendTime);
            let now_i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let timestamp_i64 = if let Some(n) = send_time_val.as_number() {
                n as i64
            } else if let Some(s) = send_time_val.as_str() {
                s.parse::<i64>().unwrap_or(now_i64)
            } else {
                now_i64
            };
            let timestamp_u128 = timestamp_i64 as u128;

            // content may be missing; default to empty string
            let content = cv
                .get_data(DataType::Content)
                .as_str()
                .unwrap_or("")
                .to_string();

            let height = cv.get_data(DataType::Height).as_number().unwrap_or(0) as i64;

            let is_local = iota_storage::users::user_manager::get_user(receiver_id).is_some();

            if is_local {
                // persist message for the receiver (storage_owner = receiver_id)
                chat_files::add_message(
                    timestamp_u128,
                    false,
                    receiver_id as i64,
                    sender_id as i64,
                    &content,
                    height,
                );
            }

            // persist message for the sender (storage_owner = sender_id)
            chat_files::add_message(
                timestamp_u128,
                true,
                sender_id as i64,
                receiver_id as i64,
                &content,
                height,
            );

            // send confirmation back to sender
            let conf_msg = CommunicationValue::new(CommunicationType::MessageSend)
                .with_id(cv.get_id())
                .with_receiver(sender_id as u64);
            self.send_message(&conf_msg).await;

            if !is_local {
                let fw_msg = CommunicationValue::new(CommunicationType::MessageOtherIota)
                    .with_id(cv.get_id())
                    .with_receiver(receiver_id as u64)
                    .with_sender(sender_id as u64)
                    .add_typed_default(DataType::Height, DataValue::SignedNumber(height as i128))
                    .add_typed_default(DataType::Content, DataValue::Str(content))
                    .add_typed_default(
                        DataType::SendTime,
                        DataValue::SignedNumber(timestamp_i64 as i128),
                    );

                let other_iota_resp = self
                    .clone()
                    .await_response(&fw_msg, Some(Duration::from_secs(10)))
                    .await;

                if let Ok(resp) = other_iota_resp {
                    let ms_raw = resp
                        .get_data(DataType::MessageState)
                        .as_string()
                        .unwrap_or_else(|| "".to_string());
                    let ms = MessageState::from_str(&ms_raw).upgrade(MessageState::Received);

                    let _ = chat_files::change_message_state(
                        timestamp_i64,
                        sender_id as i64,
                        receiver_id as i64,
                        ms.clone(),
                    );

                    self.send_message(
                        &CommunicationValue::new(CommunicationType::MessageState)
                            .with_id(cv.get_id())
                            .with_receiver(sender_id as u64)
                            .with_sender(receiver_id as u64)
                            .add_typed_default(
                                DataType::ChatPartnerId,
                                DataValue::SignedNumber(receiver_id as i128),
                            )
                            .add_typed_default(
                                DataType::SendTime,
                                DataValue::SignedNumber(timestamp_i64 as i128),
                            )
                            .add_typed_default(
                                DataType::MessageState,
                                DataValue::Str(ms.as_str().to_string()),
                            ),
                    )
                    .await;
                } else {
                    let _ = chat_files::change_message_state(
                        timestamp_i64,
                        sender_id as i64,
                        receiver_id as i64,
                        MessageState::Sent,
                    );

                    self.send_message(
                        &CommunicationValue::new(CommunicationType::MessageState)
                            .with_id(cv.get_id())
                            .with_receiver(sender_id as u64)
                            .with_sender(receiver_id as u64)
                            .add_typed_default(
                                DataType::ChatPartnerId,
                                DataValue::SignedNumber(receiver_id as i128),
                            )
                            .add_typed_default(
                                DataType::SendTime,
                                DataValue::SignedNumber(timestamp_i64 as i128),
                            )
                            .add_typed_default(
                                DataType::MessageState,
                                DataValue::Str(MessageState::Sent.as_str().to_string()),
                            ),
                    )
                    .await;
                }
                return;
            } else {
                // Build a live-delivery message for the local client (recipient)
                let user_forward = CommunicationValue::new(CommunicationType::MessageLive)
                    .with_id(cv.get_id())
                    .with_receiver(receiver_id as u64)
                    .add_typed_default(
                        DataType::SenderId,
                        DataValue::SignedNumber(sender_id as i128),
                    )
                    .add_typed_default(
                        DataType::Message,
                        typed_container(vec![
                            (DataType::Content, DataValue::Str(content.clone())),
                            (
                                DataType::SendTime,
                                DataValue::SignedNumber(timestamp_i64 as i128),
                            ),
                            (DataType::Height, DataValue::SignedNumber(height as i128)),
                        ]),
                    );

                // Attempt delivery and await a response from the local client
                let user_resp = self
                    .clone()
                    .await_response(&user_forward, Some(Duration::from_secs(3)))
                    .await;

                if let Ok(user_resp) = user_resp {
                    let ms_raw = user_resp
                        .get_data(DataType::MessageState)
                        .as_string()
                        .unwrap_or_else(|| "".to_string());
                    let ms = MessageState::from_str(&ms_raw).upgrade(MessageState::Received);

                    // update stored message state for receiver
                    let _ = chat_files::change_message_state(
                        timestamp_i64,
                        receiver_id as i64,
                        sender_id as i64,
                        ms.clone(),
                    );

                    // update stored message state for sender
                    let _ = chat_files::change_message_state(
                        timestamp_i64,
                        sender_id as i64,
                        receiver_id as i64,
                        ms.clone(),
                    );

                    // notify original sender about the delivered/read state (if read receipts are enabled)
                    if is_read_receipts_enabled().await {
                        self.send_message(
                            &CommunicationValue::new(CommunicationType::MessageState)
                                .with_id(cv.get_id())
                                .with_receiver(sender_id as u64)
                                .with_sender(receiver_id as u64)
                                .add_typed_default(
                                    DataType::ChatPartnerId,
                                    DataValue::SignedNumber(receiver_id as i128),
                                )
                                .add_typed_default(
                                    DataType::SendTime,
                                    DataValue::SignedNumber(timestamp_i64 as i128),
                                )
                                .add_typed_default(
                                    DataType::MessageState,
                                    DataValue::Str(ms.as_str().to_string()),
                                ),
                        )
                        .await;
                    }
                } else {
                    // Delivery failed or timed out; mark as Sent
                    let _ = chat_files::change_message_state(
                        timestamp_i64,
                        receiver_id as i64,
                        sender_id as i64,
                        MessageState::Sent,
                    );

                    let _ = chat_files::change_message_state(
                        timestamp_i64,
                        sender_id as i64,
                        receiver_id as i64,
                        MessageState::Sent,
                    );

                    // Send push notification to Omega since user is offline
                    let push_msg = CommunicationValue::new(CommunicationType::PushNotification)
                        .with_receiver(receiver_id as u64)
                        .add_typed_default(
                            DataType::SenderId,
                            DataValue::SignedNumber(sender_id as i128),
                        );
                    self.send_message(&push_msg).await;

                    // notify sender
                    self.send_message(
                        &CommunicationValue::new(CommunicationType::MessageState)
                            .with_id(cv.get_id())
                            .with_receiver(sender_id as u64)
                            .with_sender(receiver_id as u64)
                            .add_typed_default(
                                DataType::SendTime,
                                DataValue::SignedNumber(timestamp_i64 as i128),
                            )
                            .add_typed_default(
                                DataType::ChatPartnerId,
                                DataValue::SignedNumber(receiver_id as i128),
                            )
                            .add_typed_default(
                                DataType::MessageState,
                                DataValue::Str(MessageState::Sent.as_str().to_string()),
                            ),
                    )
                    .await;
                }
                return;
            }
        }

        if cv.is_type(CommunicationType::MessageOtherIota) {
            let sender_id = &cv.get_sender();
            let receiver_id = &cv.get_receiver();

            // parse send_time safely (number or string), fallback to now
            let send_time_val = cv.get_data(DataType::SendTime);
            let now_i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let timestamp = if let Some(n) = send_time_val.as_number() {
                n as i64
            } else if let Some(s) = send_time_val.as_str() {
                s.parse::<i64>().unwrap_or(now_i64)
            } else {
                now_i64
            };

            // content may be missing or non-string; default to empty string
            let content = cv
                .get_data(DataType::Content)
                .as_str()
                .unwrap_or("")
                .to_string();

            let height = cv.get_data(DataType::Height).as_number().unwrap_or(0) as i64;

            chat_files::add_message(
                timestamp as u128,
                false,
                *receiver_id as i64,
                *sender_id as i64,
                &content,
                height,
            );

            // Build user_forward using the parsed numeric timestamp and safe content string
            let user_forward = CommunicationValue::new(CommunicationType::MessageLive)
                .with_id(cv.get_id())
                .with_receiver(*receiver_id)
                .add_typed_default(
                    DataType::SenderId,
                    DataValue::SignedNumber(*sender_id as i128),
                )
                .add_typed_default(
                    DataType::Message,
                    typed_container(vec![
                        (DataType::Content, DataValue::Str(content.clone())),
                        (
                            DataType::SendTime,
                            DataValue::SignedNumber(timestamp as i128),
                        ),
                        (DataType::Height, DataValue::SignedNumber(height as i128)),
                    ]),
                );

            let user_resp = self
                .clone()
                .await_response(&user_forward, Some(Duration::from_secs(3)))
                .await;

            if let Ok(user_resp) = user_resp {
                let ms_raw = user_resp
                    .get_data(DataType::MessageState)
                    .as_string()
                    .unwrap_or_else(|| "".to_string());
                let ms = MessageState::from_str(&ms_raw).upgrade(MessageState::Received);

                let _ = change_message_state(
                    timestamp,
                    *receiver_id as i64,
                    *sender_id as i64,
                    ms.clone(),
                );

                // notify original sender about the delivered/read state (if read receipts are enabled)
                if is_read_receipts_enabled().await {
                    self.send_message(
                        &CommunicationValue::new(CommunicationType::MessageState)
                            .with_id(cv.get_id())
                            .with_receiver(*sender_id)
                            .with_sender(*receiver_id)
                            .add_typed_default(
                                DataType::SendTime,
                                DataValue::SignedNumber(timestamp as i128),
                            )
                            .add_typed_default(
                                DataType::ChatPartnerId,
                                DataValue::SignedNumber(*sender_id as i128),
                            )
                            .add_typed_default(
                                DataType::MessageState,
                                DataValue::Str(ms.as_str().to_string()),
                            ),
                    )
                    .await;
                }
            } else {
                // Delivery timed out/failed — update stored state and notify sender with numeric timestamp
                let _ = chat_files::change_message_state(
                    timestamp,
                    *receiver_id as i64,
                    *sender_id as i64,
                    MessageState::Sent,
                );

                // Send push notification to Omega since user is offline
                let push_msg = CommunicationValue::new(CommunicationType::PushNotification)
                    .with_receiver(*receiver_id)
                    .add_typed_default(
                        DataType::SenderId,
                        DataValue::SignedNumber(*sender_id as i128),
                    );
                self.send_message(&push_msg).await;

                self.send_message(
                    &CommunicationValue::new(CommunicationType::MessageState)
                        .with_id(cv.get_id())
                        .with_receiver(*sender_id)
                        .with_sender(*receiver_id)
                        .add_typed_default(
                            DataType::SendTime,
                            DataValue::SignedNumber(timestamp as i128),
                        )
                        .add_typed_default(
                            DataType::ChatPartnerId,
                            DataValue::SignedNumber(*receiver_id as i128),
                        )
                        .add_typed_default(
                            DataType::MessageState,
                            DataValue::Str(MessageState::Sent.as_str().to_string()),
                        ),
                )
                .await;
            }
            return;
        }

        if cv.is_type(CommunicationType::MessagesGet) {
            let my_id = cv.get_sender();
            let partner_id = cv.get_data(DataType::UserId).as_number().unwrap_or(0);
            let offset = cv.get_data(DataType::Offset).as_number().unwrap_or(0);
            let amount = cv.get_data(DataType::Amount).as_number().unwrap_or(0);
            let messages = chat_files::get_messages(
                my_id as i64,
                partner_id as i64,
                offset as i64,
                amount as i64,
            );
            let mut msg_array: Vec<DataValue> = Vec::new();
            for m in messages.members() {
                let message_time: i64 = m["message_time"].as_i64().unwrap_or(0);
                let content: String = m["content"].as_str().unwrap_or("").to_string();
                let sent_by_self: bool = m["sent_by_self"].as_bool().unwrap_or(false);
                let height: i64 = m["height"].as_i64().unwrap_or(0);
                let sender_id: i64 = if sent_by_self {
                    my_id as i64
                } else {
                    if let Some(n) = cv.get_data(DataType::ChatPartnerId).as_number() {
                        n as i64
                    } else if let Some(s) = cv.get_data(DataType::ChatPartnerId).as_str() {
                        s.parse::<i64>().unwrap_or(partner_id as i64)
                    } else {
                        partner_id as i64
                    }
                };
                let message_state: String = m["message_state"].as_str().unwrap_or("").to_string();

                let mut container = Vec::new();
                container.push((
                    DataType::SendTime,
                    DataValue::SignedNumber(message_time as i128),
                ));
                container.push((DataType::Content, DataValue::Str(content)));
                container.push((
                    DataType::SenderId,
                    DataValue::SignedNumber(sender_id as i128),
                ));
                container.push((DataType::MessageState, DataValue::Str(message_state)));
                container.push((DataType::Height, DataValue::SignedNumber(height as i128)));
                container.push((DataType::SentBySelf, DataValue::Bool(sent_by_self)));
                msg_array.push(typed_container(container));
            }

            let resp = CommunicationValue::new(CommunicationType::MessagesGet)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_typed_default(DataType::Messages, DataValue::Array(msg_array));

            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::GetChats) {
            let user_id = cv.get_sender();
            let users = chats_util::get_users(user_id as i64);
            let mut user_array = Vec::new();
            for user in users {
                let mut container = Vec::new();
                container.push((
                    DataType::UserId,
                    DataValue::SignedNumber(user.user_id as i128),
                ));
                if let Some(name) = user.user_name {
                    container.push((DataType::Username, DataValue::Str(name)));
                }
                if let Some(ts) = user.last_message_at {
                    container.push((DataType::LastMessageAt, DataValue::SignedNumber(ts as i128)));
                }
                user_array.push(typed_container(container));
            }
            let resp = CommunicationValue::new(CommunicationType::GetChats)
                .with_id(cv.get_id())
                .with_receiver(user_id)
                .add_typed_default(DataType::UserIds, DataValue::Array(user_array));
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::AddConversation) {
            let user_id = cv.get_sender();
            let other_id = match cv.get_data(DataType::ChatPartnerId).as_number() {
                Some(n) => n as i64,
                None => cv
                    .get_data(DataType::ChatPartnerId)
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0),
            };
            let mut contact = get_user(user_id as i64, other_id).unwrap_or(Contact::new(other_id));

            if let Some(name) = cv.get_data(DataType::ChatPartnerName).as_str() {
                contact.user_name = Some(name.to_string());
            }

            contact.set_last_message_at(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64,
            );
            mod_user(user_id as i64, &contact);
            let resp = CommunicationValue::new(CommunicationType::AddConversation)
                .with_id(cv.get_id())
                .with_receiver(user_id);
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::AddCommunity) {
            CommunitiesUtil::add_community(
                cv.get_sender() as i64,
                cv.get_data(DataType::CommunityAddress)
                    .as_str()
                    .unwrap()
                    .to_string(),
                cv.get_data(DataType::CommunityTitle)
                    .as_str()
                    .unwrap()
                    .to_string(),
                cv.get_data(DataType::Position)
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
            let resp = CommunicationValue::new(CommunicationType::AddCommunity)
                .with_id(cv.get_id())
                .with_receiver(cv.get_sender());
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::GetCommunities) {
            let mut comm_array = Vec::new();
            for c in CommunitiesUtil::get_communities(cv.get_sender() as i64) {
                let mut container: Vec<(DataType, DataValue)> = Vec::new();
                if let Some(address) = c["address"].as_str() {
                    container.push((
                        DataType::CommunityAddress,
                        DataValue::Str(address.to_string()),
                    ));
                }
                if let Some(title) = c["title"].as_str() {
                    container.push((DataType::CommunityTitle, DataValue::Str(title.to_string())));
                }
                if let Some(position) = c["position"].as_str() {
                    container.push((DataType::Position, DataValue::Str(position.to_string())));
                }
                comm_array.push(typed_container(container));
            }

            let resp = CommunicationValue::new(CommunicationType::GetCommunities)
                .with_id(cv.get_id())
                .with_receiver(cv.get_sender())
                .add_typed_default(DataType::Communities, DataValue::Array(comm_array));
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::RemoveCommunity) {
            CommunitiesUtil::remove_community(
                cv.get_sender() as i64,
                cv.get_data(DataType::CommunityAddress)
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
            let resp = CommunicationValue::new(CommunicationType::RemoveCommunity)
                .with_id(cv.get_id())
                .with_receiver(cv.get_sender());
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::GlobalSettingsSave) {
            let my_id = cv.get_sender();
            let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Missing settings payload".to_string()),
                    );
                self.send_message(&response).await;
                return;
            };

            save_file(
                &format!("users/{}", my_id),
                "global.settings",
                settings_value,
            );

            let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsSave)
                .with_receiver(my_id)
                .with_id(cv.get_id());

            if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
                response = response.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id as i128),
                );
            }

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::GlobalSettingsLoad) {
            let my_id = cv.get_sender();
            let path = format!("users/{}", my_id);
            let name = "global.settings";

            if !has_file(&path, name) {
                let mut response = CommunicationValue::new(CommunicationType::ErrorNotFound)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(DataType::Path, DataValue::Str(name.to_string()));

                if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
                    response = response.add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(session_id as i128),
                    );
                }

                self.send_message(&response).await;
                return;
            }

            let settings_value_str = load_file(&path, name);
            let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsLoad)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str));

            if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
                response = response.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id as i128),
                );
            }

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsSave) {
            let my_id = cv.get_sender();
            let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Missing session_id".to_string()),
                    );
                self.send_message(&response).await;
                return;
            };
            let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Missing settings_name".to_string()),
                    )
                    .add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(session_id as i128),
                    );
                self.send_message(&response).await;
                return;
            };
            let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Missing settings payload".to_string()),
                    )
                    .add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(session_id as i128),
                    );
                self.send_message(&response).await;
                return;
            };

            if !settings_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
                || settings_name.contains("..")
            {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Invalid settings_name".to_string()),
                    )
                    .add_typed_default(
                        DataType::SettingsName,
                        DataValue::Str(settings_name.to_string()),
                    )
                    .add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(session_id as i128),
                    );
                self.send_message(&response).await;
                return;
            }

            save_file(
                &format!("users/{}/settings/{}/", my_id, session_id),
                &format!("{}.settings", settings_name),
                settings_value,
            );

            let response = CommunicationValue::new(CommunicationType::SettingsSave)
                .with_receiver(my_id)
                .with_id(cv.get_id())
                .add_typed_default(
                    DataType::SettingsName,
                    DataValue::Str(settings_name.to_string()),
                )
                .add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id as i128),
                );

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsLoad) {
            let my_id = cv.get_sender();
            let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Missing session_id".to_string()),
                    );
                self.send_message(&response).await;
                return;
            };
            let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Missing settings_name".to_string()),
                    )
                    .add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(session_id as i128),
                    );
                self.send_message(&response).await;
                return;
            };

            if !settings_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
                || settings_name.contains("..")
            {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Invalid settings_name".to_string()),
                    )
                    .add_typed_default(
                        DataType::SettingsName,
                        DataValue::Str(settings_name.to_string()),
                    )
                    .add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(session_id as i128),
                    );
                self.send_message(&response).await;
                return;
            }

            let settings_file = format!("{}.settings", settings_name);
            let settings_path = format!("users/{}/settings/{}/", my_id, session_id);
            if !has_file(&settings_path, &settings_file) {
                let response = CommunicationValue::new(CommunicationType::ErrorNotFound)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::SettingsName,
                        DataValue::Str(settings_name.to_string()),
                    )
                    .add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(session_id as i128),
                    );
                self.send_message(&response).await;
                return;
            }

            let settings_value_str = load_file(&settings_path, &settings_file);
            let response = CommunicationValue::new(CommunicationType::SettingsLoad)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str))
                .add_typed_default(
                    DataType::SettingsName,
                    DataValue::Str(settings_name.to_string()),
                )
                .add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id as i128),
                );

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsList) {
            let my_id = cv.get_sender();
            let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
                let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(cv.get_id())
                    .with_receiver(my_id)
                    .add_typed_default(
                        DataType::Message,
                        DataValue::Str("Missing session_id".to_string()),
                    );
                self.send_message(&response).await;
                return;
            };

            let settings = get_children(&format!("users/{}/settings/{}/", my_id, session_id));
            let mut settings_json = Vec::new();
            for s in settings {
                let s = s.replace(".settings", "");
                if s.is_empty() {
                    continue;
                }
                let _ = settings_json.push(DataValue::Str(s));
            }
            let response = CommunicationValue::new(CommunicationType::SettingsList)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_typed_default(DataType::Settings, DataValue::Array(settings_json))
                .add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id as i128),
                );

            self.send_message(&response).await;
            return;
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    pub async fn send_message(&self, cv: &CommunicationValue) {
        if let Err(err) = self.send_message_result(cv).await {
            log_t!("send_message_failed", err);
        }
    }

    async fn send_message_result(&self, cv: &CommunicationValue) -> Result<(), String> {
        let sender_guard = self.sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
            if !sender.is_open() {
                drop(sender_guard);
                if let Some(sender) = self.sender.write().await.take() {
                    sender.close();
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

            if !cv.is_type(CommunicationType::Ping) && !cv.is_type(CommunicationType::Pong) {
                log_cv_out!(&cv);
            }

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
                let _ = (waiting_task.task)(OMIKRON_CONNECTION.clone(), response);
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
        let (tx, mut rx) = mpsc::channel(1);
        let msg_id = cv.get_id();

        WAITING_TASKS.insert(
            msg_id,
            WaitingTask {
                task: Box::new(move |_, response_cv| {
                    let inner_tx = tx.clone();
                    tokio::spawn(async move {
                        let _ = inner_tx.send(response_cv).await;
                    });
                    true
                }),
                inserted_at: Instant::now(),
            },
        );

        if let Err(send_err) = self.send_message_result(cv).await {
            WAITING_TASKS.remove(&msg_id);
            return Err(format!(
                "Request send failed (msg_id={}, reason={})",
                msg_id, send_err
            ));
        }

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(response_cv)) => {
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
                        .unwrap_or("connection error")
                        .to_string();
                    Err(format!(
                        "Request failed due to disconnect (msg_id={}, reason={})",
                        msg_id, reason
                    ))
                } else {
                    Ok(response_cv)
                }
            }
            Ok(_) => {
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
        if self.state.read().await.is_connected() {
            return Ok(());
        }

        let timeout = timeout_duration.unwrap_or(CONNECTION_TIMEOUT);
        let start = Instant::now();

        loop {
            if self.state.read().await.is_connected() {
                return Ok(());
            }

            if start.elapsed() >= timeout {
                return Err(format!(
                    "Connection not established within {} seconds",
                    timeout.as_secs()
                ));
            }

            sleep(Duration::from_millis(100)).await;
        }
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
}

// ============================================================================
// Global Instance
// ============================================================================

pub static OMIKRON_CONNECTION: LazyLock<Arc<OmikronConnection>> = LazyLock::new(|| {
    let conn = Arc::new(OmikronConnection::new());

    start_task_cleanup_loop();

    conn
});

pub async fn get_omikron_connection() -> Arc<OmikronConnection> {
    let conn = OMIKRON_CONNECTION.clone();

    conn.connect().await;
    conn
}
