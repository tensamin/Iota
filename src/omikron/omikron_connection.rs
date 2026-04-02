use crate::users::contact::Contact;
use crate::util::chat_files::{MessageState, change_message_state};
use crate::util::chats_util::{get_user, mod_user};
use crate::util::communities_util::CommunitiesUtil;
use crate::util::crypto_util::{DataFormat, SecurePayload};
use crate::util::file_util::{get_children, load_file, save_file};
use crate::util::{chat_files, chats_util};
use crate::util::{config_util::CONFIG, crypto_helper};
use crate::{ACTIVE_TASKS, SHUTDOWN, log, log_cv_in, log_cv_out, log_t};
use dashmap::DashMap;
use json::JsonValue;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use ttp_native::{Receiver, Sender};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

const OMIKRON_HOST_DEFAULT: &str = "methanium.net";
const OMIKRON_PORT_DEFAULT: u16 = 959;
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

pub struct OmikronConnection {
    state: Arc<RwLock<ConnectionState>>,
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    host: String,
    port: u16,
    pub last_ping: Arc<Mutex<i64>>,
    heartbeat_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    message_send_times: Arc<Mutex<HashMap<Uuid, Instant>>>,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    reconnect_on_close: Arc<RwLock<bool>>,
}

impl OmikronConnection {
    pub fn new() -> Self {
        Self::with_host(OMIKRON_HOST_DEFAULT, OMIKRON_PORT_DEFAULT)
    }

    pub fn with_host(host: &str, port: u16) -> Self {
        let (shutdown_tx, _) = watch::channel(false);

        OmikronConnection {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sender: Arc::new(RwLock::new(None)),
            connection_loop_handle: Arc::new(Mutex::new(None)),
            host: host.to_string(),
            port,
            last_ping: Arc::new(Mutex::new(-1)),
            heartbeat_handle: Arc::new(Mutex::new(None)),
            message_send_times: Arc::new(Mutex::new(HashMap::new())),
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            reconnect_on_close: Arc::new(RwLock::new(true)),
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

        let addr_str = format!("https://{}:{}/ws/iota/", self.host, self.port);

        let (sender, mut receiver) = ttp_native::client::connect(&addr_str, None)
            .await
            .map_err(|e| format!("Connection failed: {}", e))?;

        log_t!("omikron_connection_success");

        let sender_arc = Arc::new(sender);
        *self.sender.write().await = Some(sender_arc.clone());
        *self.state.write().await = ConnectionState::Connected { identified: false };

        // Handle registration/identification
        self.handle_authentication().await;

        // Start read loop
        let read_self = self.clone();
        let read_handle = tokio::spawn(async move {
            read_self.read_loop(&mut receiver).await;
        });

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
    // Authentication (Registration/Identification)
    // -------------------------------------------------------------------------

    async fn handle_authentication(&self) {
        let conf = CONFIG.read().await;
        let iota_id = conf.get_iota_id();
        let public_key = conf.get_public_key();
        let private_key = conf.get_private_key();
        drop(conf);

        if iota_id == 0 || public_key.is_none() || private_key.is_none() {
            log_t!("iota_register_new");

            let key_pair = crypto_helper::generate_keypair();
            let public_key_base64 = crypto_helper::public_key_to_base64(&key_pair.public);
            let _private_key_base64 = crypto_helper::secret_key_to_base64(&key_pair.secret);

            let mut conf_write = CONFIG.write().await;
            // NOTE:
            // Intentionally not storing the generated private/public keys directly into the
            // config file here to avoid persisting sensitive material in plaintext. If you
            // want to persist them, uncomment the two lines below and accept the security
            // implications (they will be saved by `conf_write.update()`).
            // conf_write.change("public_key", DataValue::Str(public_key_base64.clone()));
            // conf_write.change("private_key", DataValue::Str(private_key_base64));
            conf_write.update();
            drop(conf_write);

            let register_msg = CommunicationValue::new(CommunicationType::register_iota)
                .add_data(DataTypes::public_key, DataValue::Str(public_key_base64));

            let msg_id = register_msg.get_id();

            WAITING_TASKS.insert(
                msg_id,
                WaitingTask {
                    task: Box::new(|selfc, cv| {
                        if !cv.is_type(CommunicationType::success) {
                            return false;
                        }

                        let iota_value = cv.get_data(DataTypes::register_id);
                        let iota_id = iota_value.as_number().unwrap_or(0);

                        if iota_id != 0 {
                            tokio::spawn(async move {
                                let mut conf_write = CONFIG.write().await;
                                conf_write.change("iota_id", JsonValue::from(iota_id));
                                conf_write.update();
                                drop(conf_write);
                                log!("Registered with Iota-ID: {}", iota_id);

                                // Send identification after registration
                                let identify_msg =
                                    CommunicationValue::new(CommunicationType::identification)
                                        .add_data(DataTypes::iota_id, DataValue::Number(iota_id));
                                selfc.send_message(&identify_msg).await;
                            });
                        } else {
                            log!("Iota registration failed.");
                        }
                        true
                    }),
                    inserted_at: Instant::now(),
                },
            );

            self.send_message(&register_msg).await;
        } else {
            let identify_msg = CommunicationValue::new(CommunicationType::identification)
                .add_data(DataTypes::iota_id, DataValue::Number(iota_id));
            self.send_message(&identify_msg).await;
        }
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

            self.send_ping().await;
        }
    }

    // -------------------------------------------------------------------------
    // Message Handling (Preserved from original)
    // -------------------------------------------------------------------------

    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if !cv.is_type(CommunicationType::ping) && !cv.is_type(CommunicationType::pong) {
            log_cv_in!(&cv);
        }

        let msg_id = cv.get_id();

        // Dispatch waiting task for this message id
        if let Some((_, task)) = WAITING_TASKS.remove(&msg_id) {
            if (task.task)(self.clone(), cv.clone()) {
                return;
            }
        }

        if cv.is_type(CommunicationType::pong) {
            self.handle_pong(&cv).await;
            return;
        }

        if cv.is_type(CommunicationType::challenge) {
            self.handle_challenge(&cv).await;
            return;
        }

        if cv.is_type(CommunicationType::identification_response) {
            if let Some(_accepted) = cv.get_data(DataTypes::accepted).as_bool() {
                let mut state = self.state.write().await;
                if let ConnectionState::Connected { identified: _ } = *state {
                    *state = ConnectionState::Connected { identified: true };
                }
            }
            return;
        }

        // ************************************************ //
        // Direct messages                                  //
        // ************************************************ //

        if cv.is_type(CommunicationType::message_state) {
            let sender_id = &cv.get_sender();
            let receiver_id = &cv.get_receiver();

            // Parse send_time robustly: accept numeric or string, fallback to current time
            let send_time_val = cv.get_data(DataTypes::send_time);
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
                *receiver_id as i64,
                *sender_id as i64,
                MessageState::from_str(
                    cv.get_data(DataTypes::message_state).as_str().unwrap_or(""),
                ),
            );
        }

        // Incoming stored message: store for the recipient, attempt local delivery, notify sender.
        if cv.is_type(CommunicationType::message_send) {
            let sender_id: i64 = if let Some(n) = cv.get_data(DataTypes::sender_id).as_number() {
                n as i64
            } else if let Some(s) = cv.get_data(DataTypes::sender_id).as_str() {
                s.parse::<i64>().unwrap_or(0)
            } else {
                0
            };

            // parse receiver_id (the storage owner for this incoming message)
            let receiver_id: i64 = if let Some(n) = cv.get_data(DataTypes::receiver_id).as_number()
            {
                n as i64
            } else if let Some(s) = cv.get_data(DataTypes::receiver_id).as_str() {
                s.parse::<i64>().unwrap_or(0)
            } else {
                0
            };

            // parse send_time robustly (number or string), fallback to now
            let send_time_val = cv.get_data(DataTypes::send_time);
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
                .get_data(DataTypes::content)
                .as_str()
                .unwrap_or("")
                .to_string();

            let height = cv.get_data(DataTypes::height).as_number().unwrap_or(0) as i64;

            // persist message for the receiver (storage_owner = receiver_id)
            chat_files::add_message(
                timestamp_u128,
                false,
                receiver_id as i64,
                sender_id as i64,
                &content,
                height,
            );

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
            let conf_msg = CommunicationValue::new(CommunicationType::message_send)
                .with_id(cv.get_id())
                .with_receiver(sender_id as u64);
            self.send_message(&conf_msg).await;

            // Build a live-delivery message for the local client (recipient)
            let user_forward = CommunicationValue::new(CommunicationType::message_live)
                .with_id(cv.get_id())
                .with_receiver(receiver_id as u64)
                .add_data(DataTypes::send_time, DataValue::Number(timestamp_i64))
                .add_data(DataTypes::content, DataValue::Str(content.clone()))
                .add_data(DataTypes::sender_id, DataValue::Number(sender_id as i64))
                .add_data(DataTypes::height, DataValue::Number(height));

            // Attempt delivery and await a response from the local client
            let user_resp = self
                .clone()
                .await_response(&user_forward, Some(Duration::from_secs(10)))
                .await;

            if let Ok(user_resp) = user_resp {
                let ms_raw = user_resp
                    .get_data(DataTypes::message_state)
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

                // notify original sender about the delivered/read state
                self.send_message(
                    &CommunicationValue::new(CommunicationType::message_state)
                        .with_id(cv.get_id())
                        .with_receiver(sender_id as u64)
                        .with_sender(receiver_id as u64)
                        .add_data(DataTypes::send_time, DataValue::Number(timestamp_i64))
                        .add_data(
                            DataTypes::message_state,
                            DataValue::Str(ms.as_str().to_string()),
                        ),
                )
                .await;
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

                // notify sender
                self.send_message(
                    &CommunicationValue::new(CommunicationType::message_state)
                        .with_id(cv.get_id())
                        .with_receiver(sender_id as u64)
                        .with_sender(receiver_id as u64)
                        .add_data(DataTypes::send_time, DataValue::Number(timestamp_i64))
                        .add_data(
                            DataTypes::message_state,
                            DataValue::Str(MessageState::Sent.as_str().to_string()),
                        ),
                )
                .await;
            }
            return;
        }

        if cv.is_type(CommunicationType::message_other_iota) {
            let sender_id = &cv.get_sender();
            let receiver_id = &cv.get_receiver();

            // parse send_time safely (number or string), fallback to now
            let send_time_val = cv.get_data(DataTypes::send_time);
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
                .get_data(DataTypes::content)
                .as_str()
                .unwrap_or("")
                .to_string();

            let height = cv.get_data(DataTypes::height).as_number().unwrap_or(0) as i64;

            chat_files::add_message(
                timestamp as u128,
                false,
                *receiver_id as i64,
                *sender_id as i64,
                &content,
                height,
            );

            // Build user_forward using the parsed numeric timestamp and safe content string
            let user_forward = CommunicationValue::new(CommunicationType::message_live)
                .with_id(cv.get_id())
                .with_receiver(*receiver_id)
                .add_data(DataTypes::send_time, DataValue::Number(timestamp))
                .add_data(DataTypes::content, DataValue::Str(content.clone()))
                .add_data(DataTypes::sender_id, DataValue::Number(*sender_id as i64))
                .add_data(DataTypes::height, DataValue::Number(height));

            let user_resp = self
                .clone()
                .await_response(&user_forward, Some(Duration::from_secs(10)))
                .await;

            if let Ok(user_resp) = user_resp {
                let ms_raw = user_resp
                    .get_data(DataTypes::message_state)
                    .as_string()
                    .unwrap_or_else(|| "".to_string());
                let ms = MessageState::from_str(&ms_raw).upgrade(MessageState::Received);

                let _ = change_message_state(
                    timestamp,
                    *receiver_id as i64,
                    *sender_id as i64,
                    ms.clone(),
                );

                self.send_message(
                    &CommunicationValue::new(CommunicationType::message_state)
                        .with_id(cv.get_id())
                        .with_receiver(*sender_id)
                        .with_sender(*receiver_id)
                        .add_data(DataTypes::send_time, DataValue::Number(timestamp))
                        .add_data(
                            DataTypes::message_state,
                            DataValue::Str(ms.as_str().to_string()),
                        ),
                )
                .await;
            } else {
                // Delivery timed out/failed — update stored state and notify sender with numeric timestamp
                let _ = chat_files::change_message_state(
                    timestamp,
                    *receiver_id as i64,
                    *sender_id as i64,
                    MessageState::Sent,
                );

                self.send_message(
                    &CommunicationValue::new(CommunicationType::message_state)
                        .with_id(cv.get_id())
                        .with_receiver(*sender_id)
                        .with_sender(*receiver_id)
                        .add_data(DataTypes::send_time, DataValue::Number(timestamp))
                        .add_data(
                            DataTypes::message_state,
                            DataValue::Str(MessageState::Sent.as_str().to_string()),
                        ),
                )
                .await;
            }
            return;
        }

        if cv.is_type(CommunicationType::messages_get) {
            let my_id = cv.get_sender();
            let partner_id = cv.get_data(DataTypes::user_id).as_number().unwrap_or(0);
            let offset = cv.get_data(DataTypes::offset).as_number().unwrap_or(0);
            let amount = cv.get_data(DataTypes::amount).as_number().unwrap_or(0);
            let messages = chat_files::get_messages(my_id as i64, partner_id, offset, amount);
            let mut msg_array: Vec<DataValue> = Vec::new();
            for m in messages.members() {
                let message_time: i64 = m["message_time"].as_i64().unwrap_or(0);
                let content: String = m["content"].as_str().unwrap_or("").to_string();
                let sent_by_self: bool = m["sent_by_self"].as_bool().unwrap_or(false);
                let height: i64 = m["height"].as_i64().unwrap_or(0);
                let sender_id: i64 = if sent_by_self {
                    my_id as i64
                } else {
                    if let Some(n) = cv.get_data(DataTypes::chat_partner_id).as_number() {
                        n as i64
                    } else if let Some(s) = cv.get_data(DataTypes::chat_partner_id).as_str() {
                        s.parse::<i64>().unwrap_or(partner_id as i64)
                    } else {
                        partner_id as i64
                    }
                };
                let message_state: String = m["message_state"].as_str().unwrap_or("").to_string();

                let mut container = Vec::new();
                container.push((DataTypes::send_time, DataValue::Number(message_time)));
                container.push((DataTypes::content, DataValue::Str(content)));
                container.push((DataTypes::sender_id, DataValue::Number(sender_id)));
                container.push((DataTypes::message_state, DataValue::Str(message_state)));
                container.push((DataTypes::height, DataValue::Number(height)));
                container.push((DataTypes::sent_by_self, DataValue::Bool(sent_by_self)));
                msg_array.push(DataValue::Container(container));
            }

            let resp = CommunicationValue::new(CommunicationType::messages_get)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_data(DataTypes::messages, DataValue::Array(msg_array));

            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::get_chats) {
            let user_id = cv.get_sender();
            let users = chats_util::get_users(user_id as i64);
            let mut user_array = Vec::new();
            for user in users {
                let mut container = Vec::new();
                container.push((DataTypes::user_id, DataValue::Number(user.user_id)));
                if let Some(name) = user.user_name {
                    container.push((DataTypes::username, DataValue::Str(name)));
                }
                if let Some(ts) = user.last_message_at {
                    container.push((DataTypes::last_message_at, DataValue::Number(ts)));
                }
                user_array.push(DataValue::Container(container));
            }
            let resp = CommunicationValue::new(CommunicationType::get_chats)
                .with_id(cv.get_id())
                .with_receiver(user_id)
                .add_data(DataTypes::user_ids, DataValue::Array(user_array));
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::add_conversation) {
            let user_id = cv.get_sender();
            let other_id = match cv.get_data(DataTypes::chat_partner_id).as_number() {
                Some(n) => n as i64,
                None => cv
                    .get_data(DataTypes::chat_partner_id)
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0),
            };
            let mut contact = get_user(user_id as i64, other_id).unwrap_or(Contact::new(other_id));

            if let Some(name) = cv.get_data(DataTypes::chat_partner_name).as_str() {
                contact.user_name = Some(name.to_string());
            }

            contact.set_last_message_at(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64,
            );
            mod_user(user_id as i64, &contact);
            let resp = CommunicationValue::new(CommunicationType::add_conversation)
                .with_id(cv.get_id())
                .with_receiver(user_id);
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::add_community) {
            CommunitiesUtil::add_community(
                cv.get_sender() as i64,
                cv.get_data(DataTypes::community_address)
                    .as_str()
                    .unwrap()
                    .to_string(),
                cv.get_data(DataTypes::community_title)
                    .as_str()
                    .unwrap()
                    .to_string(),
                cv.get_data(DataTypes::position)
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
            let resp = CommunicationValue::new(CommunicationType::add_community)
                .with_id(cv.get_id())
                .with_receiver(cv.get_sender());
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::get_communities) {
            let mut comm_array = Vec::new();
            for c in CommunitiesUtil::get_communities(cv.get_sender() as i64) {
                let mut container: Vec<(DataTypes, DataValue)> = Vec::new();
                if let Some(address) = c["address"].as_str() {
                    container.push((
                        DataTypes::community_address,
                        DataValue::Str(address.to_string()),
                    ));
                }
                if let Some(title) = c["title"].as_str() {
                    container.push((
                        DataTypes::community_title,
                        DataValue::Str(title.to_string()),
                    ));
                }
                if let Some(position) = c["position"].as_str() {
                    container.push((DataTypes::position, DataValue::Str(position.to_string())));
                }
                comm_array.push(DataValue::Container(container));
            }

            let resp = CommunicationValue::new(CommunicationType::get_communities)
                .with_id(cv.get_id())
                .with_receiver(cv.get_sender())
                .add_data(DataTypes::communities, DataValue::Array(comm_array));
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::remove_community) {
            CommunitiesUtil::remove_community(
                cv.get_sender() as i64,
                cv.get_data(DataTypes::community_address)
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
            let resp = CommunicationValue::new(CommunicationType::remove_community)
                .with_id(cv.get_id())
                .with_receiver(cv.get_sender());
            self.send_message(&resp).await;
            return;
        }

        if cv.is_type(CommunicationType::settings_save) {
            let my_id = cv.get_sender();
            let settings_name = cv.get_data(DataTypes::settings_name).as_str().unwrap();
            let settings_value = cv.get_data(DataTypes::payload).as_str().unwrap();

            save_file(
                &format!("users/{}/settings/", my_id),
                &format!("{}.settings", settings_name),
                &settings_value,
            );

            let response = CommunicationValue::new(CommunicationType::settings_save)
                .with_receiver(my_id)
                .with_id(cv.get_id());

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::settings_load) {
            let my_id = cv.get_sender();
            let settings_name = cv.get_data(DataTypes::settings_name).as_string().unwrap();
            let settings_value_str = load_file(
                &format!("users/{}/settings/", my_id),
                &format!("{}.settings", settings_name),
            );
            let response = CommunicationValue::new(CommunicationType::settings_load)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_data(DataTypes::payload, DataValue::Str(settings_value_str))
                .add_data(DataTypes::settings_name, DataValue::Str(settings_name));

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::settings_list) {
            let my_id = cv.get_sender();
            let settings = get_children(&format!("users/{}/settings/", my_id));
            let mut settings_json = Vec::new();
            for s in settings {
                let s = s.replace(".settings", "");
                if s.is_empty() {
                    continue;
                }
                let _ = settings_json.push(DataValue::Str(s));
            }
            let response = CommunicationValue::new(CommunicationType::settings_list)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_data(DataTypes::settings, DataValue::Array(settings_json));

            self.send_message(&response).await;
            return;
        }
    }

    async fn handle_challenge(&self, cv: &CommunicationValue) {
        let conf = CONFIG.read().await;
        let private_key = conf.get_private_key().unwrap();
        drop(conf);

        let omikron_public_key = cv.get_data(DataTypes::public_key).as_str().unwrap();
        let encrypted_challenge = cv.get_data(DataTypes::challenge).as_str().unwrap();

        let solved_challenge = {
            if let Ok(decrypted) = SecurePayload::new(
                encrypted_challenge,
                DataFormat::Base64,
                crypto_helper::load_secret_key(&private_key).unwrap(),
            ) {
                if let Ok(decrypted) = decrypted
                    .decrypt_x448(crypto_helper::load_public_key(omikron_public_key).unwrap())
                {
                    Some(decrypted)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(decrypted) = solved_challenge {
            let solved = decrypted.export(DataFormat::Raw);

            let response = CommunicationValue::new(CommunicationType::challenge_response)
                .with_id(cv.get_id())
                .add_data(DataTypes::challenge, DataValue::Str(solved));

            self.send_message(&response).await;
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

            if !cv.is_type(CommunicationType::ping) && !cv.is_type(CommunicationType::pong) {
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
                let response = CommunicationValue::new(CommunicationType::error)
                    .with_id(key)
                    .add_data(DataTypes::message, DataValue::Str(reason.clone()));
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
                if response_cv.is_type(CommunicationType::error) {
                    let reason = response_cv
                        .get_data(DataTypes::message)
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
