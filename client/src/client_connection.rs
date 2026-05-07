use dashmap::DashMap;
use iota_logger::{log_cv_in, log_cv_out, log_t};
use iota_state::SHUTDOWN;
use iota_storage::users::contact::Contact;
use iota_storage::util::chat_files::{MessageState, change_message_state};
use iota_storage::util::chats_util::{get_user, mod_user};
use iota_storage::util::communities_util::CommunitiesUtil;
use iota_storage::util::config_util::CONFIG;
use iota_storage::util::{chat_files, chats_util};
use iota_util::crypto_helper;
use iota_util::crypto_util::{DataFormat, SecurePayload};
use iota_util::file_util::{get_children, load_file, save_file};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::task::JoinHandle;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use ttp_native::{Receiver, Sender};
use uuid::Uuid;

// ============================================================================
// Waiting Task System
// ============================================================================

#[allow(dead_code)]
pub struct ClientConnection {
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    receiver: Receiver,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub ping: Arc<RwLock<i64>>,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    pub waiting_tasks:
        DashMap<u32, Box<dyn Fn(Arc<ClientConnection>, CommunicationValue) -> bool + Send + Sync>>,
}

impl ClientConnection {
    pub fn new(
        sender: Arc<RwLock<Option<Arc<Sender>>>>,
        receiver: Receiver,
        connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
        ping: Arc<RwLock<i64>>,
        connection_id: Uuid,
        shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
        waiting_tasks: DashMap<
            u32,
            Box<dyn Fn(Arc<ClientConnection>, CommunicationValue) -> bool + Send + Sync>,
        >,
    ) -> Self {
        Self {
            sender,
            receiver,
            connection_loop_handle,
            ping,
            connection_id,
            shutdown_tx,
            waiting_tasks,
        }
    }

    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Ok(cv) = self_clone.receiver.receive().await {
                if *SHUTDOWN.read().await {
                    return;
                }

                self.clone().handle_message(cv).await;

                if !self_clone.receiver.is_open() {
                    break;
                }
            }
            // Handle Close
        });
    }

    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close();
        }

        *self.sender.write().await = None;
    }

    // -------------------------------------------------------------------------
    // Message Handling
    // -------------------------------------------------------------------------
    async fn handle_ping(self: Arc<Self>, cv: CommunicationValue) {
        // Update our ping if provided
        if let DataValue::Number(last_ping) = cv.get_data(DataTypes::last_ping) {
            let current = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let mut ping_guard = self.ping.write().await;
            *ping_guard = current as i64 - last_ping;
        }

        // Send pong response
        let response = CommunicationValue::new(CommunicationType::pong)
            .with_id(cv.get_id())
            .add_data(DataTypes::ping_iota, DataValue::Number(0));

        self.send_message(&response).await;
    }

    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if !cv.is_type(CommunicationType::ping) && !cv.is_type(CommunicationType::pong) {
            log_cv_in!(&cv);
        }

        let _msg_id = cv.get_id();

        if cv.is_type(CommunicationType::ping) {
            self.handle_ping(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::challenge) {
            self.handle_challenge(&cv).await;
            return;
        }

        if cv.is_type(CommunicationType::save_app_data) {
            let sender_id = cv.get_sender();
            let _app_data = cv
                .get_data(DataTypes::app_data)
                .as_str()
                .unwrap_or("")
                .to_string();

            let res = CommunicationValue::new(CommunicationType::save_app_data)
                .with_id(cv.get_id())
                .with_receiver(sender_id);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::load_app_data) {
            let sender_id = cv.get_sender();
            let app_data = String::new();

            let res = CommunicationValue::new(CommunicationType::load_app_data)
                .with_id(cv.get_id())
                .with_receiver(sender_id)
                .add_data(DataTypes::app_data, DataValue::Str(app_data));
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::create_app) {
            let sender_id = cv.get_sender() as i64;
            let app_identifier = cv
                .get_data(DataTypes::app_identifier)
                .as_str()
                .unwrap_or("")
                .to_string();
            let app_public_key = cv
                .get_data(DataTypes::app_public_key)
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

            let res = CommunicationValue::new(CommunicationType::create_app)
                .with_id(cv.get_id())
                .with_receiver(sender_id as u64);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::delete_app) {
            let sender_id = cv.get_sender() as i64;
            let app_identifier = cv
                .get_data(DataTypes::app_identifier)
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

            let res = CommunicationValue::new(CommunicationType::delete_app)
                .with_id(cv.get_id())
                .with_receiver(sender_id as u64);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::client_connected) {
            let user_id = cv.get_data(DataTypes::user_id).as_number().unwrap_or(0) as i64;
            let _session_id = cv.get_data(DataTypes::session_id).as_number().unwrap_or(0) as i64;

            let contacts = chats_util::get_users(user_id);
            let mut contacts_array = Vec::new();

            for (i, contact) in contacts.iter().enumerate() {
                let mut contact_container = Vec::new();
                contact_container.push((DataTypes::user_id, DataValue::Number(contact.user_id)));
                contact_container.push((
                    DataTypes::last_message_at,
                    DataValue::Number(contact.last_message_at.unwrap_or(0)),
                ));

                if let Some(ref name) = contact.user_name {
                    contact_container.push((DataTypes::username, DataValue::Str(name.clone())));
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
                    msg_container.push((DataTypes::send_time, DataValue::Number(message_time)));
                    msg_container.push((DataTypes::content, DataValue::Str(content.clone())));
                    msg_container.push((DataTypes::message_state, DataValue::Str(message_state)));
                    msg_container.push((DataTypes::height, DataValue::Number(height)));
                    msg_container.push((DataTypes::sent_by_self, DataValue::Bool(sent_by_self)));
                    msg_array.push(DataValue::Container(msg_container));

                    if msg_array.len() == 1 {
                        let sender_id = if sent_by_self {
                            user_id
                        } else {
                            contact.user_id
                        };
                        let mut last_msg = Vec::new();
                        last_msg.push((DataTypes::content, DataValue::Str(content)));
                        last_msg.push((DataTypes::sender_id, DataValue::Number(sender_id)));
                        contact_container
                            .push((DataTypes::last_message, DataValue::Container(last_msg)));
                    }
                }
                contact_container.push((DataTypes::messages, DataValue::Array(msg_array)));
                contacts_array.push(DataValue::Container(contact_container));
            }

            let resp = CommunicationValue::new(CommunicationType::client_connected)
                .with_id(cv.get_id())
                .add_data(DataTypes::contacts, DataValue::Array(contacts_array));
            self.send_message(&resp).await;
            return;
        }

        // ************************************************ //
        // Direct messages                                  //
        // ************************************************ //

        if cv.is_type(CommunicationType::message_state) {
            let sender_id = &cv.get_sender();
            let receiver_id = match cv.get_data(DataTypes::chat_partner_id).as_number() {
                Some(id) => id,
                _ => return,
            };

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
                receiver_id as i64,
                *sender_id as i64,
                MessageState::from_str(
                    cv.get_data(DataTypes::message_state).as_str().unwrap_or(""),
                ),
            );
        }

        // Incoming storsed message: store for the recipient, attempt local delivery, notify sender.
        if cv.is_type(CommunicationType::message_send) {
            let sender_id: u64 = cv.get_sender();

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
            let conf_msg = CommunicationValue::new(CommunicationType::message_send)
                .with_id(cv.get_id())
                .with_receiver(sender_id as u64);
            self.send_message(&conf_msg).await;

            if !is_local {
                let fw_msg = CommunicationValue::new(CommunicationType::message_other_iota)
                    .with_id(cv.get_id())
                    .with_receiver(receiver_id as u64)
                    .with_sender(sender_id as u64)
                    .add_data(DataTypes::height, DataValue::Number(height))
                    .add_data(DataTypes::content, DataValue::Str(content))
                    .add_data(DataTypes::send_time, DataValue::Number(timestamp_i64));

                let other_iota_resp = self
                    .clone()
                    .await_response(&fw_msg, Some(Duration::from_secs(10)))
                    .await;

                if let Ok(resp) = other_iota_resp {
                    let ms_raw = resp
                        .get_data(DataTypes::message_state)
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
                        &CommunicationValue::new(CommunicationType::message_state)
                            .with_id(cv.get_id())
                            .with_receiver(sender_id as u64)
                            .with_sender(receiver_id as u64)
                            .add_data(
                                DataTypes::chat_partner_id,
                                DataValue::Number(receiver_id as i64),
                            )
                            .add_data(DataTypes::send_time, DataValue::Number(timestamp_i64))
                            .add_data(
                                DataTypes::message_state,
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
                        &CommunicationValue::new(CommunicationType::message_state)
                            .with_id(cv.get_id())
                            .with_receiver(sender_id as u64)
                            .with_sender(receiver_id as u64)
                            .add_data(
                                DataTypes::chat_partner_id,
                                DataValue::Number(receiver_id as i64),
                            )
                            .add_data(DataTypes::send_time, DataValue::Number(timestamp_i64))
                            .add_data(
                                DataTypes::message_state,
                                DataValue::Str(MessageState::Sent.as_str().to_string()),
                            ),
                    )
                    .await;
                }
                return;
            } else {
                // Build a live-delivery message for the local client (recipient)
                let user_forward = CommunicationValue::new(CommunicationType::message_live)
                    .with_id(cv.get_id())
                    .with_receiver(receiver_id as u64)
                    .add_data(DataTypes::sender_id, DataValue::Number(sender_id as i64))
                    .add_data(
                        DataTypes::message,
                        DataValue::Container(vec![
                            (DataTypes::content, DataValue::Str(content.clone())),
                            (DataTypes::send_time, DataValue::Number(timestamp_i64)),
                            (DataTypes::height, DataValue::Number(height)),
                        ]),
                    );

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
                            .add_data(
                                DataTypes::chat_partner_id,
                                DataValue::Number(receiver_id as i64),
                            )
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
                                DataTypes::chat_partner_id,
                                DataValue::Number(receiver_id as i64),
                            )
                            .add_data(
                                DataTypes::message_state,
                                DataValue::Str(MessageState::Sent.as_str().to_string()),
                            ),
                    )
                    .await;
                }
                return;
            }
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
                .add_data(DataTypes::sender_id, DataValue::Number(*sender_id as i64))
                .add_data(
                    DataTypes::message,
                    DataValue::Container(vec![
                        (DataTypes::content, DataValue::Str(content.clone())),
                        (DataTypes::send_time, DataValue::Number(timestamp)),
                        (DataTypes::height, DataValue::Number(height)),
                    ]),
                );

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
                            DataTypes::chat_partner_id,
                            DataValue::Number(*sender_id as i64),
                        )
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
                            DataTypes::chat_partner_id,
                            DataValue::Number(*receiver_id as i64),
                        )
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
                return Err("connection closed".to_string());
            }

            let sender_clone = Arc::clone(sender);
            drop(sender_guard);

            if !cv.is_type(CommunicationType::ping) && !cv.is_type(CommunicationType::pong) {
                log_cv_out!(&cv);
            }

            if let Err(e) = sender_clone.send(cv).await {
                return Err(e.to_string());
            }

            Ok(())
        } else {
            Err("not connected".to_string())
        }
    }

    pub async fn await_response(
        self: Arc<ClientConnection>,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let (tx, mut rx) = mpsc::channel(1);
        let msg_id = cv.get_id();

        let task_tx = tx.clone();
        self.waiting_tasks.insert(
            msg_id,
            Box::new(move |_, response_cv| {
                let inner_tx = task_tx.clone();
                tokio::spawn(async move {
                    let _ = inner_tx.send(response_cv).await;
                });
                true
            }),
        );

        self.send_message(cv).await;

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(response_cv)) => Ok(response_cv),
            Ok(_) => Err("Failed to receive response, channel was closed.".to_string()),
            Err(_) => {
                self.waiting_tasks.remove(&msg_id);
                Err(format!(
                    "Request timed out after {} seconds.",
                    timeout.as_secs()
                ))
            }
        }
    }
}
