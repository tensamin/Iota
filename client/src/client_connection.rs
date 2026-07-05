use dashmap::DashMap;
use iota_logger::{log_cv_in, log_cv_out, log_t};
use iota_state::SHUTDOWN;
use iota_storage::users::contact::Contact;
use iota_storage::util::chat_files::{MessageState, change_message_state};
use iota_storage::util::chats_util::{get_user, mod_user};
use iota_storage::util::communities_util::CommunitiesUtil;
use iota_storage::util::config_util::CONFIG;
use iota_storage::util::{chat_files, chats_util};
use iota_storage::util::e2ee_storage::{self, ChatSecretQuery, StoredChatSecret};
use iota_util::crypto_helper::keyring_from_base64;
use iota_util::crypto_util::{self};
use iota_util::file_util::{get_children, load_file, save_file};
use mtp::client::{Receiver, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::task::JoinHandle;
use uuid::Uuid;

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
        .or_else(|| cv.get_data(dt).as_signed_number().and_then(|n| i64::try_from(n).ok()))
        .or_else(|| cv.get_data(dt).as_str().and_then(|s| s.parse::<i64>().ok()))
}

fn data_bytes(cv: &CommunicationValue, dt: DataType) -> Option<Vec<u8>> {
    cv.get_bytes(dt).map(|bytes| bytes.to_vec())
}

fn now_millis_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn error_response(request: &CommunicationValue, ty: CommunicationType) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_id(request.get_id())
        .with_receiver(request.get_sender())
}

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
        if let DataValue::SignedNumber(last_ping) = cv.get_data(DataType::LastPing) {
            let current = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let mut ping_guard = self.ping.write().await;
            *ping_guard = current as i64 - *last_ping as i64;
        }

        // Send pong response
        let response = CommunicationValue::new(CommunicationType::Pong)
            .with_id(cv.get_id())
            .add_typed_default(DataType::PingIota, DataValue::SignedNumber(0));

        self.send_message(&response).await;
    }

    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if !cv.is_type(CommunicationType::Ping) && !cv.is_type(CommunicationType::Pong) {
            log_cv_in!(&cv);
        }

        let _msg_id = cv.get_id();

        if cv.is_type(CommunicationType::Ping) {
            self.handle_ping(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::Challenge) {
            self.handle_challenge(&cv).await;
            return;
        }

        if cv.is_type(CommunicationType::SetChatSecret) {
            let sender_id = cv.get_sender().to_string();
            if data_string(&cv, DataType::UserId).as_deref() != Some(sender_id.as_str()) {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData)).await;
                return;
            }
            let now = now_millis_i64();
            let record = data_string(&cv, DataType::UserId)
                .zip(data_string(&cv, DataType::ChatId))
                .zip(data_string(&cv, DataType::SecretId))
                .zip(data_i64(&cv, DataType::VersionNumber))
                .zip(data_bytes(&cv, DataType::EncryptedSecret))
                .zip(data_bytes(&cv, DataType::KemCiphertext))
                .zip(data_string(&cv, DataType::WrappingScheme))
                .map(|((((((user_id, chat_id), secret_id), version), encrypted_secret), kem_ciphertext), wrapping_scheme)| {
                    StoredChatSecret {
                        user_id,
                        chat_id,
                        secret_id,
                        version,
                        encrypted_secret,
                        kem_ciphertext,
                        wrapping_scheme,
                        created_at: data_i64(&cv, DataType::CreatedAt).unwrap_or(now),
                        updated_at: now,
                    }
                });

            match record.map(e2ee_storage::put_chat_secret) {
                Some(Ok(())) => {
                    self.send_message(&error_response(&cv, CommunicationType::Success)).await;
                }
                _ => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData)).await;
                }
            }
            return;
        }

        if cv.is_type(CommunicationType::GetChatSecret) {
            let Some(user_id) = data_string(&cv, DataType::UserId) else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData)).await;
                return;
            };
            let sender_id = cv.get_sender().to_string();
            if user_id != sender_id {
                self.send_message(&error_response(&cv, CommunicationType::ErrorNotFound)).await;
                return;
            }
            let Some(chat_id) = data_string(&cv, DataType::ChatId) else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData)).await;
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
                        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(record.version as i128))
                        .add_typed_default(DataType::EncryptedSecret, DataValue::Bytes(record.encrypted_secret))
                        .add_typed_default(DataType::KemCiphertext, DataValue::Bytes(record.kem_ciphertext))
                        .add_typed_default(DataType::WrappingScheme, DataValue::Str(record.wrapping_scheme))
                        .add_typed_default(DataType::CreatedAt, DataValue::SignedNumber(record.created_at as i128))
                        .add_typed_default(DataType::UpdatedAt, DataValue::SignedNumber(record.updated_at as i128));
                    self.send_message(&response).await;
                }
                Ok(None) => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorNotFound)).await;
                }
                Err(_) => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData)).await;
                }
            }
            return;
        }

        if cv.is_type(CommunicationType::ChatSecretForward) {
            let sender_id = cv.get_sender().to_string();
            let recipient_id = data_string(&cv, DataType::RecipientUserId).unwrap_or_default();
            if data_string(&cv, DataType::SenderUserId).as_deref() != Some(sender_id.as_str())
                || recipient_id.is_empty()
            {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData)).await;
                return;
            }
            self.send_message(&cv.with_receiver(recipient_id.parse::<u64>().unwrap_or(0))).await;
            return;
        }

        if cv.is_type(CommunicationType::SaveAppData) {
            let sender_id = cv.get_sender();
            let _app_data = cv
                .get_data(DataType::AppData)
                .as_str()
                .unwrap_or("")
                .to_string();

            let res = CommunicationValue::new(CommunicationType::SaveAppData)
                .with_id(cv.get_id())
                .with_receiver(sender_id);
            self.send_message(&res).await;
            return;
        }

        if cv.is_type(CommunicationType::LoadAppData) {
            let sender_id = cv.get_sender();
            let app_data = String::new();

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
            self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData)).await;
            return;
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
                .await_response(&user_forward, Some(Duration::from_secs(10)))
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
            } else {
                // Delivery timed out/failed — update stored state and notify sender with numeric timestamp
                let _ = chat_files::change_message_state(
                    timestamp,
                    *receiver_id as i64,
                    *sender_id as i64,
                    MessageState::Sent,
                );

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

        if cv.is_type(CommunicationType::SettingsSave) {
            let my_id = cv.get_sender();
            let settings_name = cv.get_data(DataType::SettingsName).as_str().unwrap();
            let settings_value = cv.get_data(DataType::Payload).as_str().unwrap();

            save_file(
                &format!("users/{}/settings/", my_id),
                &format!("{}.settings", settings_name),
                &settings_value,
            );

            let response = CommunicationValue::new(CommunicationType::SettingsSave)
                .with_receiver(my_id)
                .with_id(cv.get_id());

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsLoad) {
            let my_id = cv.get_sender();
            let settings_name = cv.get_data(DataType::SettingsName).as_string().unwrap();
            let settings_value_str = load_file(
                &format!("users/{}/settings/", my_id),
                &format!("{}.settings", settings_name),
            );
            let response = CommunicationValue::new(CommunicationType::SettingsLoad)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str))
                .add_typed_default(DataType::SettingsName, DataValue::Str(settings_name));

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsList) {
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
            let response = CommunicationValue::new(CommunicationType::SettingsList)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_typed_default(DataType::Settings, DataValue::Array(settings_json));

            self.send_message(&response).await;
            return;
        }
    }

    async fn handle_challenge(&self, cv: &CommunicationValue) {
        let kr_str = CONFIG.load().keyring.clone().unwrap();

        let Some(keyring) = keyring_from_base64(&kr_str) else {
            return;
        };

        let encrypted_challenge = cv.get_data(DataType::Challenge).as_str().unwrap();

        let solved = crypto_util::decrypt_challenge(encrypted_challenge, &keyring).ok();

        if let Some(solved) = solved {
            let response = CommunicationValue::new(CommunicationType::ChallengeResponse)
                .with_id(cv.get_id())
                .add_typed_default(DataType::Challenge, DataValue::Str(solved));

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

            if !cv.is_type(CommunicationType::Ping) && !cv.is_type(CommunicationType::Pong) {
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
