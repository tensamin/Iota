use dashmap::DashMap;
use iota_connection::message_common::*;
use iota_connection::message_handlers;
use iota_connection::relay::message_security_class;
use iota_logger::{log_cv_in, log_cv_out, log_t};
use iota_storage::util::config_util::CONFIG;
use iota_util::crypto_helper::keyring_from_base64;
use iota_util::crypto_util::{self};
use mtp::client::{Receiver, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::Keyring;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::task::JoinHandle;
use uuid::Uuid;

// ============================================================================
// Waiting Task System
// ============================================================================

#[allow(dead_code)]
pub struct ClientConnection {
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    receiver: Receiver,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    pub waiting_tasks:
        DashMap<u32, Box<dyn Fn(Arc<ClientConnection>, CommunicationValue) -> bool + Send + Sync>>,
    shutdown: Arc<RwLock<bool>>,
    keyring: Arc<RwLock<Option<Arc<Keyring>>>>,
}

impl ClientConnection {
    pub fn new(
        sender: Arc<RwLock<Option<Arc<Sender>>>>,
        receiver: Receiver,
        connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
        connection_id: Uuid,
        shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
        waiting_tasks: DashMap<
            u32,
            Box<dyn Fn(Arc<ClientConnection>, CommunicationValue) -> bool + Send + Sync>,
        >,
        shutdown: Arc<RwLock<bool>>,
    ) -> Self {
        Self {
            sender,
            receiver,
            connection_loop_handle,
            connection_id,
            shutdown_tx,
            waiting_tasks,
            shutdown,
            keyring: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_keyring(&self, keyring: Arc<Keyring>) {
        *self.keyring.write().await = Some(keyring);
    }

    async fn local_keyring(&self) -> Result<Arc<Keyring>, String> {
        if let Some(keyring) = self.keyring.read().await.as_ref().cloned() {
            return Ok(keyring);
        }

        let keyring_data = CONFIG
            .load()
            .keyring
            .clone()
            .ok_or_else(|| "Iota keyring is not configured".to_string())?;
        let keyring = keyring_from_base64(&keyring_data)
            .ok_or_else(|| "Iota keyring is invalid".to_string())?;
        let keyring = Arc::new(keyring);
        *self.keyring.write().await = Some(keyring.clone());
        Ok(keyring)
    }

    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Ok(cv) = self_clone.receiver.receive().await {
                if *self_clone.shutdown.read().await {
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
            sender.close().await;
        }

        *self.sender.write().await = None;
    }

    // -------------------------------------------------------------------------
    // Message Handling
    // -------------------------------------------------------------------------
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        log_cv_in!(&cv);

        if cv.is_type(CommunicationType::Relay) {
            log_t!(
                "relay_from_client_rejected",
                "legacy client path has no Relay router".to_string()
            );
            let _ = self
                .send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        if matches!(
            message_security_class(&cv),
            iota_connection::relay::MessageSecurityClass::RelayOnly
        ) {
            let _ = self
                .send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        let _msg_id = cv.get_id();

        if cv.is_type(CommunicationType::Challenge) {
            self.handle_challenge(&cv).await;
            return;
        }

        if cv.is_type(CommunicationType::GetChatSecret) {
            self.send_message(&message_handlers::handle_get_chat_secret(&cv))
                .await;
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
            self.send_message(&message_handlers::handle_create_app(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::DeleteApp) {
            self.send_message(&message_handlers::handle_delete_app(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::ClientConnected) {
            self.send_message(&message_handlers::handle_client_connected(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::ClientStateAck) {
            self.send_message(&message_handlers::handle_client_state_ack(&cv))
                .await;
            return;
        }

        // ************************************************ //
        // Direct messages                                  //
        // ************************************************ //

        if cv.is_type(CommunicationType::MessageState) {
            message_handlers::handle_message_state(&cv);
            return;
        }

        if cv.is_type(CommunicationType::MessageEdit) {
            self.send_message(&message_handlers::handle_message_edit(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::MessageReactionAdd) {
            self.send_message(&message_handlers::handle_message_reaction(&cv, true))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::MessageReactionRemove) {
            self.send_message(&message_handlers::handle_message_reaction(&cv, false))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::MessageDeleteLive) {
            self.send_message(&message_handlers::handle_message_delete(&cv))
                .await;
            return;
        }

        // Incoming storsed message: store for the recipient, attempt local delivery, notify sender.
        if cv.is_type(CommunicationType::MessageSend) {
            self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::MessagesGet) {
            self.send_message(&message_handlers::handle_messages_get(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::MessageGet) {
            self.send_message(&message_handlers::handle_message_get(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::GetChats) {
            self.send_message(&message_handlers::handle_get_chats(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::AddConversation) {
            self.send_message(&message_handlers::handle_add_conversation(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::AddCommunity) {
            self.send_message(&message_handlers::handle_add_community(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::GetCommunities) {
            self.send_message(&message_handlers::handle_get_communities(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::RemoveCommunity) {
            self.send_message(&message_handlers::handle_remove_community(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsSave) {
            let my_id = cv.get_sender();
            let settings_name = cv.get_data(DataType::SettingsName).as_str().unwrap();
            let settings_value = cv.get_data(DataType::Payload).as_str().unwrap();

            let _ = iota_storage::util::settings::save(
                my_id as i64,
                iota_storage::util::settings::GLOBAL_SESSION_ID,
                settings_name,
                settings_value,
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
            let settings_value_str = iota_storage::util::settings::load(
                my_id as i64,
                iota_storage::util::settings::GLOBAL_SESSION_ID,
                &settings_name,
            )
            .ok()
            .flatten()
            .unwrap_or_default();
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
            let settings = iota_storage::util::settings::list(
                my_id as i64,
                iota_storage::util::settings::GLOBAL_SESSION_ID,
            )
            .unwrap_or_default();
            let settings_json = settings.into_iter().map(DataValue::Str).collect();
            let response = CommunicationValue::new(CommunicationType::SettingsList)
                .with_id(cv.get_id())
                .with_receiver(my_id)
                .add_typed_default(DataType::Settings, DataValue::Array(settings_json));

            self.send_message(&response).await;
            return;
        }
    }

    async fn handle_challenge(&self, cv: &CommunicationValue) {
        let Ok(keyring) = self.local_keyring().await else {
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
                    sender.close().await;
                }
                return Err("connection closed".to_string());
            }

            let sender_clone = Arc::clone(sender);
            drop(sender_guard);

            log_cv_out!(&cv);

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
