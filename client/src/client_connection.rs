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
use tokio::sync::{Mutex, RwLock, watch};
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
    pub waiting_tasks: tau::ResponseCorrelator,
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
        waiting_tasks: tau::ResponseCorrelator,
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
            self_clone.waiting_tasks.close();
            // Handle Close
        });
    }

    pub async fn stop(&self) {
        self.waiting_tasks.close();
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
        if cv.type_map().is_none() {
            return;
        }
        log_cv_in!(&cv);

        if !cv.is_type(CommunicationType::Relay)
            && cv
                .id()
                .is_some_and(|id| self.waiting_tasks.complete(id, cv.clone()))
        {
            return;
        }

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
                | iota_connection::relay::MessageSecurityClass::Unsupported
        ) {
            let _ = self
                .send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        if cv.require_id().is_err() {
            self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::Challenge) {
            self.handle_challenge(&cv).await;
            return;
        }

        if cv.is_type(CommunicationType::GetChatSecret) {
            self.send_message(&message_handlers::handle_get_chat_secret(&cv))
                .await;
            return;
        }

        if cv.is_type(CommunicationType::AccountStateRequest)
            || cv.is_type(CommunicationType::RelayReceiptPage)
        {
            // Account initialization is routed through Omikron.
            self.send_message(
                &CommunicationValue::new(CommunicationType::ErrorInvalidData).with_request_id(&cv),
            )
            .await;
            return;
        }

        if cv.is_type(CommunicationType::AccountStateApplied) {
            self.send_message(
                &CommunicationValue::new(CommunicationType::ErrorInvalidData).with_request_id(&cv),
            )
            .await;
            return;
        }

        if cv.is_type(CommunicationType::ReadNotification) {
            let mutation = message_handlers::handle_read_notification(&cv);
            self.send_message(&mutation.response).await;
            if let Some(changed) = mutation.changed {
                self.send_message(&changed).await;
            }
            return;
        }

        // ************************************************ //
        // Direct messages                                  //
        // ************************************************ //

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
            let my_id = match cv.require_sender() {
                Ok(my_id) => my_id,
                Err(_) => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                        .await;
                    return;
                }
            };
            let Ok(my_id_i64) = i64::try_from(my_id) else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };
            let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };
            let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };

            let _ = iota_storage::util::settings::save(
                my_id_i64,
                iota_storage::util::settings::GLOBAL_SESSION_ID,
                settings_name,
                settings_value,
            );

            let response = CommunicationValue::new(CommunicationType::SettingsSave)
                .with_receiver(my_id)
                .with_request_id(&cv);

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsLoad) {
            let my_id = match cv.require_sender() {
                Ok(my_id) => my_id,
                Err(_) => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                        .await;
                    return;
                }
            };
            let Ok(my_id_i64) = i64::try_from(my_id) else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };
            let Some(settings_name) = cv.get_data(DataType::SettingsName).as_string() else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };
            let settings_value_str = iota_storage::util::settings::load(
                my_id_i64,
                iota_storage::util::settings::GLOBAL_SESSION_ID,
                &settings_name,
            )
            .ok()
            .flatten()
            .unwrap_or_default();
            let response = CommunicationValue::new(CommunicationType::SettingsLoad)
                .with_request_id(&cv)
                .with_receiver(my_id)
                .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str))
                .add_typed_default(DataType::SettingsName, DataValue::Str(settings_name));

            self.send_message(&response).await;
            return;
        }

        if cv.is_type(CommunicationType::SettingsList) {
            let my_id = match cv.require_sender() {
                Ok(my_id) => my_id,
                Err(_) => {
                    self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                        .await;
                    return;
                }
            };
            let Ok(my_id_i64) = i64::try_from(my_id) else {
                self.send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            };
            let settings = iota_storage::util::settings::list(
                my_id_i64,
                iota_storage::util::settings::GLOBAL_SESSION_ID,
            )
            .unwrap_or_default();
            let settings_json = settings.into_iter().map(DataValue::Str).collect();
            let response = CommunicationValue::new(CommunicationType::SettingsList)
                .with_request_id(&cv)
                .with_receiver(my_id)
                .add_typed_default(DataType::Settings, DataValue::Array(settings_json));

            self.send_message(&response).await;
        }
    }

    async fn handle_challenge(&self, cv: &CommunicationValue) {
        let Ok(keyring) = self.local_keyring().await else {
            return;
        };

        let Some(encrypted_challenge) = cv.get_data(DataType::Challenge).as_str() else {
            return;
        };

        let solved = crypto_util::decrypt_challenge(encrypted_challenge, &keyring).ok();

        if let Some(solved) = solved {
            let response = CommunicationValue::new(CommunicationType::ChallengeResponse)
                .with_request_id(cv)
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

            log_cv_out!(cv);

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
        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));
        let expected = cv.get_comm_type_enum();
        self.waiting_tasks
            .exchange(
                cv,
                timeout,
                move |response| {
                    let actual = response.get_comm_type_enum();
                    actual.is_some() && actual == expected
                        || actual.is_some_and(tau::is_protocol_error)
                        || actual == Some(CommunicationType::Success)
                            && matches!(
                                expected,
                                Some(
                                    CommunicationType::ChallengeResponse
                                        | CommunicationType::Relay
                                        | CommunicationType::AccountStateApplied
                                        | CommunicationType::MessageEdit
                                        | CommunicationType::MessageReactionAdd
                                        | CommunicationType::MessageReactionRemove
                                        | CommunicationType::MessageDeleteLive
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
                            )
                        )
                },
                |outbound| {
                    let connection = &self;
                    async move { connection.send_message_result(&outbound).await }
                },
            )
            .await
            .map_err(|error| error.to_string())
    }
}
