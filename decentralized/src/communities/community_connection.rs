use crate::auth::auth_user::AuthUser;
use crate::communities::community::Community;
use crate::communities::interactables::interactable::Interactable;
use crate::users::user_manager::get_user;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::SinkExt;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use hkdf::Hkdf;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use json::JsonValue;
use json::number::Number;
use rand::{Rng, distributions::Alphanumeric};
use sha2::Sha256;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_tungstenite::WebSocketStream;
use tungstenite::Message;
use tungstenite::Utf8Bytes;
use uuid::Uuid;
use x448::PublicKey;
pub struct CommunityConnection {
    pub sender: Arc<RwLock<SplitSink<WebSocketStream<TokioIo<Upgraded>>, Message>>>,
    pub receiver: Arc<RwLock<SplitStream<WebSocketStream<TokioIo<Upgraded>>>>>,
    pub user_id: Arc<RwLock<i64>>,
    pub community: Arc<RwLock<Option<Arc<Community>>>>,
    identified: Arc<RwLock<bool>>,
    challenged: Arc<RwLock<bool>>,
    challenge: Arc<RwLock<String>>,
    auth: Arc<RwLock<Option<AuthUser>>>,
    pub ping: Arc<RwLock<i64>>,
}
impl CommunityConnection {
    pub fn new(
        sender: SplitSink<WebSocketStream<TokioIo<Upgraded>>, Message>,
        receiver: SplitStream<WebSocketStream<TokioIo<Upgraded>>>,
        community: Arc<Community>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sender: Arc::new(RwLock::new(sender)),
            receiver: Arc::new(RwLock::new(receiver)),
            user_id: Arc::new(RwLock::new(0)),
            community: Arc::new(RwLock::new(Some(community))),
            identified: Arc::new(RwLock::new(false)),
            challenged: Arc::new(RwLock::new(false)),
            challenge: Arc::new(RwLock::new(String::new())),
            auth: Arc::new(RwLock::new(None)),
            ping: Arc::new(RwLock::new(-1)),
        })
    }
    pub async fn send_message(&self, message: &CommunicationValue) {
        let mut sender = self.sender.write().await; // Access the SplitSink
        let message_text = Message::Text(Utf8Bytes::from(message.to_json().to_string()));
        sender.send(message_text).await.unwrap(); // Send the message via the SplitSink
    }
    pub async fn get_community(&self) -> Option<Arc<Community>> {
        self.community.read().await.clone()
    }
    pub async fn get_user_id(&self) -> i64 {
        *self.user_id.read().await
    }
    pub async fn is_identified(&self) -> bool {
        *self.identified.read().await && *self.challenged.read().await
    }

    pub async fn handle_message(self: Arc<Self>, message: String) {
        let mut cv = CommunicationValue::from_json(&message);
        let user_id = self.get_user_id().await;
        cv = cv.with_sender(user_id);

        if cv.is_type(CommunicationType::identification) && !self.is_identified().await {
            self.handle_identification(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::challenge_response) && !self.is_identified().await {
            self.handle_challenge_response(cv).await;
            return;
        }

        if !self.is_identified().await {
            return;
        }

        if cv.is_type(CommunicationType::ping) {
            self.handle_ping(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::client_changed) {
            //self.handle_client_changed(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::function) {
            self.handle_function(cv).await;
            return;
        }
    }
    async fn handle_function(&self, cv: CommunicationValue) {
        let name = cv.get_data(DataTypes::name).unwrap().as_str().unwrap();
        let path = cv.get_data(DataTypes::path).unwrap().as_str().unwrap();
        let function = cv.get_data(DataTypes::function).unwrap().as_str().unwrap();

        let result = self
            .get_community()
            .await
            .unwrap()
            .run_function(self.get_user_id().await, name, path, function, &cv)
            .await;

        self.send_message(&result).await;
    }
    async fn handle_identification(&self, cv: CommunicationValue) {
        let user_id = cv
            .get_data(DataTypes::user_id)
            .unwrap_or(&JsonValue::Number(Number::from(0)))
            .as_i64()
            .unwrap_or(0);

        let Some(user) = get_user(user_id) else {
            self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_user_id)
                .await;
            return;
        };

        {
            let mut auth_guard = self.auth.write().await;
            //*auth_guard = Some(user.clone());

            let mut user_id_guard = self.user_id.write().await;
            *user_id_guard = user_id;

            let mut identified_guard = self.identified.write().await;
            *identified_guard = true;
        }

        let challenge_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        {
            let mut challenge_guard = self.challenge.write().await;
            *challenge_guard = challenge_str.clone();
        }

        let user_public_key_bytes = match STANDARD.decode(&user.public_key) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_user_id)
                    .await;
                return;
            }
        };

        let user_pub_key: PublicKey = match PublicKey::from_bytes(&user_public_key_bytes) {
            Some(key) => key,
            __ => {
                self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_user_id)
                    .await;
                return;
            }
        };

        let Some(community) = self.community.read().await.clone() else {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        };

        let community_private_key = community.get_private_key();
        let community_public_key = community.get_public_key();

        let shared_secret = match community_private_key.to_diffie_hellman(&user_pub_key) {
            Some(secret) => secret,
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let aes_key = {
            let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
            let mut key_bytes = [0u8; 32];
            hk.expand(b"challenge", &mut key_bytes)
                .expect("HKDF failure");
            key_bytes
        };

        let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("AES init failed");

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_challenge = match cipher.encrypt(nonce, challenge_str.as_bytes()) {
            Ok(data) => data,
            Err(_) => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let mut encrypted_out = nonce_bytes.to_vec();
        encrypted_out.extend(encrypted_challenge);

        let response = CommunicationValue::new(CommunicationType::challenge)
            .add_data_str(
                DataTypes::public_key,
                STANDARD.encode(community_public_key.as_bytes()),
            )
            .add_data_str(DataTypes::challenge, STANDARD.encode(&encrypted_out))
            .with_id(cv.get_id());

        self.send_message(&response).await;
    }
    async fn handle_challenge_response(self: Arc<Self>, cv: CommunicationValue) {
        let client_challenge_response_b64 = match cv.get_data(DataTypes::challenge) {
            Some(data) => data.to_string(),
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let challenge_response_bytes = match STANDARD.decode(&client_challenge_response_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        if challenge_response_bytes.len() < 12 {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        }

        let Some(user) = self.auth.read().await.clone() else {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        };

        let Some(user_pub_bytes) = STANDARD.decode(&user.public_key).ok() else {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        };

        let Some(user_pub_key) = PublicKey::from_bytes(&user_pub_bytes) else {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        };

        let Some(community) = self.community.read().await.clone() else {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        };

        let community_private_key = community.get_private_key();

        let shared_secret = match community_private_key.to_diffie_hellman(&user_pub_key) {
            Some(secret) => secret,
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let aes_key = {
            use hkdf::Hkdf;
            use sha2::Sha256;

            let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
            let mut key_bytes = [0u8; 32];
            hk.expand(b"challenge", &mut key_bytes)
                .expect("HKDF failure");
            key_bytes
        };

        let (nonce_bytes, ciphertext) = challenge_response_bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("AES init failed");

        let decrypted_bytes = match cipher.decrypt(nonce, ciphertext) {
            Ok(pt) => pt,
            Err(_) => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let client_response = match String::from_utf8(decrypted_bytes) {
            Ok(str) => str,
            Err(_) => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let expected_challenge = self.challenge.read().await.clone();

        if client_response != expected_challenge {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            self.close().await;
            return;
        }

        {
            let mut authenticated_guard = self.challenged.write().await;
            *authenticated_guard = true;
        }

        let Some(community) = self.community.read().await.clone() else {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        };
        let arc = Arc::new(community);

        let user_id = self.get_user_id().await;
        if user_id == 0 {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        }

        arc.add_connection(self.clone()).await;

        let response = CommunicationValue::new(CommunicationType::identification_response)
            .add_data(DataTypes::interactables, {
                let a: Vec<Arc<Box<dyn Interactable>>> = arc.get_interactables(user_id).await;
                let mut c: JsonValue = JsonValue::new_object();
                for b in a {
                    let mut subject = JsonValue::new_object();
                    subject["codec"] = JsonValue::String(b.get_codec());
                    subject["data"] = b.get_data();
                    c[b.get_name()] = subject;
                }
                c
            })
            .with_id(cv.get_id());

        self.send_message(&response).await;
    }

    async fn send_error_response(&self, message_id: &Uuid, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(*message_id);
        self.send_message(&error).await;
    }
    pub async fn close(&self) {
        let mut sender = self.sender.write().await;
        let _ = sender.close().await;
    }
    pub async fn handle_close(self: Arc<Self>) {
        if self.is_identified().await {
            if self.get_user_id().await != 0 {
                self.community
                    .read()
                    .await
                    .as_ref()
                    .unwrap()
                    .remove_connection(self.clone())
                    .await;
            }
        }
    }

    async fn handle_ping(&self, cv: CommunicationValue) {
        if let Some(last_ping) = cv.get_data(DataTypes::last_ping) {
            if let Ok(ping_val) = last_ping.to_string().parse::<i64>() {
                let mut ping_guard = self.ping.write().await;
                *ping_guard = ping_val;
            }
        }

        let response = CommunicationValue::new(CommunicationType::pong).with_id(cv.get_id());

        self.send_message(&response).await;
    }
}
