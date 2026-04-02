use crate::communities::{community::Community, interactables::interactable::Interactable};
use async_trait::async_trait;
use json::JsonValue;
use std::sync::Arc;
use std::{any::Any, sync::RwLock};
use uuid::Uuid;
pub enum CallUserState {
    Active,
    Muted,
    Deafed,
}
impl CallUserState {
    pub fn parse(state: &str) -> CallUserState {
        match state {
            "active" => CallUserState::Active,
            "muted" => CallUserState::Muted,
            "deafed" => CallUserState::Deafed,
            _ => CallUserState::Active,
        }
    }
    pub fn to_string(&self) -> String {
        match self {
            CallUserState::Active => "active".to_string(),
            CallUserState::Muted => "muted".to_string(),
            CallUserState::Deafed => "deafed".to_string(),
        }
    }
}

pub struct CallUser {
    pub user_id: Uuid,
    pub user_state: CallUserState,
    pub streaming: bool,
}

pub struct VoiceChat {
    id: Uuid,
    name: String,
    path: String,
    community: Arc<Community>,
    users: RwLock<Vec<CallUser>>,
}
impl VoiceChat {
    pub fn new() -> VoiceChat {
        VoiceChat {
            id: Uuid::new_v4(),
            name: String::new(),
            path: String::new(),
            community: Arc::new(Community::new()),
            users: RwLock::new(Vec::new()),
        }
    }
    pub fn update_user_state(
        self: Arc<Self>,
        user_id: Uuid,
        state: CallUserState,
        streaming: bool,
    ) {
        if let Some(user) = self
            .users
            .write()
            .unwrap()
            .iter_mut()
            .find(|u| u.user_id == user_id)
        {
            user.user_state = state;
            user.streaming = streaming;
        }
    }
}
#[async_trait]
impl Interactable for VoiceChat {
    fn get_id(&self) -> &Uuid {
        &self.id
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn get_codec(&self) -> String {
        "voice".to_string()
    }
    fn set_name(&mut self, name: String) {
        self.name = name;
    }
    fn set_path(&mut self, path: String) {
        self.path = path;
    }
    fn get_community(&self) -> &Arc<Community> {
        &self.community
    }
    fn set_community(&mut self, community: Arc<Community>) {
        self.community = community;
    }
    fn get_name(&self) -> &String {
        &self.name
    }
    fn get_path(&self) -> &String {
        &self.path
    }
    fn get_total_path(&self) -> String {
        String::new() + &self.path + "/" + &self.name
    }
    fn get_data(&self) -> JsonValue {
        let mut data = JsonValue::new_object();
        let mut active_users = JsonValue::new_object();
        for user in self.users.read().unwrap().iter() {
            let mut user_data = JsonValue::new_object();
            let _ = user_data.insert("state", JsonValue::String(user.user_state.to_string()));
            let _ = user_data.insert("streaming", JsonValue::Boolean(user.streaming));
            let _ = active_users.insert(&user.user_id.to_string(), user_data);
        }
        let _ = data.insert("active_users", active_users);
        data
    }
    async fn run_function(&self, cv: CommunicationValue) -> CommunicationValue {
        let payload = cv.get_data(DataTypes::payload).unwrap();
        let function = cv.get_data(DataTypes::function).unwrap().as_str().unwrap();

        if function == "get_call" {
            let sender_id = payload["sender_id"].as_str().unwrap();
            let message_id = payload["message"].as_str().unwrap();
            let send_time = payload["send_time"].as_str().unwrap();

            let mut response_payload = JsonValue::new_object();
            response_payload["sender_id"] = JsonValue::String(sender_id.to_string());
            response_payload["message"] = JsonValue::String(message_id.to_string());
            response_payload["send_time"] = JsonValue::String(send_time.to_string());

            return CommunicationValue::new(CommunicationType::function)
                .with_id(cv.get_id())
                .add_data_str(DataTypes::name, self.name.clone())
                .add_data_str(DataTypes::path, self.path.clone())
                .add_data_str(DataTypes::result, "getting_call".to_string())
                .add_data(DataTypes::payload, response_payload);
        }

        if function == "update_user_state" {
            let user_id = payload["user_id"].as_str().unwrap();
            let state = payload["state"].as_str().unwrap();
            let streaming = payload["streaming"].as_bool().unwrap();

            if let Some(user) = self
                .users
                .write()
                .unwrap()
                .iter_mut()
                .find(|u| u.user_id == Uuid::parse_str(user_id).unwrap())
            {
                user.user_state = CallUserState::parse(state);
                user.streaming = streaming;
            }
            let mut response_payload = JsonValue::new_object();
            response_payload["user_id"] = JsonValue::String(user_id.to_string());
            response_payload["state"] = JsonValue::String(state.to_string());
            response_payload["streaming"] = JsonValue::Boolean(streaming);

            return CommunicationValue::new(CommunicationType::update)
                .with_id(cv.get_id())
                .add_data_str(DataTypes::name, self.name.clone())
                .add_data_str(DataTypes::path, self.path.clone())
                .add_data_str(DataTypes::result, "user_changed".to_string())
                .add_data(DataTypes::payload, response_payload);
        }
        CommunicationValue::new(CommunicationType::error).with_id(cv.get_id())
    }

    fn to_json(&self) -> JsonValue {
        let v = JsonValue::new_object();
        v
    }
    fn load(
        &mut self,
        community: Arc<Community>,
        id: Uuid,
        path: String,
        name: String,
        _json: &JsonValue,
    ) {
        self.community = community;
        self.id = id;
        self.name = name;
        self.path = path;
    }
}
