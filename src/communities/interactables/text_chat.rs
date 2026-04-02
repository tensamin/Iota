use crate::{
    communities::{
        community::Community, community_connection::CommunityConnection,
        interactables::interactable::Interactable,
    },
    log,
    util::file_util::{get_children, load_file, save_file},
};
use async_trait::async_trait;
use json::{JsonValue, array, object};
use std::fs;
use std::sync::Arc;
use std::{any::Any, collections::HashMap};
use ttp_core::{CommunicationType, CommunicationValue, DataTypes};
use uuid::Uuid;
pub struct TextChat {
    id: Uuid,
    name: String,
    path: String,
    community: Arc<Community>,
}
impl TextChat {
    pub fn new() -> TextChat {
        TextChat {
            id: Uuid::new_v4(),
            name: String::new(),
            path: String::new(),
            community: Arc::new(Community::new()),
        }
    }
    pub fn add_message(&self, send_time: u128, sender: i64, message: &str) {
        let user_dir = &format!(
            "communities/{}/interactables/{}/{}",
            self.get_community().get_name(),
            self.get_path(),
            self.get_name()
        );

        if let Err(e) = fs::create_dir_all(user_dir) {
            log!("Failed to create chat directory: {}", e);
            return;
        }

        let mut chunk_index = 0;
        let mut message_chunk = array![];

        // find latest chunk not full (max 800 msgs)
        loop {
            let file_name = format!("msgs_{}.json", chunk_index);
            let file_content = load_file(&user_dir, &file_name);

            if !file_content.is_empty() {
                if let Ok(current_chunk) = json::parse(&file_content) {
                    if current_chunk.is_array() && current_chunk.len() < 800 {
                        message_chunk = current_chunk;
                        break;
                    }
                } else {
                    log!("Failed to parse existing JSON file: {}", file_name);
                }
            } else {
                break;
            }

            chunk_index += 1;
            if chunk_index > 1000 {
                log!("Too many message chunks. Aborting add.");
                return;
            }
        }

        let json_obj = object! {
            "timestamp" => send_time as i64,
            "content" => message,
            "sender" => sender.to_string(),
        };

        if let Err(e) = message_chunk.push(json_obj) {
            log!("Failed to push new message into JSON array: {}", e);
            return;
        }

        let file_name = format!("msgs_{}.json", chunk_index);
        log!("Saving message to {}/{}", user_dir, file_name);
        save_file(&user_dir, &file_name, &message_chunk.dump());
    }
    pub fn get_messages(&self, loaded_messages: i64, amount: i64) -> JsonValue {
        let mut messages = array![];

        let mut latest_chunk_index: i32 = -1;
        let files = get_children(&format!(
            "communities/{}/interactables/{}/{}",
            self.get_community().get_name(),
            self.get_path(),
            self.get_name()
        ));

        for entry in files {
            if let Some(num) = {
                entry
                    .strip_prefix("msgs_")
                    .and_then(|s| s.strip_suffix(".json"))
            } {
                if let Ok(index) = num.parse::<i32>() {
                    if index > latest_chunk_index {
                        latest_chunk_index = index;
                    }
                }
            }
        }

        if latest_chunk_index == -1 {
            return messages;
        }

        let mut to_skip = loaded_messages;
        let mut needed = amount;

        for chunk_index in (0..=latest_chunk_index).rev() {
            if needed == 0 {
                break;
            }
            let file_name = format!("msgs_{}.json", chunk_index);
            let file_content = load_file(
                &format!(
                    "communities/{}/interactables/{}/{}",
                    self.get_community().get_name(),
                    self.get_path(),
                    self.get_name()
                ),
                &file_name,
            );
            if file_content.is_empty() {
                continue;
            }
            if let Ok(chunk) = json::parse(&file_content) {
                for i in (0..chunk.len()).rev() {
                    if needed == 0 {
                        break;
                    }
                    if to_skip > 0 {
                        to_skip -= 1;
                        continue;
                    }
                    messages.push(chunk[i].clone()).unwrap();
                    needed -= 1;
                }
            }
        }

        messages
    }
}
#[async_trait]
impl Interactable for TextChat {
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
        "text".to_string()
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
        JsonValue::new_object()
    }
    async fn run_function(&self, cv: CommunicationValue) -> CommunicationValue {
        let payload = cv.get_data(DataTypes::payload).as_container().unwrap();
        if cv.get_data(DataTypes::function).as_str().unwrap() == "get_messages" {
            let amount = payload.get(DataTypes::amount).as_i64().unwrap();
            let loaded_messages = payload["loaded_messages"].as_i64().unwrap();
            let messages = self.get_messages(loaded_messages, amount).clone();
            let mut payload = JsonValue::new_object();
            payload["messages"] = messages;
            return CommunicationValue::new(CommunicationType::function)
                .with_id(cv.get_id())
                .add_data_str(DataTypes::name, self.name.clone())
                .add_data_str(DataTypes::path, self.path.clone())
                .add_data_str(DataTypes::result, "message_chunk".to_string())
                .add_data(DataTypes::payload, payload);
        }
        if cv.get_data(DataTypes::function).unwrap().as_str().unwrap() == "send_message" {
            let message = payload["message"].as_str().unwrap();
            let milliseconds_timestamp: u128 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            self.add_message(milliseconds_timestamp, cv.get_sender(), message);

            let mut distribution_payload = JsonValue::new_object();
            distribution_payload["message"] = JsonValue::String(message.to_string());
            distribution_payload["sender_id"] = JsonValue::String(cv.get_sender().to_string());
            distribution_payload["send_time"] =
                JsonValue::String(milliseconds_timestamp.to_string());
            let distribution = CommunicationValue::new(CommunicationType::update)
                .with_id(cv.get_id())
                .add_data_str(DataTypes::name, self.name.clone())
                .add_data_str(DataTypes::path, self.path.clone())
                .add_data_str(DataTypes::result, "message_live".to_string())
                .add_data(DataTypes::payload, distribution_payload);

            let connections: HashMap<i64, Vec<Arc<CommunityConnection>>> =
                self.get_community().get_connections().await.clone();

            for con in connections.values() {
                for c in con {
                    let cd: &Arc<CommunityConnection> = c;
                    cd.send_message(&distribution).await;
                }
            }
            return CommunicationValue::new(CommunicationType::function)
                .with_id(cv.get_id())
                .add_data_str(DataTypes::name, self.name.clone())
                .add_data_str(DataTypes::path, self.path.clone())
                .add_data_str(DataTypes::result, "message_received".to_string())
                .add_data(DataTypes::payload, JsonValue::new_object());
        }
        CommunicationValue::new(CommunicationType::error).with_id(cv.get_id())
    }
    fn to_json(&self) -> JsonValue {
        JsonValue::new_object()
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
