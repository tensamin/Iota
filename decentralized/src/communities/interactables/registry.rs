use crate::communities::community::Community;
use crate::communities::interactables::category::Category;
use crate::communities::interactables::interactable::{Interactable, InteractableFactory};
use crate::communities::interactables::text_chat::TextChat;
use crate::communities::interactables::voice_chat::VoiceChat;
use crate::util::file_util;
use json::JsonValue;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub static INTERACTABLE_REGISTRY: Lazy<Arc<Mutex<HashMap<String, InteractableFactory>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));
pub async fn load_interactables() {
    INTERACTABLE_REGISTRY
        .lock()
        .await
        .insert(TextChat::new().get_codec(), || {
            Box::new(TextChat::new()) as Box<dyn Interactable>
        });
    INTERACTABLE_REGISTRY
        .lock()
        .await
        .insert(VoiceChat::new().get_codec(), || {
            Box::new(VoiceChat::new()) as Box<dyn Interactable>
        });
    INTERACTABLE_REGISTRY
        .lock()
        .await
        .insert(Category::new().get_codec(), || {
            Box::new(Category::new()) as Box<dyn Interactable>
        });
}
pub async fn register_interactable(name: String, interactable: InteractableFactory) {
    INTERACTABLE_REGISTRY
        .lock()
        .await
        .insert(name.to_string(), interactable)
        .unwrap();
}
pub async fn get_interactable(name: &str) -> Box<dyn Interactable> {
    INTERACTABLE_REGISTRY.lock().await.get(name).unwrap()()
}
pub async fn save(interactable: &Arc<Box<dyn Interactable>>) {
    let mut json_object: JsonValue = interactable.to_json().clone();
    json_object["codec"] = JsonValue::String(interactable.get_codec());
    json_object["id"] = JsonValue::String(interactable.get_id().to_string());
    file_util::save_file(
        &format!(
            "communities/{}/interactables/{}",
            interactable.get_community().get_name(),
            interactable.get_path()
        ),
        &format!("{}.json", interactable.get_name()),
        &json_object.to_string(),
    );
}
pub async fn load(
    c: Arc<Community>,
    path: String,
    name: String,
) -> Box<dyn Interactable + 'static> {
    let s = file_util::load_file(
        &format!("communities/{}/interactables/{}", c.get_name(), path),
        &format!("{}.json", name),
    );
    let json_object: JsonValue = json::parse(&s).unwrap();
    let codec: String = json_object["codec"].as_str().unwrap().to_string();
    let id: String = json_object["id"].as_str().unwrap().to_string();
    let mut interactable = get_interactable(&codec).await;
    interactable.load(c, Uuid::parse_str(&id).unwrap(), path, name, &json_object);
    interactable
}
