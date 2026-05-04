use crate::communities::community::{self, Community};
use crate::log;
use crate::util::file_util;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub static COMMUNITY_REGISTRY: Lazy<Arc<Mutex<HashMap<String, Arc<Community>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub async fn add_community(community: Arc<Community>) {
    COMMUNITY_REGISTRY
        .lock()
        .await
        .insert(community.get_name().to_string(), community);
}
pub async fn remove_community(name: &str) {
    COMMUNITY_REGISTRY.lock().await.remove(name);
}
pub async fn clear() {
    COMMUNITY_REGISTRY.lock().await.clear();
}
pub async fn get_community(name: &str) -> Option<Arc<Community>> {
    if let Some(c) = COMMUNITY_REGISTRY.lock().await.get(name) {
        Some(c.clone())
    } else {
        None
    }
}

pub async fn load_communities() {
    let community_names = file_util::get_children("communities");
    for name in community_names {
        if let Some(community) = community::load(&name).await {
            add_community(community).await;
        } else {
            log!("failed to load the {} community", &name);
        }
    }
}
pub async fn save_communities() {
    for community in COMMUNITY_REGISTRY.lock().await.values() {
        community.save().await;
    }
}

pub async fn get_communities() -> Vec<Arc<Community>> {
    COMMUNITY_REGISTRY.lock().await.values().cloned().collect()
}

pub async fn rename_community(old_name: &str, new_name: &str) {
    if let Some(community) = COMMUNITY_REGISTRY.lock().await.remove(old_name) {
        COMMUNITY_REGISTRY
            .lock()
            .await
            .insert(new_name.to_string(), community);
    }
}
