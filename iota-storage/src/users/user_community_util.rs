use iota_util::file_util::{load_file, save_file};
use json::{self, Array, JsonValue};

pub struct UserCommunityUtil;

impl UserCommunityUtil {
    pub fn add_community(storage_owner: i64, address: String, title: String, position: String) {
        let file_path = format!("users/{}/", storage_owner);
        let mut communities = Self::load_array(&file_path, "communities.json");

        let mut community = JsonValue::new_object();
        community["title"] = JsonValue::String(title);
        community["address"] = JsonValue::String(address);
        community["position"] = JsonValue::String(position);

        communities.push(community);

        save_file(
            &file_path,
            "communities.json",
            &JsonValue::Array(communities).to_string(),
        );
    }

    pub fn remove_community(storage_owner: i64, community_address: String) {
        let file_path = format!("users/{}/", storage_owner);
        let communities = Self::load_array(&file_path, "communities.json");

        let filtered: Array = communities
            .iter()
            .filter(|entry| entry["address"].as_str() != Some(&community_address))
            .cloned()
            .collect();
        save_file(
            &file_path,
            "communities.json",
            &JsonValue::Array(filtered).to_string(),
        );
    }

    pub fn get_communities(storage_owner: i64) -> Array {
        let file_path = format!("users/{}/", storage_owner);
        Self::load_array(&file_path, "communities.json")
    }

    fn load_array(dir: &str, name: &str) -> Array {
        let content = load_file(dir, name);
        if content.is_empty() {
            return Array::new();
        }

        let parsed = json::parse(&content);
        match parsed {
            Ok(JsonValue::Array(arr)) => arr,
            _ => Array::new(),
        }
    }
}
