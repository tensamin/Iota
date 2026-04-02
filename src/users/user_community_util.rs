use crate::util::file_util::save_file;
use json::{self, Array, JsonValue};
use std::fs;
use std::path::Path;

pub struct UserCommunityUtil;

impl UserCommunityUtil {
    pub fn add_community(storage_owner: i64, address: String, title: String, position: String) {
        let file_path = format!("users/{}/", storage_owner);
        let mut communities = Self::load_array(&file_path);

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
        let communities = Self::load_array(&file_path);

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
        let file_path = format!("users/{}/communities.json", storage_owner);
        Self::load_array(&file_path)
    }

    fn load_array(file_path: &str) -> Array {
        if !Path::new(file_path).exists() {
            return Array::new();
        }

        match fs::read_to_string(file_path) {
            Ok(content) => {
                let parsed = json::parse(&content);
                match parsed {
                    Ok(JsonValue::Array(arr)) => arr,
                    _ => Array::new(),
                }
            }
            Err(err) => {
                eprintln!("Failed to read file {}: {}", file_path, err);
                Array::new()
            }
        }
    }
}
