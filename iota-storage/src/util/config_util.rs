use iota_util::file_util::{load_file, save_file};
use json::JsonValue;
use once_cell::sync::Lazy;
use tokio::sync::RwLock;

pub static CONFIG: Lazy<RwLock<ConfigUtil>> = Lazy::new(|| RwLock::new(ConfigUtil::new()));

pub struct ConfigUtil {
    pub config: JsonValue,
    pub unique: bool,
}

impl ConfigUtil {
    pub fn new() -> Self {
        Self {
            config: JsonValue::new_object(),
            unique: false,
        }
    }
    pub fn clear(&mut self) {
        self.config = JsonValue::new_object();
        self.unique = false;
    }
    pub fn load(&mut self) {
        let s = load_file("", "config.json");
        if s.is_empty() {
            // File might be missing or empty/being written.
            // We don't want to wipe the current config if it already has data.
            // But if it's the first load, it will stay empty.
            return;
        }

        match json::parse(&s) {
            Ok(parsed) => {
                self.config = parsed;
                self.unique = false;
            }
            Err(e) => {
                eprintln!("Failed to parse config.json: {}. Content: '{}'", e, s);
                // Keep the current config rather than wiping it.
            }
        }
    }

    pub fn get_iota_id(&self) -> i64 {
        self.config["iota_id"].as_i64().unwrap_or(0)
    }

    pub fn get_port(&self) -> u16 {
        self.config["port"].as_u16().unwrap_or(1984)
    }

    pub fn get_public_key(&self) -> Option<String> {
        self.config["public_key"].as_str().map(String::from)
    }

    pub fn get_private_key(&self) -> Option<String> {
        self.config["private_key"].as_str().map(String::from)
    }

    pub fn get(&self, key: &str) -> &JsonValue {
        &self.config[key]
    }

    pub fn change(&mut self, key: &str, value: JsonValue) {
        self.config[key] = value;
        self.unique = true;
    }

    pub fn update(&mut self) {
        if self.unique {
            save_file("", "config.json", &self.config.to_string());
            self.unique = false;
        }
    }
}
