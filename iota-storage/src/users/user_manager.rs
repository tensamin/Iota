use crate::users::user_profile::UserProfile;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_util::crypto_helper::{self, hex_hash, keyring_from_base64, public_key_bundle_to_base64};
use iota_util::file_util::{load_file, save_file};
use json::JsonValue;
use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
use std::io::{self};
use std::sync::Mutex;

static USERS: Lazy<Mutex<Vec<UserProfile>>> = Lazy::new(|| Mutex::new(Vec::new()));
static UNIQUE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

#[allow(dead_code)]
pub async fn load_from_tu(username: &str) -> Result<(), ()> {
    let file_content = load_file("", &format!("{}.tu", username));
    let segments = file_content.split("::").collect::<Vec<&str>>();
    let (uuid_str, _omega_host) = segments[0].split_once('@').unwrap_or((segments[0], ""));
    let uuid = uuid_str.parse::<i64>().unwrap_or(0);
    let b64_private_key = segments[1];

    let keyring = keyring_from_base64(b64_private_key).unwrap();
    let pub_key_bundle = keyring.public_key_bundle();
    let keyring_b64 = crypto_helper::keyring_to_base64(&keyring);

    let mut bytes = [0u8; 192];
    OsRng.fill_bytes(&mut bytes);
    let reset_token = STANDARD.encode(&bytes);

    let user_profile = UserProfile::new(
        uuid,
        username.to_string(),
        Some(username.to_string()),
        public_key_bundle_to_base64(&pub_key_bundle),
        hex_hash(&keyring_b64),
        reset_token,
    );
    USERS.lock().unwrap().push(user_profile);
    Ok(())
}

pub fn add_user(user: UserProfile) {
    USERS.lock().unwrap().push(user);
}

pub fn update_user(user: UserProfile) {
    let mut users = USERS.lock().unwrap();
    if let Some(pos) = users.iter().position(|u| u.user_id == user.user_id) {
        users[pos] = user;
    }
    *UNIQUE.lock().unwrap() = true;
}
pub fn get_user_by_username(username: &str) -> Option<UserProfile> {
    USERS
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .find(|u| u.username == username)
}

pub fn get_user(user_id: i64) -> Option<UserProfile> {
    USERS
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .find(|u| u.user_id == user_id)
}

pub fn get_users() -> Vec<UserProfile> {
    USERS.lock().unwrap().clone()
}

pub fn remove_user(user_id: i64) {
    let mut users = USERS.lock().unwrap();
    users.retain(|u| u.user_id != user_id);
    *UNIQUE.lock().unwrap() = true;
}

pub fn save_users() {
    *UNIQUE.lock().unwrap() = false;
    let users = USERS.lock().unwrap();
    let arr: Vec<JsonValue> = users.iter().map(|u| u.to_json()).collect();
    let json_str = JsonValue::Array(arr).dump();

    save_file("", "users.json", &json_str);
}

pub fn clear() {
    let mut users = USERS.lock().unwrap();
    users.clear();
    *UNIQUE.lock().unwrap() = true;
}

pub async fn load_users() -> io::Result<()> {
    let content = load_file("", "users.json");
    if content.trim().is_empty() {
        return Ok(());
    }

    let parsed =
        json::parse(&content).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    if let JsonValue::Array(arr) = parsed {
        let mut users = USERS.lock().unwrap();
        for j in arr.iter() {
            if let Some(up) = UserProfile::from_json(j).await {
                users.push(up);
            }
        }
    }
    if *UNIQUE.lock().unwrap() {
        save_users();
    }
    Ok(())
}

#[allow(dead_code)]
pub fn set_unique(val: bool) {
    *UNIQUE.lock().unwrap() = val;
}

pub fn save_app_data(user_id: i64, app_identifier: &str, data: &str) {
    let path = format!("users/{}/apps", user_id);
    let name = format!("{}.json", app_identifier);
    save_file(&path, &name, data);
}

pub fn load_app_data(user_id: i64, app_identifier: &str) -> String {
    let path = format!("users/{}/apps", user_id);
    let name = format!("{}.json", app_identifier);
    load_file(&path, &name)
}
