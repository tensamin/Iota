use crate::omikron::omikron_connection::OMIKRON_CONNECTION;
use crate::users::user_profile::UserProfile;
use crate::util::crypto_helper::{self, public_key_to_base64};
use crate::util::file_util::{load_file, save_file};
use crate::util::logger::PrintType;
use crate::{RELOAD, SHUTDOWN};
use crate::{log, log_cv};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hex::{self};
use json::JsonValue;
use once_cell::sync::Lazy;
use rand::Rng;
use rand_core::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::io::{self};
use std::sync::Mutex;
use std::time::Duration;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use x448::{PublicKey, Secret};

static USERS: Lazy<Mutex<Vec<UserProfile>>> = Lazy::new(|| Mutex::new(Vec::new()));
static UNIQUE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

#[allow(dead_code)]
pub async fn load_from_tu(username: &str) -> Result<(), ()> {
    let file_content = load_file("", &format!("{}.tu", username));
    let segments = file_content.split("::").collect::<Vec<&str>>();
    let uuid = segments[0].parse::<i64>().unwrap_or(0);
    let b64_private_key = segments[1];

    let secret: Secret = crypto_helper::load_secret_key(b64_private_key).unwrap();
    let public_key = PublicKey::from(&secret);

    let mut bytes = [0u8; 192];
    OsRng.fill(bytes.as_mut());
    let reset_token = STANDARD.encode(&bytes);

    let user_profile = UserProfile::new(
        uuid,
        username.to_string(),
        Some(username.to_string()),
        crypto_helper::public_key_to_base64(&public_key),
        crypto_helper::hex_hash(b64_private_key),
        reset_token,
    );
    USERS.lock().unwrap().push(user_profile);
    Ok(())
}

pub async fn create_user(username: &str) -> (Option<UserProfile>, Option<String>) {
    let register_cv = CommunicationValue::new(CommunicationType::get_register);

    let conn = OMIKRON_CONNECTION.clone();

    let response_cv = match conn
        .await_response(&register_cv, Some(Duration::from_secs(20)))
        .await
    {
        Ok(cv) => cv,
        Err(_) => return (None, None),
    };
    log_cv!(PrintType::Omega, response_cv);

    let user_id = match response_cv.get_data(DataTypes::user_id).as_number() {
        Some(id) => id,
        None => return (None, None),
    };
    let mut buf = [0u8; 56];
    let mut rng = OsRng;
    rng.fill_bytes(&mut buf);
    let private_key = Secret::from_bytes(&buf).unwrap();
    let public_key = PublicKey::from(&private_key);

    let mut hasher = Sha256::new();
    hasher.update(&STANDARD.encode(&private_key.as_bytes()).as_bytes());
    let result = hasher.finalize();
    let private_key_hash = hex::encode(result);

    let mut bytes = [0u8; 192];
    OsRng.fill(bytes.as_mut());
    let reset_token = STANDARD.encode(&bytes);

    let up = UserProfile::new(
        user_id,
        username.to_string(),
        None,
        STANDARD.encode(&public_key.as_bytes()),
        private_key_hash,
        reset_token.clone(),
    );

    let cv = CommunicationValue::new(CommunicationType::complete_register_user)
        .add_data(DataTypes::user_id, DataValue::Number(user_id))
        .add_data(DataTypes::username, DataValue::Str(username.to_string()))
        .add_data(
            DataTypes::public_key,
            DataValue::Str(public_key_to_base64(&public_key)),
        )
        .add_data(DataTypes::iota_id, DataValue::Number(user_id))
        .add_data(DataTypes::reset_token, DataValue::Str(reset_token));

    let response_cv = conn
        .await_response(&cv, Some(Duration::from_secs(20)))
        .await;

    if let Ok(resp) = response_cv {
        log_cv!(PrintType::Omega, resp);
        if !resp.is_type(CommunicationType::success) {
            return (None, None);
        }
    } else {
        return (None, None);
    }
    *SHUTDOWN.write().await = true;
    *RELOAD.write().await = true;
    log!("Created User");
    save_file(
        "",
        &format!("{}.tu", username),
        &format!("{}::{}", user_id, STANDARD.encode(&private_key.as_bytes())),
    );

    USERS.lock().unwrap().push(up.clone());
    save_users();
    (Some(up), Some(STANDARD.encode(&private_key.as_bytes())))
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
