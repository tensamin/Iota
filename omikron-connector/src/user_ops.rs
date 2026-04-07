use base64::{Engine as _, engine::general_purpose::STANDARD};
use hex;
use iota_logger::{PrintType, log, log_cv};
use iota_state::{RELOAD, SHUTDOWN};
use iota_storage::users::user_manager::{add_user, save_users};
use iota_storage::users::user_profile::UserProfile;
use iota_util::crypto_helper::public_key_to_base64;
use iota_util::file_util::save_file;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::Duration;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use x448::{PublicKey, Secret};

use crate::omikron_connection::OMIKRON_CONNECTION;

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
    OsRng.fill_bytes(&mut bytes);
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

    add_user(up.clone());
    save_users();
    (Some(up), Some(STANDARD.encode(&private_key.as_bytes())))
}
