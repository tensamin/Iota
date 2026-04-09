use base64::{Engine as _, engine::general_purpose::STANDARD};
use hex;
use iota_logger::{PrintType, log, log_cv, log_t};
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
    let register_communication_value = CommunicationValue::new(CommunicationType::get_register);

    let connection = OMIKRON_CONNECTION.clone();

    let response_communication_value = match connection
        .await_response(&register_communication_value, Some(Duration::from_secs(20)))
        .await
    {
        Ok(communication_value) => communication_value,
        Err(e) => {
            log_t!("User creation: {}", e);
            return (None, None);
        }
    };
    log_cv!(PrintType::Omega, response_communication_value);

    let user_id = match response_communication_value
        .get_data(DataTypes::user_id)
        .as_number()
    {
        Some(id) => id,
        None => {
            log_t!("User creation: Response returned none");
            return (None, None);
        }
    };
    let mut buffer = [0u8; 56];
    let mut rng = OsRng;
    rng.fill_bytes(&mut buffer);
    let private_key = Secret::from_bytes(&buffer).unwrap();
    let public_key = PublicKey::from(&private_key);

    let mut hasher = Sha256::new();
    hasher.update(&STANDARD.encode(&private_key.as_bytes()).as_bytes());
    let result = hasher.finalize();
    let private_key_hash = hex::encode(result);

    let mut bytes = [0u8; 192];
    OsRng.fill_bytes(&mut bytes);
    let reset_token = STANDARD.encode(&bytes);

    let user_profile = UserProfile::new(
        user_id,
        username.to_string(),
        None,
        STANDARD.encode(&public_key.as_bytes()),
        private_key_hash,
        reset_token.clone(),
    );

    let communication_value = CommunicationValue::new(CommunicationType::complete_register_user)
        .add_data(DataTypes::user_id, DataValue::Number(user_id))
        .add_data(DataTypes::username, DataValue::Str(username.to_string()))
        .add_data(
            DataTypes::public_key,
            DataValue::Str(public_key_to_base64(&public_key)),
        )
        .add_data(DataTypes::iota_id, DataValue::Number(user_id))
        .add_data(DataTypes::reset_token, DataValue::Str(reset_token));

    let response_communication_value = connection
        .await_response(&communication_value, Some(Duration::from_secs(20)))
        .await;

    if let Ok(response) = response_communication_value {
        log_cv!(PrintType::Omega, response);
        if !response.is_type(CommunicationType::success) {
            return (None, None);
        }
    } else {
        log_t!("User creation: Response returned none");
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

    add_user(user_profile.clone());
    save_users();
    (
        Some(user_profile),
        Some(STANDARD.encode(&private_key.as_bytes())),
    )
}
