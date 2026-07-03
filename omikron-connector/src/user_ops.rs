use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_logger::{PrintType, log, log_cv, log_t};
use iota_state::{RELOAD, SHUTDOWN};
use iota_storage::users::user_manager::{add_user, save_users};
use iota_storage::users::user_profile::UserProfile;
use iota_util::crypto_helper::{self, hex_hash, public_key_bundle_to_base64};
use iota_util::file_util::save_file;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use rand_core::{OsRng, RngCore};
use std::time::Duration;

use crate::omikron_connection::OMIKRON_CONNECTION;

pub async fn create_user(username: &str) -> (Option<UserProfile>, Option<String>) {
    let register_communication_value = CommunicationValue::new(CommunicationType::GetRegister);

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
        .get_data(DataType::UserId)
        .as_number()
    {
        Some(id) => id,
        None => {
            log_t!("User creation: Response returned none");
            return (None, None);
        }
    };
    let keyring = crypto_helper::generate_keyring();
    let pub_key_bundle = keyring.public_key_bundle();
    let keyring_b64 = crypto_helper::keyring_to_base64(&keyring);

    let private_key_hash = hex_hash(&keyring_b64);

    let mut bytes = [0u8; 192];
    OsRng.fill_bytes(&mut bytes);
    let reset_token = STANDARD.encode(&bytes);

    let user_profile = UserProfile::new(
        user_id as i64,
        username.to_string(),
        None,
        public_key_bundle_to_base64(&pub_key_bundle),
        private_key_hash,
        reset_token.clone(),
    );

    let communication_value = CommunicationValue::new(CommunicationType::CompleteRegisterUser)
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id as i128))
        .add_typed_default(DataType::Username, DataValue::Str(username.to_string()))
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(public_key_bundle_to_base64(&pub_key_bundle)),
        )
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(user_id as i128))
        .add_typed_default(DataType::ResetToken, DataValue::Str(reset_token));

    let response_communication_value = connection
        .await_response(&communication_value, Some(Duration::from_secs(20)))
        .await;

    if let Ok(response) = response_communication_value {
        log_cv!(PrintType::Omega, response);
        if !response.is_type(CommunicationType::Success) {
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
        &format!("{}::{}", user_id, keyring_b64),
    );

    add_user(user_profile.clone());
    save_users();
    (
        Some(user_profile),
        Some(keyring_b64),
    )
}
