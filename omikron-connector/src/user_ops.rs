use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_logger::{PrintType, log, log_cv, log_t};
use iota_storage::users::user_manager::try_add_user;
use iota_storage::users::user_profile::UserProfile;
use iota_util::crypto_helper::{self, hex_hash, public_key_bundle_to_base64};
use iota_util::file_util::try_save_file;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use rand_core::{OsRng, RngCore};
use std::time::Duration;

use crate::OmikronClient;
use crate::omega_discovery;

#[derive(Debug)]
pub enum CreateUserError {
    InvalidUsername,
    Transport(crate::OmikronError),
    InvalidResponse,
    RemoteRejected,
    LocalPersistence(String),
}

fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.chars().count() <= 15
        && !username.chars().any(char::is_control)
        && !username.contains(['/', '\\'])
}

async fn request_user_id(connection: &dyn OmikronClient) -> Result<(i64, String), CreateUserError> {
    let request = CommunicationValue::new(CommunicationType::GetRegister);
    let response = connection
        .await_response(&request, Duration::from_secs(20))
        .await
        .map_err(CreateUserError::Transport)?;

    if !response.is_type(CommunicationType::GetRegister) {
        return Err(CreateUserError::InvalidResponse);
    }

    let user_id = response
        .get_data(DataType::UserId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| (1..(1_i64 << 48)).contains(id))
        .ok_or(CreateUserError::InvalidResponse)?;
    let registration_token = response
        .get_data(DataType::RegisterId)
        .as_str()
        .filter(|token| uuid::Uuid::parse_str(token).is_ok())
        .map(str::to_owned)
        .ok_or(CreateUserError::InvalidResponse)?;
    Ok((user_id, registration_token))
}

/// A completion response can be lost after Omega commits the user.  Confirm
/// the exact remote record before treating that transport failure as success.
async fn registration_committed(connection: &dyn OmikronClient, profile: &UserProfile) -> bool {
    let request = CommunicationValue::new(CommunicationType::GetUserData).add_typed_default(
        DataType::UserId,
        DataValue::SignedNumber(profile.user_id.into()),
    );
    let Ok(response) = connection
        .await_response(&request, Duration::from_secs(5))
        .await
    else {
        return false;
    };
    response.get_data(DataType::UserId).as_number() == Some(profile.user_id.into())
        && response.get_data(DataType::Username).as_str() == Some(profile.username.as_str())
        && response.get_data(DataType::PublicKey).as_str() == Some(profile.public_key.as_str())
}

pub async fn create_user(
    connection: &dyn OmikronClient,
    username: &str,
) -> Result<UserProfile, CreateUserError> {
    if !valid_username(username) {
        return Err(CreateUserError::InvalidUsername);
    }
    let (user_id, registration_token) = request_user_id(connection).await?;
    log!("User creation: Omega allocated user ID {user_id}");
    let keyring = crypto_helper::generate_keyring();
    let pub_key_bundle = keyring.public_key_bundle();
    let keyring_b64 = crypto_helper::keyring_to_base64(&keyring);

    let private_key_hash = hex_hash(&keyring_b64);

    let mut bytes = [0u8; 192];
    OsRng.fill_bytes(&mut bytes);
    let reset_token = STANDARD.encode(&bytes);

    let user_profile = UserProfile::new(
        user_id,
        username.to_string(),
        None,
        public_key_bundle_to_base64(&pub_key_bundle),
        private_key_hash,
        reset_token.clone(),
    );

    let communication_value = CommunicationValue::new(CommunicationType::CompleteRegisterUser)
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
        .add_typed_default(DataType::Username, DataValue::Str(username.to_string()))
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(public_key_bundle_to_base64(&pub_key_bundle)),
        )
        .add_typed_default(DataType::ResetToken, DataValue::Str(reset_token))
        .add_typed_default(DataType::RegisterId, DataValue::Str(registration_token));

    let response_communication_value = connection
        .await_response(&communication_value, Duration::from_secs(20))
        .await;

    match response_communication_value {
        Ok(response) => {
            log_cv!(PrintType::Omega, response);
            if !response.is_type(CommunicationType::Success) {
                return Err(CreateUserError::RemoteRejected);
            }
        }
        Err(error) => {
            if registration_committed(connection, &user_profile).await {
                log!(
                    "User creation: completion response was lost; verified user {} remotely",
                    user_id
                );
            } else {
                log_t!("User creation: {}", error.to_string());
                return Err(match error {
                    crate::OmikronError::Internal(_) => CreateUserError::RemoteRejected,
                    error => CreateUserError::Transport(error),
                });
            }
        }
    }
    log!("Created User");
    try_save_file(
        "",
        &format!("{}.tu", username),
        &format!(
            "{}@{}::{}",
            user_id,
            omega_discovery::omega_host(),
            keyring_b64
        ),
    )
    .map_err(|error| CreateUserError::LocalPersistence(error.to_string()))?;

    try_add_user(user_profile.clone())
        .map_err(|error| CreateUserError::LocalPersistence(error.to_string()))?;
    Ok(user_profile)
}

#[cfg(test)]
mod tests {
    use super::{CreateUserError, request_user_id, valid_username};
    use crate::{OmikronClient, OmikronError};
    use async_trait::async_trait;
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
    use std::time::Duration;

    struct RegistrationClient {
        response: CommunicationValue,
    }

    #[async_trait]
    impl OmikronClient for RegistrationClient {
        async fn send_message(&self, _: &CommunicationValue) -> Result<(), OmikronError> {
            unreachable!()
        }

        async fn await_response(
            &self,
            request: &CommunicationValue,
            _: Duration,
        ) -> Result<CommunicationValue, OmikronError> {
            assert!(request.is_type(CommunicationType::GetRegister));
            Ok(self.response.clone().with_id(request.get_id()))
        }

        async fn reconnect(&self) -> Result<(), OmikronError> {
            unreachable!()
        }

        async fn rotate_identity(&self) -> Result<(), OmikronError> {
            unreachable!()
        }

        async fn is_connected(&self) -> bool {
            true
        }
    }

    #[test]
    fn validates_usernames_before_remote_registration() {
        assert!(valid_username("alice"));
        assert!(valid_username("fifteen_char_ok"));
        assert!(!valid_username(""));
        assert!(!valid_username("sixteen_chars_bad"));
        assert!(!valid_username("path/name"));
        assert!(!valid_username("line\nbreak"));
    }

    #[tokio::test]
    async fn uses_user_id_allocated_by_omega() {
        let client = RegistrationClient {
            response: CommunicationValue::new(CommunicationType::GetRegister)
                .add_typed_default(DataType::UserId, DataValue::SignedNumber(4_294_967_311))
                .add_typed_default(
                    DataType::RegisterId,
                    DataValue::Str("00000000-0000-4000-8000-000000000001".into()),
                ),
        };

        assert_eq!(
            request_user_id(&client).await.unwrap(),
            (4_294_967_311, "00000000-0000-4000-8000-000000000001".into())
        );
    }

    #[tokio::test]
    async fn rejects_registration_response_without_a_positive_user_id() {
        let client = RegistrationClient {
            response: CommunicationValue::new(CommunicationType::GetRegister)
                .add_typed_default(DataType::UserId, DataValue::SignedNumber(0)),
        };

        assert!(matches!(
            request_user_id(&client).await,
            Err(CreateUserError::InvalidResponse)
        ));
    }
}
