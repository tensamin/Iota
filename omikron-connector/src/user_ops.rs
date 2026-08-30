use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_logger::{PrintType, log, log_cv, log_t};
use iota_storage::users::pending_operations::{
    self, PendingUserOperation, PendingUserOperationKind, PendingUserOperationPhase,
};
use iota_storage::users::user_manager::try_add_user;
use iota_storage::users::user_profile::UserProfile;
use iota_storage::util::config_util::CONFIG;
use iota_util::crypto_helper::{self, hex_hash, public_key_bundle_to_base64};
use iota_util::file_util::{remove_user_credential, write_user_credential};
use iota_util::mtp_compat::OptionalDataValueExt;
use iota_util::tu::TuCredential;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::{Ed25519Signer, MlDsaSigner, SignatureScheme};
use rand_core::{OsRng, RngCore};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::OmikronClient;
use crate::omega_discovery;

#[derive(Debug)]
pub enum CreateUserError {
    InvalidUsername,
    Transport(crate::OmikronError),
    InvalidResponse,
    RemoteRejected,
    LocalFinalizationPending { user_id: i64 },
    LocalPersistence(String),
}

#[derive(Debug)]
pub enum LifecycleUserError {
    InvalidCredential(String),
    OmegaHostMismatch,
    RemoteRejected,
    Transport(crate::OmikronError),
    LocalPersistence(String),
}

impl From<crate::OmikronError> for LifecycleUserError {
    fn from(value: crate::OmikronError) -> Self {
        Self::Transport(value)
    }
}

fn lifecycle_payload(domain: &[u8], user_id: i64, iota_id: i64, nonce: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(domain.len() + 24);
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&user_id.to_be_bytes());
    payload.extend_from_slice(&iota_id.to_be_bytes());
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload
}

fn configured_iota_id() -> Result<i64, LifecycleUserError> {
    CONFIG
        .load()
        .iota_id
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            LifecycleUserError::InvalidCredential("Iota identity is not registered".into())
        })
}

fn sign_lifecycle_payload(
    credential: &TuCredential,
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), LifecycleUserError> {
    let classical = Ed25519Signer::new(&credential.keyring.sig_cl_secret_key)
        .map_err(|error| LifecycleUserError::InvalidCredential(error.to_string()))?
        .sign(payload)
        .map_err(|error| LifecycleUserError::InvalidCredential(error.to_string()))?;
    let pq = MlDsaSigner::new(
        &credential.keyring.sig_pq_secret_key,
        &credential.keyring.sig_pq_public_key,
    )
    .map_err(|error| LifecycleUserError::InvalidCredential(error.to_string()))?
    .sign(payload)
    .map_err(|error| LifecycleUserError::InvalidCredential(error.to_string()))?;
    Ok((classical, pq))
}

async fn inspect_credential_account(
    connection: &dyn OmikronClient,
    credential: &TuCredential,
) -> Result<(String, String, i64), LifecycleUserError> {
    if credential.omega_host != omega_discovery::omega_host() {
        return Err(LifecycleUserError::OmegaHostMismatch);
    }
    let request = CommunicationValue::new(CommunicationType::GetUserData).add_typed_default(
        DataType::UserId,
        DataValue::SignedNumber(credential.user_id.into()),
    );
    let response = connection
        .await_response(&request, Duration::from_secs(20))
        .await?;
    if !response.is_type(CommunicationType::GetUserData) {
        return Err(LifecycleUserError::RemoteRejected);
    }
    let username = response
        .get_data(DataType::Username)
        .as_str()
        .map(str::to_owned)
        .ok_or(LifecycleUserError::RemoteRejected)?;
    let public_key = response
        .get_data(DataType::PublicKey)
        .as_str()
        .map(str::to_owned)
        .ok_or(LifecycleUserError::RemoteRejected)?;
    let created_at = response
        .get_data(DataType::CreatedAt)
        .as_signed_number()
        .and_then(|value| i64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(LifecycleUserError::RemoteRejected)?;
    if public_key != public_key_bundle_to_base64(&credential.public_key_bundle()) {
        return Err(LifecycleUserError::RemoteRejected);
    }
    Ok((username, public_key, created_at))
}

async fn credential_proof(
    connection: &dyn OmikronClient,
    credential: &TuCredential,
    begin: CommunicationType,
    challenge: CommunicationType,
    complete: CommunicationType,
    domain: &[u8],
) -> Result<(), LifecycleUserError> {
    let iota_id = configured_iota_id()?;
    let begin_request = CommunicationValue::new(begin).add_typed_default(
        DataType::UserId,
        DataValue::SignedNumber(credential.user_id.into()),
    );
    let challenge_response = connection
        .await_response(&begin_request, Duration::from_secs(20))
        .await?;
    if !challenge_response.is_type(challenge) {
        return Err(LifecycleUserError::RemoteRejected);
    }
    let nonce = challenge_response
        .get_data(DataType::ServerNonce)
        .as_signed_number()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(LifecycleUserError::RemoteRejected)?;
    let (signature, pq_signature) = sign_lifecycle_payload(
        credential,
        &lifecycle_payload(domain, credential.user_id, iota_id, nonce),
    )?;
    let complete_request = CommunicationValue::new(complete)
        .add_typed_default(
            DataType::UserId,
            DataValue::SignedNumber(credential.user_id.into()),
        )
        .add_typed_default(DataType::ServerNonce, DataValue::SignedNumber(nonce.into()))
        .add_typed_default(DataType::Signature, DataValue::Bytes(signature))
        .add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_signature));
    let response = connection
        .await_response(&complete_request, Duration::from_secs(20))
        .await?;
    if response.is_type(CommunicationType::Success) {
        Ok(())
    } else {
        Err(LifecycleUserError::RemoteRejected)
    }
}

/// Attach or migrate an existing account. Local state is written only after
/// Omega has accepted the credential proof and changed its assignment.
pub async fn attach_user_from_tu(
    connection: &dyn OmikronClient,
    contents: &str,
) -> Result<UserProfile, LifecycleUserError> {
    let credential = TuCredential::parse(contents)
        .map_err(|error| LifecycleUserError::InvalidCredential(error.to_string()))?;
    let (username, public_key, created_at) =
        inspect_credential_account(connection, &credential).await?;
    let profile = UserProfile::new_with_created_at(
        credential.user_id,
        username,
        None,
        public_key,
        hex_hash(contents),
        String::new(),
        created_at,
    );
    pending_operations::upsert(&PendingUserOperation {
        user_id: profile.user_id,
        operation: PendingUserOperationKind::Attach,
        username: profile.username.clone(),
        public_key: Some(profile.public_key.clone()),
        private_key_hash: Some(profile.private_key_hash.clone()),
        reset_token: Some(profile.reset_token.clone()),
        registration_token: None,
        phase: PendingUserOperationPhase::Prepared,
        created_at: now_millis(),
    })
    .map_err(|error| LifecycleUserError::LocalPersistence(error.to_string()))?;
    write_user_credential(&profile.username, &credential.to_canonical_string())
        .map_err(|error| LifecycleUserError::LocalPersistence(error.to_string()))?;
    pending_operations::update_phase(
        profile.user_id,
        PendingUserOperationPhase::CredentialWritten,
    )
    .map_err(|error| LifecycleUserError::LocalPersistence(error.to_string()))?;
    if let Err(error) = credential_proof(
        connection,
        &credential,
        CommunicationType::AttachUserBegin,
        CommunicationType::AttachUserChallenge,
        CommunicationType::AttachUserComplete,
        b"tensamin:user-attach:v1\0",
    )
    .await
    {
        if matches!(error, LifecycleUserError::RemoteRejected) {
            let _ = pending_operations::remove(profile.user_id);
            let _ = remove_user_credential(profile.user_id, Some(&profile.username));
        }
        return Err(error);
    }
    try_add_user(profile.clone())
        .map_err(|error| LifecycleUserError::LocalPersistence(error.to_string()))?;
    pending_operations::remove(profile.user_id)
        .map_err(|error| LifecycleUserError::LocalPersistence(error.to_string()))?;
    Ok(profile)
}

pub async fn complete_delete_user_with_tu(
    connection: &dyn OmikronClient,
    contents: &str,
    expected_user_id: i64,
) -> Result<(), LifecycleUserError> {
    let credential = TuCredential::parse(contents)
        .map_err(|error| LifecycleUserError::InvalidCredential(error.to_string()))?;
    if credential.user_id != expected_user_id {
        return Err(LifecycleUserError::InvalidCredential(
            "credential user ID does not match deletion target".into(),
        ));
    }
    inspect_credential_account(connection, &credential).await?;
    credential_proof(
        connection,
        &credential,
        CommunicationType::DeleteUserCredentialBegin,
        CommunicationType::DeleteUserCredentialChallenge,
        CommunicationType::DeleteUserCredentialComplete,
        b"tensamin:user-delete:v1\0",
    )
    .await
}

/// Repair local management state after a release or migration committed in
/// Omega but local cleanup was interrupted. Hosted data is retained.
pub async fn reconcile_managed_users(connection: &dyn OmikronClient) {
    let Ok(local_iota_id) = configured_iota_id() else {
        return;
    };
    let pending = match pending_operations::get_all() {
        Ok(pending) => pending,
        Err(error) => {
            log!("Pending user operation reconciliation could not read storage: {error}");
            return;
        }
    };
    for operation in pending {
        let request = CommunicationValue::new(CommunicationType::GetUserData).add_typed_default(
            DataType::UserId,
            DataValue::SignedNumber(operation.user_id.into()),
        );
        let response = connection
            .await_response(&request, Duration::from_secs(10))
            .await
            .ok();
        let remote_iota_id = response.as_ref().and_then(|response| {
            response
                .get_data(DataType::IotaId)
                .as_signed_number()
                .and_then(|value| i64::try_from(value).ok())
        });
        let remote_matches = response.as_ref().is_some_and(|response| {
            response.is_type(CommunicationType::GetUserData)
                && remote_iota_id == Some(local_iota_id)
                && response.get_data(DataType::Username).as_str() == Some(&operation.username)
                && response.get_data(DataType::PublicKey).as_str()
                    == operation.public_key.as_deref()
        });
        let completion_retried = matches!(operation.operation, PendingUserOperationKind::Create)
            && matches!(
                operation.phase,
                PendingUserOperationPhase::Prepared | PendingUserOperationPhase::CredentialWritten
            )
            && !remote_matches
            && complete_pending_create(connection, &operation).await;
        match operation.operation {
            PendingUserOperationKind::Create | PendingUserOperationKind::Attach
                if remote_matches || completion_retried =>
            {
                let credential_present = iota_util::file_util::read_user_credential_with_legacy(
                    operation.user_id,
                    &operation.username,
                )
                .ok()
                .flatten()
                .is_some();
                if !credential_present {
                    log!(
                        "Pending user {} has no credential; leaving it unresolved",
                        operation.user_id
                    );
                    continue;
                }
                let Some(public_key) = operation.public_key else {
                    continue;
                };
                let profile = UserProfile::new(
                    operation.user_id,
                    operation.username,
                    None,
                    public_key,
                    operation.private_key_hash.unwrap_or_default(),
                    operation.reset_token.unwrap_or_default(),
                );
                if try_add_user(profile).is_ok() {
                    let _ = pending_operations::remove(operation.user_id);
                }
            }
            PendingUserOperationKind::Release if remote_iota_id != Some(local_iota_id) => {
                if iota_storage::users::user_manager::release_user(operation.user_id).is_ok() {
                    let _ = pending_operations::remove(operation.user_id);
                }
            }
            _ => {}
        }
    }
    for user in iota_storage::users::user_manager::get_users() {
        let request = CommunicationValue::new(CommunicationType::GetUserData).add_typed_default(
            DataType::UserId,
            DataValue::SignedNumber(user.user_id.into()),
        );
        let Ok(response) = connection
            .await_response(&request, Duration::from_secs(10))
            .await
        else {
            continue;
        };
        let remote_iota_id = response
            .get_data(DataType::IotaId)
            .as_signed_number()
            .and_then(|value| i64::try_from(value).ok());
        if remote_iota_id != Some(local_iota_id) {
            let _ = iota_storage::users::user_manager::release_user(user.user_id);
        }
    }
}

/*
 * Retry completion only while the locally persisted operation still owns a
 * valid registration lease. Omega treats an exact repeat as idempotent, which
 * repairs an interrupted request without allocating another user ID.
 */
async fn complete_pending_create(
    connection: &dyn OmikronClient,
    operation: &PendingUserOperation,
) -> bool {
    let Some(public_key) = operation.public_key.as_ref() else {
        return false;
    };
    let Some(reset_token) = operation.reset_token.as_ref() else {
        return false;
    };
    let Some(registration_token) = operation.registration_token.as_ref() else {
        return false;
    };
    let request = CommunicationValue::new(CommunicationType::CompleteRegisterUser)
        .add_typed_default(
            DataType::UserId,
            DataValue::SignedNumber(operation.user_id.into()),
        )
        .add_typed_default(
            DataType::Username,
            DataValue::Str(operation.username.clone()),
        )
        .add_typed_default(DataType::PublicKey, DataValue::Str(public_key.clone()))
        .add_typed_default(DataType::ResetToken, DataValue::Str(reset_token.clone()))
        .add_typed_default(
            DataType::RegisterId,
            DataValue::Str(registration_token.clone()),
        );
    match connection
        .await_response(&request, Duration::from_secs(20))
        .await
    {
        Ok(response) if response.is_type(CommunicationType::Success) => {
            if let Err(error) = pending_operations::update_phase(
                operation.user_id,
                PendingUserOperationPhase::RemoteCommitted,
            ) {
                log!(
                    "Pending user {} completed remotely but could not update its phase: {error}",
                    operation.user_id
                );
            }
            true
        }
        Ok(response) => {
            log!(
                "Pending user {} registration retry was rejected with {}",
                operation.user_id,
                response.get_type()
            );
            false
        }
        Err(error) => {
            log!(
                "Pending user {} registration retry failed: {error}",
                operation.user_id
            );
            false
        }
    }
}

fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 15
        && username
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
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
    let credential = format!(
        "{}@{}::{}",
        user_id,
        omega_discovery::omega_host(),
        keyring_b64
    );
    pending_operations::upsert(&PendingUserOperation {
        user_id,
        operation: PendingUserOperationKind::Create,
        username: user_profile.username.clone(),
        public_key: Some(user_profile.public_key.clone()),
        private_key_hash: Some(user_profile.private_key_hash.clone()),
        reset_token: Some(user_profile.reset_token.clone()),
        registration_token: Some(registration_token.clone()),
        phase: PendingUserOperationPhase::Prepared,
        created_at: now_millis(),
    })
    .map_err(|error| CreateUserError::LocalPersistence(error.to_string()))?;
    write_user_credential(username, &credential)
        .map_err(|error| CreateUserError::LocalPersistence(error.to_string()))?;
    pending_operations::update_phase(user_id, PendingUserOperationPhase::CredentialWritten)
        .map_err(|error| CreateUserError::LocalPersistence(error.to_string()))?;

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
                let _ = pending_operations::remove(user_id);
                let _ = remove_user_credential(user_id, Some(username));
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
    pending_operations::update_phase(user_id, PendingUserOperationPhase::RemoteCommitted)
        .map_err(|_| CreateUserError::LocalFinalizationPending { user_id })?;
    try_add_user(user_profile.clone())
        .map_err(|_| CreateUserError::LocalFinalizationPending { user_id })?;
    pending_operations::update_phase(user_id, PendingUserOperationPhase::LocalCommitted)
        .map_err(|_| CreateUserError::LocalFinalizationPending { user_id })?;
    pending_operations::remove(user_id)
        .map_err(|_| CreateUserError::LocalFinalizationPending { user_id })?;
    log!("Created User");
    Ok(user_profile)
}

#[cfg(test)]
mod tests {
    use super::{CreateUserError, request_user_id, valid_username};
    use crate::{OmikronClient, OmikronError};
    use async_trait::async_trait;
    use iota_connection::message_common::CommunicationResponseExt;
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
            Ok(self.response.clone().with_request_id(request))
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
        assert!(valid_username("abc123def456ghi"));
        assert!(!valid_username(""));
        assert!(!valid_username("sixteen_chars_bad"));
        assert!(!valid_username("path/name"));
        assert!(!valid_username("upperCase"));
        assert!(!valid_username("underscore_name"));
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
