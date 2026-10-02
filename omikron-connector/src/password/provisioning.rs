use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::mapref::entry::Entry;
use iota_opaque::{
    credential,
    opaque::{self, PasswordLoginBindingV1, PasswordServerSetup},
};
use iota_storage::users::{password_credentials, user_manager};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::PublicKeyBundle;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    MAX_CREDENTIAL_BYTES, MAX_OPAQUE_BYTES, OmikronConnection, PasswordFinishError, PendingLogin,
    app_protection::{PROVISIONING_CREDENTIAL_ENCRYPTION, PROVISIONING_CREDENTIAL_SIGNATURE},
    runtime::AttemptLease,
    wire::{bytes, key_fingerprint, positive, public_key, public_key_fingerprint, session, typed},
};

struct PreparedPasswordStart {
    request_id: u32,
    session_id: Uuid,
    participant_id: u64,
    user_id: i64,
    iota_id: i64,
    contact_key: PublicKeyBundle,
    ke1: Vec<u8>,
    setup: Arc<PasswordServerSetup>,
    attempt: AttemptLease,
    delay: Duration,
}

impl OmikronConnection {
    pub(crate) async fn handle_password_provisioning_start(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        let prepared = match self.prepare_password_provisioning_start(frame) {
            Ok(prepared) => prepared,
            Err(error) => {
                iota_logger::log!("Password KE1 admission failed: {error}");
                self.password_error(frame, CommunicationType::ErrorNotAuthenticated)
                    .await;
                return;
            }
        };
        let request_id = prepared.request_id;
        let connection = self.clone();
        tokio::spawn(async move {
            match connection
                .execute_password_provisioning_start(prepared)
                .await
            {
                Ok(response) => {
                    if let Err(error) = connection.send_message(&response).await {
                        iota_logger::log!("Password KE2 delivery failed: {error}");
                    }
                }
                Err(error) => {
                    iota_logger::log!("Password KE1 processing failed: {error}");
                    let response =
                        CommunicationValue::new(CommunicationType::ErrorNotAuthenticated)
                            .with_id(request_id);
                    let _ = connection.send_message(&response).await;
                }
            }
        });
    }

    fn prepare_password_provisioning_start(
        &self,
        frame: &CommunicationValue,
    ) -> Result<PreparedPasswordStart, String> {
        let content = frame.payload();
        let request_id = frame.id().ok_or("missing request ID")?;
        let session_id = session(content)?;
        let participant_id = u64::try_from(positive(content, DataType::ProvisioningParticipantId)?)
            .map_err(|error| error.to_string())?;
        let user_id = positive(content, DataType::UserId)?;
        let iota_id = positive(content, DataType::IotaId)?;
        if Some(iota_id as u64) != iota_storage::util::config_util::CONFIG.load().iota_id {
            return Err("wrong Iota".into());
        }
        let contact_key = public_key(content)?;
        let ke1 = bytes(content, DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        opaque::validate_login_request(&ke1).map_err(|error| error.to_string())?;
        let setup = self
            .password_auth
            .setup()
            .map_err(|error| error.to_string())?;
        let (attempt, delay) = self
            .password_auth
            .begin_attempt(user_id)
            .map_err(|error| error.to_string())?;
        Ok(PreparedPasswordStart {
            request_id,
            session_id,
            participant_id,
            user_id,
            iota_id,
            contact_key,
            ke1,
            setup,
            attempt,
            delay,
        })
    }

    async fn execute_password_provisioning_start(
        &self,
        prepared: PreparedPasswordStart,
    ) -> Result<CommunicationValue, String> {
        let PreparedPasswordStart {
            request_id,
            session_id,
            participant_id,
            user_id,
            iota_id,
            contact_key,
            ke1,
            setup,
            attempt,
            delay,
        } = prepared;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let principal = self.password_principal(user_id).await?;
        let (response, pending) = self
            .password_auth
            .run_blocking(move || {
                let contact_key_sha256 = public_key_fingerprint(&contact_key)?;
                let binding = PasswordLoginBindingV1 {
                    principal: &principal,
                    iota_id,
                    session_id,
                    contact_key_sha256: &contact_key_sha256,
                };
                // Run the same lookups for every account and use a dummy record when absent.
                let profile = user_manager::get_user(user_id).map_err(|error| error.to_string())?;
                let credential =
                    password_credentials::get(user_id).map_err(|error| error.to_string())?;
                let compatible_credential = credential.as_ref().filter(|credential| {
                    profile.is_some() && credential.opaque_profile == opaque::CURRENT_OPAQUE_PROFILE
                });
                let response = opaque::server_login_start(
                    &setup,
                    compatible_credential.map(|value| value.opaque_record.as_slice()),
                    &ke1,
                    &binding,
                )
                .map_err(|error| error.to_string())?;
                let pending = PendingLogin {
                    user_id,
                    participant_id,
                    contact_key,
                    state: Some(response.state),
                    real_record: compatible_credential.is_some(),
                    created: Instant::now(),
                    attempt: Some(attempt),
                    record_hash: compatible_credential
                        .map(|value| Sha256::digest(&value.opaque_record).to_vec()),
                };
                Ok::<_, String>((response.response, pending))
            })
            .await??;
        match self.password_auth.logins.entry(session_id) {
            Entry::Vacant(slot) => {
                slot.insert(pending);
            }
            Entry::Occupied(_) => {
                return Err("session already started".into());
            }
        }
        Ok(
            CommunicationValue::new(CommunicationType::PasswordProvisioningResponse)
                .with_id(request_id)
                .add_typed_default(DataType::Uuid, DataValue::Str(session_id.to_string()))
                .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(response)),
        )
    }

    pub(crate) async fn handle_password_provisioning_finish(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        match self.provisioning_finish(frame).await {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password KE3 failed: {error}");
                self.password_error(frame, CommunicationType::ErrorNotAuthenticated)
                    .await;
            }
        }
    }

    pub(super) async fn provisioning_finish(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let id = session(frame.payload())?;
        let (_, mut pending) = self
            .password_auth
            .logins
            .remove(&id)
            .ok_or("OPAQUE session expired")?;
        match self.finish_pending_login(frame, id, &mut pending).await {
            Ok(response) => Ok(response),
            Err(error) => {
                if let Some(attempt) = pending.attempt.take() {
                    if error.counts_as_guess() {
                        attempt.failure();
                    } else {
                        attempt.cancel();
                    }
                }
                Err(error.to_string())
            }
        }
    }

    async fn finish_pending_login(
        &self,
        frame: &CommunicationValue,
        id: Uuid,
        pending: &mut PendingLogin,
    ) -> Result<CommunicationValue, PasswordFinishError> {
        let content = frame.payload();
        if pending.created.elapsed() >= self.password_auth.pending_ttl
            || pending.user_id
                != positive(content, DataType::UserId)
                    .map_err(|_| PasswordFinishError::InvalidClientMessage)?
            || pending.participant_id
                != u64::try_from(
                    positive(content, DataType::ProvisioningParticipantId)
                        .map_err(|_| PasswordFinishError::InvalidClientMessage)?,
                )
                .map_err(|_| PasswordFinishError::InvalidClientMessage)?
            || pending
                .contact_key
                .try_as_bytes()
                .map_err(|_| PasswordFinishError::InvalidClientMessage)?
                != public_key(content)
                    .map_err(|_| PasswordFinishError::InvalidClientMessage)?
                    .try_as_bytes()
                    .map_err(|_| PasswordFinishError::InvalidClientMessage)?
        {
            return Err(PasswordFinishError::BindingMismatch);
        }
        let iota_id = positive(content, DataType::IotaId)
            .map_err(|_| PasswordFinishError::InvalidClientMessage)?;
        if Some(iota_id as u64) != iota_storage::util::config_util::CONFIG.load().iota_id {
            return Err(PasswordFinishError::BindingMismatch);
        }
        let ke3 = bytes(content, DataType::OpaqueMessage, MAX_OPAQUE_BYTES)
            .map_err(|_| PasswordFinishError::InvalidClientMessage)?;
        let principal = self
            .password_principal(pending.user_id)
            .await
            .map_err(|_| PasswordFinishError::CredentialUnavailable)?;
        let state = pending
            .state
            .take()
            .ok_or(PasswordFinishError::InvalidClientMessage)?;
        let user_id = pending.user_id;
        let contact_key = pending.contact_key.clone();
        let real_record = pending.real_record;
        let record_hash = pending.record_hash.clone();
        let created = pending.created;
        let pending_ttl = self.password_auth.pending_ttl;
        let credential = self
            .password_auth
            .run_blocking(move || {
                if created.elapsed() >= pending_ttl {
                    return Err(PasswordFinishError::BindingMismatch);
                }
                let contact_key_sha256 = public_key_fingerprint(&contact_key)
                    .map_err(|_| PasswordFinishError::InvalidClientMessage)?;
                let binding = PasswordLoginBindingV1 {
                    principal: &principal,
                    iota_id,
                    session_id: id,
                    contact_key_sha256: &contact_key_sha256,
                };
                match opaque::server_login_finish(state, &ke3, &binding) {
                    Ok(()) => {}
                    Err(opaque::LoginFinishError::AuthenticationFailed) => {
                        return Err(PasswordFinishError::Authentication);
                    }
                    Err(opaque::LoginFinishError::InvalidMessage) => {
                        return Err(PasswordFinishError::InvalidClientMessage);
                    }
                }
                if !real_record {
                    return Err(PasswordFinishError::Authentication);
                }
                let credential = password_credentials::get(user_id)
                    .map_err(|_| PasswordFinishError::Storage)?
                    .ok_or(PasswordFinishError::CredentialUnavailable)?;
                if credential.opaque_profile != opaque::CURRENT_OPAQUE_PROFILE {
                    return Err(PasswordFinishError::CredentialUnavailable);
                }
                if record_hash.as_deref()
                    != Some(Sha256::digest(&credential.opaque_record).as_slice())
                {
                    return Err(PasswordFinishError::CredentialChanged);
                }
                let profile = user_manager::get_user(user_id)
                    .map_err(|_| PasswordFinishError::Storage)?
                    .ok_or(PasswordFinishError::CredentialUnavailable)?;
                if credential.account_public_key_sha256
                    != key_fingerprint(&profile.public_key)
                        .map_err(|_| PasswordFinishError::CredentialUnavailable)?
                    || credential.encrypted_tu_credential.len() > MAX_CREDENTIAL_BYTES
                    || credential::validate_envelope(&credential.encrypted_tu_credential).is_err()
                {
                    return Err(PasswordFinishError::CredentialUnavailable);
                }
                Ok(credential)
            })
            .await
            .map_err(|_| PasswordFinishError::Storage)??;
        // Only the same registered credential can clear password pressure.
        if let Some(attempt) = pending.attempt.take() {
            attempt.success();
        }
        let wire =
            |kind, value| typed(kind, value).map_err(|_| PasswordFinishError::InvalidClientMessage);
        let content = DataValue::Container(vec![
            wire(DataType::Uuid, DataValue::Str(id.to_string()))?,
            wire(
                DataType::ProvisioningMethod,
                DataValue::Str("password".into()),
            )?,
            wire(
                DataType::UserId,
                DataValue::SignedNumber(pending.user_id.into()),
            )?,
            wire(DataType::IotaId, DataValue::SignedNumber(iota_id.into()))?,
            wire(
                DataType::EncryptedCredential,
                DataValue::Bytes(credential.encrypted_tu_credential),
            )?,
            wire(
                DataType::Sha256,
                DataValue::Bytes(credential.account_public_key_sha256),
            )?,
        ]);
        let keyring = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or(PasswordFinishError::NodeUnavailable)?;
        self.build_protected(
            frame,
            CommunicationType::ProvisioningCredential,
            iota_id as u64,
            pending.participant_id,
            content,
            pending.contact_key.clone(),
            PROVISIONING_CREDENTIAL_SIGNATURE,
            PROVISIONING_CREDENTIAL_ENCRYPTION,
            &keyring,
        )
        .map_err(|_| PasswordFinishError::NodeUnavailable)
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use dashmap::DashSet;
    use iota_storage::util::config_util::CONFIG;
    use mtp::crypto::Keyring;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn delayed_password_start_releases_general_handler_capacity() {
        let mut config = (**CONFIG.load()).clone();
        let iota_id = config.iota_id.unwrap_or(11);
        config.iota_id = Some(iota_id);
        let previous = CONFIG.swap(Arc::new(config));

        let mut connection = OmikronConnection::new(
            Arc::new(DashSet::new()),
            Arc::new(std::sync::Mutex::new(iota_state::AppState::new())),
        );
        Arc::get_mut(&mut connection.password_auth)
            .unwrap()
            .throttle
            .soft_delay_step = Duration::from_millis(400);
        let connection = Arc::new(connection);
        connection
            .password_auth
            .setup
            .set(Arc::new(opaque::generate_server_setup()))
            .ok()
            .unwrap();
        let user_id = 777;
        connection
            .password_auth
            .begin_attempt(user_id)
            .unwrap()
            .0
            .failure();
        let ke1 = opaque::client_login_start(b"password").unwrap().request;
        let frame = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
            .with_id(42)
            .add_typed_default(DataType::Uuid, DataValue::Str(Uuid::new_v4().to_string()))
            .add_typed_default(
                DataType::ProvisioningParticipantId,
                DataValue::UnsignedNumber(1),
            )
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()))
            .add_typed_default(
                DataType::PublicKey,
                DataValue::Str(
                    Keyring::generate()
                        .public_key_bundle()
                        .try_to_base64()
                        .unwrap(),
                ),
            )
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(ke1));
        let malformed = frame.clone().with_data(
            DataType::OpaqueMessage,
            DataValue::Bytes(b"not a KE1".to_vec()),
        );
        assert!(
            connection
                .prepare_password_provisioning_start(&malformed)
                .is_err()
        );
        assert_eq!(
            connection
                .password_auth
                .attempts
                .get(&user_id)
                .unwrap()
                .in_flight,
            0
        );
        let general = Arc::new(Semaphore::new(1));
        let permit = general.clone().acquire_owned().await.unwrap();
        connection
            .clone()
            .handle_password_provisioning_start(&frame)
            .await;
        drop(permit);

        assert_eq!(
            connection
                .password_auth
                .attempts
                .get(&user_id)
                .unwrap()
                .in_flight,
            1
        );
        let normal = tokio::time::timeout(Duration::from_millis(100), general.acquire())
            .await
            .expect("normal work must acquire the general permit during password delay")
            .unwrap();
        drop(normal);
        assert_eq!(
            connection
                .password_auth
                .attempts
                .get(&user_id)
                .unwrap()
                .in_flight,
            1
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while connection
                .password_auth
                .attempts
                .get(&user_id)
                .unwrap()
                .in_flight
                != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        CONFIG.store(previous);
    }
}
