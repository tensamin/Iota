use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::mapref::entry::Entry;
use iota_opaque::opaque::{self, PasswordLoginBindingV1, PasswordServerSetup};
use iota_storage::users::{password_credentials, user_manager};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::PublicKeyBundle;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    MAX_OPAQUE_BYTES, OmikronConnection, PasswordFinishError, PendingLogin,
    app_protection::{PROVISIONING_CREDENTIAL_ENCRYPTION, PROVISIONING_CREDENTIAL_SIGNATURE},
    wire::{bytes, positive, public_key, public_key_fingerprint, session, typed},
};

const PASSWORD_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

struct PreparedPasswordStart {
    connection_generation: u64,
    request_id: u32,
    session_id: Uuid,
    participant_id: u64,
    user_id: i64,
    iota_id: i64,
    contact_key: PublicKeyBundle,
    ke1: Vec<u8>,
    setup: Arc<PasswordServerSetup>,
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
        let session_id = prepared.session_id;
        let user_id = prepared.user_id;
        let participant_id = prepared.participant_id;
        let generation = prepared.connection_generation;
        let type_map = frame
            .type_map()
            .expect("handler request has a negotiated type map")
            .clone();
        let connection = self.clone();
        let pending = self.track_operation();
        self.preparation_tasks.lock().await.spawn(async move {
            let _pending = pending;
            match connection
                .execute_password_provisioning_start(prepared)
                .await
            {
                Ok(response) => {
                    if let Err(error) = connection.send_message(&response).await {
                        connection.password_auth.abort_login(
                            session_id,
                            user_id,
                            participant_id,
                            generation,
                        );
                        iota_logger::log!("Password KE2 delivery failed: {error}");
                    }
                }
                Err(error) => {
                    connection.password_auth.abort_login(
                        session_id,
                        user_id,
                        participant_id,
                        generation,
                    );
                    iota_logger::log!("Password KE1 processing failed: {error}");
                    let response = CommunicationValue::new_with_type_map(
                        CommunicationType::ErrorNotAuthenticated,
                        &type_map,
                    )
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
        if !self.password_auth.malformed_budget_available() {
            return Err("password service busy".into());
        }
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
        let advertised_account_key = if super::wire::field(content, DataType::Sha256).is_ok() {
            let key = bytes(content, DataType::Sha256, 32)?;
            if key.len() != 32 {
                return Err("invalid account fingerprint".into());
            }
            Some(key)
        } else {
            None
        };
        let ke1 = bytes(content, DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        opaque::validate_login_request(&ke1).map_err(|error| {
            self.password_auth.malformed_request();
            error.to_string()
        })?;
        let setup = self
            .password_auth
            .setup()
            .map_err(|error| error.to_string())?;
        let (attempt, delay) = self
            .password_auth
            .begin_attempt(user_id)
            .map_err(|error| error.to_string())?;
        let connection_generation = self.password_connection_generation();
        match self.password_auth.logins.entry(session_id) {
            Entry::Vacant(slot) => {
                slot.insert(PendingLogin {
                    connection_generation,
                    user_id,
                    participant_id,
                    contact_key: contact_key.clone(),
                    advertised_account_key,
                    state: None,
                    real_record: false,
                    record_hash: None,
                    created: Instant::now(),
                    attempt: Some(attempt),
                });
            }
            Entry::Occupied(_) => return Err("session already started".into()),
        }
        Ok(PreparedPasswordStart {
            connection_generation,
            request_id,
            session_id,
            participant_id,
            user_id,
            iota_id,
            contact_key,
            ke1,
            setup,
            delay,
        })
    }

    async fn execute_password_provisioning_start(
        &self,
        prepared: PreparedPasswordStart,
    ) -> Result<CommunicationValue, String> {
        let PreparedPasswordStart {
            connection_generation,
            request_id,
            session_id,
            participant_id,
            user_id,
            iota_id,
            contact_key,
            ke1,
            setup,
            delay,
        } = prepared;
        let cancellation = self.preparation_cancellation();
        if cancellation.is_cancelled() {
            return Err("connection closed".into());
        }
        if !delay.is_zero() {
            tokio::select! {
                _ = cancellation.cancelled() => return Err("connection closed".into()),
                _ = tokio::time::sleep(delay) => {},
            }
        }
        let principal = self.password_principal(user_id).await?;
        let discovered_key = self.validate_password_hosting(user_id).await?;
        let discovered_fingerprint = super::wire::key_fingerprint(&discovered_key)?;
        if self
            .password_auth
            .logins
            .get(&session_id)
            .is_some_and(|pending| {
                pending
                    .advertised_account_key
                    .as_ref()
                    .is_some_and(|advertised| advertised != &discovered_fingerprint)
            })
        {
            return Err("discovered account key changed".into());
        }
        let runtime = self.password_auth.clone();
        let (response, state, real_record, record_hash) =
            self.password_auth
                .run_blocking(move || {
                    if !runtime.logins.get(&session_id).is_some_and(|pending| {
                        pending.created.elapsed() < PASSWORD_OPERATION_TIMEOUT
                    }) {
                        return Err("password exchange cancelled".to_owned());
                    }
                    let contact_key_sha256 = public_key_fingerprint(&contact_key)?;
                    let binding = PasswordLoginBindingV1 {
                        principal: &principal,
                        iota_id,
                        session_id,
                        contact_key_sha256: &contact_key_sha256,
                    };
                    // Run the same lookups for every account and use a dummy record when absent.
                    let profile =
                        user_manager::get_user(user_id).map_err(|error| error.to_string())?;
                    let credential =
                        password_credentials::get(user_id).map_err(|error| error.to_string())?;
                    let compatible_credential = credential.as_ref().filter(|credential| {
                        profile.as_ref().is_some_and(|profile| {
                            profile.public_key == discovered_key
                                && super::credential_ready(
                                    credential,
                                    &profile.public_key,
                                    &setup,
                                    &principal,
                                    iota_id,
                                )
                        })
                    });
                    let response = opaque::server_login_start(
                        &setup,
                        compatible_credential.map(|value| value.opaque_record.as_slice()),
                        &ke1,
                        &binding,
                    )
                    .map_err(|error| error.to_string())?;
                    let hash = compatible_credential
                        .map(|value| Sha256::digest(&value.opaque_record).to_vec());
                    Ok::<_, String>((
                        response.response,
                        response.state,
                        compatible_credential.is_some(),
                        hash,
                    ))
                })
                .await??;
        let mut pending = self
            .password_auth
            .logins
            .get_mut(&session_id)
            .ok_or("password exchange cancelled")?;
        if pending.connection_generation != connection_generation
            || pending.user_id != user_id
            || pending.participant_id != participant_id
            || pending.created.elapsed() >= PASSWORD_OPERATION_TIMEOUT
        {
            return Err("password exchange expired".into());
        }
        pending.state = Some(state);
        pending.real_record = real_record;
        pending.record_hash = record_hash;
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
            .remove_if(&id, |_, pending| {
                pending.connection_generation == self.password_connection_generation()
                    && positive(frame.payload(), DataType::UserId).ok() == Some(pending.user_id)
                    && positive(frame.payload(), DataType::ProvisioningParticipantId)
                        .ok()
                        .and_then(|id| u64::try_from(id).ok())
                        == Some(pending.participant_id)
            })
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

    // This control message is accepted only on the authenticated Iota connector,
    // never from a client. All binding fields must match before consuming state.
    pub(crate) async fn handle_password_provisioning_abort(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        let result = (|| {
            let id = session(frame.payload())?;
            let user_id = positive(frame.payload(), DataType::UserId)?;
            let participant =
                positive(frame.payload(), DataType::ProvisioningParticipantId)? as u64;
            let iota = positive(frame.payload(), DataType::IotaId)? as u64;
            if Some(iota) != iota_storage::util::config_util::CONFIG.load().iota_id {
                return Err("wrong Iota".to_owned());
            }
            let generation = self.password_connection_generation();
            self.password_auth
                .abort_login(id, user_id, participant, generation);
            Ok::<_, String>(())
        })();
        self.password_error(
            frame,
            if result.is_ok() {
                CommunicationType::Success
            } else {
                CommunicationType::ErrorInvalidData
            },
        )
        .await;
    }

    async fn finish_pending_login(
        &self,
        frame: &CommunicationValue,
        id: Uuid,
        pending: &mut PendingLogin,
    ) -> Result<CommunicationValue, PasswordFinishError> {
        let operation_started = Instant::now();
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
        opaque::validate_login_finalization(&ke3)
            .map_err(|_| PasswordFinishError::InvalidClientMessage)?;
        let principal = self
            .password_principal(pending.user_id)
            .await
            .map_err(|_| PasswordFinishError::CredentialUnavailable)?;
        let discovered_key = self
            .validate_password_hosting(pending.user_id)
            .await
            .map_err(|_| PasswordFinishError::CredentialUnavailable)?;
        let discovered_fingerprint = super::wire::key_fingerprint(&discovered_key)
            .map_err(|_| PasswordFinishError::CredentialUnavailable)?;
        let (release_key, authorization_generation) =
            password_credentials::authorization(pending.user_id)
                .map_err(|_| PasswordFinishError::CredentialUnavailable)?;
        if pending
            .advertised_account_key
            .as_ref()
            .is_some_and(|advertised| advertised != &discovered_fingerprint)
        {
            return Err(PasswordFinishError::CredentialChanged);
        }
        let state = pending
            .state
            .take()
            .ok_or(PasswordFinishError::InvalidClientMessage)?;
        let user_id = pending.user_id;
        let contact_key = pending.contact_key.clone();
        let real_record = pending.real_record;
        let record_hash = pending.record_hash.clone();
        let setup = self
            .password_auth
            .setup()
            .map_err(|_| PasswordFinishError::CredentialUnavailable)?;
        let credential = self
            .password_auth
            .run_blocking(move || {
                // Admission checked the idle TTL. A consumed KE3 keeps its lease
                // for this bounded processing budget, even across that idle TTL.
                if operation_started.elapsed() >= PASSWORD_OPERATION_TIMEOUT {
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
                if profile.public_key != discovered_key
                    || !super::credential_ready(
                        &credential,
                        &profile.public_key,
                        &setup,
                        &principal,
                        iota_id,
                    )
                {
                    return Err(PasswordFinishError::CredentialUnavailable);
                }
                Ok(credential)
            })
            .await
            .map_err(|_| PasswordFinishError::Storage)??;
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
                DataValue::Bytes(credential.encrypted_tu_credential.clone()),
            )?,
            wire(
                DataType::Sha256,
                DataValue::Bytes(credential.account_public_key_sha256.clone()),
            )?,
        ]);
        let keyring = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or(PasswordFinishError::NodeUnavailable)?;
        if operation_started.elapsed() >= PASSWORD_OPERATION_TIMEOUT {
            return Err(PasswordFinishError::BindingMismatch);
        }
        let response = self
            .build_protected(
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
            .map_err(|_| PasswordFinishError::NodeUnavailable)?;
        #[cfg(test)]
        let gate = { self.password_auth.release_gate.lock().unwrap().take() };
        #[cfg(test)]
        if let Some((prepared, release)) = gate {
            prepared.notify_one();
            release.notified().await;
        }
        if operation_started.elapsed() >= PASSWORD_OPERATION_TIMEOUT {
            return Err(PasswordFinishError::BindingMismatch);
        }
        // This atomic snapshot grants release. Disablement or rotation that
        // wins first rejects it. A later commit cannot retract ciphertext in flight.
        password_credentials::authorize_release(
            &credential,
            &release_key,
            authorization_generation,
        )
        .map_err(|_| PasswordFinishError::CredentialChanged)?;
        if operation_started.elapsed() >= PASSWORD_OPERATION_TIMEOUT {
            return Err(PasswordFinishError::BindingMismatch);
        }
        // Clear pressure only after the protected credential is ready to deliver.
        if let Some(attempt) = pending.attempt.take() {
            attempt.success();
        }
        Ok(response)
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
