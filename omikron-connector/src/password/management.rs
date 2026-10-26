use std::{sync::Arc, time::Instant};

use iota_opaque::{credential, opaque};
use iota_storage::users::{
    password_credentials::{self, PasswordCredential},
    user_manager,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use uuid::Uuid;

use super::{
    MAX_CREDENTIAL_BYTES, MAX_OPAQUE_BYTES, OmikronConnection,
    app_protection::{PASSWORD_RESPONSE_ENCRYPTION, PASSWORD_RESPONSE_SIGNATURE},
    runtime::PendingEnrollment,
    wire::{bytes, key_fingerprint, now_millis, session, typed},
};

impl OmikronConnection {
    pub(crate) async fn handle_password_enrollment_start(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        match self.enrollment_start(frame).await {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password enrollment start failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    async fn enrollment_start(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let (opened, public_key, authorization_generation) = self
            .open_password_command(frame, CommunicationType::PasswordEnrollmentStart, true)
            .await?;
        let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
        let permit = self.password_auth.begin_enrollment()?;
        let principal = self.password_principal(user_id).await?;
        let request = bytes(opened.content(), DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let setup = self
            .password_auth
            .setup()
            .map_err(|error| error.to_string())?;
        let response = self
            .password_auth
            .run_blocking(move || {
                opaque::server_registration_start(&setup, &request, principal.as_bytes())
                    .map_err(|error| error.to_string())
            })
            .await??;
        let enrollment_id = Uuid::new_v4();
        let response = self
            .protected_response(
                frame,
                CommunicationType::PasswordEnrollmentResponse,
                user_id,
                DataValue::Container(vec![
                    typed(DataType::Uuid, DataValue::Str(enrollment_id.to_string()))?,
                    typed(DataType::OpaqueMessage, DataValue::Bytes(response))?,
                ]),
                PASSWORD_RESPONSE_SIGNATURE,
                PASSWORD_RESPONSE_ENCRYPTION,
            )
            .await?;
        self.password_auth.enrollments.insert(
            enrollment_id,
            PendingEnrollment {
                public_key,
                authorization_generation,
                user_id,
                created: Instant::now(),
                _permit: permit,
            },
        );
        Ok(response)
    }

    pub(crate) async fn handle_password_enrollment_finish(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        match self.enrollment_finish(frame).await {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password enrollment finish failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    pub(super) async fn enrollment_finish(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let (opened, expected_public_key, authorization_generation) = self
            .open_password_command(frame, CommunicationType::PasswordEnrollmentFinish, true)
            .await?;
        let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
        let enrollment_id = session(opened.content())?;
        let (_, pending) = self
            .password_auth
            .enrollments
            .remove_if(&enrollment_id, |_, pending| pending.user_id == user_id)
            .ok_or("enrollment expired")?;
        if pending.user_id != user_id
            || pending.created.elapsed() >= self.password_auth.pending_ttl
            || pending.public_key != expected_public_key
            || pending.authorization_generation != authorization_generation
        {
            return Err("enrollment mismatch".into());
        }
        let upload = bytes(opened.content(), DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let encrypted = bytes(
            opened.content(),
            DataType::EncryptedCredential,
            MAX_CREDENTIAL_BYTES,
        )?;
        credential::validate_envelope(&encrypted).map_err(|error| error.to_string())?;
        let opaque_record =
            opaque::server_registration_finish(&upload).map_err(|error| error.to_string())?;
        let fingerprint = key_fingerprint(&expected_public_key)?;
        let now = now_millis() as i64;
        let setup = self
            .password_auth
            .setup()
            .map_err(|error| error.to_string())?;
        let principal = self.password_principal(user_id).await?;
        let iota_id = iota_storage::util::config_util::CONFIG
            .load()
            .iota_id
            .ok_or("Iota has no identity")? as i64;
        use sha2::{Digest, Sha256};
        let operation_id = opened.message_id().to_string();
        let request_sha256 = Sha256::digest(
            frame
                .clone()
                .without_id()
                .to_bytes()
                .map_err(|error| error.to_string())?,
        );
        password_credentials::commit_enrollment(
            &PasswordCredential {
                user_id,
                opaque_profile: opaque::CURRENT_OPAQUE_PROFILE,
                opaque_record,
                encrypted_tu_credential: encrypted,
                account_public_key_sha256: fingerprint,
                created_at: now,
                updated_at: now,
                setup_sha256: Some(
                    Sha256::digest(opaque::serialize_server_setup(&setup).as_slice()).to_vec(),
                ),
                password_principal: Some(principal),
                password_iota_id: Some(iota_id),
            },
            &expected_public_key,
            authorization_generation,
            (&operation_id, &request_sha256),
        )
        .map_err(|error| error.to_string())?;
        self.password_auth.cancel_logins_for_user(user_id);
        if let Err(error) = self.password_auth.validate_storage() {
            iota_logger::log!("Password storage validation failed after enrollment: {error}");
        }
        self.protected_response(
            frame,
            CommunicationType::PasswordEnrollmentStatus,
            user_id,
            DataValue::Container(vec![typed(DataType::Enabled, DataValue::Bool(true))?]),
            PASSWORD_RESPONSE_SIGNATURE,
            PASSWORD_RESPONSE_ENCRYPTION,
        )
        .await
    }

    pub(crate) async fn handle_password_enrollment_status(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        if frame.get_data(DataType::SecurePayload).is_some() {
            match self.password_mutation_status(frame).await {
                Ok(response) => {
                    let _ = self.send_message(&response).await;
                }
                Err(error) => {
                    iota_logger::log!("Password mutation status failed: {error}");
                    self.password_error(frame, CommunicationType::ErrorInternal)
                        .await;
                }
            }
            return;
        }
        if self.password_auth.setup().is_err() {
            self.password_error(frame, CommunicationType::ErrorInternal)
                .await;
            return;
        }
        let result = async {
            let (opened, _, _) = self
                .open_password_command(frame, CommunicationType::PasswordEnrollmentStatus, true)
                .await?;
            let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
            let setup = self
                .password_auth
                .setup()
                .map_err(|error| error.to_string())?;
            let principal = self.password_principal(user_id).await?;
            let iota_id = iota_storage::util::config_util::CONFIG
                .load()
                .iota_id
                .ok_or("Iota has no identity")? as i64;
            let profile = user_manager::get_user(user_id)
                .map_err(|error| error.to_string())?
                .ok_or("account not hosted")?;
            let enabled = password_credentials::get(user_id)
                .map_err(|error| error.to_string())?
                .is_some_and(|credential| {
                    super::credential_ready(
                        &credential,
                        &profile.public_key,
                        &setup,
                        &principal,
                        iota_id,
                    )
                });
            self.protected_response(
                frame,
                CommunicationType::PasswordEnrollmentStatus,
                user_id,
                DataValue::Container(vec![typed(DataType::Enabled, DataValue::Bool(enabled))?]),
                PASSWORD_RESPONSE_SIGNATURE,
                PASSWORD_RESPONSE_ENCRYPTION,
            )
            .await
        }
        .await;
        match result {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password status failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    pub(crate) async fn handle_password_enrollment_disable(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        let result = async {
            let (opened, expected_public_key, authorization_generation) = self
                .open_password_command(frame, CommunicationType::PasswordEnrollmentDisable, true)
                .await?;
            let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
            use sha2::{Digest, Sha256};
            let operation_id = opened.message_id().to_string();
            let request_sha256 = Sha256::digest(
                frame
                    .clone()
                    .without_id()
                    .to_bytes()
                    .map_err(|error| error.to_string())?,
            );
            password_credentials::commit_disable(
                user_id,
                &expected_public_key,
                authorization_generation,
                (&operation_id, &request_sha256),
            )
            .map_err(|error| error.to_string())?;
            self.password_auth.cancel_logins_for_user(user_id);
            if let Err(error) = self.password_auth.validate_storage() {
                iota_logger::log!("Password storage validation failed after disablement: {error}");
            }
            self.protected_response(
                frame,
                CommunicationType::PasswordEnrollmentStatus,
                user_id,
                DataValue::Container(vec![typed(DataType::Enabled, DataValue::Bool(false))?]),
                PASSWORD_RESPONSE_SIGNATURE,
                PASSWORD_RESPONSE_ENCRYPTION,
            )
            .await
        }
        .await;
        match result {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password disable failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    /// The wrapper carries the original account-protected command unchanged.
    /// Verifying it authorizes a receipt read, never replay of its mutation.
    pub(super) async fn password_mutation_status(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        use sha2::{Digest, Sha256};
        let original = frame
            .get_data(DataType::SecurePayload)
            .and_then(DataValue::as_bytes)
            .ok_or("missing protected operation")?;
        if original.len() > 512 * 1024 {
            return Err("protected operation too large".into());
        }
        let version = frame
            .get_data(DataType::Version)
            .and_then(DataValue::as_str)
            .and_then(mtp::type_map::Version::parse)
            .ok_or("missing operation type map")?;
        let original =
            CommunicationValue::try_from_bytes_with(&original, &mtp::codec::TypeMap::new(version))
                .map_err(|error| error.to_string())?;
        let kind = original
            .get_comm_type_enum()
            .filter(|kind| {
                matches!(
                    kind,
                    CommunicationType::PasswordEnrollmentFinish
                        | CommunicationType::PasswordEnrollmentDisable
                )
            })
            .ok_or("not a durable password mutation")?;
        let (opened, key, generation) = self.open_password_command(&original, kind, false).await?;
        if frame.sender() != Some(opened.signer_id()) {
            return Err("wrong operation owner".into());
        }
        let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
        let operation_id = opened.message_id().to_string();
        let digest = Sha256::digest(
            original
                .without_id()
                .to_bytes()
                .map_err(|error| error.to_string())?,
        );
        let Some(enabled) = password_credentials::mutation_outcome(
            user_id,
            &key,
            generation,
            (&operation_id, &digest),
        )
        .map_err(|error| error.to_string())?
        else {
            // Absence does not prove rollback. The sender must retain its uncertain intent.
            return Ok(CommunicationValue::new_with_type_map(
                CommunicationType::ErrorInternal,
                frame.type_map().ok_or("missing type map")?,
            )
            .with_id(frame.id().ok_or("missing request ID")?));
        };
        self.protected_response(
            frame,
            CommunicationType::PasswordEnrollmentStatus,
            user_id,
            DataValue::Container(vec![
                typed(DataType::Enabled, DataValue::Bool(enabled))?,
                typed(DataType::Status, DataValue::Str("committed".into()))?,
                typed(DataType::Sha256, DataValue::Bytes(digest.to_vec()))?,
            ]),
            PASSWORD_RESPONSE_SIGNATURE,
            PASSWORD_RESPONSE_ENCRYPTION,
        )
        .await
    }
}
