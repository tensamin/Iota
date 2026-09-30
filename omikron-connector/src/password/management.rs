use std::{sync::Arc, time::Instant};

use iota_storage::users::{
    password_credentials::{self, PasswordCredential},
    user_manager,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use opague_integration::opaque;
use uuid::Uuid;

use super::{
    MAX_CREDENTIAL_BYTES, MAX_OPAQUE_BYTES, OmikronConnection,
    app_protection::{PASSWORD_RESPONSE_ENCRYPTION, PASSWORD_RESPONSE_SIGNATURE},
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
        let opened = self
            .open_password_command(frame, CommunicationType::PasswordEnrollmentStart)
            .await?;
        let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
        if self.password_auth.enrollments.len() >= self.password_auth.max_pending {
            return Err("too many enrollments".into());
        }
        let principal = self.password_principal(user_id).await?;
        let request = bytes(opened.content(), DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let setup = self
            .password_auth
            .setup()
            .map_err(|error| error.to_string())?;
        let response = opaque::server_registration_start(&setup, &request, principal.as_bytes())
            .map_err(|error| error.to_string())?;
        let enrollment_id = Uuid::new_v4();
        self.password_auth
            .enrollments
            .insert(enrollment_id, (user_id, Instant::now()));
        self.protected_response(
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
        .await
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
        let opened = self
            .open_password_command(frame, CommunicationType::PasswordEnrollmentFinish)
            .await?;
        let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
        let enrollment_id = session(opened.content())?;
        let (_, (pending_user, started)) = self
            .password_auth
            .enrollments
            .remove(&enrollment_id)
            .ok_or("enrollment expired")?;
        if pending_user != user_id || started.elapsed() >= self.password_auth.pending_ttl {
            return Err("enrollment mismatch".into());
        }
        let upload = bytes(opened.content(), DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let encrypted = bytes(
            opened.content(),
            DataType::EncryptedCredential,
            MAX_CREDENTIAL_BYTES,
        )?;
        let opaque_record =
            opaque::server_registration_finish(&upload).map_err(|error| error.to_string())?;
        let profile = user_manager::get_user(user_id)
            .map_err(|error| error.to_string())?
            .ok_or("account not hosted")?;
        let fingerprint = key_fingerprint(&profile.public_key)?;
        let now = now_millis() as i64;
        password_credentials::upsert(&PasswordCredential {
            user_id,
            opaque_profile: opaque::CURRENT_OPAQUE_PROFILE,
            opaque_record,
            encrypted_tu_credential: encrypted,
            account_public_key_sha256: fingerprint,
            created_at: now,
            updated_at: now,
        })
        .map_err(|error| error.to_string())?;
        self.password_auth.cancel_logins_for_user(user_id);
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
        let result = async {
            let opened = self
                .open_password_command(frame, CommunicationType::PasswordEnrollmentStatus)
                .await?;
            let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
            let enabled = password_credentials::get(user_id)
                .map_err(|error| error.to_string())?
                .is_some_and(|credential| {
                    credential.opaque_profile == opaque::CURRENT_OPAQUE_PROFILE
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
            let opened = self
                .open_password_command(frame, CommunicationType::PasswordEnrollmentDisable)
                .await?;
            let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
            password_credentials::delete(user_id).map_err(|error| error.to_string())?;
            self.password_auth.cancel_logins_for_user(user_id);
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
}
