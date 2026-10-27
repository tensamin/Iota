use iota_storage::{users::user_manager, util::protected_replay};
use mtp::{
    codec::{
        CommunicationType, CommunicationValue, DataValue, ProtectedMessageBuilder,
        ProtectedOpenOptions, ProtectionPolicy, ReplayError, ReplayGuard, VerifiedProtectedMessage,
        open_protected_with_checked, open_protected_with_without_replay,
    },
    crypto::{DualSigner, PublicKeyBundle},
};
use rand_core::{OsRng, RngCore};

use super::{
    OmikronConnection,
    app_protection::{PASSWORD_MANAGEMENT_ENCRYPTION, PASSWORD_MANAGEMENT_SIGNATURE, purpose},
    wire::now_millis,
};

struct CommandReplayGuard;

impl ReplayGuard for CommandReplayGuard {
    fn accept(
        &mut self,
        signer_id: u64,
        message_id: mtp::common::MessageId,
        created_at: u64,
    ) -> Result<bool, ReplayError> {
        let now = now_millis();
        if created_at < now.saturating_sub(7 * 24 * 60 * 60 * 1000)
            || created_at > now.saturating_add(5 * 60 * 1000)
        {
            return Ok(false);
        }
        let signer =
            i64::try_from(signer_id).map_err(|error| ReplayError::Store(error.to_string()))?;
        let time =
            i64::try_from(created_at).map_err(|error| ReplayError::Store(error.to_string()))?;
        protected_replay::accept(signer, &message_id.to_string(), time)
            .map_err(|error| ReplayError::Store(error.to_string()))
    }
}

impl OmikronConnection {
    pub(super) async fn password_management_error(
        &self,
        frame: &CommunicationValue,
        kind: CommunicationType,
        failure: tau::password::Failure,
    ) {
        let Some(map) = frame.type_map() else {
            return;
        };
        let Ok(payload) = failure.payload(map) else {
            return;
        };
        if let Ok((opened, _, _)) = self.open_password_command(frame, kind, false).await
            && let Ok(user_id) = i64::try_from(opened.signer_id())
        {
            if let Ok(response) = self
                .protected_response(
                    frame,
                    failure.message_type(),
                    user_id,
                    payload,
                    super::app_protection::PASSWORD_RESPONSE_SIGNATURE,
                    super::app_protection::PASSWORD_RESPONSE_ENCRYPTION,
                )
                .await
            {
                let _ = self.send_message(&response).await;
            }
        } else {
            let mut response = CommunicationValue::new_with_type_map(failure.message_type(), map)
                .with_payload(payload);
            if let Some(id) = frame.id() {
                response = response.with_id(id);
            }
            let _ = self.send_message(&response).await;
        }
    }

    pub(super) async fn open_password_command(
        &self,
        frame: &CommunicationValue,
        kind: CommunicationType,
        consume_replay: bool,
    ) -> Result<(VerifiedProtectedMessage, String, i64), String> {
        let iota_id = iota_storage::util::config_util::CONFIG
            .load()
            .iota_id
            .ok_or("Iota has no identity")?;
        let keyring = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or("Iota has no keyring")?;
        let mut replay = CommandReplayGuard;
        let authenticated_key = std::cell::RefCell::new(None);
        let resolve_signer = |signer_id| {
            let id = i64::try_from(signer_id).ok()?;
            let (key, generation) =
                iota_storage::users::password_credentials::authorization(id).ok()?;
            *authenticated_key.borrow_mut() = Some((key.clone(), generation));
            Some(vec![PublicKeyBundle::from_base64(&key).ok()?])
        };
        let options = ProtectedOpenOptions::new(
            Some(iota_id),
            purpose(PASSWORD_MANAGEMENT_SIGNATURE),
            purpose(PASSWORD_MANAGEMENT_ENCRYPTION),
            ProtectionPolicy::dual(),
        );
        let opened = if consume_replay {
            open_protected_with_checked(
                frame,
                &[keyring.as_ref()],
                None,
                resolve_signer,
                options,
                &mut replay,
            )
        } else {
            // Only read-only receipt lookup uses this path. It cannot consume
            // an enrollment, invoke OPAQUE finish, or mutate a credential.
            open_protected_with_without_replay(
                frame,
                &[keyring.as_ref()],
                None,
                resolve_signer,
                options,
            )
        }
        .map_err(|error| error.to_string())?;
        if opened.message_type() != kind {
            return Err("wrong protected command type".into());
        }
        if frame
            .sender()
            .is_some_and(|sender| sender != opened.signer_id())
        {
            return Err("authenticated account does not match protected signer".into());
        }
        let (key, generation) = authenticated_key
            .into_inner()
            .ok_or("missing account key")?;
        Ok((opened, key, generation))
    }

    pub(super) async fn protected_response(
        &self,
        frame: &CommunicationValue,
        kind: CommunicationType,
        user_id: i64,
        content: DataValue,
        signature: u8,
        encryption: u8,
    ) -> Result<CommunicationValue, String> {
        let iota_id = iota_storage::util::config_util::CONFIG
            .load()
            .iota_id
            .ok_or("Iota has no identity")?;
        let keyring = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or("Iota has no keyring")?;
        let recipient = PublicKeyBundle::from_base64(
            &user_manager::get_user(user_id)
                .map_err(|error| error.to_string())?
                .ok_or("account not hosted")?
                .public_key,
        )
        .map_err(|error| error.to_string())?;
        self.build_protected(
            frame,
            kind,
            iota_id,
            user_id as u64,
            content,
            recipient,
            signature,
            encryption,
            &keyring,
        )
    }

    #[expect(clippy::too_many_arguments, reason = "explicit protected frame fields")]
    pub(super) fn build_protected(
        &self,
        frame: &CommunicationValue,
        kind: CommunicationType,
        signer_id: u64,
        recipient_id: u64,
        content: DataValue,
        recipient: PublicKeyBundle,
        signature: u8,
        encryption: u8,
        keyring: &mtp::crypto::Keyring,
    ) -> Result<CommunicationValue, String> {
        let mut timing = super::timing::Timing::start(super::timing::Stage::ProtectedResponse);
        let signer = DualSigner::new(
            &keyring.sig_cl_secret_key,
            &keyring.sig_pq_secret_key,
            &keyring.sig_pq_public_key,
        )
        .map_err(|error| error.to_string())?;
        let mut rng = OsRng;
        let id = ((rng.next_u64() as u128) << 64) | rng.next_u64() as u128;
        let response = ProtectedMessageBuilder::new(
            kind,
            content,
            signer_id,
            recipient_id,
            &signer,
            purpose(signature),
            purpose(encryption),
        )
        .message_id(id)
        .created_at(now_millis())
        .recipients(vec![recipient])
        .frame_id(frame.id().ok_or("missing request ID")?)
        .build()
        .map_err(|error| error.to_string())?;
        timing.success();
        Ok(response)
    }

    pub(super) async fn password_error(&self, frame: &CommunicationValue, kind: CommunicationType) {
        let Some(map) = frame.type_map() else {
            return;
        };
        if kind.try_to_id(map).is_none() {
            return;
        }
        let mut response = CommunicationValue::new_with_type_map(kind, map);
        let failure = match kind {
            CommunicationType::ErrorNotAuthenticated => tau::password::Failure::Unauthorized,
            CommunicationType::ErrorInternal => tau::password::Failure::DependencyUnavailable,
            _ => tau::password::Failure::InvalidRequest,
        };
        let Ok(payload) = failure.payload(map) else {
            return;
        };
        response = response.with_payload(payload);
        if let Some(id) = frame.id() {
            response = response.with_id(id);
        }
        let _ = self.send_message(&response).await;
    }
}
