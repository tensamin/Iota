use super::*;

impl OmikronConnection {
    /// Omega-authorized account cleanup. The storage operation is idempotent;
    /// acknowledgement is therefore safe to retry after a reconnect.
    pub(super) async fn handle_erase_hosted_user_data(self: Arc<Self>, cv: &CommunicationValue) {
        if !targets_iota(cv, CONFIG.load().iota_id) {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }
        let Some(user_id) = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0)
        else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };

        if iota_storage::users::user_manager::erase_user_locally(user_id).is_err() {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                .await;
            return;
        }

        let acknowledgement = CommunicationValue::new(CommunicationType::EraseHostedUserDataAck)
            .with_request_id(cv)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
        let _ = self.send_message(&acknowledgement).await;
    }

    /* Omega sends only public account metadata here. The locally created
     * profile records an external credential origin and never receives a TU. */
    pub(super) async fn handle_iota_user_provisioning(self: Arc<Self>, cv: &CommunicationValue) {
        if !targets_iota(cv, CONFIG.load().iota_id) {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0);
        let username = cv.get_data(DataType::Username).as_str().map(str::to_owned);
        let public_key = cv.get_data(DataType::PublicKey).as_str().map(str::to_owned);
        let invitation_id = cv
            .get_data(DataType::InvitationId)
            .as_signed_number()
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value > 0);
        let invitation_revision = cv
            .get_data(DataType::InvitationRevision)
            .as_signed_number()
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value > 0);
        let Some((user_id, username, public_key, invitation_id, invitation_revision)) = user_id
            .zip(username)
            .zip(public_key)
            .zip(invitation_id)
            .zip(invitation_revision)
            .map(|((((id, username), key), invitation_id), revision)| {
                (id, username, key, invitation_id, revision)
            })
        else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let profile = iota_storage::users::user_profile::UserProfile::new(
            user_id, username, None, public_key, None, None,
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let mut result = iota_storage::users::invitations::apply_external_invitation_provisioning(
            invitation_id,
            invitation_revision,
            &profile,
            now,
        );
        if matches!(
            result,
            Ok(iota_storage::users::invitations::ProvisioningResult::MissingInvitation)
        ) && self.sync_omega_invitations().await.is_ok()
        {
            result = iota_storage::users::invitations::apply_external_invitation_provisioning(
                invitation_id,
                invitation_revision,
                &profile,
                now,
            );
        }
        match result {
            Ok(
                iota_storage::users::invitations::ProvisioningResult::Created
                | iota_storage::users::invitations::ProvisioningResult::AlreadyApplied,
            ) => {}
            Ok(iota_storage::users::invitations::ProvisioningResult::RevocationPending) => {
                self.flush_pending_invitation_actions().await;
                return;
            }
            Ok(iota_storage::users::invitations::ProvisioningResult::Conflict) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
            Ok(iota_storage::users::invitations::ProvisioningResult::MissingInvitation) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                    .await;
                return;
            }
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                    .await;
                return;
            }
        }
        let acknowledgement =
            CommunicationValue::new(CommunicationType::AcknowledgeIotaUserProvision)
                .with_request_id(cv)
                .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
                .add_typed_default(
                    DataType::InvitationId,
                    DataValue::SignedNumber(invitation_id.into()),
                );
        let _ = self.send_message(&acknowledgement).await;
    }
}

impl OmikronConnection {
    pub(super) async fn handle_relay_receipt_page(self: Arc<Self>, cv: &CommunicationValue) {
        // Like AccountStateRequest, the sender comes from the authenticated
        // Omikron route. The shared handler validates owner and page bounds;
        // send_message retains this handler's originating attempt.
        let response = message_handlers::handle_relay_receipt_page(cv);
        if let Err(error) = self.send_message(&response).await {
            log!("RelayReceiptPage response delivery failed: {error}");
        }
    }

    pub(super) async fn handle_account_state_request(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_account_state_request(cv);
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok());
        if response.is_type(CommunicationType::AccountStateSnapshot) {
            log!("AccountStateSnapshot user={:?} stage=generated", user_id);
            if let Some(user_id) = user_id
                && let Err(error) = relay_queue::pause_client_deliveries(user_id)
            {
                log!("Pending Relay state-sync pause failed: {}", error);
            }

            if let Err(error) = self.send_message(&response).await {
                log!(
                    "Initial AccountStateSnapshot delivery failed for user {:?}: {}",
                    user_id,
                    error
                );
            } else {
                log!(
                    "AccountStateSnapshot user={:?} stage=sent_to_omikron",
                    user_id
                );
            }
            return;
        }

        if let Err(error) = self.send_message(&response).await {
            log!("AccountStateRequest response delivery failed: {}", error);
        }
    }

    pub(super) async fn handle_account_state_applied(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_account_state_applied(cv);
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok());
        if self.send_message(&response).await.is_ok()
            && response.is_type(CommunicationType::Success)
            && let Some(user_id) = user_id
        {
            if let Err(error) = relay_queue::resume_client_deliveries(user_id) {
                log!("Pending Relay client resume failed: {}", error);
            } else {
                self.flush_pending_relays_for_user(Some(user_id)).await;
            }
        }
    }
}
