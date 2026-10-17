use super::*;

impl OmikronConnection {
    pub(super) async fn sync_pending_invitation_revocations(&self) -> Result<(), String> {
        let invitations = iota_storage::users::invitations::list()
            .map_err(|error| format!("failed to load pending invitation actions: {error}"))?;
        for invitation in invitations.into_iter().filter(|invitation| {
            invitation.authority == iota_storage::users::invitations::InvitationAuthority::Omega
                && invitation.pending_action
                    == Some(iota_storage::users::invitations::PendingAction::Revoke)
        }) {
            let request = CommunicationValue::new(CommunicationType::RevokeUserInvitation)
                .add_typed_default(
                    DataType::InvitationAuthority,
                    DataValue::Str("omega".into()),
                )
                .add_typed_default(
                    DataType::InvitationId,
                    DataValue::SignedNumber(invitation.invitation_id.into()),
                );
            let response = self
                .await_response(&request, Some(Duration::from_secs(20)))
                .await?;
            if response.is_type(CommunicationType::Success) {
                let Some(revision) = response
                    .get_data(DataType::InvitationRevision)
                    .as_signed_number()
                    .and_then(|value| i64::try_from(value).ok())
                else {
                    return Err("Omega revoke response omitted invitation revision".into());
                };
                let state = match response.get_data(DataType::InvitationState).as_str() {
                    Some("pending") => iota_storage::users::invitations::InvitationState::Pending,
                    Some("provisioning") => {
                        iota_storage::users::invitations::InvitationState::Provisioning
                    }
                    Some("redeemed") => iota_storage::users::invitations::InvitationState::Redeemed,
                    Some("revoked") => iota_storage::users::invitations::InvitationState::Revoked,
                    Some("expired") => iota_storage::users::invitations::InvitationState::Expired,
                    _ => return Err("Omega revoke response contained invalid state".into()),
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                iota_storage::users::invitations::apply_revoke_result(
                    invitation.invitation_id,
                    state,
                    revision,
                    (state == iota_storage::users::invitations::InvitationState::Revoked)
                        .then_some(now),
                    now,
                )
                .map_err(|error| format!("failed to apply invitation revoke result: {error}"))?;
            } else {
                return Err("Omega returned the wrong invitation revoke response type".into());
            }
        }
        Ok(())
    }

    pub async fn flush_pending_invitation_actions(&self) {
        if self
            .invitation_sync
            .flush_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        struct FlushGuard<'a>(&'a AtomicBool);
        impl Drop for FlushGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _flush = FlushGuard(&self.invitation_sync.flush_in_progress);
        let now = Instant::now();
        if self
            .invitation_sync
            .next_retry_at
            .lock()
            .await
            .is_some_and(|retry_at| retry_at > now)
        {
            return;
        }
        match self.sync_pending_invitation_revocations().await {
            Ok(()) => {
                *self.invitation_sync.next_retry_at.lock().await = None;
                *self.invitation_sync.retry_delay.lock().await = Duration::from_secs(5);
            }
            Err(error) => {
                log!("Pending invitation action flush failed: {}", error);
                let mut delay = self.invitation_sync.retry_delay.lock().await;
                *self.invitation_sync.next_retry_at.lock().await = Some(now + *delay);
                *delay = next_invitation_retry_delay(*delay);
            }
        }
    }

    pub async fn sync_omega_invitations(&self) -> Result<(), OmikronError> {
        let request = CommunicationValue::new(CommunicationType::ListUserInvitations)
            .add_typed_default(
                DataType::InvitationAuthority,
                DataValue::Str("omega".into()),
            );
        let response = self
            .await_response_typed(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(map_await_response_error)?;
        if !response.is_type(CommunicationType::ListUserInvitations) {
            return Err(OmikronError::Internal(
                "Omega returned the wrong invitation snapshot response type".into(),
            ));
        }
        let Some(DataValue::Array(remote)) = response.get_data(DataType::Invitations) else {
            return Err(OmikronError::Internal(
                "Omega invitation snapshot omitted Invitations".into(),
            ));
        };
        let type_map = response.type_map().ok_or_else(|| {
            OmikronError::Internal(
                "Omega invitation snapshot omitted its negotiated type map".into(),
            )
        })?;
        let synced_at = now_millis_i64();
        let expected_iota_id = CONFIG
            .load()
            .iota_id
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| OmikronError::Internal("Iota identity is not configured".into()))?;
        let mut invitations = Vec::with_capacity(remote.len());
        for invitation in remote {
            let DataValue::Container(fields) = invitation else {
                return Err(OmikronError::Internal(
                    "Omega invitation snapshot contained a non-container record".into(),
                ));
            };
            invitations.push(parse_omega_invitation(
                fields,
                type_map,
                expected_iota_id,
                synced_at,
            )?);
        }
        iota_storage::users::invitations::merge_omega_snapshot(&invitations, synced_at).map_err(
            |error| {
                OmikronError::Storage(format!(
                    "failed to persist Omega invitation snapshot: {error}"
                ))
            },
        )?;
        Ok(())
    }
}
