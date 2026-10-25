use super::*;
use iota_storage::util::call_envelopes::epochs::{self, Error, Key, Mutation, Stage};

pub(super) fn owner_authority(keys: &PublicKeyBundle) -> Option<String> {
    let bytes = keys.try_as_bytes().ok()?;
    let fingerprint = mtp::crypto::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Some(format!("omikron-key:{fingerprint}"))
}

impl OmikronConnection {
    /// Inbound mutation authority is the authenticated attempt, never a user
    /// field in the request or whichever peer a later reconnect selected.
    pub(super) async fn call_envelope_owner(&self) -> Option<i64> {
        let bound = self.bound_attempt.as_ref()?;
        let current = self.active_attempt.read().await;
        if bound.cancellation.is_cancelled()
            || !bound.sender.is_open()
            || !current
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, bound))
            || !self.is_identified().await
        {
            return None;
        }
        bound.owner_omikron_id.filter(|id| *id > 0)
    }

    pub(super) fn call_recipient_is_hosted(user: i64) -> bool {
        user > 0 && epochs::recipient_is_hosted(user).unwrap_or(false)
    }

    pub(super) async fn handle_call_key_envelope(self: Arc<Self>, cv: &CommunicationValue) {
        let result = self.call_key_envelope(cv).await;
        let response = match result {
            Ok(response) => response,
            Err(Error::NotFound) => error_response(cv, CommunicationType::ErrorNotFound),
            Err(Error::Invalid | Error::Conflict) => {
                error_response(cv, CommunicationType::ErrorInvalidData)
            }
            Err(Error::Storage(error)) => {
                log!("Call epoch envelope storage failed: {error}");
                error_response(cv, CommunicationType::ErrorInternal)
            }
        };
        let _ = self.send_message(&response).await;
    }

    async fn call_key_envelope(
        &self,
        cv: &CommunicationValue,
    ) -> Result<CommunicationValue, Error> {
        let owner = self.call_envelope_owner().await.ok_or(Error::Invalid)?;
        let tm = cv.type_map().ok_or(Error::Invalid)?;
        // This data ID is used only after validating its negotiated name.
        let payload_id = DataTypeId(256);
        if tm.data_type_name(payload_id.0) != Some("CallPayload") {
            return Err(Error::Invalid);
        }
        let payload = cv
            .data()
            .and_then(|fields| fields.iter().find(|(id, _)| *id == payload_id))
            .and_then(|(_, value)| value.as_bytes())
            .ok_or(Error::Invalid)?;
        if payload.len() > 32 * 1024 {
            return Err(Error::Invalid);
        }
        enum Request {
            Stage(Stage),
            Get(Key),
            Mutation(Mutation, bool),
        }
        let request = match cv.get_type_name() {
            Some("CallKeyEnvelopeStage") => {
                Request::Stage(serde_json::from_slice(&payload).map_err(|_| Error::Invalid)?)
            }
            Some("CallKeyEnvelopeGet") => {
                Request::Get(serde_json::from_slice(&payload).map_err(|_| Error::Invalid)?)
            }
            Some("CallKeyEnvelopeActivate") => Request::Mutation(
                serde_json::from_slice(&payload).map_err(|_| Error::Invalid)?,
                true,
            ),
            Some("CallKeyEnvelopeRevoke") => Request::Mutation(
                serde_json::from_slice(&payload).map_err(|_| Error::Invalid)?,
                false,
            ),
            _ => return Err(Error::Invalid),
        };
        let key = match &request {
            Request::Stage(stage) => &stage.key,
            Request::Get(key) => key,
            Request::Mutation(mutation, _) => &mutation.key,
        };
        if !key.validate(matches!(&request, Request::Mutation(_, false))) {
            return Err(Error::Invalid);
        }
        let user = i64::try_from(key.recipient.user_id).map_err(|_| Error::Invalid)?;
        if !Self::call_recipient_is_hosted(user) {
            return Err(Error::Invalid);
        }
        let principal = self
            .password_principal(user)
            .await
            .map_err(|_| Error::Invalid)?;
        let authority = principal.rsplit_once('#').ok_or(Error::Invalid)?.0;
        if key.recipient.authority != authority
            || self
                .bound_attempt
                .as_ref()
                .and_then(|attempt| attempt.owner_authority.as_deref())
                != Some(key.call_id.owner_authority.as_str())
        {
            return Err(Error::Invalid);
        }
        // Discovery above can await network I/O. Recheck the originating attempt
        // before committing, so superseded connections fail closed.
        if self.call_envelope_owner().await != Some(owner) {
            return Err(Error::Invalid);
        }
        let active = self.active_attempt.read().await;
        let bound = self.bound_attempt.as_ref().ok_or(Error::Invalid)?;
        if bound.cancellation.is_cancelled()
            || !active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, bound))
        {
            return Err(Error::Invalid);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Invalid)?
            .as_millis() as i64;
        let delivery = match request {
            Request::Stage(stage) => epochs::stage(&stage, owner, user, now),
            Request::Get(key) => epochs::get(&key, owner, user, now),
            Request::Mutation(value, activate) => {
                epochs::mutate(&value, activate, owner, user, now)
            }
        }?;
        drop(active);
        let bytes = serde_json::to_vec(&delivery).map_err(|_| Error::Invalid)?;
        CommunicationValue::new_with_type_map(cv.get_comm_type_enum().ok_or(Error::Invalid)?, tm)
            .with_request_id(cv)
            .add_data(payload_id, DataValue::Bytes(bytes))
            .map_err(|_| Error::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unbound_or_disconnected_connector_has_no_envelope_authority() {
        let connector = OmikronConnection::new(
            Arc::new(DashSet::new()),
            Arc::new(std::sync::Mutex::new(AppState::new())),
        );
        assert_eq!(connector.call_envelope_owner().await, None);
        connector
            .set_state(ConnectionState::Connected { identified: true })
            .await;
        assert_eq!(connector.call_envelope_owner().await, None);
    }
}
