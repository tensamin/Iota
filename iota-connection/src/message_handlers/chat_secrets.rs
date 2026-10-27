use super::*;
use tau::chat_secret::ReadUnavailable;

pub fn validated_chat_secret_read_target(
    cv: &CommunicationValue,
) -> Result<
    (
        iota_identity::PrincipalId,
        iota_identity::PrincipalId,
        Option<i64>,
    ),
    CommunicationValue,
> {
    let request = tau::chat_secret::ReadRequest::from_frame(cv)
        .map_err(|_| error_response(cv, CommunicationType::ErrorInvalidData))?;
    let sender_id = required_sender_id(cv)?;
    let store = iota_storage::identity::SqlitePrincipalStore;
    let owner = match store
        .principal_for_local_user(iota_identity::LocalUserId(sender_id))
        .and_then(|handle| {
            handle
                .map(|handle| store.get_principal(handle))
                .transpose()
                .map(Option::flatten)
        }) {
        Ok(Some(owner)) => owner,
        Ok(None) => return Err(error_response(cv, CommunicationType::ErrorNotFound)),
        Err(error) => return Err(internal_handler_error(cv, "chat_secret.owner", error)),
    };
    let owner_wire = tau_relay_protocol::Principal::try_from(&owner.principal)
        .map_err(|_| error_response(cv, CommunicationType::ErrorInvalidData))?;
    if owner_wire != request.owner {
        return Err(error_response(cv, CommunicationType::ErrorNotFound));
    }
    let peer = request
        .pair
        .partner(&owner_wire)
        .map_err(|_| error_response(cv, CommunicationType::ErrorNotFound))?;
    let peer_id = match iota_identity::PrincipalId::try_from(peer.clone()) {
        Ok(peer) => peer,
        Err(_) => return Err(error_response(cv, CommunicationType::ErrorInvalidData)),
    };
    let partner = match store.get_by_canonical_id(&peer_id) {
        Ok(Some(partner)) => partner,
        Ok(None) => return Err(error_response(cv, CommunicationType::ErrorNotFound)),
        Err(error) => return Err(internal_handler_error(cv, "chat_secret.peer", error)),
    };
    let version = request.epoch.map(|epoch| epoch.get());
    Ok((owner.principal, partner.principal, version))
}

pub fn handle_get_chat_secret(cv: &CommunicationValue) -> CommunicationValue {
    match read_chat_secret(cv) {
        Ok(response) => response,
        Err(ChatSecretReadError::Identity(response)) => response,
        Err(ChatSecretReadError::Unavailable(state)) => state
            .to_frame(cv)
            .unwrap_or_else(|_| error_response(cv, CommunicationType::ErrorProtocol)),
        Err(ChatSecretReadError::Storage(error)) => {
            let state = match error {
                StorageError::MessageUnauthorized | StorageError::RelayOwnerUnavailable => {
                    ReadUnavailable::Unauthorized
                }
                StorageError::ChatSecretConflict | StorageError::InvalidRelayPayload(_) => {
                    ReadUnavailable::Conflict
                }
                _ => ReadUnavailable::RetryableDependency,
            };
            state
                .to_frame(cv)
                .unwrap_or_else(|_| error_response(cv, CommunicationType::ErrorProtocol))
        }
    }
}

pub enum ChatSecretReadError {
    Identity(CommunicationValue),
    Unavailable(ReadUnavailable),
    Storage(StorageError),
}

/// Keeps validated absence separate from storage and identity failures for outbox reconciliation.
pub fn read_chat_secret(
    cv: &CommunicationValue,
) -> Result<CommunicationValue, ChatSecretReadError> {
    let (owner, partner, version) = match validated_chat_secret_read_target(cv) {
        Ok(target) => target,
        Err(response) => return Err(ChatSecretReadError::Identity(response)),
    };
    let sender_id = required_sender_id(cv).expect("validated sender");
    let principal_chat_id =
        match iota_storage::util::chat_secret_recovery::canonical_chat_id(&owner, &partner) {
            Ok(chat) => chat,
            Err(error) => return Err(ChatSecretReadError::Storage(error)),
        };
    let stored_secret_id = e2ee_storage::principal_secret_id(&principal_chat_id);
    let record = iota_storage::util::db::with_db(|connection| {
        let tx = connection.unchecked_transaction()?;
        use iota_storage::util::chat_secret_recovery as recovery;
        if recovery::canonical_owner_on(&tx, iota_identity::LocalUserId(sender_id))? != owner {
            return Err(StorageError::MessageUnauthorized);
        }
        let acceptance = recovery::pair_acceptance_on(&tx, &owner, &partner)?;
        let Some(escrow) = recovery::escrow_for_recovery_on(
            &tx,
            &owner,
            &partner,
            &owner,
            version.or(acceptance.latest_committed_version),
        )?
        else {
            let state = match version.or(acceptance.latest_committed_version) {
                Some(epoch) => match recovery::epoch_state_on(&tx, &owner, &partner, epoch)? {
                    Some(recovery::EpochState::Committed) => {
                        ReadUnavailable::AcceptedButEnvelopeUnavailable
                    }
                    Some(recovery::EpochState::Pending) => ReadUnavailable::Pending,
                    None => ReadUnavailable::EpochUnavailable,
                },
                None if acceptance.has_pending
                    || recovery::pending_initial_proposal_on(&tx, &owner, &partner)? =>
                {
                    ReadUnavailable::Pending
                }
                None => ReadUnavailable::NoSuchConversation,
            };
            return Ok(Err(state));
        };
        let Some(envelope) = escrow.envelopes.iter().find(|copy| copy.owner == owner) else {
            return Err(StorageError::ChatSecretConflict);
        };
        let storage_user = sender_id.to_string();
        let Some(record) = e2ee_storage::get_chat_secret_on(
            &tx,
            &ChatSecretQuery {
                user_id: storage_user,
                chat_id: principal_chat_id.clone(),
                secret_id: Some(stored_secret_id.clone()),
                version: Some(escrow.version),
            },
        )?
        else {
            return Ok(Err(ReadUnavailable::AcceptedButEnvelopeUnavailable));
        };
        if record.encrypted_secret != envelope.encrypted_secret
            || record.kem_ciphertext != envelope.kem_ciphertext
            || record.wrapping_scheme != escrow.wrapping_scheme
        {
            return Err(StorageError::ChatSecretConflict);
        }
        Ok(Ok(record))
    });
    match record {
        Ok(Ok(record)) => {
            let response = (|| {
                let mut scope = tau::chat_secret::ReadRequest::from_frame(cv)?;
                scope.epoch = Some(tau::chat_secret::SecretEpoch::try_from(record.version)?);
                tau::chat_secret::ReadResponse {
                    scope,
                    encrypted_secret: record.encrypted_secret,
                    kem_ciphertext: record.kem_ciphertext,
                    wrapping_scheme: record.wrapping_scheme,
                    created_at: record.created_at,
                    updated_at: record.updated_at,
                }
                .to_frame(cv)
            })();
            response.map_err(|error: tau::chat_secret::ReadCodecError| {
                ChatSecretReadError::Storage(StorageError::Other(error.to_string()))
            })
        }
        Ok(Err(state)) => Err(ChatSecretReadError::Unavailable(state)),
        Err(error) => Err(ChatSecretReadError::Storage(error)),
    }
}

pub(super) fn contact_value(
    contact: &iota_storage::users::contact::Contact,
    messages: &[chat_files::StoredMessage],
    storage_owner: i64,
    map: &mtp::codec::TypeMap,
) -> Result<DataValue, StorageError> {
    let handle = contact
        .principal
        .ok_or_else(|| StorageError::Other("contact principal is missing".into()))?;
    let principal = iota_storage::identity::SqlitePrincipalStore
        .get_principal(handle)
        .map_err(|error| StorageError::Other(error.to_string()))?
        .ok_or_else(|| StorageError::Other("contact principal was not found".into()))?;
    let canonical = serde_json::to_string(&principal.principal)
        .map_err(|error| StorageError::Other(error.to_string()))?;
    let mut fields = vec![
        (DataType::UserId, DataValue::SignedNumber(handle.0.into())),
        (DataType::Principal, DataValue::Str(canonical.clone())),
        (DataType::UserAddress, DataValue::Str(canonical)),
    ];
    if let Some(name) = &contact.user_name {
        fields.push((DataType::Username, DataValue::Str(name.clone())));
    }
    if contact.created_at > 0 {
        fields.push((
            DataType::CreatedAt,
            DataValue::SignedNumber(contact.created_at.into()),
        ));
    }
    if let Some(last_message_at) = contact.last_message_at {
        fields.push((
            DataType::LastMessageAt,
            DataValue::SignedNumber(last_message_at as i128),
        ));
    }
    fields.push((
        DataType::Notifications,
        DataValue::SignedNumber(contact.notifications.into()),
    ));
    fields.push((
        DataType::Messages,
        DataValue::Array(
            messages
                .iter()
                .filter(|message| message.external_principal == Some(handle))
                .map(|message| stored_message_value(message, storage_owner, handle.0, map))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| StorageError::Other(error.to_string()))?,
        ),
    ));
    tau::typed_container(map, fields).map_err(|error| StorageError::Other(error.to_string()))
}
