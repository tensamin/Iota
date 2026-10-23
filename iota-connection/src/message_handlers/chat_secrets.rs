use super::*;

pub fn handle_get_chat_secret(cv: &CommunicationValue) -> CommunicationValue {
    let Some(user_id) = data_string(cv, DataType::UserId) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
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
        Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => return internal_handler_error(cv, "chat_secret.owner", error),
    };
    if !serde_json::to_string(&owner.principal).is_ok_and(|canonical| canonical == user_id) {
        return error_response(cv, CommunicationType::ErrorNotFound);
    }
    let Some(chat_id) = data_string(cv, DataType::ChatId) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    let participants = match canonical_chat_pair(&chat_id) {
        Ok(participants) => participants,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let owner_wire = tau_relay_protocol::Principal {
        authority: owner.principal.authority.as_str().into(),
        user_id: owner.principal.user_id,
    };
    let peer = if participants[0] == owner_wire {
        &participants[1]
    } else if participants[1] == owner_wire {
        &participants[0]
    } else {
        return error_response(cv, CommunicationType::ErrorNotFound);
    };
    let peer_id =
        match serde_json::from_value::<iota_identity::PrincipalId>(serde_json::json!(peer)) {
            Ok(peer) => peer,
            Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
        };
    let partner = match store.get_by_canonical_id(&peer_id) {
        Ok(Some(partner)) => partner,
        Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => return internal_handler_error(cv, "chat_secret.peer", error),
    };
    let Some(principal_chat_id) = e2ee_storage::principal_chat_id(owner.handle, partner.handle)
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let requested_secret_id = tau_relay_protocol::chat_secret_id(&chat_id);
    if data_string(cv, DataType::SecretId).as_deref() != Some(requested_secret_id.as_str()) {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let version = data_i64(cv, DataType::VersionNumber);
    if cv.get_data(DataType::VersionNumber).is_some() && version.is_none_or(|version| version <= 0)
    {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let stored_secret_id = e2ee_storage::principal_secret_id(&principal_chat_id);
    let record = iota_storage::util::db::with_immediate_transaction(|tx| {
        let storage_user = sender_id.to_string();
        if owner.principal.authority == partner.principal.authority {
            let first = owner.principal.user_id.min(partner.principal.user_id);
            let second = owner.principal.user_id.max(partner.principal.user_id);
            // Numeric imports are safe only if neither ID is shared by another authority.
            let unique: bool = tx.query_row(
                "SELECT COUNT(*) = 2 FROM principals WHERE remote_user_id IN (?1, ?2)",
                rusqlite::params![first as i64, second as i64],
                |row| row.get(0),
            )?;
            if unique {
                let legacy_chat = format!("{first}:{second}");
                e2ee_storage::migrate_chat_secret_namespace_in_tx(
                    tx,
                    &storage_user,
                    &legacy_chat,
                    &format!("chat:{legacy_chat}:main"),
                    &principal_chat_id,
                    &stored_secret_id,
                )?;
            }
        }
        e2ee_storage::get_chat_secret_on(
            tx,
            &ChatSecretQuery {
                user_id: storage_user,
                chat_id: principal_chat_id.clone(),
                secret_id: Some(stored_secret_id.clone()),
                version,
            },
        )
    });
    match record {
        Ok(Some(record)) => CommunicationValue::new(CommunicationType::ChatSecretResponse)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(sender_id))
            .add_typed_default(DataType::UserId, DataValue::Str(user_id))
            .add_typed_default(DataType::ChatId, DataValue::Str(chat_id))
            .add_typed_default(DataType::SecretId, DataValue::Str(requested_secret_id))
            .add_typed_default(
                DataType::VersionNumber,
                DataValue::SignedNumber(record.version as i128),
            )
            .add_typed_default(
                DataType::EncryptedSecret,
                DataValue::Bytes(record.encrypted_secret),
            )
            .add_typed_default(
                DataType::KemCiphertext,
                DataValue::Bytes(record.kem_ciphertext),
            )
            .add_typed_default(
                DataType::WrappingScheme,
                DataValue::Str(record.wrapping_scheme),
            )
            .add_typed_default(
                DataType::CreatedAt,
                DataValue::SignedNumber(record.created_at as i128),
            )
            .add_typed_default(
                DataType::UpdatedAt,
                DataValue::SignedNumber(record.updated_at as i128),
            ),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotSet),
        Err(_) => error_response(cv, CommunicationType::ErrorInternal),
    }
}

pub(super) fn canonical_chat_pair(chat_id: &str) -> Result<[tau_relay_protocol::Principal; 2], ()> {
    let encoded = chat_id.strip_prefix("principal:").ok_or(())?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    let pair: [tau_relay_protocol::Principal; 2] =
        serde_json::from_slice(&bytes).map_err(|_| ())?;
    if pair[0] == pair[1] || tau_relay_protocol::canonical_chat_id(&pair[0], &pair[1]) != chat_id {
        return Err(());
    }
    Ok(pair)
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
