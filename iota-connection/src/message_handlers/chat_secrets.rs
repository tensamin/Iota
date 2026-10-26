use super::*;

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
    let mut seen = std::collections::HashSet::new();
    for (field, _) in cv.iter_typed_data() {
        if !matches!(
            field,
            Some(
                DataType::UserId | DataType::ChatId | DataType::SecretId | DataType::VersionNumber
            )
        ) || !seen.insert(field)
        {
            return Err(error_response(cv, CommunicationType::ErrorInvalidData));
        }
    }
    let Some(user_id) = data_string(cv, DataType::UserId) else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
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
    let Some(chat_id) = data_string(cv, DataType::ChatId) else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };

    let numeric = !chat_id.starts_with("principal:");
    let participants = if numeric {
        if user_id != owner.principal.user_id.to_string() {
            return Err(error_response(cv, CommunicationType::ErrorNotFound));
        }
        let Some((first, second)) = numeric_chat_pair(&chat_id) else {
            return Err(error_response(cv, CommunicationType::ErrorInvalidData));
        };
        let pair = iota_storage::util::db::with_db(|db| {
            let mut statement = db.prepare("SELECT authority_id, remote_user_id FROM principals WHERE remote_user_id IN (?1, ?2) ORDER BY remote_user_id")?;
            let rows = statement.query_map(rusqlite::params![first as i64, second as i64], |row| Ok(tau_relay_protocol::Principal { authority: row.get(0)?, user_id: row.get::<_, i64>(1)? as u64 }))?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }).map_err(|error| internal_handler_error(cv, "chat_secret.numeric_pair", error))?;
        let Ok(pair) = <[_; 2]>::try_from(pair) else {
            return Err(error_response(cv, CommunicationType::ErrorInvalidData));
        };
        if pair[0].user_id != first || pair[1].user_id != second {
            return Err(error_response(cv, CommunicationType::ErrorInvalidData));
        }
        pair
    } else {
        if !serde_json::to_string(&owner.principal).is_ok_and(|canonical| canonical == user_id) {
            return Err(error_response(cv, CommunicationType::ErrorNotFound));
        }
        canonical_chat_pair(&chat_id)
            .map_err(|_| error_response(cv, CommunicationType::ErrorInvalidData))?
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
        return Err(error_response(cv, CommunicationType::ErrorNotFound));
    };
    let peer_id =
        match serde_json::from_value::<iota_identity::PrincipalId>(serde_json::json!(peer)) {
            Ok(peer) => peer,
            Err(_) => return Err(error_response(cv, CommunicationType::ErrorInvalidData)),
        };
    let partner = match store.get_by_canonical_id(&peer_id) {
        Ok(Some(partner)) => partner,
        Ok(None) => return Err(error_response(cv, CommunicationType::ErrorNotFound)),
        Err(error) => return Err(internal_handler_error(cv, "chat_secret.peer", error)),
    };
    let requested_secret_id = tau_relay_protocol::chat_secret_id(&chat_id);
    if data_string(cv, DataType::SecretId).as_deref() != Some(requested_secret_id.as_str()) {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    let version = data_i64(cv, DataType::VersionNumber);
    if cv.get_data(DataType::VersionNumber).is_some() && version.is_none_or(|version| version <= 0)
    {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    Ok((owner.principal, partner.principal, version))
}

fn numeric_chat_pair(chat: &str) -> Option<(u64, u64)> {
    let (first, second) = chat.split_once(':')?;
    let first = first.parse::<u64>().ok()?;
    let second = second.parse::<u64>().ok()?;
    (first > 0
        && first < second
        && second <= i64::MAX as u64
        && chat == format!("{first}:{second}"))
    .then_some((first, second))
}

pub fn handle_get_chat_secret(cv: &CommunicationValue) -> CommunicationValue {
    let (owner, partner, version) = match validated_chat_secret_read_target(cv) {
        Ok(target) => target,
        Err(response) => return response,
    };
    let sender_id = required_sender_id(cv).expect("validated sender");
    let chat_id = data_string(cv, DataType::ChatId).expect("validated chat");
    let principal_chat_id =
        match iota_storage::util::chat_secret_recovery::canonical_chat_id(&owner, &partner) {
            Ok(chat) => chat,
            Err(error) => return internal_handler_error(cv, "chat_secret.namespace", error),
        };
    let stored_secret_id = e2ee_storage::principal_secret_id(&principal_chat_id);
    let record = iota_storage::util::db::with_db(|connection| {
        let tx = connection.unchecked_transaction()?;
        use iota_storage::util::chat_secret_recovery as recovery;
        if recovery::canonical_owner_on(&tx, iota_identity::LocalUserId(sender_id))? != owner {
            return Err(StorageError::MessageUnauthorized);
        }
        if !chat_id.starts_with("principal:") {
            let unique: bool = tx.query_row(
                "SELECT COUNT(*) = 2 FROM principals WHERE remote_user_id IN (?1, ?2)",
                rusqlite::params![owner.user_id as i64, partner.user_id as i64],
                |row| row.get(0),
            )?;
            if !unique {
                return Err(StorageError::MessageUnauthorized);
            }
        }
        let acceptance = recovery::pair_acceptance_on(&tx, &owner, &partner)?;
        if !chat_id.starts_with("principal:") {
            let original_secret_id = format!("chat:{chat_id}:main");
            if let Some(legacy) = e2ee_storage::get_chat_secret_on(
                &tx,
                &ChatSecretQuery {
                    user_id: sender_id.to_string(),
                    chat_id: chat_id.clone(),
                    secret_id: Some(original_secret_id.clone()),
                    version,
                },
            )? {
                let pair = recovery::sorted_pair(&owner, &partner)?;
                let pending: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM chat_secret_epochs WHERE first_principal=?1 AND second_principal=?2 AND version=?3 AND state='pending')",
                    rusqlite::params![recovery::principal_key(&pair[0])?, recovery::principal_key(&pair[1])?, legacy.version],
                    |row| row.get(0),
                )?;
                let stale = version.is_none()
                    && acceptance
                        .latest_committed_version
                        .is_some_and(|latest| latest > legacy.version);
                if !pending && !stale {
                    // Only a retained original owner row proves the old wrapping
                    // namespace. Renamed canonical/handle rows cannot use this path.
                    if let Some(proof) = recovery::escrow_for_recovery_on(
                        &tx,
                        &owner,
                        &partner,
                        &owner,
                        Some(legacy.version),
                    )? {
                        let copy = proof
                            .envelopes
                            .iter()
                            .find(|copy| copy.owner == owner)
                            .ok_or(StorageError::ChatSecretConflict)?;
                        if proof.namespace.chat_id != chat_id
                            || proof.namespace.secret_id != original_secret_id
                            || !matches!(copy.recipient_id, recovery::OriginalRecipientId::Numeric(id) if id == owner.user_id)
                            || copy.encrypted_secret != legacy.encrypted_secret
                            || copy.kem_ciphertext != legacy.kem_ciphertext
                            || proof.wrapping_scheme != legacy.wrapping_scheme
                        {
                            return Err(StorageError::ChatSecretConflict);
                        }
                    }
                    return Ok(Some((
                        legacy,
                        owner.user_id.to_string(),
                        recovery::WrappingNamespace {
                            chat_id: chat_id.clone(),
                            secret_id: original_secret_id,
                        },
                    )));
                }
            }
        }
        let Some(escrow) =
            recovery::escrow_for_recovery_on(
                &tx,
                &owner,
                &partner,
                &owner,
                version.or(acceptance.latest_committed_version),
            )?
        else {
            return Ok(None);
        };
        let Some(envelope) = escrow.envelopes.iter().find(|copy| copy.owner == owner) else {
            return Err(StorageError::ChatSecretConflict);
        };
        // Numeric reads must not rename a canonical-wrapped ciphertext.
        if !chat_id.starts_with("principal:")
            && (escrow.namespace.chat_id != chat_id
                || escrow.namespace.secret_id != format!("chat:{chat_id}:main")
                || !matches!(envelope.recipient_id, recovery::OriginalRecipientId::Numeric(id) if id == owner.user_id))
        {
            return Err(StorageError::ChatSecretConflict);
        }
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
            return Ok(None);
        };
        if record.encrypted_secret != envelope.encrypted_secret
            || record.kem_ciphertext != envelope.kem_ciphertext
            || record.wrapping_scheme != escrow.wrapping_scheme
        {
            return Err(StorageError::ChatSecretConflict);
        }
        let original_user = match &envelope.recipient_id {
            recovery::OriginalRecipientId::Numeric(id) => id.to_string(),
            recovery::OriginalRecipientId::Principal(principal) => principal.clone(),
        };
        Ok(Some((record, original_user, escrow.namespace)))
    });
    match record {
        Ok(Some((record, user_id, namespace))) => {
            CommunicationValue::new(CommunicationType::ChatSecretResponse)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(sender_id))
                .add_typed_default(DataType::UserId, DataValue::Str(user_id))
                .add_typed_default(DataType::ChatId, DataValue::Str(namespace.chat_id))
                .add_typed_default(DataType::SecretId, DataValue::Str(namespace.secret_id))
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
                )
        }
        Ok(None) => error_response(cv, CommunicationType::ErrorInternal),
        Err(error) => internal_handler_error(cv, "chat_secret.read", error),
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
