use super::*;

pub fn handle_message_edit(cv: &CommunicationValue) -> CommunicationValue {
    let mutation = match message_mutation(cv) {
        Ok(mutation) => mutation,
        Err(response) => return response,
    };
    let Some(content) = cv.get_data(DataType::Content).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    match chat_files::edit_message_for_principal(
        mutation.sender_id,
        mutation.partner_id,
        mutation.partner_principal,
        mutation.send_time,
        mutation.sender_id,
        content,
    ) {
        Ok(()) => success_response(cv),
        Err(_) => error_response(cv, CommunicationType::ErrorNotFound),
    }
}

pub fn handle_message_reaction(cv: &CommunicationValue, add: bool) -> CommunicationValue {
    let mutation = match message_mutation(cv) {
        Ok(mutation) => mutation,
        Err(response) => return response,
    };
    let Some(reaction) = cv.get_data(DataType::Reaction).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if reaction.is_empty() || reaction.len() > 64 {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }

    let result = if add {
        chat_files::add_reaction_for_principal(
            mutation.sender_id,
            mutation.partner_id,
            mutation.partner_principal,
            mutation.send_time,
            mutation.sender_id,
            mutation.sender_principal,
            reaction,
        )
    } else {
        chat_files::remove_reaction_for_principal(
            mutation.sender_id,
            mutation.partner_id,
            mutation.partner_principal,
            mutation.send_time,
            mutation.sender_id,
            mutation.sender_principal,
            reaction,
        )
    };

    match result {
        Ok(()) => success_response(cv),
        Err(iota_storage::storage_error::StorageError::ReactionLimitReached) => {
            error_response(cv, CommunicationType::ErrorInvalidData)
        }
        Err(_) => error_response(cv, CommunicationType::ErrorNotFound),
    }
}

pub fn handle_message_delete(cv: &CommunicationValue) -> CommunicationValue {
    let mutation = match message_mutation(cv) {
        Ok(mutation) => mutation,
        Err(response) => return response,
    };

    match chat_files::delete_message_for_principal(
        mutation.sender_id,
        mutation.partner_id,
        mutation.partner_principal,
        mutation.send_time,
    ) {
        Ok(()) => success_response(cv),
        Err(_) => error_response(cv, CommunicationType::ErrorNotFound),
    }
}

pub(super) fn canonical_principal_value(
    handle: iota_identity::PrincipalHandle,
) -> Result<DataValue, StorageError> {
    let principal = iota_storage::identity::SqlitePrincipalStore
        .get_principal(handle)
        .map_err(|error| StorageError::Other(error.to_string()))?
        .ok_or_else(|| StorageError::Other("stored principal was not found".into()))?;
    serde_json::to_string(&principal.principal)
        .map(DataValue::Str)
        .map_err(|error| StorageError::Other(error.to_string()))
}

pub(super) fn stored_message_fields(
    message: &chat_files::StoredMessage,
    storage_owner: i64,
    partner_id: i64,
    map: &mtp::codec::TypeMap,
) -> Result<Vec<(DataType, DataValue)>, StorageError> {
    let sender_principal = if message.sent_by_self {
        iota_storage::identity::SqlitePrincipalStore
            .principal_for_local_user(iota_identity::LocalUserId(storage_owner))
            .map_err(|error| StorageError::Other(error.to_string()))?
    } else {
        message
            .relay_signer_principal
            .or(message.external_principal)
    }
    .ok_or_else(|| StorageError::Other("message sender principal is missing".into()))?;
    let mut fields = vec![
        (
            DataType::Principal,
            canonical_principal_value(sender_principal)?,
        ),
        (
            DataType::ChatPartnerId,
            DataValue::SignedNumber(partner_id.into()),
        ),
        (
            DataType::MessageId,
            DataValue::SignedNumber(message.id as i128),
        ),
        (
            DataType::SendTime,
            DataValue::SignedNumber(message.message_time as i128),
        ),
        (DataType::Content, DataValue::Str(message.content.clone())),
        (
            DataType::MessageState,
            DataValue::Str(message.message_state.clone()),
        ),
        (
            DataType::Height,
            DataValue::SignedNumber(message.height as i128),
        ),
        (
            DataType::VersionNumber,
            DataValue::SignedNumber(message.key_version as i128),
        ),
    ];
    let sender_id = if message.sent_by_self {
        storage_owner
    } else {
        partner_id
    };
    if let Ok(sender_id) = u128::try_from(sender_id) {
        fields.push((DataType::SenderId, DataValue::UnsignedNumber(sender_id)));
    }
    if let Some(relay_message_id) = &message.relay_message_id {
        fields.push((
            DataType::RelayMessageId,
            DataValue::Str(relay_message_id.clone()),
        ));
    }
    for (data_type, timestamp) in [
        (DataType::AuthoredAt, message.authored_at),
        (
            DataType::OriginIotaReceivedAt,
            message.origin_iota_received_at,
        ),
        (
            DataType::DestinationIotaReceivedAt,
            message.destination_iota_received_at,
        ),
        (DataType::ClientReceivedAt, message.client_received_at),
        (
            DataType::ClientReceivedRecordedAt,
            message.client_received_recorded_at,
        ),
        (DataType::ReadAt, message.read_at),
        (DataType::ReadRecordedAt, message.read_recorded_at),
    ] {
        if let Some(timestamp) = timestamp {
            fields.push((data_type, DataValue::SignedNumber(timestamp.into())));
        }
    }
    if let Some(failed_at) = message.delivery_failed_at {
        fields.push((
            DataType::UpdatedAt,
            DataValue::SignedNumber(failed_at.into()),
        ));
    }
    if let Some(failure) = &message.delivery_failure {
        fields.push((DataType::ErrorType, DataValue::Str(failure.clone())));
    }
    if message.edited {
        fields.push((DataType::Edited, DataValue::Bool(true)));
    }
    if let Some(reply_to) = message.reply_to.and_then(|id| u64::try_from(id).ok()) {
        fields.push((
            DataType::ReplyId,
            DataValue::UnsignedNumber(u128::from(reply_to)),
        ));
    }
    if !message.reactions.is_empty() {
        let reactions = message
            .reactions
            .iter()
            .map(|reaction| {
                let principal = reaction
                    .principal
                    .ok_or_else(|| StorageError::Other("reaction principal is missing".into()))?;
                tau::typed_container(
                    map,
                    vec![
                        (DataType::Principal, canonical_principal_value(principal)?),
                        (
                            DataType::Reaction,
                            DataValue::Str(reaction.reaction.clone()),
                        ),
                        (
                            DataType::SenderId,
                            DataValue::SignedNumber(reaction.user_id as i128),
                        ),
                    ],
                )
                .map_err(|error| StorageError::Other(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        fields.push((DataType::Reactions, DataValue::Array(reactions)));
    }
    Ok(fields)
}

pub(super) fn stored_message_value(
    message: &chat_files::StoredMessage,
    storage_owner: i64,
    partner_id: i64,
    map: &mtp::codec::TypeMap,
) -> Result<DataValue, StorageError> {
    tau::typed_container(
        map,
        stored_message_fields(message, storage_owner, partner_id, map)?,
    )
    .map_err(|error| StorageError::Other(error.to_string()))
}

pub fn handle_messages_get(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(partner_id) = data_i64(cv, DataType::UserId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(offset) = data_i64(cv, DataType::Offset).filter(|offset| *offset >= 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(amount) = data_i64(cv, DataType::Amount).filter(|amount| *amount > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match chats_util::get_user_by_principal(my_id_i64, iota_identity::PrincipalHandle(partner_id)) {
        Ok(Some(_)) => {}
        Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => return internal_handler_error(cv, "messages.contact", error),
    }
    let messages = match chat_files::get_messages_for_principal(
        my_id_i64,
        iota_identity::PrincipalHandle(partner_id),
        offset,
        amount,
    ) {
        Ok(messages) => messages,
        Err(error) => return internal_handler_error(cv, "messages.get", error),
    };
    let mut msg_array: Vec<DataValue> = Vec::new();
    for m in &messages {
        let Ok(value) = stored_message_value(
            m,
            my_id_i64,
            partner_id,
            cv.type_map().unwrap_or(&mtp::codec::TypeMap::latest()),
        ) else {
            return error_response(cv, CommunicationType::ErrorInternal);
        };
        msg_array.push(value);
    }

    CommunicationValue::new(CommunicationType::MessagesGet)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Messages, DataValue::Array(msg_array))
}

pub fn handle_message_get(cv: &CommunicationValue) -> CommunicationValue {
    let Some(send_time) = data_i64(cv, DataType::SendTime) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let partner_id = data_i64(cv, DataType::ChatPartnerId);
    let owner = match required_sender_id(cv) {
        Ok(owner) => owner,
        Err(response) => return response,
    };

    let (message, offset) = match partner_id {
        Some(partner_id) => match message_with_alias_offset(owner, partner_id, send_time) {
            Ok(Some((message, offset))) => (message, Some(offset)),
            Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
            Err(error) => return internal_handler_error(cv, "message.get", error),
        },
        None => match chat_files::get_message(owner, send_time, None, None) {
            Ok(Some(message)) => (message, None),
            Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
            Err(error) => return internal_handler_error(cv, "message.get", error),
        },
    };

    let mut response = CommunicationValue::new(CommunicationType::MessageGet)
        .with_request_id(cv)
        .with_receiver(u64::try_from(owner).expect("authenticated sender is non-negative"));
    let Some(alias) = message.external_principal else {
        return error_response(cv, CommunicationType::ErrorInternal);
    };
    let Ok(fields) = stored_message_fields(
        &message,
        owner,
        alias.0,
        cv.type_map().unwrap_or(&mtp::codec::TypeMap::latest()),
    ) else {
        return error_response(cv, CommunicationType::ErrorInternal);
    };
    for (data_type, value) in fields {
        response = response.add_typed_default(data_type, value);
    }
    if let Some(offset) = offset {
        response =
            response.add_typed_default(DataType::Offset, DataValue::SignedNumber(offset as i128));
    }
    response
}

pub(super) fn message_with_alias_offset(
    owner: i64,
    alias: i64,
    send_time: i64,
) -> Result<Option<(chat_files::StoredMessage, i64)>, StorageError> {
    let principal = iota_identity::PrincipalHandle(alias);
    let Some(contact) = chats_util::get_user_by_principal(owner, principal)? else {
        return Ok(None);
    };
    let Some(message) =
        chat_files::get_message(owner, send_time, Some(contact.user_id), Some(principal))?
    else {
        return Ok(None);
    };
    let offset = iota_storage::util::db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE storage_owner = ?1 AND external_principal = ?2 AND deleted_by_external = 0 AND history_deleted = 0 AND (COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) > COALESCE(?3, ?4) OR (COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) = COALESCE(?3, ?4) AND id > ?4))",
            rusqlite::params![owner, alias, message.destination_iota_received_at.or(message.origin_iota_received_at).or(message.authored_at), message.id], |row| row.get(0))?)
    })?;
    Ok(Some((message, offset)))
}

pub fn handle_get_chats(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match cv.require_sender() {
        Ok(user_id) => user_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(user_id_i64) = i64::try_from(user_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let users = match chats_util::get_users(user_id_i64) {
        Ok(users) => users,
        Err(error) => return internal_handler_error(cv, "chats.get", error),
    };
    let mut user_array = Vec::new();
    for user in users {
        let value = match contact_value(
            &user,
            &[],
            user_id_i64,
            cv.type_map().unwrap_or(&mtp::codec::TypeMap::latest()),
        ) {
            Ok(value) => value,
            Err(error) => return internal_handler_error(cv, "chats.metadata", error),
        };
        user_array.push(value);
    }
    CommunicationValue::new(CommunicationType::GetChats)
        .with_request_id(cv)
        .with_receiver(user_id)
        .add_typed_default(DataType::UserIds, DataValue::Array(user_array))
}
