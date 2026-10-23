use super::*;

pub fn handle_call_contact_check(cv: &CommunicationValue) -> CommunicationValue {
    let (Some(sender), Some(recipient)) = (
        data_i64(cv, DataType::SenderId).filter(|id| *id > 0),
        data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0),
    ) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match chats_util::get_user(sender, recipient) {
        Ok(contact) => CommunicationValue::new(CommunicationType::CallContactCheck)
            .with_request_id(cv)
            .add_typed_default(DataType::IsBlocked, DataValue::Bool(contact.is_some())),
        Err(error) => internal_handler_error(cv, "call.contact_check", error),
    }
}

pub fn handle_call_envelope_store(
    cv: &CommunicationValue,
    owner_omikron_id: i64,
) -> CommunicationValue {
    let Some(recipient_id) = data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(inviter_id) = data_i64(cv, DataType::CallInviterId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(call_id) =
        data_string(cv, DataType::CallId).filter(|id| uuid::Uuid::parse_str(id).is_ok())
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(created_at) = data_i64(cv, DataType::CreatedAt) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let secret_value = cv.get_data(DataType::CallSecret);
    let Some(secret) = secret_value.as_ref() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(tm) = cv.type_map() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let field = |dt: DataType| secret.get_field(dt.try_to_id(tm)?);
    let (
        Some(secret_id),
        Some(version_number),
        Some(encrypted_secret),
        Some(kem_ciphertext),
        Some(wrapping_scheme),
    ) = (
        field(DataType::SecretId).and_then(DataValue::as_str),
        field(DataType::VersionNumber)
            .and_then(DataValue::as_number)
            .and_then(|n| i64::try_from(n).ok()),
        field(DataType::EncryptedSecret).and_then(DataValue::as_bytes),
        field(DataType::KemCiphertext).and_then(DataValue::as_bytes),
        field(DataType::WrappingScheme).and_then(DataValue::as_str),
    )
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let now = now_millis_i64();
    let expires_at = created_at.saturating_add(3 * 24 * 60 * 60 * 1000);
    if created_at > now + 60_000
        || expires_at <= now
        || secret_id.len() > 256
        || encrypted_secret.len() > 1024
        || kem_ciphertext.len() > 4096
        || wrapping_scheme.len() > 128
    {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let envelope = CallEnvelope {
        recipient_id,
        call_id,
        owner_omikron_id,
        inviter_id,
        created_at,
        expires_at,
        secret_id: secret_id.to_string(),
        version_number,
        encrypted_secret,
        kem_ciphertext,
        wrapping_scheme: wrapping_scheme.to_string(),
    };
    match call_envelopes::store(&envelope, now) {
        Ok(true) => success_response(cv),
        Ok(false) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => internal_handler_error(cv, "call.envelope_store", error),
    }
}

pub fn handle_call_envelope_get(
    cv: &CommunicationValue,
    owner_omikron_id: i64,
) -> CommunicationValue {
    let (Some(recipient_id), Some(call_id)) = (
        data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0),
        data_string(cv, DataType::CallId).filter(|id| uuid::Uuid::parse_str(id).is_ok()),
    ) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match call_envelopes::get(recipient_id, &call_id, owner_omikron_id, now_millis_i64()) {
        Ok(Some(envelope)) => {
            let Ok(secret) = typed_container(vec![
                (DataType::SecretId, DataValue::Str(envelope.secret_id)),
                (
                    DataType::VersionNumber,
                    DataValue::SignedNumber(envelope.version_number.into()),
                ),
                (
                    DataType::EncryptedSecret,
                    DataValue::Bytes(envelope.encrypted_secret),
                ),
                (
                    DataType::KemCiphertext,
                    DataValue::Bytes(envelope.kem_ciphertext),
                ),
                (
                    DataType::WrappingScheme,
                    DataValue::Str(envelope.wrapping_scheme),
                ),
            ]) else {
                return error_response(cv, CommunicationType::ErrorInvalidData);
            };
            CommunicationValue::new(CommunicationType::CallEnvelopeGet)
                .with_request_id(cv)
                .add_typed_default(DataType::CallSecret, secret)
                .add_typed_default(
                    DataType::CallInviterId,
                    DataValue::SignedNumber(envelope.inviter_id.into()),
                )
                .add_typed_default(
                    DataType::CreatedAt,
                    DataValue::SignedNumber(envelope.created_at.into()),
                )
        }
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => internal_handler_error(cv, "call.envelope_get", error),
    }
}

pub fn handle_call_contact_accept(cv: &CommunicationValue) -> CommunicationValue {
    let (Some(recipient), Some(inviter)) = (
        data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0),
        data_i64(cv, DataType::CallInviterId).filter(|id| *id > 0),
    ) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match add_conversation_for_user(recipient, inviter, None) {
        Ok(()) => success_response(cv),
        Err(error) => internal_handler_error(cv, "call.contact_accept", error),
    }
}
