use super::*;

pub(super) fn authenticated_user(cv: &CommunicationValue) -> Result<i64, CommunicationValue> {
    let user_id = required_sender_id(cv)?;
    if user_id <= 0 {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    Ok(user_id)
}

pub fn handle_user_block(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(blocked_user_id) = data_i64(cv, DataType::BlockedUserId).filter(|id| *id > 0) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Ok(Some(contact)) =
        chats_util::get_user_by_principal(user_id, iota_identity::PrincipalHandle(blocked_user_id))
    else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        };
    };
    let Some(blocked_principal) = contact.principal else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        };
    };
    match blocked_users::block(user_id, blocked_principal) {
        Ok(record) => PolicyMutation {
            response: CommunicationValue::new(CommunicationType::UserBlock)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::BlockedUserId,
                    DataValue::SignedNumber(blocked_user_id.into()),
                )
                .add_typed_default(
                    DataType::VersionNumber,
                    DataValue::SignedNumber(record.revision.into()),
                ),
            changed: Some(
                CommunicationValue::new(CommunicationType::BlockedUsersChanged)
                    .with_id(next_notification_id())
                    .with_receiver(sender_wire_id(user_id))
                    .add_typed_default(
                        DataType::BlockedUserId,
                        DataValue::SignedNumber(blocked_user_id.into()),
                    )
                    .add_typed_default(
                        DataType::VersionNumber,
                        DataValue::SignedNumber(record.revision.into()),
                    )
                    .add_typed_default(DataType::Deleted, DataValue::Bool(record.deleted)),
            ),
        },
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "blocked_users.block", error),
            changed: None,
        },
    }
}

pub fn handle_user_unblock(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(blocked_user_id) = data_i64(cv, DataType::BlockedUserId).filter(|id| *id > 0) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Ok(Some(contact)) =
        chats_util::get_user_by_principal(user_id, iota_identity::PrincipalHandle(blocked_user_id))
    else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        };
    };
    let Some(blocked_principal) = contact.principal else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        };
    };
    match blocked_users::unblock(user_id, blocked_principal) {
        Ok(mutation) => PolicyMutation {
            response: CommunicationValue::new(CommunicationType::UserUnblock)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::BlockedUserId,
                    DataValue::SignedNumber(blocked_user_id.into()),
                ),
            changed: mutation.map(|mutation| {
                CommunicationValue::new(CommunicationType::BlockedUsersChanged)
                    .with_id(next_notification_id())
                    .with_receiver(sender_wire_id(user_id))
                    .add_typed_default(
                        DataType::BlockedUserId,
                        DataValue::SignedNumber(blocked_user_id.into()),
                    )
                    .add_typed_default(
                        DataType::VersionNumber,
                        DataValue::SignedNumber(mutation.revision.into()),
                    )
                    .add_typed_default(DataType::Deleted, DataValue::Bool(mutation.deleted))
            }),
        },
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "blocked_users.unblock", error),
            changed: None,
        },
    }
}

pub fn handle_blocked_users_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = authenticated_user(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match blocked_users::list(user_id) {
        Ok(users) => CommunicationValue::new(CommunicationType::BlockedUsersGet)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(
                DataType::BlockedUserIds,
                DataValue::Array(
                    users
                        .into_iter()
                        .map(|blocked| DataValue::SignedNumber(blocked.blocked_principal.0.into()))
                        .collect(),
                ),
            ),
        Err(error) => internal_handler_error(cv, "blocked_users.get", error),
    }
}

pub(super) fn receipt_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    policy: receipt_policy::ReceiptPolicy,
) -> CommunicationValue {
    let response = CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(policy.user_id));
    add_receipt_policy_data(response, &policy)
}

pub fn handle_receipt_policy_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = authenticated_user(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match receipt_policy::get(user_id) {
        Ok(policy) => receipt_response(cv, CommunicationType::ReceiptPolicyGet, policy),
        Err(error) => internal_handler_error(cv, "receipt_policy.get", error),
    }
}

pub fn handle_receipt_policy_set(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let (Some(read), Some(received)) = (
        cv.get_data(DataType::SendReadReceipts)
            .and_then(DataValue::as_bool),
        cv.get_data(DataType::SendReceivedReceipts)
            .and_then(DataValue::as_bool),
    ) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match receipt_policy::set(user_id, read, received) {
        Ok(policy) => {
            let response = receipt_response(cv, CommunicationType::ReceiptPolicySet, policy);
            let changed = receipt_response(cv, CommunicationType::ReceiptPolicyChanged, policy)
                .with_id(next_notification_id());
            PolicyMutation {
                response,
                changed: Some(changed),
            }
        }
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "receipt_policy.set", error),
            changed: None,
        },
    }
}

pub(super) fn storage_policy_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    policy: message_storage_policy::MessageStoragePolicy,
) -> CommunicationValue {
    let (history_mode, duration) = match policy.history_mode {
        message_storage_policy::MessageHistoryMode::Retain => ("retain", None),
        message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery => {
            ("delete_after_client_delivery", None)
        }
    };
    let retention_duration = match policy.retention {
        message_storage_policy::MessageRetention::Forever => None,
        message_storage_policy::MessageRetention::Duration { duration_ms } => Some(duration_ms),
    };
    let mut response = CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(policy.user_id))
        .add_typed_default(
            DataType::MessageHistoryMode,
            DataValue::Str(history_mode.into()),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(policy.revision.into()),
        );
    if let Some(duration_ms) = retention_duration.or(duration) {
        response = response.add_typed_default(
            DataType::MessageRetentionDuration,
            DataValue::SignedNumber(duration_ms.into()),
        );
    }
    response
}

pub fn handle_message_storage_policy_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = authenticated_user(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match message_storage_policy::get(user_id) {
        Ok(policy) => {
            storage_policy_response(cv, CommunicationType::MessageStoragePolicyGet, policy)
        }
        Err(error) => internal_handler_error(cv, "message_storage_policy.get", error),
    }
}

pub fn handle_message_storage_policy_set(cv: &CommunicationValue) -> PolicyMutation {
    let Ok(user_id) = authenticated_user(cv) else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(history_mode) = cv
        .get_data(DataType::MessageHistoryMode)
        .and_then(DataValue::as_str)
    else {
        return PolicyMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let history_mode = match history_mode {
        "retain" => message_storage_policy::MessageHistoryMode::Retain,
        "delete_after_client_delivery" => {
            message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery
        }
        _ => {
            return PolicyMutation {
                response: error_response(cv, CommunicationType::ErrorInvalidData),
                changed: None,
            };
        }
    };
    let retention = match data_i64(cv, DataType::MessageRetentionDuration) {
        Some(duration_ms) => message_storage_policy::MessageRetention::Duration { duration_ms },
        None => message_storage_policy::MessageRetention::Forever,
    };
    match message_storage_policy::set(user_id, history_mode, retention) {
        Ok(policy) => {
            let response =
                storage_policy_response(cv, CommunicationType::MessageStoragePolicySet, policy);
            let changed =
                storage_policy_response(cv, CommunicationType::MessageStoragePolicyChanged, policy)
                    .with_id(next_notification_id());
            PolicyMutation {
                response,
                changed: Some(changed),
            }
        }
        Err(error) => PolicyMutation {
            response: internal_handler_error(cv, "message_storage_policy.set", error),
            changed: None,
        },
    }
}

/* This request is issued over Omikron's trusted Iota connection. Clients have
 * no route to it, preventing arbitrary block-relationship disclosure. */
pub fn handle_user_block_check(cv: &CommunicationValue) -> CommunicationValue {
    let Some(sender_id) = data_i64(cv, DataType::SenderId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(receiver_id) = data_i64(cv, DataType::ReceiverId).filter(|id| *id > 0) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match blocked_users::is_blocked(receiver_id, sender_id) {
        Ok(blocked) => CommunicationValue::new(CommunicationType::UserBlockCheck)
            .with_request_id(cv)
            .add_typed_default(DataType::IsBlocked, DataValue::Bool(blocked)),
        Err(error) => internal_handler_error(cv, "blocked_users.check", error),
    }
}
