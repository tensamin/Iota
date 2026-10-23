use super::*;

pub(super) fn current_contact_ids(user_id: i64) -> Result<DataValue, StorageError> {
    let ids = chats_util::get_users(user_id)?
        .into_iter()
        .map(|contact| {
            contact
                .principal
                .map(|handle| handle.0)
                .ok_or_else(|| StorageError::Other("contact principal is missing".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(contact_ids_value(ids))
}

pub(super) fn contact_ids_value(ids: impl IntoIterator<Item = i64>) -> DataValue {
    let mut contact_ids = ids.into_iter().collect::<Vec<_>>();
    contact_ids.sort_unstable();
    contact_ids.dedup();

    DataValue::Array(
        contact_ids
            .into_iter()
            .map(|user_id| DataValue::SignedNumber(user_id as i128))
            .collect(),
    )
}

pub(super) fn account_state_error(cv: &CommunicationValue) -> CommunicationValue {
    error_response(cv, CommunicationType::ErrorInvalidData)
}

pub(super) fn add_receipt_policy_data(
    response: CommunicationValue,
    policy: &receipt_policy::ReceiptPolicy,
) -> CommunicationValue {
    response
        .add_typed_default(
            DataType::SendReadReceipts,
            DataValue::Bool(policy.send_read_receipts),
        )
        .add_typed_default(
            DataType::SendReceivedReceipts,
            DataValue::Bool(policy.send_received_receipts),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(policy.revision.into()),
        )
}

/// The sender is authenticated by MTP; a UserId embedded by a client is never trusted here.
pub fn handle_account_state_request(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return account_state_error(cv),
    };
    match read_fenced_snapshot(
        || snapshot_head(user_id),
        || Ok(account_state_snapshot(cv, user_id)),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => internal_handler_error(cv, "account_state.fence", error),
    }
}

pub(super) fn snapshot_head(owner: i64) -> Result<Option<i64>, StorageError> {
    use rusqlite::OptionalExtension;
    iota_storage::util::db::with_db(|conn| {
        Ok(conn
            .query_row(
                "SELECT version FROM sync_heads WHERE user_id = ?1",
                [owner],
                |row| row.get(0),
            )
            .optional()?)
    })
}

pub(super) fn read_fenced_snapshot<T>(
    mut head: impl FnMut() -> Result<Option<i64>, StorageError>,
    mut snapshot: impl FnMut() -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    // Covered relay effects advance this head in the same transaction as their state.
    for _ in 0..3 {
        let before = head()?;
        let value = snapshot()?;
        if head()? == before {
            return Ok(value);
        }
    }
    Err(StorageError::Other(
        "account snapshot changed during all read attempts".into(),
    ))
}

pub(super) fn account_state_snapshot(cv: &CommunicationValue, user_id: i64) -> CommunicationValue {
    let latest = mtp::codec::TypeMap::latest();
    let map = cv.type_map().unwrap_or(&latest);
    let store = iota_storage::identity::SqlitePrincipalStore;
    let principal = match store
        .principal_for_local_user(iota_identity::LocalUserId(user_id))
        .and_then(|handle| {
            handle
                .map(|handle| store.get_principal(handle))
                .transpose()
                .map(Option::flatten)
        }) {
        Ok(Some(principal)) => principal,
        Ok(None) => return error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => return internal_handler_error(cv, "account_state.owner", error),
    };
    let canonical = match serde_json::to_string(&principal.principal) {
        Ok(canonical) => canonical,
        Err(error) => return internal_handler_error(cv, "account_state.owner", error),
    };
    let contacts = match chats_util::get_users(user_id) {
        Ok(contacts) => contacts,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let messages = match chat_files::get_all_messages(user_id) {
        Ok(messages) => messages,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let settings = match synced_settings::list(user_id) {
        Ok(settings) => settings,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let message_values = messages
        .iter()
        .map(|message| {
            let alias = message
                .external_principal
                .ok_or_else(|| StorageError::Other("message principal is missing".into()))?
                .0;
            stored_message_value(message, user_id, alias, map)
                .map_err(|error| StorageError::Other(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>();
    let contact_values = match contacts
        .iter()
        .map(|contact| contact_value(contact, &messages, user_id, map))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(values) => values,
        Err(error) => return internal_handler_error(cv, "account_state.contacts", error),
    };
    let message_values = match message_values {
        Ok(values) => values,
        Err(error) => return internal_handler_error(cv, "account_state.messages", error),
    };
    let setting_values = match settings
        .iter()
        .map(|setting| synced_setting_value(setting, map))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(values) => values,
        Err(error) => return internal_handler_error(cv, "account_state.settings", error),
    };
    let blocked_users = match blocked_users::list(user_id) {
        Ok(users) => users,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let receipt_policy = match receipt_policy::get(user_id) {
        Ok(policy) => policy,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let message_storage_policy = match message_storage_policy::get(user_id) {
        Ok(policy) => policy,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let contact_ids = match current_contact_ids(user_id) {
        Ok(contact_ids) => contact_ids,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let communities = match community_values(user_id, map) {
        Ok(communities) => communities,
        Err(error) => return internal_handler_error(cv, "account_state.snapshot", error),
    };
    let retention_duration = match message_storage_policy.retention {
        message_storage_policy::MessageRetention::Forever => None,
        message_storage_policy::MessageRetention::Duration { duration_ms } => Some(duration_ms),
    };
    let after = match receipt_number(cv, DataType::ReceiptCursor, Some(0)) {
        Ok(value) => value,
        Err(()) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let receipts = match crate::prepared_relay::snapshot_receipts(
        user_id,
        after,
        None,
        iota_storage::util::relay_acceptance_receipts::PAGE_LIMIT,
    ) {
        Ok(receipts) => receipts,
        Err(error) => return internal_handler_error(cv, "account_state.receipts", error),
    };
    let response =
        CommunicationValue::new_with_type_map(CommunicationType::AccountStateSnapshot, map)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(DataType::Principal, DataValue::Str(canonical.clone()))
            .add_typed_default(DataType::UserAddress, DataValue::Str(canonical))
            .add_typed_default(DataType::Contacts, DataValue::Array(contact_values))
            .add_typed_default(DataType::Messages, DataValue::Array(message_values))
            .add_typed_default(DataType::Settings, DataValue::Array(setting_values))
            .add_typed_default(
                DataType::BlockedUserIds,
                DataValue::Array(
                    blocked_users
                        .into_iter()
                        .map(|blocked| DataValue::SignedNumber(blocked.blocked_principal.0.into()))
                        .collect(),
                ),
            );
    let response = match add_receipt_page(response, receipts, map) {
        Ok(response) => response,
        Err(error) => return internal_handler_error(cv, "account_state.receipts", error),
    };
    let mut response = add_receipt_policy_data(response, &receipt_policy)
        .add_typed_default(
            DataType::MessageHistoryMode,
            DataValue::Str(match message_storage_policy.history_mode {
                message_storage_policy::MessageHistoryMode::Retain => "retain".into(),
                message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery => {
                    "delete_after_client_delivery".into()
                }
            }),
        )
        .add_typed_default(DataType::Communities, DataValue::Array(communities))
        .add_typed_default(DataType::UserIds, contact_ids)
        .add_typed_default(DataType::Calls, DataValue::Array(Vec::new()));
    if let Some(duration_ms) = retention_duration {
        response = response.add_typed_default(
            DataType::MessageRetentionDuration,
            DataValue::SignedNumber(duration_ms.into()),
        );
    }
    response
}

pub fn handle_account_state_applied(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return account_state_error(cv),
    };
    let _ = user_id;
    success_response(cv)
}

pub(super) fn receipt_number(
    cv: &CommunicationValue,
    field: DataType,
    default: Option<i64>,
) -> Result<i64, ()> {
    match cv.get_data(field) {
        None => default.ok_or(()),
        Some(value) => value
            .as_number()
            .and_then(|n| i64::try_from(n).ok())
            .filter(|n| *n >= 0)
            .ok_or(()),
    }
}

pub(super) fn add_receipt_page(
    response: CommunicationValue,
    page: iota_storage::util::relay_acceptance_receipts::ReceiptPage,
    map: &mtp::codec::TypeMap,
) -> Result<CommunicationValue, StorageError> {
    let records = page
        .records
        .into_iter()
        .map(|record| {
            tau::typed_container(
                map,
                vec![
                    (DataType::Principal, DataValue::Str(record.principal)),
                    (DataType::RelayMessageId, DataValue::Str(record.message_id)),
                    (
                        DataType::ReceiptSequence,
                        DataValue::SignedNumber(record.sequence.into()),
                    ),
                    (
                        DataType::ReceiptAcceptedAt,
                        DataValue::SignedNumber(record.accepted_at.into()),
                    ),
                ],
            )
            .map_err(|error| StorageError::Other(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(response
        .add_typed_default(DataType::AcceptedIds, DataValue::Array(records))
        .add_typed_default(
            DataType::ReceiptCursor,
            DataValue::SignedNumber(page.cursor.into()),
        )
        .add_typed_default(
            DataType::ReceiptUpper,
            DataValue::SignedNumber(page.upper.into()),
        )
        .add_typed_default(DataType::ReceiptMore, DataValue::Bool(page.more))
        .add_typed_default(DataType::ReceiptComplete, DataValue::Bool(!page.more)))
}

pub fn handle_relay_receipt_page(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return account_state_error(cv),
    };
    let bounds = (
        receipt_number(cv, DataType::ReceiptCursor, None),
        receipt_number(cv, DataType::ReceiptUpper, None),
        receipt_number(
            cv,
            DataType::Amount,
            Some(iota_storage::util::relay_acceptance_receipts::PAGE_LIMIT as i64),
        ),
    );
    let (Ok(after), Ok(upper), Ok(limit)) = bounds else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if after > upper
        || limit == 0
        || limit > iota_storage::util::relay_acceptance_receipts::PAGE_LIMIT as i64
    {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let latest = mtp::codec::TypeMap::latest();
    let map = cv.type_map().unwrap_or(&latest);
    match crate::prepared_relay::snapshot_receipts(user_id, after, Some(upper), limit as usize)
        .and_then(|page| {
            add_receipt_page(
                CommunicationValue::new_with_type_map(CommunicationType::RelayReceiptPage, map)
                    .with_request_id(cv)
                    .with_receiver(sender_wire_id(user_id)),
                page,
                map,
            )
        }) {
        Ok(response) => response,
        Err(error) => internal_handler_error(cv, "account_state.receipt_page", error),
    }
}
