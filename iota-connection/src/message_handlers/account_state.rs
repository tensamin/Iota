use super::*;

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
    let outcome = tau::sync::decode_request(cv)
        .and_then(|request| {
            iota_storage::util::sync::paged::execute(user_id, &request)
                .map_err(|_| tau::sync::SyncError::Retryable)
        })
        .unwrap_or_else(|error| tau::sync::Response::Unavailable { error });
    tau::sync::encode_response(cv, &outcome).unwrap_or_else(|_| account_state_error(cv))
}

pub fn handle_account_state_applied(cv: &CommunicationValue) -> CommunicationValue {
    // Only a scoped acknowledgement of a fully issued page can make delivery ready.
    account_state_error(cv)
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
        receipt_number(
            cv,
            DataType::Amount,
            Some(iota_storage::util::relay_acceptance_receipts::PAGE_LIMIT as i64),
        ),
    );
    let (Ok(after), Ok(limit)) = bounds else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let upper = match cv.get_data(DataType::ReceiptUpper) {
        None if after == 0 => None,
        Some(_) => match receipt_number(cv, DataType::ReceiptUpper, None) {
            Ok(upper) => Some(upper),
            Err(()) => return account_state_error(cv),
        },
        None => return account_state_error(cv),
    };
    if upper.is_some_and(|upper| after > upper)
        || limit == 0
        || limit > iota_storage::util::relay_acceptance_receipts::PAGE_LIMIT as i64
    {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let Some(map) = cv.type_map().filter(|map| map.fingerprint().is_some()) else {
        return error_response(cv, CommunicationType::ErrorProtocol);
    };
    match crate::prepared_relay::snapshot_receipts(user_id, after, upper, limit as usize).and_then(
        |page| {
            add_receipt_page(
                CommunicationValue::new_with_type_map(CommunicationType::RelayReceiptPage, map)
                    .with_request_id(cv)
                    .with_receiver(sender_wire_id(user_id)),
                page,
                map,
            )
        },
    ) {
        Ok(response) => response,
        Err(error) => internal_handler_error(cv, "account_state.receipt_page", error),
    }
}
