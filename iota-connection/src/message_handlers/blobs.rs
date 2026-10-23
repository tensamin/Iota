use super::*;

pub(super) fn blob_metadata_value(
    blob: &UserBlobMetadata,
) -> Result<DataValue, tau::ProtocolValueError> {
    typed_container(vec![
        (DataType::BlobId, DataValue::Str(blob.blob_id.clone())),
        (
            DataType::VersionNumber,
            DataValue::SignedNumber(blob.revision.into()),
        ),
        (
            DataType::UpdatedAt,
            DataValue::SignedNumber(blob.updated_at.into()),
        ),
    ])
}

pub(super) fn blob_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    blob: &UserBlob,
) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(blob.user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob.blob_id.clone()))
        .add_typed_default(DataType::Blob, DataValue::Bytes(blob.blob.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(blob.revision.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(blob.updated_at.into()),
        )
}

pub(super) fn blob_mutation_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    blob: &UserBlob,
) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(blob.user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob.blob_id.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(blob.revision.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(blob.updated_at.into()),
        )
}

pub(super) fn blob_changed(blob: &UserBlob) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::UserBlobChanged)
        .with_id(next_notification_id())
        .with_receiver(sender_wire_id(blob.user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob.blob_id.clone()))
        .add_typed_default(DataType::Blob, DataValue::Bytes(blob.blob.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(blob.revision.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(blob.updated_at.into()),
        )
        .add_typed_default(DataType::Deleted, DataValue::Bool(false))
}

pub(super) fn blob_deleted(user_id: i64, blob_id: String, revision: i64) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::UserBlobChanged)
        .with_id(next_notification_id())
        .with_receiver(sender_wire_id(user_id))
        .add_typed_default(DataType::BlobId, DataValue::Str(blob_id))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(revision.into()),
        )
        .add_typed_default(DataType::Deleted, DataValue::Bool(true))
}

pub(super) fn blob_request(cv: &CommunicationValue) -> Result<(i64, String), CommunicationValue> {
    let user_id = required_sender_id(cv)?;
    if user_id <= 0 {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    let id = cv
        .get_data(DataType::BlobId)
        .and_then(DataValue::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorInvalidData))?;
    Ok((user_id, id.to_owned()))
}

pub fn handle_user_blob_put(cv: &CommunicationValue) -> BlobMutation {
    let Ok((user_id, blob_id)) = blob_request(cv) else {
        return BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(blob) = cv.get_data(DataType::Blob).and_then(DataValue::as_bytes) else {
        return BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let expected_revision = data_i64(cv, DataType::ExpectedRevision);
    match user_blobs::put(user_id, &blob_id, &blob, expected_revision) {
        Ok(stored) => BlobMutation {
            response: blob_mutation_response(cv, CommunicationType::UserBlobPut, &stored),
            changed: Some(blob_changed(&stored)),
        },
        Err(iota_storage::storage_error::StorageError::RevisionConflict) => BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        },
        Err(error) => BlobMutation {
            response: internal_handler_error(cv, "user_blobs.put", error),
            changed: None,
        },
    }
}

pub fn handle_user_blob_get(cv: &CommunicationValue) -> CommunicationValue {
    let Ok((user_id, blob_id)) = blob_request(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_blobs::get(user_id, &blob_id) {
        Ok(Some(blob)) => blob_response(cv, CommunicationType::UserBlobGet, &blob),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => internal_handler_error(cv, "user_blobs.get", error),
    }
}

pub fn handle_user_blob_delete(cv: &CommunicationValue) -> BlobMutation {
    let Ok((user_id, blob_id)) = blob_request(cv) else {
        return BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match user_blobs::delete(user_id, &blob_id, data_i64(cv, DataType::ExpectedRevision)) {
        Ok(Some(deleted)) => BlobMutation {
            response: CommunicationValue::new(CommunicationType::UserBlobDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(DataType::BlobId, DataValue::Str(blob_id.clone()))
                .add_typed_default(
                    DataType::VersionNumber,
                    DataValue::SignedNumber(deleted.revision.into()),
                ),
            changed: deleted
                .changed
                .then(|| blob_deleted(user_id, blob_id, deleted.revision)),
        },
        Ok(None) => BlobMutation {
            response: CommunicationValue::new(CommunicationType::UserBlobDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id)),
            changed: None,
        },
        Err(iota_storage::storage_error::StorageError::RevisionConflict) => BlobMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        },
        Err(error) => BlobMutation {
            response: internal_handler_error(cv, "user_blobs.delete", error),
            changed: None,
        },
    }
}

pub fn handle_user_blob_list(cv: &CommunicationValue) -> CommunicationValue {
    let Ok(user_id) = required_sender_id(cv) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if user_id <= 0 {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    }
    let after_id = match cv.get_data(DataType::Offset).and_then(DataValue::as_number) {
        Some(raw) => match i64::try_from(raw) {
            Ok(id) if id > 0 => Some(id),
            _ => return error_response(cv, CommunicationType::ErrorInvalidData),
        },
        None => None,
    };
    match user_blobs::list_metadata_page(user_id, after_id) {
        Ok((blobs, next)) => {
            let Ok(values) = blobs
                .iter()
                .map(blob_metadata_value)
                .collect::<Result<Vec<_>, _>>()
            else {
                return error_response(cv, CommunicationType::ErrorInvalidData);
            };
            CommunicationValue::new(CommunicationType::UserBlobList)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::Offset,
                    DataValue::SignedNumber(next.unwrap_or(0).into()),
                )
                .add_typed_default(DataType::Blobs, DataValue::Array(values))
        }
        Err(error) => internal_handler_error(cv, "user_blobs.list", error),
    }
}
