use super::*;

pub(super) fn asset_metadata_value(
    asset: &UserAssetMetadata,
) -> Result<DataValue, tau::ProtocolValueError> {
    typed_container(vec![
        (DataType::AssetId, DataValue::Str(asset.asset_id.clone())),
        (DataType::Size, DataValue::SignedNumber(asset.size.into())),
        (DataType::Sha256, DataValue::Bytes(asset.sha256.clone())),
        (DataType::MimeType, DataValue::Str(asset.mime_type.clone())),
        (
            DataType::VersionNumber,
            DataValue::SignedNumber(asset.revision.into()),
        ),
        (
            DataType::CreatedAt,
            DataValue::SignedNumber(asset.created_at.into()),
        ),
        (
            DataType::UpdatedAt,
            DataValue::SignedNumber(asset.updated_at.into()),
        ),
    ])
}

pub(super) fn asset_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    asset: &UserAssetMetadata,
) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(asset.user_id))
        .add_typed_default(DataType::AssetId, DataValue::Str(asset.asset_id.clone()))
        .add_typed_default(DataType::Size, DataValue::SignedNumber(asset.size.into()))
        .add_typed_default(DataType::Sha256, DataValue::Bytes(asset.sha256.clone()))
        .add_typed_default(DataType::MimeType, DataValue::Str(asset.mime_type.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(asset.revision.into()),
        )
        .add_typed_default(
            DataType::CreatedAt,
            DataValue::SignedNumber(asset.created_at.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(asset.updated_at.into()),
        )
}

pub(super) fn upload_response(
    cv: &CommunicationValue,
    ty: CommunicationType,
    status: &UploadStatus,
) -> CommunicationValue {
    let mut response = CommunicationValue::new(ty)
        .with_request_id(cv)
        .with_receiver(cv.sender().unwrap_or_default())
        .add_typed_default(DataType::UploadId, DataValue::Str(status.upload_id.clone()))
        .add_typed_default(DataType::AssetId, DataValue::Str(status.asset_id.clone()))
        .add_typed_default(DataType::Size, DataValue::SignedNumber(status.size.into()))
        .add_typed_default(DataType::Sha256, DataValue::Bytes(status.sha256.clone()))
        .add_typed_default(DataType::MimeType, DataValue::Str(status.mime_type.clone()))
        .add_typed_default(
            DataType::Offset,
            DataValue::SignedNumber(status.offset.into()),
        )
        .add_typed_default(DataType::State, DataValue::Str(status.state.clone()))
        .add_typed_default(
            DataType::CreatedAt,
            DataValue::SignedNumber(status.created_at.into()),
        )
        .add_typed_default(
            DataType::UpdatedAt,
            DataValue::SignedNumber(status.updated_at.into()),
        );
    if let Some(revision) = status.revision {
        response = response.add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(revision.into()),
        );
    }
    if let Some(committed_at) = status.committed_at {
        response = response.add_typed_default(
            DataType::CommittedAt,
            DataValue::SignedNumber(committed_at.into()),
        );
    }
    response
}

pub(super) fn asset_error(cv: &CommunicationValue, error: StorageError) -> CommunicationValue {
    let (kind, category) = match &error {
        StorageError::AssetResourceLimit(_) => {
            (CommunicationType::ErrorInvalidData, "asset_resource_limit")
        }
        _ => (CommunicationType::ErrorInternal, "asset_request_failed"),
    };
    if kind == CommunicationType::ErrorInternal {
        log_event!(
            PrintType::Client,
            LogLevel::Error,
            "request.internal_error",
            "operation=user_assets message_id={:?} sender={:?} error={}",
            cv.id(),
            cv.sender(),
            error
        );
    }
    error_response(cv, kind).add_typed_default(DataType::ErrorType, DataValue::Str(category.into()))
}

pub(super) fn upload_request(cv: &CommunicationValue) -> Result<(i64, String), CommunicationValue> {
    let user_id = required_sender_id(cv)?;
    let upload_id = cv
        .get_data(DataType::UploadId)
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| error_response(cv, CommunicationType::ErrorInvalidData))?;
    Ok((user_id, upload_id.to_owned()))
}

pub fn handle_user_asset_upload_start(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Some(upload_id) = cv.get_data(DataType::UploadId).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(asset_id) = cv.get_data(DataType::AssetId).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(size) = data_i64(cv, DataType::Size) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(sha256) = cv.get_data(DataType::Sha256).and_then(DataValue::as_bytes) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(mime_type) = cv.get_data(DataType::MimeType).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_assets::start(user_id, upload_id, asset_id, size, &sha256, mime_type) {
        Ok(status) => upload_response(cv, CommunicationType::UserAssetUploadStart, &status),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_upload_chunk(cv: &CommunicationValue) -> CommunicationValue {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(offset) = data_i64(cv, DataType::Offset) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(chunk) = cv.get_data(DataType::Blob).and_then(DataValue::as_bytes) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_assets::append(user_id, &upload_id, offset, &chunk) {
        Ok(status) => upload_response(cv, CommunicationType::UserAssetUploadChunk, &status),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_upload_status(cv: &CommunicationValue) -> CommunicationValue {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match user_assets::status(user_id, &upload_id) {
        Ok(Some(status)) => upload_response(cv, CommunicationType::UserAssetUploadStatus, &status),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_upload_commit(cv: &CommunicationValue) -> AssetMutation {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => {
            return AssetMutation {
                response,
                changed: None,
            };
        }
    };
    match user_assets::commit(user_id, &upload_id) {
        Ok((asset, changed)) => AssetMutation {
            response: asset_response(cv, CommunicationType::UserAssetUploadCommit, &asset),
            changed: changed.then(|| {
                asset_response(cv, CommunicationType::UserAssetChanged, &asset)
                    .with_id(next_notification_id())
                    .add_typed_default(DataType::Deleted, DataValue::Bool(false))
            }),
        },
        Err(error) => AssetMutation {
            response: asset_error(cv, error),
            changed: None,
        },
    }
}

pub fn handle_user_asset_upload_abort(cv: &CommunicationValue) -> CommunicationValue {
    let (user_id, upload_id) = match upload_request(cv) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match user_assets::abort(user_id, &upload_id) {
        Ok(_) => CommunicationValue::new(CommunicationType::UserAssetUploadAbort)
            .with_request_id(cv)
            .with_receiver(sender_wire_id(user_id))
            .add_typed_default(DataType::UploadId, DataValue::Str(upload_id)),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_get_chunk(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Some(asset_id) = cv.get_data(DataType::AssetId).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(offset) = data_i64(cv, DataType::Offset) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(amount) = data_i64(cv, DataType::Amount).and_then(|value| usize::try_from(value).ok())
    else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    match user_assets::read_chunk(user_id, asset_id, offset, amount) {
        Ok(Some((asset, bytes))) => {
            asset_response(cv, CommunicationType::UserAssetGetChunk, &asset)
                .add_typed_default(DataType::Offset, DataValue::SignedNumber(offset.into()))
                .add_typed_default(DataType::Blob, DataValue::Bytes(bytes))
        }
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_list(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let after_id = match cv.get_data(DataType::Offset).and_then(DataValue::as_number) {
        Some(raw) => match i64::try_from(raw) {
            Ok(id) if id > 0 => Some(id),
            _ => return error_response(cv, CommunicationType::ErrorInvalidData),
        },
        None => None,
    };
    match user_assets::list_page(user_id, after_id) {
        Ok((assets, next)) => {
            let Ok(values) = assets
                .iter()
                .map(asset_metadata_value)
                .collect::<Result<Vec<_>, _>>()
            else {
                return error_response(cv, CommunicationType::ErrorInvalidData);
            };
            CommunicationValue::new(CommunicationType::UserAssetList)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::Offset,
                    DataValue::SignedNumber(next.unwrap_or(0).into()),
                )
                .add_typed_default(DataType::Assets, DataValue::Array(values))
        }
        Err(error) => asset_error(cv, error),
    }
}

pub fn handle_user_asset_delete(cv: &CommunicationValue) -> AssetMutation {
    let user_id = match required_sender_id(cv) {
        Ok(id) if id > 0 => id,
        _ => {
            return AssetMutation {
                response: error_response(cv, CommunicationType::ErrorInvalidData),
                changed: None,
            };
        }
    };
    let Some(asset_id) = cv.get_data(DataType::AssetId).as_str() else {
        return AssetMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    match user_assets::delete(user_id, asset_id) {
        Ok(Some(asset)) => AssetMutation {
            response: asset_response(cv, CommunicationType::UserAssetDelete, &asset),
            changed: Some(
                asset_response(cv, CommunicationType::UserAssetChanged, &asset)
                    .with_id(next_notification_id())
                    .add_typed_default(DataType::Deleted, DataValue::Bool(true)),
            ),
        },
        Ok(None) => AssetMutation {
            response: CommunicationValue::new(CommunicationType::UserAssetDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(DataType::AssetId, DataValue::Str(asset_id.to_owned())),
            changed: None,
        },
        Err(error) => AssetMutation {
            response: asset_error(cv, error),
            changed: None,
        },
    }
}
