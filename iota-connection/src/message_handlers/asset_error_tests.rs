use super::*;

#[test]
fn storage_errors_do_not_expose_internal_paths() {
    let request = CommunicationValue::new(CommunicationType::UserAssetUploadStart).with_id(7);
    let internal = asset_error(
        &request,
        StorageError::Other("private path /srv/assets/key".into()),
    );
    assert!(internal.is_type(CommunicationType::ErrorInternal));
    assert_eq!(
        internal
            .get_data(DataType::ErrorType)
            .and_then(DataValue::as_str),
        Some("asset_request_failed")
    );
    let limit = asset_error(
        &request,
        StorageError::AssetResourceLimit("max_asset_bytes"),
    );
    assert!(limit.is_type(CommunicationType::ErrorInvalidData));
    assert_eq!(
        limit
            .get_data(DataType::ErrorType)
            .and_then(DataValue::as_str),
        Some("asset_resource_limit")
    );
}
