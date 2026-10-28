use super::*;
use iota_storage::util::files;
use serde::de::DeserializeOwned;
use tau_relay_protocol::files::*;

fn payload<T: DeserializeOwned>(cv: &CommunicationValue) -> Result<T, StorageError> {
    let json = cv
        .get_data(DataType::Json)
        .as_str()
        .ok_or(StorageError::InvalidRelayPayload("file JSON"))?;
    if json.len() > MAX_CONTROL_BYTES {
        return Err(StorageError::InvalidRelayPayload("file JSON length"));
    }
    serde_json::from_str(json).map_err(|_| StorageError::InvalidRelayPayload("file JSON schema"))
}

/// Dispatch only after the transport has bound sender to a hosted account.
pub fn handle_file_request(cv: &CommunicationValue) -> CommunicationValue {
    let owner = match required_sender_id(cv) {
        Ok(owner) if owner > 0 => owner,
        _ => return error_response(cv, CommunicationType::ErrorNotAuthenticated),
    };
    let result = (|| -> Result<serde_json::Value, StorageError> {
        match cv.get_comm_type_enum() {
            Some(CommunicationType::FileUploadStart) => {
                return files::upload_start(owner, &payload::<FileUploadStart>(cv)?);
            }
            Some(CommunicationType::FileMetadataPut) => {
                files::metadata_put(owner, &payload::<MetadataUpdate>(cv)?)?
            }
            Some(CommunicationType::FileKeyEnvelopePut) => {
                files::rewrap(owner, &payload::<RewrapKey>(cv)?)?
            }
            Some(CommunicationType::FileFolderPut) => {
                files::folder_put(owner, &payload::<Folder>(cv)?)?
            }
            Some(CommunicationType::FileFolderDelete) => {
                files::entry_delete(owner, &payload::<DeleteEntry>(cv)?, true)?
            }
            Some(CommunicationType::FilePlacementPut) => {
                files::placement_put(owner, &payload::<Placement>(cv)?)?
            }
            Some(CommunicationType::FilePlacementDelete) => {
                files::entry_delete(owner, &payload::<DeleteEntry>(cv)?, false)?
            }
            Some(CommunicationType::FileVersionPublish) => {
                files::publish(owner, &payload::<PublishVersion>(cv)?)?
            }
            Some(CommunicationType::FileListPage) => {
                return files::list_page(owner, &payload::<ListPage>(cv)?);
            }
            Some(CommunicationType::FileChangesGet) => {
                return files::changes(owner, &payload::<ChangesPage>(cv)?);
            }
            Some(CommunicationType::FileGetManifest | CommunicationType::FileReplicaStatus) => {
                return files::manifest(owner, &payload::<FileKey>(cv)?);
            }
            Some(CommunicationType::FileReplicaAccept) => {
                files::replication::accept(owner, &payload::<FileKey>(cv)?)?
            }
            Some(CommunicationType::FileReplicaCancel) => {
                files::replication::cancel(owner, &payload::<FileKey>(cv)?)?
            }
            Some(CommunicationType::FileDelete) => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Delete {
                    file_id: String,
                }
                files::delete_file(owner, &payload::<Delete>(cv)?.file_id)?;
            }
            _ => return Err(StorageError::UnsupportedRelayOperation),
        }
        Ok(serde_json::json!({"ok":true}))
    })();
    match result {
        Ok(value) => CommunicationValue::new_with_type_map(
            cv.get_comm_type_enum().expect("file operation"),
            cv.type_map().expect("authenticated dictionary"),
        )
        .with_request_id(cv)
        .with_receiver(sender_wire_id(owner))
        .add_typed_default(DataType::Json, DataValue::Str(value.to_string())),
        Err(error) => {
            let (kind, category) = match error {
                StorageError::MessageUnauthorized | StorageError::HostedAuthorizationDenied => (
                    CommunicationType::ErrorNotAuthenticated,
                    "file_unauthorized",
                ),
                StorageError::MissingRelayDependency => {
                    (CommunicationType::ErrorNotFound, "file_not_found")
                }
                StorageError::AssetResourceLimit(_) => {
                    (CommunicationType::ErrorInvalidData, "file_resource_limit")
                }
                StorageError::InvalidRelayPayload(_) | StorageError::RevisionConflict => (
                    CommunicationType::ErrorInvalidData,
                    "file_invalid_or_conflict",
                ),
                _ => (CommunicationType::ErrorInternal, "file_request_failed"),
            };
            error_response(cv, kind)
                .add_typed_default(DataType::ErrorType, DataValue::Str(category.into()))
        }
    }
}

/// Shared dispatch for direct hosted connections. Relays and peer reads must
/// never enter this owner-scoped path.
pub fn handle_file_storage_request(cv: &CommunicationValue) -> Option<Vec<CommunicationValue>> {
    let response = match cv.get_comm_type_enum()? {
        CommunicationType::FileFolderPut
        | CommunicationType::FileKeyEnvelopePut
        | CommunicationType::FileMetadataPut
        | CommunicationType::FileUploadStart
        | CommunicationType::FileFolderDelete
        | CommunicationType::FilePlacementPut
        | CommunicationType::FilePlacementDelete
        | CommunicationType::FileVersionPublish
        | CommunicationType::FileListPage
        | CommunicationType::FileGetManifest
        | CommunicationType::FileDelete
        | CommunicationType::FileChangesGet
        | CommunicationType::FileReplicaAccept
        | CommunicationType::FileReplicaCancel
        | CommunicationType::FileReplicaStatus => handle_file_request(cv),
        CommunicationType::UserAssetUploadStart => handle_user_asset_upload_start(cv),
        CommunicationType::UserAssetUploadChunk => handle_user_asset_upload_chunk(cv),
        CommunicationType::UserAssetUploadStatus => handle_user_asset_upload_status(cv),
        CommunicationType::UserAssetUploadAbort => handle_user_asset_upload_abort(cv),
        CommunicationType::UserAssetGetChunk => handle_user_asset_get_chunk(cv),
        CommunicationType::UserAssetList => handle_user_asset_list(cv),
        CommunicationType::UserAssetUploadCommit | CommunicationType::UserAssetDelete => {
            let mutation = if cv.is_type(CommunicationType::UserAssetUploadCommit) {
                handle_user_asset_upload_commit(cv)
            } else {
                handle_user_asset_delete(cv)
            };
            let mut responses = vec![mutation.response];
            responses.extend(mutation.changed);
            return Some(responses);
        }
        _ => return None,
    };
    Some(vec![response])
}
