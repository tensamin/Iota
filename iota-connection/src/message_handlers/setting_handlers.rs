use super::*;

pub(super) fn synced_setting_value(
    setting: &SyncedSetting,
    map: &mtp::codec::TypeMap,
) -> Result<DataValue, tau::ProtocolValueError> {
    tau::typed_container(
        map,
        vec![
            (
                DataType::SettingId,
                DataValue::SignedNumber(setting.id.into()),
            ),
            (
                DataType::SettingScope,
                DataValue::Str(setting.scope.as_str().to_string()),
            ),
            (
                DataType::SettingTarget,
                DataValue::Str(setting.scope_key.clone()),
            ),
            (DataType::SettingsName, DataValue::Str(setting.name.clone())),
            (DataType::Payload, DataValue::Str(setting.payload.clone())),
            (
                DataType::VersionNumber,
                DataValue::SignedNumber(setting.revision.into()),
            ),
        ],
    )
}

pub fn handle_global_settings_save(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings payload".to_string()),
            );
    };

    if let Err(error) = settings::save_global(my_id_i64, settings_value) {
        return internal_handler_error(cv, "settings.global_save", error);
    }

    let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsSave)
        .with_receiver(my_id)
        .with_request_id(cv);

    if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
        response =
            response.add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }

    response
}

pub fn handle_global_settings_load(cv: &CommunicationValue) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Ok(settings_value) = settings::load_global(my_id_i64) else {
        return error_response(cv, CommunicationType::ErrorInternal);
    };
    let Some(settings_value_str) = settings_value else {
        let mut response = CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Path,
                DataValue::Str("global.settings".to_string()),
            );

        if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
            response = response
                .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
        }

        return response;
    };

    let mut response = CommunicationValue::new(CommunicationType::GlobalSettingsLoad)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str));

    if let Some(session_id) = cv.get_data(DataType::SessionId).as_number() {
        response =
            response.add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }

    response
}

pub fn handle_settings_save(
    cv: &CommunicationValue,
    _expected_session_id: i128,
) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid session_id".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };
    let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings_name".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };
    let Some(settings_value) = cv.get_data(DataType::Payload).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings payload".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };

    if !settings_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        || settings_name.contains("..")
    {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid settings_name".to_string()),
            )
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str(settings_name.to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    if let Err(error) = settings::save(my_id_i64, session_id_i64, settings_name, settings_value) {
        return internal_handler_error(cv, "settings.save", error);
    }

    CommunicationValue::new(CommunicationType::SettingsSave)
        .with_receiver(my_id)
        .with_request_id(cv)
        .add_typed_default(
            DataType::SettingsName,
            DataValue::Str(settings_name.to_string()),
        )
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id))
}

pub fn handle_settings_load(
    cv: &CommunicationValue,
    _expected_session_id: i128,
) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid session_id".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(settings_name) = cv.get_data(DataType::SettingsName).as_str() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing settings_name".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };

    if !settings_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        || settings_name.contains("..")
    {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid settings_name".to_string()),
            )
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str(settings_name.to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }

    let Ok(settings_value) = settings::load(my_id_i64, session_id_i64, settings_name) else {
        return error_response(cv, CommunicationType::ErrorInternal);
    };
    let Some(settings_value_str) = settings_value else {
        return CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::SettingsName,
                DataValue::Str(settings_name.to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    };

    CommunicationValue::new(CommunicationType::SettingsLoad)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Payload, DataValue::Str(settings_value_str))
        .add_typed_default(
            DataType::SettingsName,
            DataValue::Str(settings_name.to_string()),
        )
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id))
}

pub fn handle_settings_list(
    cv: &CommunicationValue,
    _expected_session_id: i128,
) -> CommunicationValue {
    let my_id = match cv.require_sender() {
        Ok(my_id) => my_id,
        Err(_) => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let Ok(my_id_i64) = i64::try_from(my_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Missing session_id".to_string()),
            );
    };
    if session_id == 0 || session_id > 1_000_000 {
        return CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_request_id(cv)
            .with_receiver(my_id)
            .add_typed_default(
                DataType::Message,
                DataValue::Str("Invalid session_id".to_string()),
            )
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }
    let Ok(session_id_i64) = i64::try_from(session_id) else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };

    let Ok(settings) = settings::list(my_id_i64, session_id_i64) else {
        return error_response(cv, CommunicationType::ErrorInternal);
    };
    let settings_json = settings.into_iter().map(DataValue::Str).collect();
    CommunicationValue::new(CommunicationType::SettingsList)
        .with_request_id(cv)
        .with_receiver(my_id)
        .add_typed_default(DataType::Settings, DataValue::Array(settings_json))
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id))
}

pub(super) fn setting_response(
    cv: &CommunicationValue,
    response_type: CommunicationType,
    setting: &SyncedSetting,
) -> CommunicationValue {
    CommunicationValue::new(response_type)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(setting.user_id))
        .add_typed_default(
            DataType::SettingId,
            DataValue::SignedNumber(setting.id.into()),
        )
        .add_typed_default(
            DataType::SettingScope,
            DataValue::Str(setting.scope.as_str().to_string()),
        )
        .add_typed_default(
            DataType::SettingTarget,
            DataValue::Str(setting.scope_key.clone()),
        )
        .add_typed_default(DataType::SettingsName, DataValue::Str(setting.name.clone()))
        .add_typed_default(DataType::Payload, DataValue::Str(setting.payload.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(setting.revision.into()),
        )
}

pub(super) fn setting_changed(setting: &SyncedSetting) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::SyncedSettingChanged)
        .with_receiver(sender_wire_id(setting.user_id))
        .add_typed_default(
            DataType::SettingId,
            DataValue::SignedNumber(setting.id.into()),
        )
        .add_typed_default(
            DataType::SettingScope,
            DataValue::Str(setting.scope.as_str().to_string()),
        )
        .add_typed_default(
            DataType::SettingTarget,
            DataValue::Str(setting.scope_key.clone()),
        )
        .add_typed_default(DataType::SettingsName, DataValue::Str(setting.name.clone()))
        .add_typed_default(DataType::Payload, DataValue::Str(setting.payload.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(setting.revision.into()),
        )
}

pub(super) fn setting_deleted(
    user_id: i64,
    deleted: &synced_settings::DeletedSetting,
) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::SyncedSettingChanged)
        .with_receiver(sender_wire_id(user_id))
        .add_typed_default(
            DataType::DeletedSettingIds,
            DataValue::Array(vec![DataValue::SignedNumber(deleted.id.into())]),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(deleted.revision.into()),
        )
}

pub(super) fn parse_setting_locator(
    cv: &CommunicationValue,
) -> Result<SettingLocator, CommunicationValue> {
    let Some(scope_name) = cv.get_data(DataType::SettingScope).as_str() else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    let Some(scope) = SettingScope::parse(scope_name) else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    let Some(scope_key) = cv.get_data(DataType::SettingTarget).as_str() else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    let Some(name) = cv.get_data(DataType::SettingsName).as_str() else {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    };
    if !synced_settings::is_valid_name(name) {
        return Err(error_response(cv, CommunicationType::ErrorInvalidData));
    }
    match scope {
        SettingScope::User if !scope_key.is_empty() => {
            Err(error_response(cv, CommunicationType::ErrorInvalidData))
        }
        SettingScope::Contact if !scope_key.parse::<i64>().is_ok_and(|id| id > 0) => {
            Err(error_response(cv, CommunicationType::ErrorInvalidData))
        }
        SettingScope::Community if scope_key.is_empty() => {
            Err(error_response(cv, CommunicationType::ErrorInvalidData))
        }
        _ => Ok(SettingLocator {
            scope,
            scope_key: scope_key.to_string(),
            name: name.to_string(),
        }),
    }
}

pub(super) fn validate_setting_target(
    cv: &CommunicationValue,
    user_id: i64,
    locator: &SettingLocator,
) -> Result<(), CommunicationType> {
    match locator.scope {
        SettingScope::User => Ok(()),
        SettingScope::Contact => {
            let contact_id = locator
                .scope_key
                .parse::<i64>()
                .map_err(|_| CommunicationType::ErrorInvalidData)?;
            match chats_util::has_principal(user_id, iota_identity::PrincipalHandle(contact_id)) {
                Ok(true) => Ok(()),
                Ok(false) => Err(CommunicationType::ErrorInvalidData),
                Err(error) => {
                    internal_handler_error(cv, "settings.validate_contact", error);
                    Err(CommunicationType::ErrorInternal)
                }
            }
        }
        SettingScope::Community => {
            match CommunitiesUtil::has_community(user_id, &locator.scope_key) {
                Ok(true) => Ok(()),
                Ok(false) => Err(CommunicationType::ErrorInvalidData),
                Err(error) => {
                    internal_handler_error(cv, "settings.validate_community", error);
                    Err(CommunicationType::ErrorInternal)
                }
            }
        }
    }
}

pub(super) fn setting_mutation_error(
    cv: &CommunicationValue,
    error_type: CommunicationType,
) -> SettingMutation {
    SettingMutation {
        response: error_response(cv, error_type),
        changed: None,
    }
}

pub fn handle_synced_setting_set(cv: &CommunicationValue) -> SettingMutation {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return setting_mutation_error(cv, CommunicationType::ErrorInvalidData),
    };
    let locator = match parse_setting_locator(cv) {
        Ok(locator) => locator,
        Err(response) => {
            return SettingMutation {
                response,
                changed: None,
            };
        }
    };
    if let Err(error_type) = validate_setting_target(cv, user_id, &locator) {
        return setting_mutation_error(cv, error_type);
    }
    let Some(payload) = cv.get_data(DataType::Payload).as_str() else {
        return setting_mutation_error(cv, CommunicationType::ErrorInvalidData);
    };
    match synced_settings::set(
        user_id,
        locator.scope,
        &locator.scope_key,
        &locator.name,
        payload,
    ) {
        Ok(setting) => SettingMutation {
            response: setting_response(cv, CommunicationType::SyncedSettingSet, &setting),
            changed: Some(setting_changed(&setting)),
        },
        Err(error) => SettingMutation {
            response: internal_handler_error(cv, "settings.set", error),
            changed: None,
        },
    }
}

pub fn handle_synced_setting_get(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    let locator = match parse_setting_locator(cv) {
        Ok(locator) => locator,
        Err(response) => return response,
    };
    if let Err(error_type) = validate_setting_target(cv, user_id, &locator) {
        return error_response(cv, error_type);
    }
    match synced_settings::get(user_id, locator.scope, &locator.scope_key, &locator.name) {
        Ok(Some(setting)) => setting_response(cv, CommunicationType::SyncedSettingGet, &setting),
        Ok(None) => error_response(cv, CommunicationType::ErrorNotFound),
        Err(error) => internal_handler_error(cv, "settings.get", error),
    }
}

pub fn handle_synced_setting_delete(cv: &CommunicationValue) -> SettingMutation {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return setting_mutation_error(cv, CommunicationType::ErrorInvalidData),
    };
    let locator = match parse_setting_locator(cv) {
        Ok(locator) => locator,
        Err(response) => {
            return SettingMutation {
                response,
                changed: None,
            };
        }
    };
    if let Err(error_type) = validate_setting_target(cv, user_id, &locator) {
        return setting_mutation_error(cv, error_type);
    }
    match synced_settings::delete(user_id, locator.scope, &locator.scope_key, &locator.name) {
        Ok(Some(deleted)) => SettingMutation {
            response: CommunicationValue::new(CommunicationType::SyncedSettingDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(
                    DataType::SettingId,
                    DataValue::SignedNumber(deleted.id.into()),
                )
                .add_typed_default(
                    DataType::VersionNumber,
                    DataValue::SignedNumber(deleted.revision.into()),
                ),
            changed: deleted.changed.then(|| setting_deleted(user_id, &deleted)),
        },
        Ok(None) => SettingMutation {
            response: CommunicationValue::new(CommunicationType::SyncedSettingDelete)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id)),
            changed: None,
        },
        Err(error) => SettingMutation {
            response: internal_handler_error(cv, "settings.delete", error),
            changed: None,
        },
    }
}

pub fn handle_synced_settings_list(cv: &CommunicationValue) -> CommunicationValue {
    let user_id = match required_sender_id(cv) {
        Ok(user_id) if user_id > 0 => user_id,
        _ => return error_response(cv, CommunicationType::ErrorInvalidData),
    };
    match synced_settings::list(user_id) {
        Ok(settings) => {
            let Ok(values) = settings
                .iter()
                .map(|setting| {
                    synced_setting_value(
                        setting,
                        cv.type_map().unwrap_or(&mtp::codec::TypeMap::latest()),
                    )
                })
                .collect::<Result<Vec<_>, _>>()
            else {
                return error_response(cv, CommunicationType::ErrorInvalidData);
            };
            CommunicationValue::new(CommunicationType::SyncedSettingsList)
                .with_request_id(cv)
                .with_receiver(sender_wire_id(user_id))
                .add_typed_default(DataType::Settings, DataValue::Array(values))
        }
        Err(error) => internal_handler_error(cv, "settings.list", error),
    }
}
