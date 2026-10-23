use super::{handle_synced_setting_get, handle_synced_setting_set, parse_setting_locator};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

fn request() -> CommunicationValue {
    CommunicationValue::new(CommunicationType::SyncedSettingSet)
        .with_id(1)
        .with_sender(7)
        .add_typed_default(DataType::SettingScope, DataValue::Str("user".to_string()))
        .add_typed_default(DataType::SettingTarget, DataValue::Str(String::new()))
        .add_typed_default(
            DataType::SettingsName,
            DataValue::Str("notifications.enabled".to_string()),
        )
}

#[test]
fn missing_sender_is_rejected_for_synced_settings() {
    let response = handle_synced_setting_get(&request().without_sender());

    assert!(response.is_type(CommunicationType::ErrorInvalidData));
    assert_eq!(response.id(), Some(1));
    assert_eq!(response.receiver(), None);
}

#[test]
fn user_scope_rejects_a_non_empty_target() {
    let request =
        request().add_typed_default(DataType::SettingTarget, DataValue::Str("123".to_string()));

    let response = handle_synced_setting_set(&request).response;

    assert!(response.is_type(CommunicationType::ErrorInvalidData));
}

#[test]
fn contact_scope_rejects_a_malformed_target() {
    let request = request()
        .add_typed_default(
            DataType::SettingScope,
            DataValue::Str("contact".to_string()),
        )
        .add_typed_default(
            DataType::SettingTarget,
            DataValue::Str("not-a-user".to_string()),
        );

    let response = handle_synced_setting_set(&request).response;

    assert!(response.is_type(CommunicationType::ErrorInvalidData));
}

#[test]
fn community_scope_requires_an_address() {
    let request = request()
        .add_typed_default(
            DataType::SettingScope,
            DataValue::Str("community".to_string()),
        )
        .add_typed_default(DataType::SettingTarget, DataValue::Str(String::new()));

    let response = handle_synced_setting_set(&request).response;

    assert!(response.is_type(CommunicationType::ErrorInvalidData));
}

#[test]
fn invalid_setting_name_is_rejected() {
    let request = request().add_typed_default(
        DataType::SettingsName,
        DataValue::Str("notifications..enabled".to_string()),
    );

    let response = parse_setting_locator(&request);

    assert!(response.is_err());
}
