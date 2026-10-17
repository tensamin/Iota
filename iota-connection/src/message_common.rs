use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::type_map::TypeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub use iota_util::mtp_compat::{MtpFieldError, OptionalDataValueExt, RequiredCommunicationFields};

pub use tau::{CommunicationResponseExt, data_i64, data_string};

/// Handler requests must carry the map negotiated by their transport.
pub fn error_response(request: &CommunicationValue, kind: CommunicationType) -> CommunicationValue {
    let type_map = request
        .type_map()
        .expect("handler request has a negotiated type map");
    tau::error_response(request, kind, type_map)
}

/// Encode nested values for handlers that explicitly emit the latest protocol.
/// Negotiated-map encoding uses tau::typed_container with its explicit map.
pub fn typed_container(
    items: Vec<(DataType, DataValue)>,
) -> Result<DataValue, tau::ProtocolValueError> {
    tau::typed_container(&TypeMap::latest(), items)
}

#[derive(Debug, Clone)]
pub struct ChatSecretRecipient {
    pub user_id: String,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

pub fn recipient_from_value(value: &DataValue, type_map: &TypeMap) -> Option<ChatSecretRecipient> {
    let user_id = value
        .get_field(DataType::UserId.try_to_id(type_map)?)?
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .get_field(DataType::UserId.try_to_id(type_map)?)?
                .as_number()
                .map(|n| n.to_string())
        })?;
    let encrypted_secret = value
        .get_field(DataType::EncryptedSecret.try_to_id(type_map)?)?
        .as_bytes()?;
    let kem_ciphertext = value
        .get_field(DataType::KemCiphertext.try_to_id(type_map)?)?
        .as_bytes()?;

    Some(ChatSecretRecipient {
        user_id,
        encrypted_secret,
        kem_ciphertext,
    })
}

pub fn chat_secret_recipients(cv: &CommunicationValue) -> Option<Vec<ChatSecretRecipient>> {
    let type_map = cv.type_map()?;
    let recipients = cv
        .payload()
        .get_field(DataType::Recipients.try_to_id(type_map)?)?
        .as_array()?;
    let parsed = recipients
        .iter()
        .map(|value| recipient_from_value(value, type_map))
        .collect::<Option<Vec<_>>>()?;

    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

pub fn now_millis_i64() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::error_response;
    use mtp::codec::{CommunicationType, CommunicationValue};

    #[test]
    fn error_response_preserves_an_absent_request_id() {
        let request = CommunicationValue::new(CommunicationType::GetChats)
            .without_id()
            .with_sender(42);
        let response = error_response(&request, CommunicationType::ErrorInvalidData);

        assert_eq!(response.id(), None);
        assert_eq!(response.receiver(), Some(42));
    }

    #[test]
    fn error_response_copies_an_existing_request_id() {
        let request = CommunicationValue::new(CommunicationType::GetChats)
            .with_id(7)
            .with_sender(42);
        let response = error_response(&request, CommunicationType::ErrorInvalidData);

        assert_eq!(response.id(), Some(7));
        assert_eq!(response.receiver(), Some(42));
    }
}
