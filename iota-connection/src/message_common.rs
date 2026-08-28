use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::type_map::TypeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub use iota_util::mtp_compat::{MtpFieldError, OptionalDataValueExt, RequiredCommunicationFields};

pub trait CommunicationResponseExt {
    fn with_request_id(self, request: &CommunicationValue) -> Self;
}

impl CommunicationResponseExt for CommunicationValue {
    fn with_request_id(mut self, request: &CommunicationValue) -> Self {
        self = self.without_id();
        if let Some(id) = request.id() {
            self = self.with_id(id);
        }
        self
    }
}

pub fn typed_container(items: Vec<(DataType, DataValue)>) -> DataValue {
    use mtp::type_map::{DataTypeId, TypeMap};
    let tm = TypeMap::latest();
    DataValue::Container(
        items
            .into_iter()
            .filter_map(|(dt, dv)| tm.data_id_enum(dt).map(|id| (DataTypeId(id), dv)))
            .collect(),
    )
}

pub fn data_string(cv: &CommunicationValue, dt: DataType) -> Option<String> {
    cv.get_data(dt)
        .and_then(DataValue::as_str)
        .map(|s| s.to_string())
        .or_else(|| {
            cv.get_data(dt)
                .and_then(DataValue::as_number)
                .map(|n| n.to_string())
        })
        .or_else(|| {
            cv.get_data(dt)
                .and_then(DataValue::as_signed_number)
                .map(|n| n.to_string())
        })
}

pub fn data_i64(cv: &CommunicationValue, dt: DataType) -> Option<i64> {
    cv.get_data(dt)
        .and_then(DataValue::as_number)
        .and_then(|n| i64::try_from(n).ok())
        .or_else(|| {
            cv.get_data(dt)
                .and_then(DataValue::as_signed_number)
                .and_then(|n| i64::try_from(n).ok())
        })
        .or_else(|| {
            cv.get_data(dt)
                .and_then(DataValue::as_str)
                .and_then(|s| s.parse::<i64>().ok())
        })
}

#[derive(Debug, Clone)]
pub struct ChatSecretRecipient {
    pub user_id: String,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

pub fn recipient_from_value(value: &DataValue) -> Option<ChatSecretRecipient> {
    let tm = TypeMap::latest();
    let user_id = value
        .get_field(DataType::UserId.try_to_id(&tm)?)?
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .get_field(DataType::UserId.try_to_id(&tm)?)?
                .as_number()
                .map(|n| n.to_string())
        })?;
    let encrypted_secret = value
        .get_field(DataType::EncryptedSecret.try_to_id(&tm)?)?
        .as_bytes()?;
    let kem_ciphertext = value
        .get_field(DataType::KemCiphertext.try_to_id(&tm)?)?
        .as_bytes()?;

    Some(ChatSecretRecipient {
        user_id,
        encrypted_secret,
        kem_ciphertext,
    })
}

pub fn chat_secret_recipients(cv: &CommunicationValue) -> Option<Vec<ChatSecretRecipient>> {
    let recipients = cv.get_data(DataType::Recipients)?.as_array()?;
    let parsed = recipients
        .iter()
        .map(recipient_from_value)
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

pub fn error_response(request: &CommunicationValue, ty: CommunicationType) -> CommunicationValue {
    let mut response = CommunicationValue::new(ty).without_id();
    if let Some(id) = request.id() {
        response = response.with_id(id);
    }
    if let Some(sender) = request.sender() {
        response = response.with_receiver(sender);
    }
    response
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
