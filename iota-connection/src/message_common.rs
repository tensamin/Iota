use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::type_map::TypeMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| cv.get_data(dt).as_number().map(|n| n.to_string()))
        .or_else(|| cv.get_data(dt).as_signed_number().map(|n| n.to_string()))
}

pub fn data_i64(cv: &CommunicationValue, dt: DataType) -> Option<i64> {
    cv.get_data(dt)
        .as_number()
        .and_then(|n| i64::try_from(n).ok())
        .or_else(|| {
            cv.get_data(dt)
                .as_signed_number()
                .and_then(|n| i64::try_from(n).ok())
        })
        .or_else(|| cv.get_data(dt).as_str().and_then(|s| s.parse::<i64>().ok()))
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
    let recipients = cv.get_data(DataType::Recipients).as_array()?;
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

pub fn set_chat_secret_cv_for_recipient(
    source: &CommunicationValue,
    recipient: &ChatSecretRecipient,
) -> CommunicationValue {
    let recipient_value = typed_container(vec![
        (DataType::UserId, DataValue::Str(recipient.user_id.clone())),
        (
            DataType::EncryptedSecret,
            DataValue::Bytes(recipient.encrypted_secret.clone()),
        ),
        (
            DataType::KemCiphertext,
            DataValue::Bytes(recipient.kem_ciphertext.clone()),
        ),
    ]);

    CommunicationValue::new(CommunicationType::SetChatSecret)
        .with_id(source.get_id())
        .with_sender(source.get_sender())
        .with_receiver(recipient.user_id.parse::<u64>().unwrap_or(0))
        .add_typed_default(DataType::ChatId, source.get_data(DataType::ChatId).clone())
        .add_typed_default(
            DataType::SecretId,
            source.get_data(DataType::SecretId).clone(),
        )
        .add_typed_default(
            DataType::VersionNumber,
            source.get_data(DataType::VersionNumber).clone(),
        )
        .add_typed_default(
            DataType::WrappingScheme,
            source.get_data(DataType::WrappingScheme).clone(),
        )
        .add_typed_default(
            DataType::CreatedAt,
            source.get_data(DataType::CreatedAt).clone(),
        )
        .add_typed_default(
            DataType::Recipients,
            DataValue::Array(vec![recipient_value]),
        )
}

pub fn now_millis_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn error_response(request: &CommunicationValue, ty: CommunicationType) -> CommunicationValue {
    CommunicationValue::new(ty)
        .with_id(request.get_id())
        .with_receiver(request.get_sender())
}
