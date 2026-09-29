use std::time::{SystemTime, UNIX_EPOCH};

use mtp::{
    codec::{DataType, DataTypeId, DataValue, TypeMap},
    crypto::PublicKeyBundle,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(super) fn field(content: &DataValue, kind: DataType) -> Result<&DataValue, String> {
    let id = kind
        .try_to_id(&TypeMap::latest())
        .ok_or("unknown data field")?;
    let DataValue::Container(fields) = content else {
        return Err("content is not a container".into());
    };
    fields
        .iter()
        .find_map(|(field_id, value)| (*field_id == id).then_some(value))
        .ok_or_else(|| format!("missing {kind:?}"))
}

pub(super) fn typed(kind: DataType, value: DataValue) -> Result<(DataTypeId, DataValue), String> {
    Ok((
        kind.try_to_id(&TypeMap::latest()).ok_or("unknown field")?,
        value,
    ))
}

pub(super) fn bytes(content: &DataValue, kind: DataType, max: usize) -> Result<Vec<u8>, String> {
    let value = field(content, kind)?
        .as_bytes()
        .ok_or("field is not bytes")?;
    if value.is_empty() || value.len() > max {
        return Err("field exceeds size limits".into());
    }
    Ok(value)
}

pub(super) fn positive(content: &DataValue, kind: DataType) -> Result<i64, String> {
    field(content, kind)?
        .as_number()
        .and_then(|value| i64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("invalid {kind:?}"))
}

pub(super) fn session(content: &DataValue) -> Result<Uuid, String> {
    Uuid::parse_str(
        field(content, DataType::Uuid)?
            .as_str()
            .ok_or("invalid session UUID")?,
    )
    .map_err(|error| error.to_string())
}

pub(super) fn public_key(content: &DataValue) -> Result<PublicKeyBundle, String> {
    let encoded = field(content, DataType::PublicKey)?
        .as_str()
        .ok_or("invalid public key")?;
    if encoded.len() > 16 * 1024 {
        return Err("public key too large".into());
    }
    PublicKeyBundle::from_base64(encoded).map_err(|error| error.to_string())
}

pub(super) fn key_fingerprint(encoded: &str) -> Result<Vec<u8>, String> {
    let bundle = PublicKeyBundle::from_base64(encoded).map_err(|error| error.to_string())?;
    Ok(Sha256::digest(bundle.try_as_bytes().map_err(|error| error.to_string())?).to_vec())
}
