use uuid::Uuid;

use super::{OpaqueIntegrationError, OpaqueProfileV1};

#[derive(Clone, Copy)]
pub struct PasswordLoginBindingV1<'a> {
    pub principal: &'a str,
    pub iota_id: i64,
    pub session_id: Uuid,
    pub contact_key_sha256: &'a [u8; 32],
}

pub fn server_identifier(iota_id: i64) -> Vec<u8> {
    let mut result = OpaqueProfileV1::SERVER_ID_DOMAIN.to_vec();
    result.extend_from_slice(&iota_id.to_be_bytes());
    result
}

pub fn login_context(
    binding: &PasswordLoginBindingV1<'_>,
) -> Result<Vec<u8>, OpaqueIntegrationError> {
    let mut result = OpaqueProfileV1::LOGIN_CONTEXT_DOMAIN.to_vec();
    let principal = binding.principal.as_bytes();
    let length =
        u32::try_from(principal.len()).map_err(|_| OpaqueIntegrationError::FieldTooLarge)?;
    result.extend_from_slice(&length.to_be_bytes());
    result.extend_from_slice(principal);
    result.extend_from_slice(&binding.iota_id.to_be_bytes());
    result.extend_from_slice(binding.session_id.as_bytes());
    result.extend_from_slice(binding.contact_key_sha256);
    Ok(result)
}
