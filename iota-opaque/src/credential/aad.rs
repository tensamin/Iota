use super::CredentialError;
use crate::opaque::CURRENT_OPAQUE_PROFILE;

#[derive(Clone, Copy)]
pub struct CredentialBindingV1<'a> {
    pub principal: &'a str,
    pub iota_id: i64,
    pub account_public_key_sha256: &'a [u8; 32],
}

pub(crate) fn associated_data(
    binding: &CredentialBindingV1<'_>,
) -> Result<Vec<u8>, CredentialError> {
    let principal = binding.principal.as_bytes();
    let length = u32::try_from(principal.len()).map_err(|_| CredentialError::FieldTooLarge)?;
    let mut output = b"tensamin:opaque-credential-aad:v1\0".to_vec();
    output.extend_from_slice(&CURRENT_OPAQUE_PROFILE.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(principal);
    output.extend_from_slice(&binding.iota_id.to_be_bytes());
    output.extend_from_slice(binding.account_public_key_sha256);
    Ok(output)
}
