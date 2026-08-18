use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::crypto::{
    EncryptionType, Keyring, MultiEncryptedMessage, PublicKeyBundle, decrypt_multi_for,
    encrypt_multi_for,
};

const CHALLENGE_PURPOSE: u8 = 0x01;
const LEGACY_AAD_DOMAIN: &[u8] = b"IOTA-MTP-AAD-1";

fn bind_aad(plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let aad_len = u32::try_from(aad.len())
        .map_err(|_| "associated data is too large to encode".to_string())?;
    let mut bound = Vec::with_capacity(
        LEGACY_AAD_DOMAIN
            .len()
            .saturating_add(4)
            .saturating_add(aad.len())
            .saturating_add(plaintext.len()),
    );
    bound.extend_from_slice(LEGACY_AAD_DOMAIN);
    bound.extend_from_slice(&aad_len.to_be_bytes());
    bound.extend_from_slice(aad);
    bound.extend_from_slice(plaintext);
    Ok(bound)
}

fn unbind_aad(bound: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let header_len = LEGACY_AAD_DOMAIN.len() + 4;
    if bound.len() < header_len || &bound[..LEGACY_AAD_DOMAIN.len()] != LEGACY_AAD_DOMAIN {
        return Err("associated-data binding is invalid".to_string());
    }
    let length_start = LEGACY_AAD_DOMAIN.len();
    let length_end = length_start + 4;
    let aad_len = u32::from_be_bytes(
        bound[length_start..length_end]
            .try_into()
            .map_err(|_| "associated-data length is invalid".to_string())?,
    ) as usize;
    let aad_start = length_end;
    let aad_end = aad_start
        .checked_add(aad_len)
        .ok_or_else(|| "associated-data length overflows".to_string())?;
    if aad_end > bound.len() || &bound[aad_start..aad_end] != aad {
        return Err("associated data does not match".to_string());
    }
    Ok(bound[aad_end..].to_vec())
}

#[derive(Clone, Copy, Debug)]
pub enum DataFormat {
    Raw,
    Base64,
    Hex,
}

pub fn encrypt(
    plaintext: &[u8],
    aad: &[u8],
    recipient_pub_key_bundle: &PublicKeyBundle,
) -> Result<Vec<u8>, String> {
    let bound_plaintext = bind_aad(plaintext, aad)?;
    let encrypted = encrypt_multi_for(
        EncryptionType::MlKemChaCha20Poly1305,
        CHALLENGE_PURPOSE,
        &bound_plaintext,
        std::slice::from_ref(recipient_pub_key_bundle),
    )
    .map_err(|e| format!("encryption error: {e:?}"))?;
    encrypted
        .to_bytes()
        .map_err(|e| format!("encryption encoding error: {e:?}"))
}

pub fn decrypt(ciphertext: &[u8], aad: &[u8], keyring: &Keyring) -> Result<Vec<u8>, String> {
    let message = MultiEncryptedMessage::from_bytes(ciphertext)
        .map_err(|e| format!("decryption envelope error: {e:?}"))?;
    let bound_plaintext = decrypt_multi_for(&message, CHALLENGE_PURPOSE, keyring)
        .map_err(|e| format!("decryption error: {e:?}"))?;
    unbind_aad(&bound_plaintext, aad)
}

pub fn encrypt_challenge(
    challenge: &str,
    recipient_pub_key_bundle: &PublicKeyBundle,
) -> Result<String, String> {
    let blob = encrypt(challenge.as_bytes(), b"challenge", recipient_pub_key_bundle)?;
    Ok(STANDARD.encode(&blob))
}

pub fn decrypt_challenge(encrypted: &str, keyring: &Keyring) -> Result<String, String> {
    let blob = STANDARD
        .decode(encrypted)
        .map_err(|e| format!("base64 decode error: {}", e))?;
    let pt = decrypt(&blob, b"challenge", keyring)?;
    String::from_utf8(pt).map_err(|e| format!("utf8 decode error: {}", e))
}

pub fn export(data: &[u8], format: DataFormat) -> Result<String, String> {
    match format {
        DataFormat::Raw => {
            String::from_utf8(data.to_vec()).map_err(|error| format!("utf8 decode error: {error}"))
        }
        DataFormat::Base64 => Ok(STANDARD.encode(data)),
        DataFormat::Hex => Ok(hex::encode(data)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_binds_associated_data() -> Result<(), String> {
        let keyring = Keyring::generate();
        let ciphertext = encrypt(b"challenge", b"context", &keyring.public_key_bundle())?;

        assert_eq!(decrypt(&ciphertext, b"context", &keyring)?, b"challenge");
        assert!(decrypt(&ciphertext, b"other-context", &keyring).is_err());
        Ok(())
    }
}
