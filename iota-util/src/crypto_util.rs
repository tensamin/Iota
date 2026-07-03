use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp_crypto::{EncryptionType, Keyring, PublicKeyBundle, encrypt_for, decrypt_with};

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
    encrypt_for(
        EncryptionType::MlKemChaCha20Poly1305,
        recipient_pub_key_bundle,
        plaintext,
        aad,
    )
    .map_err(|e| format!("encryption error: {:?}", e))
}

pub fn decrypt(
    ciphertext: &[u8],
    aad: &[u8],
    keyring: &Keyring,
) -> Result<Vec<u8>, String> {
    decrypt_with(ciphertext, keyring, aad)
        .map_err(|e| format!("decryption error: {:?}", e))
}

pub fn encrypt_challenge(
    challenge: &str,
    recipient_pub_key_bundle: &PublicKeyBundle,
) -> Result<String, String> {
    let blob = encrypt(challenge.as_bytes(), b"challenge", recipient_pub_key_bundle)?;
    Ok(STANDARD.encode(&blob))
}

pub fn decrypt_challenge(
    encrypted: &str,
    keyring: &Keyring,
) -> Result<String, String> {
    let blob =
        STANDARD.decode(encrypted).map_err(|e| format!("base64 decode error: {}", e))?;
    let pt = decrypt(&blob, b"challenge", keyring)?;
    String::from_utf8(pt).map_err(|e| format!("utf8 decode error: {}", e))
}

pub fn export(data: &[u8], format: DataFormat) -> String {
    match format {
        DataFormat::Raw => String::from_utf8_lossy(data).to_string(),
        DataFormat::Base64 => STANDARD.encode(data),
        DataFormat::Hex => hex::encode(data),
    }
}
