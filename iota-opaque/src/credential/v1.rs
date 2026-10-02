use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::{
    CredentialBindingV1, CredentialError, aad::associated_data, kdf::derive_credential_key,
};
use crate::opaque::OpaqueExportKey;

const MAGIC: &[u8; 8] = b"TSCRED\0\0";
pub(super) const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 24;
const TAG_LEN: usize = 16;

pub fn encrypt(
    export_key: &OpaqueExportKey,
    binding: &CredentialBindingV1<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, CredentialError> {
    let key = derive_credential_key(export_key)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| CredentialError::Encryption)?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = associated_data(binding)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CredentialError::Encryption)?;
    let mut envelope = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&VERSION.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Checks framing and version only. Ciphertext authentication requires the client's export key.
pub fn validate_envelope(envelope: &[u8]) -> Result<(), CredentialError> {
    if envelope.len() < 10 || &envelope[..8] != MAGIC {
        return Err(CredentialError::InvalidEnvelope);
    }
    let version = u16::from_be_bytes([envelope[8], envelope[9]]);
    if version != VERSION {
        return Err(CredentialError::UnsupportedVersion(version));
    }
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(CredentialError::InvalidEnvelope);
    }
    Ok(())
}

pub fn decrypt(
    export_key: &OpaqueExportKey,
    binding: &CredentialBindingV1<'_>,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    validate_envelope(envelope)?;
    let key = derive_credential_key(export_key)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| CredentialError::KeyDerivation)?;
    let aad = associated_data(binding)?;
    cipher
        .decrypt(
            XNonce::from_slice(&envelope[10..HEADER_LEN]),
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CredentialError::Authentication)
}
