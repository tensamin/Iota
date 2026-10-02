use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{CredentialError, v1::VERSION};
use crate::opaque::{CURRENT_OPAQUE_PROFILE, OpaqueExportKey};

pub(crate) fn derive_credential_key(
    export_key: &OpaqueExportKey,
) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
    let hkdf = Hkdf::<Sha256>::new(None, export_key.as_bytes());
    let mut info = b"tensamin:opaque-export-key:credential:v1\0".to_vec();
    info.extend_from_slice(&CURRENT_OPAQUE_PROFILE.to_be_bytes());
    info.extend_from_slice(&VERSION.to_be_bytes());
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, &mut *key)
        .map_err(|_| CredentialError::KeyDerivation)?;
    Ok(key)
}
