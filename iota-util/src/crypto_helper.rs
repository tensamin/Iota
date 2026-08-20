use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::crypto::{Keyring, PublicKeyBundle};

pub fn generate_keyring() -> Keyring {
    Keyring::generate()
}

pub fn keyring_to_base64(keyring: &Keyring) -> String {
    let bytes = keyring
        .try_to_bytes()
        .expect("keyring fields must fit the wire format");
    STANDARD.encode(bytes)
}

pub fn keyring_from_base64(s: &str) -> Option<Keyring> {
    let bytes = STANDARD.decode(s).ok()?;
    Keyring::from_bytes(&bytes).ok()
}

pub fn public_key_bundle_to_base64(bundle: &PublicKeyBundle) -> String {
    let bytes = bundle
        .try_as_bytes()
        .expect("public key bundle fields must fit the wire format");
    STANDARD.encode(bytes)
}

pub fn public_key_bundle_from_base64(s: &str) -> Option<PublicKeyBundle> {
    let bytes = STANDARD.decode(s).ok()?;
    PublicKeyBundle::from_bytes(&bytes).ok()
}

pub fn hex_hash(input: &str) -> String {
    hex::encode(mtp::crypto::sha256(input.as_bytes()))
}
