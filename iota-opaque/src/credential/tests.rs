use super::*;
use crate::opaque::OpaqueExportKey;

#[test]
fn envelope_authenticates_key_identity_nonce_and_ciphertext() {
    let key = OpaqueExportKey::new(vec![0x77; 64]);
    let wrong_key = OpaqueExportKey::new(vec![0x88; 64]);
    let binding = CredentialBindingV1 {
        principal: "omega-key:example#7",
        iota_id: 11,
        account_public_key_sha256: &[0x11; 32],
    };
    let plaintext = b"canonical credential bytes\0";
    let envelope = encrypt(&key, &binding, plaintext).unwrap();
    assert_eq!(
        decrypt(&key, &binding, &envelope).unwrap().as_slice(),
        plaintext
    );
    assert_ne!(envelope, encrypt(&key, &binding, plaintext).unwrap());
    assert!(matches!(
        decrypt(&wrong_key, &binding, &envelope),
        Err(CredentialError::Authentication)
    ));
    for changed in [
        CredentialBindingV1 {
            principal: "omega-key:example#8",
            ..binding
        },
        CredentialBindingV1 {
            iota_id: 12,
            ..binding
        },
        CredentialBindingV1 {
            account_public_key_sha256: &[0x22; 32],
            ..binding
        },
    ] {
        assert!(matches!(
            decrypt(&key, &changed, &envelope),
            Err(CredentialError::Authentication)
        ));
    }
    for offset in [10, 34, envelope.len() - 1] {
        let mut changed = envelope.clone();
        changed[offset] ^= 1;
        assert!(matches!(
            decrypt(&key, &binding, &changed),
            Err(CredentialError::Authentication)
        ));
    }
    for length in 0..50 {
        assert!(matches!(
            decrypt(&key, &binding, &envelope[..length]),
            Err(CredentialError::InvalidEnvelope)
        ));
    }
    let mut changed = envelope.clone();
    changed[0] ^= 1;
    assert!(matches!(
        decrypt(&key, &binding, &changed),
        Err(CredentialError::InvalidEnvelope)
    ));
    changed = envelope.clone();
    changed[9] = 2;
    assert!(matches!(
        decrypt(&key, &binding, &changed),
        Err(CredentialError::UnsupportedVersion(2))
    ));
    let empty = encrypt(&key, &binding, b"").unwrap();
    assert!(decrypt(&key, &binding, &empty).unwrap().is_empty());
}
