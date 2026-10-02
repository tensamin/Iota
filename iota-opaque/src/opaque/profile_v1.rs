use generic_array::{ArrayLength, GenericArray};
use opaque_ke::{CipherSuite, Ristretto255, TripleDh, ksf::Ksf};

pub struct OpaqueProfileV1;

impl OpaqueProfileV1 {
    pub const ID: i64 = 1;
    pub const SERVER_ID_DOMAIN: &'static [u8] = b"tensamin:iota-password\0";
    pub const LOGIN_CONTEXT_DOMAIN: &'static [u8] = b"tensamin:password-provisioning\0";
}

pub const CURRENT_OPAQUE_PROFILE: i64 = OpaqueProfileV1::ID;

/// Persistent profile-1 parameters. Changes require a new profile ID.
pub struct PasswordKsfV1(argon2::Argon2<'static>);

impl Default for PasswordKsfV1 {
    fn default() -> Self {
        let params = argon2::Params::new(19 * 1024, 2, 1, None)
            .expect("PasswordKsfV1 parameters must be valid");
        Self(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

impl Ksf for PasswordKsfV1 {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        let mut output = GenericArray::<u8, L>::default();
        self.0
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;
        Ok(output)
    }
}

impl CipherSuite for OpaqueProfileV1 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = PasswordKsfV1;
}
