mod aad;
mod error;
mod kdf;
mod v1;

pub use aad::CredentialBindingV1;
pub use error::CredentialError;
pub use v1::{decrypt, encrypt, validate_envelope};

#[cfg(test)]
mod tests;
