#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential field is too large")]
    FieldTooLarge,
    #[error("credential key derivation failed")]
    KeyDerivation,
    #[error("credential encryption failed")]
    Encryption,
    #[error("credential authentication failed")]
    Authentication,
    #[error("invalid encrypted credential")]
    InvalidEnvelope,
    #[error("unsupported encrypted credential version: {0}")]
    UnsupportedVersion(u16),
}
