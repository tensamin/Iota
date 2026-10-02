#[derive(Debug, thiserror::Error)]
pub enum OpaqueIntegrationError {
    #[error("invalid OPAQUE exchange: {0}")]
    Opaque(String),
    #[error("OPAQUE context field is too large")]
    FieldTooLarge,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginFinishError {
    #[error("invalid OPAQUE finalization message")]
    InvalidMessage,
    #[error("OPAQUE authentication failed")]
    AuthenticationFailed,
}
