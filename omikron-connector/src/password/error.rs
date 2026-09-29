#[derive(Debug, thiserror::Error)]
pub(super) enum PasswordFinishError {
    #[error("authentication failed")]
    Authentication,
    #[error("invalid password protocol message")]
    InvalidClientMessage,
    #[error("OPAQUE session binding mismatch")]
    BindingMismatch,
    #[error("password credential changed during login")]
    CredentialChanged,
    #[error("credential unavailable")]
    CredentialUnavailable,
    #[error("password storage unavailable")]
    Storage,
    #[error("Iota keyring unavailable")]
    NodeUnavailable,
}

impl PasswordFinishError {
    pub(super) fn counts_as_guess(&self) -> bool {
        matches!(
            self,
            Self::Authentication | Self::InvalidClientMessage | Self::BindingMismatch
        )
    }
}
