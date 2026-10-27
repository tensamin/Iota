#[derive(Debug, thiserror::Error)]
pub(super) enum PasswordFinishError {
    #[error("{0}")]
    Identity(tau::password::Failure),
    #[error("password exchange expired")]
    Expired,
    #[error("password processing timed out")]
    ProcessingTimeout,
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
    pub(super) fn failure(&self) -> tau::password::Failure {
        use tau::password::Failure;
        match self {
            Self::Identity(failure) => *failure,
            Self::Expired => Failure::Expired,
            Self::ProcessingTimeout => Failure::DependencyUnavailable,
            Self::Authentication => Failure::Unauthorized,
            Self::InvalidClientMessage | Self::BindingMismatch => Failure::InvalidRequest,
            Self::CredentialChanged => Failure::Conflict,
            Self::CredentialUnavailable | Self::Storage | Self::NodeUnavailable => {
                Failure::DependencyUnavailable
            }
        }
    }

    pub(super) fn counts_as_guess(&self) -> bool {
        matches!(
            self,
            Self::Authentication
                | Self::InvalidClientMessage
                | Self::BindingMismatch
                | Self::Expired
        )
    }
}
