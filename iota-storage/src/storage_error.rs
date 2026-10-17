use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("invalid relay application payload: {0}")]
    InvalidRelayPayload(&'static str),
    #[error("unsupported relay application operation")]
    UnsupportedRelayOperation,
    #[error("relay dependency is missing")]
    MissingRelayDependency,
    #[error("relay storage owner is no longer eligible for application")]
    RelayOwnerUnavailable,
    #[error("hosted authorization is missing, disabled, or stale")]
    HostedAuthorizationDenied,
    #[error("hosted authentication generation is exhausted")]
    HostedGenerationExhausted,
    #[error("Database error: {0}")]
    Db(rusqlite::Error),
    #[error("Connection pool error: {0}")]
    Pool(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message has reached the unique reaction limit")]
    ReactionLimitReached,
    #[error("message signer is not authorized for this operation")]
    MessageUnauthorized,
    #[error("immutable pending relay conflict")]
    PendingRelayConflict,
    #[error("revision conflict")]
    RevisionConflict,
    #[error("pending relay ownership is unknown")]
    PendingRelayOwnershipUnknown,
    #[error("pending client relay acknowledgement is ambiguous")]
    AmbiguousRelayDelivery,
    #[error("unknown relay state: {0}")]
    UnknownRelayState(String),
    #[error("invalid relay state transition")]
    InvalidRelayTransition,
    #[error("stale relay processing claim")]
    StaleRelayClaim,
    #[error("relay processing generation is exhausted")]
    RelayGenerationExhausted,
    #[error("immutable chat secret version conflict")]
    ChatSecretConflict,
    #[error("chat secret version is out of sequence")]
    ChatSecretSequence,
    #[error("asset resource limit: {0}")]
    AssetResourceLimit(&'static str),
    #[error("{0}")]
    Other(String),
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        match &error {
            rusqlite::Error::SqliteFailure(_, Some(message))
                if message == "hosted auth generation exhausted" =>
            {
                Self::HostedGenerationExhausted
            }
            rusqlite::Error::SqliteFailure(_, Some(message))
                if message == "missing hosted auth state" =>
            {
                Self::HostedAuthorizationDenied
            }
            _ => Self::Db(error),
        }
    }
}
