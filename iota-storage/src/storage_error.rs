use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("Connection pool error: {0}")]
    Pool(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message has reached the unique reaction limit")]
    ReactionLimitReached,
    #[error("revision conflict")]
    RevisionConflict,
    #[error("pending relay ownership is unknown")]
    PendingRelayOwnershipUnknown,
    #[error("asset resource limit: {0}")]
    AssetResourceLimit(&'static str),
    #[error("{0}")]
    Other(String),
}
