use async_trait::async_trait;
use mtp::codec::{CommunicationType, CommunicationValue};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OmikronError {
    Disconnected(String),
    Timeout(String),
    Authentication(String),
    Rejected(CommunicationType, String),
    Storage(String),
    Internal(String),
}

impl std::fmt::Display for OmikronError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected(v)
            | Self::Timeout(v)
            | Self::Authentication(v)
            | Self::Rejected(_, v)
            | Self::Storage(v)
            | Self::Internal(v) => f.write_str(v),
        }
    }
}
impl std::error::Error for OmikronError {}

pub enum OmikronStartupError {
    Construction(String),
    InitialConnectionTimeout {
        connection: std::sync::Arc<crate::omikron_connection::OmikronConnection>,
    },
    Authentication {
        connection: std::sync::Arc<crate::omikron_connection::OmikronConnection>,
    },
}

#[async_trait]
pub trait OmikronClient: Send + Sync {
    async fn send_message(&self, value: &CommunicationValue) -> Result<(), OmikronError>;
    async fn await_response(
        &self,
        value: &CommunicationValue,
        timeout: Duration,
    ) -> Result<CommunicationValue, OmikronError>;
    async fn sync_omega_invitations(&self) -> Result<(), OmikronError> {
        Err(OmikronError::Internal(
            "invitation synchronization is unavailable".into(),
        ))
    }
    async fn flush_pending_invitation_actions(&self) {}
    async fn reconnect(&self) -> Result<(), OmikronError>;
    /// Replace the local Iota identity and wait for the new identity to
    /// register/authenticate. This is deliberately available while offline:
    /// it is the recovery operation for an authentication failure.
    async fn rotate_identity(&self) -> Result<(), OmikronError>;
    async fn is_connected(&self) -> bool;
}
