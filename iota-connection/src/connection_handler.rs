use async_trait::async_trait;
use iota_identity::{AuthorityId, IotaNodeId};
use mtp::codec::{CommunicationType, CommunicationValue};
use std::fmt;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionError {
    Disconnected(String),
    Timeout(String),
    Protocol(String),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected(message) | Self::Timeout(message) | Self::Protocol(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for ConnectionError {}

#[async_trait]
pub trait ConnectionHandler: Send + Sync {
    async fn send_message(&self, value: &CommunicationValue) -> Result<(), ConnectionError>;

    async fn await_response(
        &self,
        value: &CommunicationValue,
        timeout: Option<Duration>,
    ) -> Result<CommunicationValue, ConnectionError>;

    async fn is_connected(&self) -> bool;

    async fn is_identified(&self) -> bool;

    async fn stop(&self);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDestination {
    Iota(IotaNodeId),
    LegacyOmegaIota { omega: AuthorityId, iota_id: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteOutcome {
    Accepted {
        relay_message_id: String,
        destination_accepted_at: i64,
    },
    Rejected {
        response_type: CommunicationType,
    },
    Retryable {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteError {
    NoRoute(IotaNodeId),
    Delivery(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute(destination) => {
                write!(formatter, "no route to Iota {}", destination.as_str())
            }
            Self::Delivery(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for RouteError {}

#[async_trait]
pub trait PeerRouter: Send + Sync {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError>;
}
