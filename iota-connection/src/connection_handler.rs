use async_trait::async_trait;
use iota_identity::{AuthorityId, IotaNodeId};
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
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

impl RouteOutcome {
    /// A transport response may settle only the immutable operation sent on it.
    pub fn from_relay_response(
        request: &CommunicationValue,
        response: CommunicationValue,
    ) -> Result<Self, RouteError> {
        let Some(DataValue::Bytes(payload)) = request.get_data(DataType::SecurePayload) else {
            return Err(RouteError::Delivery("missing signed relay request".into()));
        };
        let wire = tau_relay_protocol::RelayWire::from_json(payload)
            .map_err(|_| RouteError::Delivery("invalid signed relay request".into()))?;
        let matching_identity = request.id().is_some()
            && response.id() == request.id()
            && response.get_data(DataType::RelayMessageId).as_str()
                == Some(wire.message_id.as_str())
            && matches!(response.get_data(DataType::SecurePayload), Some(DataValue::Bytes(actual)) if actual == &relay_response_identity(&wire)?);
        let status = response.get_data(DataType::Status).as_str();
        if response.is_type(CommunicationType::Success) {
            if !matching_identity || !matches!(status, Some("accepted" | "already_accepted")) {
                return Err(RouteError::Delivery(
                    "unrelated or malformed relay acceptance".into(),
                ));
            }
            let accepted_at = response
                .get_data(DataType::RelayAcceptedAt)
                .as_number()
                .and_then(|value| i64::try_from(value).ok())
                .filter(|value| *value >= 0)
                .ok_or_else(|| {
                    RouteError::Delivery("relay acceptance omitted its timestamp".into())
                })?;
            return Ok(Self::Accepted {
                relay_message_id: wire.message_id,
                destination_accepted_at: accepted_at,
            });
        }
        if matching_identity
            && status == Some("rejected")
            && let Some(
                response_type @ (CommunicationType::ErrorInvalidData
                | CommunicationType::ErrorNotAuthenticated),
            ) = response.get_comm_type_enum()
        {
            return Ok(Self::Rejected { response_type });
        }
        Ok(Self::Retryable {
            reason: format!(
                "relay response is not a permanent rejection: {:?}",
                response.get_comm_type_enum()
            ),
        })
    }
}

fn relay_response_identity(wire: &tau_relay_protocol::RelayWire) -> Result<Vec<u8>, RouteError> {
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        signer: &'a tau_relay_protocol::Principal,
        recipient: &'a tau_relay_protocol::Principal,
        destination: &'a str,
        message_id: &'a str,
    }
    // Compare this fixed canonical encoding directly. Untrusted responses need no JSON allocation.
    serde_json::to_vec(&Identity {
        signer: &wire.signer,
        recipient: &wire.recipient,
        destination: &wire.destination,
        message_id: &wire.message_id,
    })
    .map_err(|_| RouteError::Delivery("cannot encode relay response identity".into()))
}

/// Terminal replies bind to canonical principals and node, never a transport ID or local handle.
pub fn bind_relay_response_identity(
    request: &CommunicationValue,
    response: CommunicationValue,
) -> Result<CommunicationValue, RouteError> {
    let Some(DataValue::Bytes(payload)) = request.get_data(DataType::SecurePayload) else {
        return Err(RouteError::Delivery("missing signed relay request".into()));
    };
    let wire = tau_relay_protocol::RelayWire::from_json(payload)
        .map_err(|_| RouteError::Delivery("invalid signed relay request".into()))?;
    Ok(response.add_typed_default(
        DataType::SecurePayload,
        DataValue::Bytes(relay_response_identity(&wire)?),
    ))
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
