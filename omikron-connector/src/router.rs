use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use iota_identity::AuthorityId;
use iota_util::mtp_compat::OptionalDataValueExt;
use iota_util::route_target::RouteTarget;
use mtp::codec::{CommunicationType, CommunicationValue, DataType};
use std::sync::Arc;
use std::time::Duration;

use crate::OmikronClient;

pub struct OmikronPeerRouter {
    client: Arc<dyn OmikronClient>,
    authority: AuthorityId,
}

impl OmikronPeerRouter {
    pub fn new(client: Arc<dyn OmikronClient>, authority: AuthorityId) -> Self {
        Self { client, authority }
    }
}

#[async_trait]
impl PeerRouter for OmikronPeerRouter {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let (omega, iota_id) = match destination {
            RouteDestination::LegacyOmegaIota { omega, iota_id } => (omega, *iota_id),
            RouteDestination::Iota(node) => return Err(RouteError::NoRoute(node.clone())),
        };
        if omega != &self.authority {
            return Ok(RouteOutcome::Retryable {
                reason: "legacy Omega route belongs to another authority".into(),
            });
        }
        if frame.receiver() != RouteTarget::Iota(iota_id).wire_id() {
            return Err(RouteError::Delivery(
                "relay frame receiver does not match its route destination".into(),
            ));
        }
        let response = self
            .client
            .await_response(&frame, Duration::from_secs(20))
            .await
            .map_err(|error| RouteError::Delivery(error.to_string()))?;
        if response.is_type(CommunicationType::Success) {
            let relay_message_id = response
                .get_data(DataType::RelayMessageId)
                .as_str()
                .ok_or_else(|| {
                    RouteError::Delivery("relay acceptance omitted its message ID".into())
                })?
                .to_owned();
            let destination_accepted_at = response
                .get_data(DataType::RelayAcceptedAt)
                .as_number()
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| {
                    RouteError::Delivery("relay acceptance omitted its timestamp".into())
                })?;
            Ok(RouteOutcome::Accepted {
                relay_message_id,
                destination_accepted_at,
            })
        } else {
            Ok(RouteOutcome::Rejected {
                response_type: response
                    .get_comm_type_enum()
                    .unwrap_or(CommunicationType::ErrorInternal),
            })
        }
    }
}
