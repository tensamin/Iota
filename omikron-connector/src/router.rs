use async_trait::async_trait;
use iota_connection::connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome};
use mtp::codec::{CommunicationType, CommunicationValue};
use std::sync::Arc;
use std::time::Duration;

use crate::{OmikronClient, OmikronError};

pub struct OmikronPeerRouter {
    client: Arc<dyn OmikronClient>,
}

impl OmikronPeerRouter {
    pub fn new(client: Arc<dyn OmikronClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PeerRouter for OmikronPeerRouter {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let RouteDestination::Iota(node) = destination else {
            return Err(RouteError::Delivery(
                "legacy numeric relay routing is unsupported".into(),
            ));
        };
        let declared = iota_connection::federated_relay::parse_wire(&frame)
            .map_err(|error| RouteError::Delivery(format!("invalid relay envelope: {error}")))?;
        if declared.destination != node.as_str() {
            return Err(RouteError::Delivery(
                "signed relay destination does not match its route target".into(),
            ));
        }
        let response = match self
            .client
            .await_response(&frame, Duration::from_secs(20))
            .await
        {
            Ok(response) => response,
            Err(OmikronError::Rejected(CommunicationType::ErrorInternal, _)) => {
                return Ok(RouteOutcome::Retryable {
                    reason: "destination reported a temporary relay failure".into(),
                });
            }
            Err(OmikronError::Rejected(_, _)) => {
                return Ok(RouteOutcome::Retryable {
                    reason: "relay rejection omitted its immutable acknowledgement fields".into(),
                });
            }
            Err(error) => return Err(RouteError::Delivery(error.to_string())),
        };
        RouteOutcome::from_relay_response(&frame, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OmikronError;
    use iota_connection::{
        connection_handler::bind_relay_response_identity, federated_relay::FederatedRelay,
    };
    use iota_identity::IotaNodeId;
    use iota_identity::{AuthorityId, PrincipalId};
    use mtp::codec::{DataType, DataValue};
    use mtp::crypto::Keyring;
    use std::sync::{Mutex, OnceLock};

    struct MockClient {
        response: CommunicationValue,
        frames: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl OmikronClient for MockClient {
        async fn send_message(&self, _: &CommunicationValue) -> Result<(), OmikronError> {
            unreachable!()
        }

        async fn await_response(
            &self,
            frame: &CommunicationValue,
            timeout: Duration,
        ) -> Result<CommunicationValue, OmikronError> {
            assert_eq!(timeout, Duration::from_secs(20));
            self.frames.lock().unwrap().push(frame.to_bytes().unwrap());
            if !frame.is_type(CommunicationType::Relay)
                && let Some(kind) = self
                    .response
                    .get_comm_type_enum()
                    .filter(|kind| tau::is_protocol_error(*kind))
            {
                // Match the real client's typed protocol error boundary.
                return Err(OmikronError::Rejected(
                    kind,
                    "destination rejected relay".into(),
                ));
            }
            Ok(self.response.clone())
        }

        async fn reconnect(&self) -> Result<(), OmikronError> {
            unreachable!()
        }

        async fn rotate_identity(&self) -> Result<(), OmikronError> {
            unreachable!()
        }

        async fn is_connected(&self) -> bool {
            unreachable!()
        }
    }

    fn router(response: CommunicationValue) -> (OmikronPeerRouter, Arc<MockClient>) {
        let client = Arc::new(MockClient {
            response,
            frames: Mutex::new(Vec::new()),
        });
        let router = OmikronPeerRouter::new(client.clone());
        (router, client)
    }

    fn relay_frame(destination: &IotaNodeId) -> CommunicationValue {
        static KEYS: OnceLock<[Keyring; 2]> = OnceLock::new();
        let keys = KEYS.get_or_init(|| [Keyring::generate(), Keyring::generate()]);
        let frame = FederatedRelay::sign(
            PrincipalId {
                authority: AuthorityId::new("authority:origin").unwrap(),
                user_id: 1,
            },
            PrincipalId {
                authority: AuthorityId::new("authority:recipient").unwrap(),
                user_id: 2,
            },
            destination.clone(),
            "original-message".into(),
            1,
            CommunicationValue::new(CommunicationType::Success),
            &keys[0],
            vec![keys[1].public_key_bundle()],
        )
        .unwrap()
        .into_frame(73)
        .unwrap();
        let Some(DataValue::Bytes(payload)) = frame.get_data(DataType::SecurePayload) else {
            panic!("signed relay payload is missing")
        };
        // Preserve noncanonical whitespace while retaining the authentic signed envelope.
        let wire: serde_json::Value = serde_json::from_slice(payload).unwrap();
        frame.add_typed_default(
            DataType::SecurePayload,
            DataValue::Bytes(serde_json::to_vec_pretty(&wire).unwrap()),
        )
    }

    #[tokio::test]
    async fn matching_canonical_destination_forwards_original_frame_unchanged() {
        let node = IotaNodeId::new(format!("iota:v1:{}", "01".repeat(32))).unwrap();
        let frame = relay_frame(&node);
        let original = frame.to_bytes().unwrap();
        let (router, client) = router(CommunicationValue::new(CommunicationType::ErrorNotFound));

        assert!(matches!(
            router
                .route(&RouteDestination::Iota(node), frame)
                .await
                .unwrap(),
            RouteOutcome::Retryable { .. }
        ));
        assert_eq!(*client.frames.lock().unwrap(), vec![original]);
    }

    #[tokio::test]
    async fn mismatching_canonical_destination_is_rejected_before_forwarding() {
        let declared = IotaNodeId::new(format!("iota:v1:{}", "01".repeat(32))).unwrap();
        let target = IotaNodeId::new(format!("iota:v1:{}", "02".repeat(32))).unwrap();
        let (router, client) = router(CommunicationValue::new(CommunicationType::ErrorInternal));

        assert_eq!(
            router
                .route(&RouteDestination::Iota(target), relay_frame(&declared))
                .await,
            Err(RouteError::Delivery(
                "signed relay destination does not match its route target".into(),
            )),
        );
        assert!(client.frames.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn legacy_omega_iota_is_rejected_before_forwarding() {
        let node = IotaNodeId::new(format!("iota:v1:{}", "01".repeat(32))).unwrap();
        let (router, client) = router(CommunicationValue::new(CommunicationType::ErrorInternal));
        let destination = RouteDestination::LegacyOmegaIota {
            omega: AuthorityId::new("omega:router.example").unwrap(),
            iota_id: 7,
        };

        assert_eq!(
            router.route(&destination, relay_frame(&node)).await,
            Err(RouteError::Delivery(
                "legacy numeric relay routing is unsupported".into()
            )),
        );
        assert!(client.frames.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn error_internal_is_retryable() {
        let node = IotaNodeId::new(format!("iota:v1:{}", "01".repeat(32))).unwrap();
        let (router, client) = router(CommunicationValue::new(CommunicationType::ErrorInternal));

        assert!(matches!(
            router
                .route(&RouteDestination::Iota(node.clone()), relay_frame(&node))
                .await
                .unwrap(),
            RouteOutcome::Retryable { .. }
        ));
        assert_eq!(client.frames.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn success_extracts_ack_identity() {
        let node = IotaNodeId::new(format!("iota:v1:{}", "01".repeat(32))).unwrap();
        let request = relay_frame(&node);
        let response = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(
                DataType::RelayMessageId,
                DataValue::Str("original-message".into()),
            )
            .add_typed_default(
                DataType::RelayAcceptedAt,
                DataValue::SignedNumber(1_700_000_123),
            )
            .add_typed_default(DataType::Status, DataValue::Str("accepted".into()));
        let response =
            bind_relay_response_identity(&request, response.with_id(request.id().unwrap()))
                .unwrap();
        let (router, client) = router(response);

        assert_eq!(
            router
                .route(&RouteDestination::Iota(node), request)
                .await
                .unwrap(),
            RouteOutcome::Accepted {
                relay_message_id: "original-message".into(),
                destination_accepted_at: 1_700_000_123,
            },
        );
        assert_eq!(client.frames.lock().unwrap().len(), 1);
    }
}
