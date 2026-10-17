#[allow(dead_code, reason = "fixtures are shared with other relay tests")]
mod relay_support;

use iota_connection::connection_handler::{RouteOutcome, bind_relay_response_identity};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::Keyring;
use relay_support::*;

#[tokio::test]
async fn terminal_responses_bind_canonical_signer_recipient_and_node() {
    let directory = tempfile_directory();
    initialize(&directory);
    let fixture = Fixture::new(true);
    let request = fixture.frame(0, "shared-message-id", send(10));
    let accepted = CommunicationValue::new(CommunicationType::Success)
        .with_id(request.id().unwrap())
        .add_typed_default(
            DataType::RelayMessageId,
            DataValue::Str("shared-message-id".into()),
        )
        .add_typed_default(DataType::Status, DataValue::Str("accepted".into()))
        .add_typed_default(DataType::RelayAcceptedAt, DataValue::SignedNumber(1));
    let matching = bind_relay_response_identity(&request, accepted.clone()).unwrap();
    assert!(matches!(
        RouteOutcome::from_relay_response(&request, matching),
        Ok(RouteOutcome::Accepted { .. })
    ));

    let other_signer = fixture.frame(1, "shared-message-id", send(10));
    let Some(DataValue::Bytes(bytes)) = request.get_data(DataType::SecurePayload) else {
        panic!("missing payload");
    };
    let wire = tau_relay_protocol::RelayWire::from_json(bytes).unwrap();
    let mut other_recipient = wire.clone();
    other_recipient.recipient.user_id += 1;
    let mut other_node = wire;
    other_node.destination =
        iota_identity::IotaNodeId::from_public_keys(&Keyring::generate().public_key_bundle())
            .unwrap()
            .as_str()
            .to_owned();
    let other_recipient = request.clone().add_typed_default(
        DataType::SecurePayload,
        DataValue::Bytes(serde_json::to_vec(&other_recipient).unwrap()),
    );
    let other_node = request.clone().add_typed_default(
        DataType::SecurePayload,
        DataValue::Bytes(serde_json::to_vec(&other_node).unwrap()),
    );
    for unrelated in [other_signer, other_recipient, other_node] {
        let reply = bind_relay_response_identity(&unrelated, accepted.clone()).unwrap();
        assert!(RouteOutcome::from_relay_response(&request, reply).is_err());
        let rejection = CommunicationValue::new(CommunicationType::ErrorInvalidData)
            .with_id(request.id().unwrap())
            .add_typed_default(
                DataType::RelayMessageId,
                DataValue::Str("shared-message-id".into()),
            )
            .add_typed_default(DataType::Status, DataValue::Str("rejected".into()));
        let rejection = bind_relay_response_identity(&unrelated, rejection).unwrap();
        assert!(matches!(
            RouteOutcome::from_relay_response(&request, rejection),
            Ok(RouteOutcome::Retryable { .. })
        ));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

fn tempfile_directory() -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("relay-response-binding-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).unwrap();
    path
}
