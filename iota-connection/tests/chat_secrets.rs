#[allow(dead_code)]
mod relay_support;

use iota_connection::{
    federated_relay::{protocol, protocol_principal},
    message_handlers::handle_get_chat_secret,
    relay_service::RelayOutcome,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use relay_support::{Fixture, accepted, execute, initialize, secret};

fn proposal(fixture: &Fixture, version: i128, marker: u8) -> CommunicationValue {
    let mut frame = secret(fixture);
    let mut recipients = frame
        .get_data(DataType::Recipients)
        .unwrap()
        .as_array()
        .unwrap();
    for (index, recipient) in recipients.iter_mut().enumerate() {
        let field = DataType::EncryptedSecret
            .try_to_id(frame.type_map().unwrap())
            .unwrap();
        let entry = recipient
            .container_entries_mut()
            .unwrap()
            .iter_mut()
            .find(|(id, _)| *id == field)
            .unwrap();
        entry.1 = DataValue::Bytes(vec![marker, index as u8 + 1]);
    }
    frame.set_data(DataType::Recipients, DataValue::Array(recipients));
    frame.set_data(DataType::VersionNumber, DataValue::SignedNumber(version));
    frame
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_shared_iota_initialization_preserves_identity_versions_and_existing_keys() {
    let storage =
        std::env::temp_dir().join(format!("tensamin-chat-secrets-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&storage).unwrap();
    initialize(&storage);
    let mut fixture = Fixture::new(true);
    let principals = fixture.ids.each_ref().map(protocol_principal);
    let chat_id = protocol::canonical_chat_id(&principals[0], &principals[1]);
    let read = |owner: usize, version: i128| {
        let request = CommunicationValue::new(CommunicationType::GetChatSecret)
            .with_id(1)
            .with_sender(owner as u64 + 1)
            .add_typed_default(
                DataType::UserId,
                DataValue::Str(serde_json::to_string(&fixture.ids[owner]).unwrap()),
            )
            .add_typed_default(DataType::ChatId, DataValue::Str(chat_id.clone()))
            .add_typed_default(
                DataType::SecretId,
                DataValue::Str(protocol::chat_secret_id(&chat_id)),
            )
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(version));
        handle_get_chat_secret(&request)
    };

    // The lower-ID recipient has no connected client when initialization begins.
    let iota_connection::relay_service::IngressSource::HostedClient { mut session } =
        fixture.sources[0].clone()
    else {
        unreachable!()
    };
    iota_storage::hosted_auth::remove(&session.connection_id.to_string()).unwrap();
    accepted(
        fixture
            .accept(1, "initial-higher", proposal(&fixture, 1, 7))
            .await,
    );
    for owner in 0..2 {
        assert_eq!(
            read(owner, 1).get_data(DataType::EncryptedSecret),
            Some(&DataValue::Bytes(vec![7, owner as u8 + 1]))
        );
    }

    let conflict = fixture
        .accept(1, "conflicting-initial", proposal(&fixture, 1, 9))
        .await;
    assert!(matches!(conflict, RelayOutcome::Rejected { .. }));
    let rotation = fixture
        .accept(1, "non-authoritative-rotation", proposal(&fixture, 2, 8))
        .await;
    assert!(matches!(rotation, RelayOutcome::Rejected { .. }));
    assert!(read(1, 2).is_type(CommunicationType::ErrorNotSet));

    // Reconnect the authoritative participant for subsequent rotations.
    session.connection_id = uuid::Uuid::new_v4();
    session.hosted_lease.as_mut().unwrap().connection_id = session.connection_id.to_string();
    iota_storage::hosted_auth::register(session.hosted_lease.as_ref().unwrap()).unwrap();
    fixture.sources[0] = iota_connection::relay_service::IngressSource::HostedClient { session };
    accepted(
        fixture
            .accept(0, "authoritative-rotation", proposal(&fixture, 2, 8))
            .await,
    );
    for owner in 0..2 {
        assert_eq!(
            read(owner, 1).get_data(DataType::EncryptedSecret),
            Some(&DataValue::Bytes(vec![7, owner as u8 + 1]))
        );
        assert_eq!(
            read(owner, 2).get_data(DataType::EncryptedSecret),
            Some(&DataValue::Bytes(vec![8, owner as u8 + 1]))
        );
    }
    let impersonation = CommunicationValue::new(CommunicationType::GetChatSecret)
        .with_sender(1)
        .add_typed_default(
            DataType::UserId,
            DataValue::Str(serde_json::to_string(&fixture.ids[1]).unwrap()),
        )
        .add_typed_default(DataType::ChatId, DataValue::Str(chat_id));
    assert!(handle_get_chat_secret(&impersonation).is_type(CommunicationType::ErrorNotFound));

    // The initialization exception ends as soon as either account is not hosted here.
    execute("DELETE FROM hosted_principals WHERE local_user_id = 1");
    let outcome = fixture
        .accept(1, "no-longer-shared", proposal(&fixture, 1, 7))
        .await;
    assert!(matches!(outcome, RelayOutcome::Rejected { .. }));
    std::fs::remove_dir_all(storage).unwrap();
}
