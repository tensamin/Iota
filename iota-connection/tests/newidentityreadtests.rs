#![allow(
    dead_code,
    reason = "shared relay fixtures expose helpers used by other suites"
)]

mod relay_support;

use iota_connection::message_handlers::handle_account_state_request;
use mtp::codec::{CommunicationType as C, CommunicationValue, DataType as D, DataValue};
use relay_support::{Fixture, accepted, initialize, secret, send};

#[tokio::test]
async fn snapshots_cover_accepted_edits_and_reactions_but_not_bootstrap_notifications() {
    let path = std::env::temp_dir().join(format!("snapshot-receipts-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    initialize(&path);
    let fixture = Fixture::new(true);
    accepted(fixture.accept(0, "secret", secret(&fixture)).await);
    accepted(
        fixture
            .accept(
                0,
                "contact",
                CommunicationValue::new(C::AddConversation)
                    .add_typed_default(D::ChatPartnerId, DataValue::SignedNumber(2)),
            )
            .await,
    );
    accepted(fixture.accept(0, "send", send(100)).await);
    for (id, content) in [("old-edit", "older"), ("new-edit", "newest")] {
        accepted(
            fixture
                .accept(
                    0,
                    id,
                    CommunicationValue::new(C::MessageEdit)
                        .add_typed_default(D::SendTime, DataValue::SignedNumber(100))
                        .add_typed_default(D::VersionNumber, DataValue::SignedNumber(1))
                        .add_typed_default(D::Content, DataValue::Str(content.into())),
                )
                .await,
        );
    }
    accepted(
        fixture
            .accept(
                1,
                "reaction",
                CommunicationValue::new(C::MessageReactionAdd)
                    .add_typed_default(D::SendTime, DataValue::SignedNumber(100))
                    .add_typed_default(D::Reaction, DataValue::Str("yes".into())),
            )
            .await,
    );

    for owner in [1, 2] {
        let request = CommunicationValue::new(C::AccountStateRequest).with_sender(owner);
        let snapshot = handle_account_state_request(&request);
        assert!(snapshot.is_type(C::AccountStateSnapshot), "{snapshot:?}");
        let map = request.type_map().unwrap();
        let field =
            |value: &DataValue, ty: D| value.get_field(ty.try_to_id(map).unwrap()).unwrap().clone();
        let messages = snapshot.get_data(D::Messages).unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(field(&messages[0], D::Content).as_str(), Some("newest"));
        assert_eq!(
            field(&messages[0], D::Principal).as_str(),
            Some(serde_json::to_string(&fixture.ids[0]).unwrap().as_str())
        );
        let reactions = field(&messages[0], D::Reactions)
            .as_array()
            .unwrap()
            .to_vec();
        assert_eq!(reactions.len(), 1);
        assert_eq!(
            field(&reactions[0], D::Principal).as_str(),
            Some(serde_json::to_string(&fixture.ids[1]).unwrap().as_str())
        );
        let receipts = snapshot
            .get_data(D::AcceptedIds)
            .unwrap()
            .as_array()
            .unwrap();
        let mut covered = receipts
            .iter()
            .map(|receipt| {
                let id = field(receipt, D::RelayMessageId)
                    .as_str()
                    .unwrap()
                    .to_owned();
                let signer = if id == "reaction" { 1 } else { 0 };
                assert_eq!(
                    field(receipt, D::Principal).as_str(),
                    Some(
                        serde_json::to_string(&fixture.ids[signer])
                            .unwrap()
                            .as_str()
                    )
                );
                id
            })
            .collect::<Vec<_>>();
        covered.sort();
        assert_eq!(covered, ["new-edit", "old-edit", "reaction", "send"]);
    }
}
