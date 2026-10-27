#![allow(
    dead_code,
    reason = "shared relay fixtures expose helpers used by other suites"
)]

mod relay_support;

use iota_connection::message_handlers::{handle_account_state_request, handle_relay_receipt_page};
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
        let principal = &fixture.ids[owner as usize - 1];
        let map = mtp::codec::TypeMap::new(mtp::type_map::Version(1, 0));
        let request = tau::sync::encode_request(
            &tau::sync::Request::Snapshot {
                scope: tau::sync::Scope {
                    principal: tau_relay_protocol::Principal::try_from(principal).unwrap(),
                    device_id: "snapshot-test".into(),
                    authorization_generation: iota_storage::hosted_auth::resolve(
                        iota_identity::LocalUserId(owner as i64),
                    )
                    .unwrap()
                    .0
                    .auth_generation,
                    schema: tau::sync::SCHEMA.into(),
                    dictionary: tau_relay_protocol::dictionary_fingerprint("1.0").unwrap(),
                },
                page: None,
                limit: 128,
            },
            &map,
            7,
        )
        .unwrap()
        .with_sender(owner);
        let snapshot = handle_account_state_request(&request);
        assert!(snapshot.is_type(C::AccountStateSnapshot), "{snapshot:?}");
        let map = request.type_map().unwrap();
        let field =
            |value: &DataValue, ty: D| value.get_field(ty.try_to_id(map).unwrap()).unwrap().clone();
        let tau::sync::Response::Snapshot { records, .. } =
            tau::sync::decode_response(&snapshot, &request).unwrap()
        else {
            panic!("expected snapshot");
        };
        let messages = records
            .iter()
            .filter(|record| record.entity == tau::sync::Entity::Message)
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].value["content"], "newest");
        assert_eq!(
            messages[0].value["relay_signer_principal_identity"],
            serde_json::to_value(&fixture.ids[0]).unwrap()
        );
        let reactions = messages[0].value["reactions"].as_array().unwrap();
        assert_eq!(reactions.len(), 1);
        assert_eq!(
            reactions[0]["principal"],
            serde_json::to_value(&fixture.ids[1]).unwrap()
        );
        let receipt_page = handle_relay_receipt_page(
            &CommunicationValue::new(C::RelayReceiptPage)
                .with_sender(owner)
                .add_typed_default(D::ReceiptCursor, DataValue::SignedNumber(0)),
        );
        let receipts = receipt_page
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
