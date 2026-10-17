#[allow(dead_code)]
mod relay_support;

use iota_connection::{message_handlers, relay_service::RelayOutcome};
use iota_storage::util::{db, relay_acceptance_receipts};
use mtp::codec::{CommunicationType as C, CommunicationValue as V, DataType as D, DataValue as W};
use relay_support::*;

#[tokio::test]
async fn live_receipt_publication_and_snapshot_pagination() {
    let path = std::env::temp_dir().join(format!("receipt-pagination-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    initialize(&path);
    let fixture = Fixture::new(true);
    accepted(fixture.accept(0, "secret", secret(&fixture)).await);
    accepted(
        fixture
            .accept(
                0,
                "conversation",
                V::new(C::AddConversation).add_typed_default(D::ChatPartnerId, W::SignedNumber(2)),
            )
            .await,
    );
    assert_eq!(count("SELECT COUNT(*) FROM relay_acceptance_receipts"), 0);

    let message = fixture.frame(0, "message", send(100));
    accepted(
        fixture
            .service
            .accept_relay(fixture.sources[0].clone(), message.clone())
            .await
            .unwrap(),
    );
    accepted(
        fixture
            .service
            .accept_relay(fixture.sources[0].clone(), message)
            .await
            .unwrap(),
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM relay_acceptance_receipts WHERE message_id='message'"),
        2
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM relay_acceptance_receipts r JOIN relay_inbox i ON i.signer_principal=r.signer_principal AND i.message_id=r.message_id WHERE r.accepted_at=i.accepted_at"
        ),
        2
    );

    execute(
        "CREATE TRIGGER fail_receipt BEFORE INSERT ON relay_acceptance_receipts
        WHEN NEW.message_id='rollback' AND NEW.storage_owner=2
        BEGIN SELECT RAISE(ABORT, 'receipt insertion interrupted'); END;",
    );
    let result = fixture
        .service
        .accept_relay(
            fixture.sources[0].clone(),
            fixture.frame(0, "rollback", send(101)),
        )
        .await;
    assert!(!matches!(result, Ok(RelayOutcome::Accepted { .. })));
    assert_eq!(
        count("SELECT COUNT(*) FROM messages WHERE relay_message_id='rollback'"),
        0
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM relay_acceptance_receipts WHERE message_id='rollback'"),
        0
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM pending_relays WHERE relay_message_id='rollback'"),
        0
    );
    execute("DROP TRIGGER fail_receipt;");

    db::with_immediate_transaction(|tx| {
        for n in 0..300 {
            relay_acceptance_receipts::insert_in_tx(
                tx,
                1,
                fixture.handles[0].0,
                &format!("history-{n}"),
                n,
            )?;
        }
        Ok(())
    })
    .unwrap();
    // Receipt reads must be independent of historical operation decoding.
    execute("UPDATE relay_inbox SET prepared_operation=x'ffff' WHERE message_id='message';");
    let snapshot = message_handlers::handle_account_state_request(
        &V::new(C::AccountStateRequest).with_sender(1),
    );
    assert!(snapshot.is_type(C::AccountStateSnapshot), "{snapshot:?}");
    let first = snapshot
        .get_data(D::AcceptedIds)
        .and_then(W::as_array)
        .unwrap();
    assert_eq!(first.len(), 128);
    let upper = snapshot
        .get_data(D::ReceiptUpper)
        .and_then(W::as_number)
        .unwrap();
    let mut cursor = snapshot
        .get_data(D::ReceiptCursor)
        .and_then(W::as_number)
        .unwrap();
    db::with_immediate_transaction(|tx| {
        relay_acceptance_receipts::insert_in_tx(tx, 1, fixture.handles[0].0, "concurrent", 1000)
    })
    .unwrap();
    let mut total = first.len();
    loop {
        let page = message_handlers::handle_relay_receipt_page(
            &V::new(C::RelayReceiptPage)
                .with_sender(1)
                .add_typed_default(D::ReceiptCursor, W::SignedNumber(cursor))
                .add_typed_default(D::ReceiptUpper, W::SignedNumber(upper))
                .add_typed_default(D::Amount, W::SignedNumber(128)),
        );
        assert!(page.is_type(C::RelayReceiptPage));
        let records = page.get_data(D::AcceptedIds).and_then(W::as_array).unwrap();
        assert!(records.len() <= 128);
        total += records.len();
        cursor = page
            .get_data(D::ReceiptCursor)
            .and_then(W::as_number)
            .unwrap();
        assert_eq!(
            page.get_data(D::ReceiptUpper).and_then(W::as_number),
            Some(upper)
        );
        if page.get_data(D::ReceiptComplete).and_then(W::as_bool) == Some(true) {
            break;
        }
    }
    assert_eq!(total, 301);
    assert_eq!(cursor, upper);
    let other = relay_acceptance_receipts::receipt_page(2, 0, None, 128).unwrap();
    assert_eq!(other.records.len(), 1);
    assert_eq!(other.records[0].message_id, "message");

    // Purge must remove only this storage owner's normalized coverage.
    iota_storage::users::user_manager::erase_user_locally(1).unwrap();
    assert_eq!(
        count("SELECT COUNT(*) FROM relay_acceptance_receipts WHERE storage_owner=1"),
        0
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM relay_acceptance_receipts WHERE storage_owner=2"),
        1
    );
    std::fs::remove_dir_all(path).unwrap();
}
