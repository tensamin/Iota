use super::{add_receipt_policy_data, read_fenced_snapshot};
use iota_storage::util::receipt_policy::ReceiptPolicy;
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType};

#[test]
fn snapshot_fence_retries_body_and_receipts_after_a_concurrent_change() {
    let version = std::cell::Cell::new(1);
    let attempts = std::cell::Cell::new(0);
    let snapshot = read_fenced_snapshot(
        || Ok(Some(version.get())),
        || {
            attempts.set(attempts.get() + 1);
            let body_version = version.get();
            if attempts.get() == 1 {
                // A committed mutation appears between the body and receipt reads.
                version.set(2);
            }
            Ok((body_version, version.get()))
        },
    )
    .unwrap();
    assert_eq!(snapshot, (2, 2));
    assert_eq!(attempts.get(), 2);
}

#[test]
fn snapshot_fence_fails_after_three_unstable_reads() {
    let version = std::cell::Cell::new(0);
    let result = read_fenced_snapshot(
        || Ok(Some(version.get())),
        || {
            version.set(version.get() + 1);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(version.get(), 3);
}

#[test]
fn snapshot_receipt_policy_includes_its_revision() {
    let policy = ReceiptPolicy {
        user_id: 7,
        send_read_receipts: false,
        send_received_receipts: true,
        revision: 42,
        updated_at: 100,
    };

    let response = add_receipt_policy_data(
        CommunicationValue::new(CommunicationType::AccountStateSnapshot),
        &policy,
    );

    assert_eq!(
        response
            .get_data(DataType::VersionNumber)
            .as_signed_number(),
        Some(42)
    );
    assert_eq!(
        response.get_data(DataType::SendReadReceipts).as_bool(),
        Some(false)
    );
    assert_eq!(
        response.get_data(DataType::SendReceivedReceipts).as_bool(),
        Some(true)
    );
}
