use super::add_receipt_policy_data;
use iota_storage::util::receipt_policy::ReceiptPolicy;
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType};

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
