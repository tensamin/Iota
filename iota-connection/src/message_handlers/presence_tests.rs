use super::{contact_ids_value, handle_get_chats, message_mutation};
use mtp::codec::{CommunicationType, CommunicationValue, DataValue};

#[test]
fn contact_snapshot_is_sorted_and_deduplicated() {
    assert_eq!(
        contact_ids_value([9, 3, 9, 4, 3]),
        DataValue::Array(vec![
            DataValue::SignedNumber(3),
            DataValue::SignedNumber(4),
            DataValue::SignedNumber(9),
        ])
    );
}

#[test]
fn message_mutation_rejects_a_missing_authenticated_sender() {
    let request = CommunicationValue::new(CommunicationType::MessageEdit).with_id(11);
    let response = message_mutation(&request).expect_err("missing sender must be rejected");

    assert!(response.is_type(CommunicationType::ErrorInvalidData));
    assert_eq!(response.id(), Some(11));
    assert_eq!(response.receiver(), None);
}

#[test]
fn read_handler_rejects_a_missing_authenticated_sender() {
    let request = CommunicationValue::new(CommunicationType::GetChats).with_id(12);
    let response = handle_get_chats(&request);

    assert!(response.is_type(CommunicationType::ErrorInvalidData));
    assert_eq!(response.id(), Some(12));
    assert_eq!(response.receiver(), None);
}
