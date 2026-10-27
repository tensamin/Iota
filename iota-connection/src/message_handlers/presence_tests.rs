use super::{handle_get_chats, message_mutation};
use mtp::codec::{CommunicationType, CommunicationValue};

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
