use super::stored_message_value;
use iota_storage::util::chat_files::StoredMessage;

#[test]
fn relay_message_value_rejects_missing_canonical_sender() {
    let message = StoredMessage {
        external_principal: None,
        id: 1,
        external_user: 9,
        relay_signer_id: Some(9),
        relay_signer_principal: None,
        relay_message_id: Some("relay-1".to_string()),
        message_time: 2,
        authored_at: None,
        origin_iota_received_at: None,
        destination_iota_received_at: None,
        client_received_at: None,
        client_received_recorded_at: None,
        read_at: None,
        read_recorded_at: None,
        delivery_failed_at: None,
        delivery_failure: None,
        content: "message".to_string(),
        edited: false,
        sent_by_self: false,
        message_state: "sent".to_string(),
        height: 1,
        key_version: 1,
        reply_to: None,
        reactions: Vec::new(),
    };

    assert!(stored_message_value(&message, 7, 9, &mtp::codec::TypeMap::latest()).is_err());
}
