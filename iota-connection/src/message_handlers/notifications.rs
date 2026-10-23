use super::*;

pub(super) fn notification_response(
    ty: CommunicationType,
    request: &CommunicationValue,
    owner: i64,
    contact: &iota_storage::users::contact::Contact,
) -> CommunicationValue {
    let mut response = CommunicationValue::new(ty)
        .with_request_id(request)
        .with_receiver(sender_wire_id(owner))
        .add_typed_default(
            DataType::ChatPartnerId,
            DataValue::SignedNumber(
                contact
                    .principal
                    .expect("principal-scoped notification")
                    .0
                    .into(),
            ),
        )
        .add_typed_default(
            DataType::Notifications,
            DataValue::SignedNumber(contact.notifications.into()),
        );
    if let Some(last_message_at) = contact.last_message_at {
        response = response.add_typed_default(
            DataType::LastMessageAt,
            DataValue::SignedNumber(last_message_at.into()),
        );
    }
    response
}

pub fn handle_read_notification(cv: &CommunicationValue) -> NotificationMutation {
    let Ok(owner) = required_sender_id(cv) else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(partner_id) = data_i64(cv, DataType::ChatPartnerId).filter(|id| *id > 0) else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };
    let Some(through) = data_i64(cv, DataType::LastMessageAt).filter(|time| *time >= 0) else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInvalidData),
            changed: None,
        };
    };

    let Ok(Some(contact)) =
        chats_util::get_user_by_principal(owner, iota_identity::PrincipalHandle(partner_id))
    else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        };
    };
    let Some(principal) = contact.principal else {
        return NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        };
    };

    match chats_util::read_notifications(owner, principal, through) {
        Ok(Some(contact)) => NotificationMutation {
            response: notification_response(
                CommunicationType::ReadNotification,
                cv,
                owner,
                &contact,
            ),
            changed: Some(
                notification_response(CommunicationType::PushNotification, cv, owner, &contact)
                    .with_id(next_notification_id()),
            ),
        },
        Ok(None) => NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorNotFound),
            changed: None,
        },
        Err(_) => NotificationMutation {
            response: error_response(cv, CommunicationType::ErrorInternal),
            changed: None,
        },
    }
}
