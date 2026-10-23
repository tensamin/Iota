use super::*;
use iota_auth::SessionCapabilities;

#[tokio::test]
async fn local_delivery_acknowledgements_bind_identity_and_connection() {
    let signer = iota_identity::PrincipalId {
        authority: iota_identity::AuthorityId::for_iota(
            &iota_identity::IotaNodeId::from_public_keys(
                &mtp::crypto::Keyring::generate().public_key_bundle(),
            )
            .unwrap(),
        ),
        user_id: 7,
    };
    let old = tau::ResponseCorrelator::new();
    let replacement = tau::ResponseCorrelator::new();
    let frame = CommunicationValue::new(CommunicationType::Relay)
        .with_id(99)
        .add_typed_default(DataType::SecurePayload, DataValue::Bytes(vec![1, 2, 3]));
    let (sent, mut outbound) = tokio::sync::mpsc::unbounded_channel();
    async fn exchange(
        correlator: &tau::ResponseCorrelator,
        frame: &CommunicationValue,
        expected: iota_identity::PrincipalId,
        sent: tokio::sync::mpsc::UnboundedSender<CommunicationValue>,
    ) -> Result<CommunicationValue, tau::RequestError> {
        correlator
            .exchange(
                frame,
                std::time::Duration::from_secs(1),
                move |response| local_delivery_ack_matches(response, "stable-message", &expected),
                move |frame| async move { sent.send(frame).map_err(|error| error.to_string()) },
            )
            .await
    }
    let old_exchange = exchange(&old, &frame, signer.clone(), sent.clone());
    let new_exchange = exchange(&replacement, &frame, signer.clone(), sent);
    let acknowledge = async {
        let old_wire = outbound.recv().await.unwrap();
        let new_wire = outbound.recv().await.unwrap();
        assert_eq!(
            old_wire.get_data(DataType::SecurePayload),
            frame.get_data(DataType::SecurePayload)
        );
        assert_eq!(
            new_wire.get_data(DataType::SecurePayload),
            frame.get_data(DataType::SecurePayload)
        );
        assert_ne!(new_wire.id(), frame.id());
        let response = CommunicationValue::new(CommunicationType::Success)
            .with_id(old_wire.id().unwrap())
            .add_typed_default(
                DataType::RelayMessageId,
                DataValue::Str("stable-message".into()),
            )
            .add_typed_default(
                DataType::Principal,
                DataValue::Str(serde_json::to_string(&signer).unwrap()),
            );
        assert!(old.complete(old_wire.id().unwrap(), response.clone()));
        assert_eq!(replacement.len(), 1);
        let wrong_message = response.clone().add_typed_default(
            DataType::RelayMessageId,
            DataValue::Str("different-message".into()),
        );
        assert!(!replacement.complete(new_wire.id().unwrap(), wrong_message));
        let mut foreign_signer = signer.clone();
        foreign_signer.user_id += 1;
        let wrong_signer = response.clone().add_typed_default(
            DataType::Principal,
            DataValue::Str(serde_json::to_string(&foreign_signer).unwrap()),
        );
        assert!(!replacement.complete(new_wire.id().unwrap(), wrong_signer));
        assert!(replacement.complete(
            new_wire.id().unwrap(),
            response.with_id(new_wire.id().unwrap())
        ));
    };
    let (old_response, new_response, ()) = tokio::join!(old_exchange, new_exchange, acknowledge);
    assert_eq!(old_response.unwrap().id(), Some(99));
    assert_eq!(new_response.unwrap().id(), Some(99));
}

#[test]
fn signed_message_send_alias_is_not_a_relay_envelope() {
    let message = CommunicationValue::new(CommunicationType::MessageSend)
        .with_id(7)
        .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
        .add_typed_default(DataType::SecurePayload, DataValue::Bytes(vec![1, 2, 3]));

    let session = AuthenticatedSession {
        connection_id: Uuid::new_v4(),
        identity: SessionIdentity::Hosted {
            local_user: LocalUserId(7),
            principal: PrincipalHandle(9),
        },
        capabilities: SessionCapabilities::hosted(),
        hosted_lease: None,
    };
    assert!(authorized_hosted_frame(&session, message).is_none());
}

#[test]
fn receipt_pages_require_hosted_account_data_authority() {
    let mut capabilities = SessionCapabilities::default();
    capabilities.grant(SessionCapability::Messaging);
    let mut session = AuthenticatedSession {
        connection_id: Uuid::new_v4(),
        identity: SessionIdentity::Hosted {
            local_user: LocalUserId(7),
            principal: PrincipalHandle(9),
        },
        capabilities,
        hosted_lease: None,
    };
    let request = CommunicationValue::new(CommunicationType::RelayReceiptPage).with_sender(99);
    assert!(authorized_hosted_frame(&session, request.clone()).is_none());
    session.capabilities.grant(SessionCapability::AccountData);
    assert_eq!(
        authorized_hosted_frame(&session, request.clone())
            .unwrap()
            .sender(),
        Some(7)
    );
    session.identity = SessionIdentity::Foreign {
        principal: PrincipalHandle(9),
    };
    assert!(authorized_hosted_frame(&session, request).is_none());
}

#[test]
fn hosted_session_replaces_untrusted_request_sender() {
    let session = AuthenticatedSession {
        connection_id: Uuid::new_v4(),
        identity: SessionIdentity::Hosted {
            local_user: LocalUserId(7),
            principal: PrincipalHandle(9),
        },
        capabilities: SessionCapabilities::hosted(),
        hosted_lease: None,
    };
    for request in [
        CommunicationType::AccountStateRequest,
        CommunicationType::RelayReceiptPage,
    ] {
        let frame = CommunicationValue::new(request).with_sender(99);
        assert_eq!(
            authorized_hosted_frame(&session, frame).unwrap().sender(),
            Some(7)
        );
    }
}
