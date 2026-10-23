use super::*;

impl ClientConnectionManager {
    /// This future belongs to the admitted connection's receive loop. Dropping
    /// that loop cancels its exchanges without removing durable queue records.
    pub(super) async fn deliver_pending(
        &self,
        session: &AuthenticatedSession,
        active: &HostedConnection,
        shutdown: &CancellationToken,
    ) {
        let Some(lease) = session.hosted_lease.as_ref() else {
            return;
        };
        let mut retry = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                _ = active.delivery_ready.notified() => {},
                _ = retry.tick() => {},
            }
            if !self.session_is_registered(session)
                || iota_storage::hosted_auth::verify(lease).is_err()
            {
                return;
            }
            if !active
                .state_applied
                .load(std::sync::atomic::Ordering::Acquire)
            {
                continue;
            }
            if let Err(error) = iota_storage::util::relay_queue::resume_client_deliveries(
                lease.identity.local_user.0,
            ) {
                iota_logger::log!("Cannot resume local pending delivery: {}", error);
                continue;
            }
            for _ in 0..100 {
                let claimed = match iota_storage::util::relay_queue::claim_ready_for_user(
                    lease.identity.local_user.0,
                    session.principal(),
                    60_000,
                ) {
                    Ok(Some(claimed)) => claimed,
                    Ok(None) => break,
                    Err(error) => {
                        iota_logger::log!("Cannot claim local pending delivery: {}", error);
                        break;
                    }
                };
                let pending = &claimed.pending;
                let signer = match pending
                    .signer_principal
                    .map(|principal| {
                        iota_storage::identity::SqlitePrincipalStore.get_principal(principal)
                    })
                    .transpose()
                {
                    Ok(signer) => signer.flatten(),
                    Err(error) => {
                        iota_logger::log!(
                            "Cannot resolve local delivery signer {}: {}",
                            pending.id,
                            error
                        );
                        if let Err(error) = iota_storage::util::relay_queue::record_retry_claimed(
                            &claimed,
                            iota_storage::util::sync::now_millis(),
                            "local_delivery_identity_unavailable",
                        ) {
                            iota_logger::log!(
                                "Cannot retry local dispatch claim {}: {}",
                                pending.id,
                                error
                            );
                        }
                        continue;
                    }
                };
                let decoded = (|| {
                    if pending.destination_principal != Some(session.principal()) {
                        return None;
                    }
                    let signer = signer?;
                    let recipient = iota_storage::identity::SqlitePrincipalStore
                        .get_principal(session.principal())
                        .ok()??;
                    let message_id = pending.relay_message_id.clone()?;
                    let version = mtp::type_map::Version::parse(&pending.type_map_version)?;
                    let frame = CommunicationValue::from_bytes_with(
                        &pending.frame,
                        &mtp::type_map::TypeMap::new(version),
                    )
                    .ok()?;
                    let wire = iota_connection::federated_relay::parse_wire(&frame).ok()?;
                    (wire.signer
                        == iota_connection::federated_relay::protocol_principal(&signer.principal)
                        && wire.message_id == message_id
                        && wire.recipient
                            == iota_connection::federated_relay::protocol_principal(
                                &recipient.principal,
                            ))
                    .then_some((frame, signer, message_id))
                })();
                let Some((frame, signer, message_id)) = decoded else {
                    if let Err(error) = iota_storage::util::relay_queue::quarantine_claimed(
                        &claimed,
                        "invalid_local_delivery",
                    ) {
                        iota_logger::log!(
                            "Cannot quarantine local pending delivery {}: {}",
                            pending.id,
                            error
                        );
                    }
                    continue;
                };
                let dispatch_claim = &claimed;
                let exchange = active.responses.exchange(
                    &frame,
                    std::time::Duration::from_secs(30),
                    move |response| {
                        local_delivery_ack_matches(response, &message_id, &signer.principal)
                            || response
                                .get_comm_type_enum()
                                .is_some_and(tau::is_protocol_error)
                    },
                    |outbound| async move {
                        if !self.session_is_registered(session)
                            || iota_storage::hosted_auth::verify(lease).is_err()
                            || !iota_storage::util::relay_queue::verify_current_claim(
                                dispatch_claim,
                            )
                            .map_err(|error| error.to_string())?
                        {
                            return Err("hosted delivery authorization expired".to_owned());
                        }
                        active
                            .sender
                            .send(&outbound)
                            .await
                            .map_err(|error| error.to_string())
                    },
                );
                let response = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        if let Err(error) = iota_storage::util::relay_queue::release_claim(&claimed) {
                            iota_logger::log!("Cannot release local dispatch claim {}: {}", pending.id, error);
                        }
                        return;
                    },
                    response = exchange => response,
                };
                if !self.session_is_registered(session)
                    || iota_storage::hosted_auth::verify(lease).is_err()
                {
                    if let Err(error) = iota_storage::util::relay_queue::release_claim(&claimed) {
                        iota_logger::log!(
                            "Cannot release revoked local dispatch claim {}: {}",
                            pending.id,
                            error
                        );
                    }
                    return;
                }
                let result = match response {
                    Ok(response) if response.is_type(CommunicationType::Success) => {
                        iota_storage::util::db::with_immediate_transaction(|tx| {
                            iota_storage::hosted_auth::verify_in_tx(tx, lease)?;
                            iota_storage::util::client_relay_delivery::acknowledge_claimed_client_delivery_in_tx(tx, &claimed).map(|_| ())
                        })
                    }
                    _ => iota_storage::util::relay_queue::record_retry_claimed(
                        &claimed,
                        iota_storage::util::sync::now_millis(),
                        "local_delivery_acknowledgement_failed",
                    )
                    .map(|_| ()),
                };
                if let Err(error) = result {
                    iota_logger::log!(
                        "Cannot complete local pending delivery {}: {}",
                        pending.id,
                        error
                    );
                }
            }
        }
    }
}

pub(super) fn local_delivery_ack_matches(
    response: &CommunicationValue,
    message_id: &str,
    signer: &iota_identity::PrincipalId,
) -> bool {
    response.is_type(CommunicationType::Success)
        && response.get_data(DataType::RelayMessageId).as_str() == Some(message_id)
        && response
            .get_data(DataType::Principal)
            .as_str()
            .and_then(|value| serde_json::from_str::<iota_identity::PrincipalId>(value).ok())
            .as_ref()
            == Some(signer)
}

pub(super) fn authorized_hosted_frame(
    session: &AuthenticatedSession,
    frame: CommunicationValue,
) -> Option<CommunicationValue> {
    if tau::message_security_class_with(
        &frame,
        &[],
        &[
            CommunicationType::AccountStateRequest,
            CommunicationType::RelayReceiptPage,
            CommunicationType::AccountStateApplied,
            CommunicationType::MessagesGet,
            CommunicationType::MessageGet,
            CommunicationType::GetChatSecret,
            CommunicationType::GetChats,
            CommunicationType::UserResolve,
        ],
    ) != tau::MessageSecurityClass::AuthenticatedLocalRequest
    {
        return None;
    }
    let SessionIdentity::Hosted { local_user, .. } = &session.identity else {
        return None;
    };
    let capability = if frame.is_type(CommunicationType::AccountStateRequest)
        || frame.is_type(CommunicationType::RelayReceiptPage)
        || frame.is_type(CommunicationType::AccountStateApplied)
    {
        SessionCapability::AccountData
    } else if frame.is_type(CommunicationType::MessagesGet)
        || frame.is_type(CommunicationType::MessageGet)
        || frame.is_type(CommunicationType::GetChatSecret)
        || frame.is_type(CommunicationType::GetChats)
    {
        SessionCapability::Messaging
    } else if frame.is_type(CommunicationType::UserResolve) {
        SessionCapability::Federation
    } else {
        return None;
    };
    if !session.allows(&capability) {
        return None;
    }
    let sender = u64::try_from(local_user.0).ok()?;
    Some(frame.with_sender(sender))
}
