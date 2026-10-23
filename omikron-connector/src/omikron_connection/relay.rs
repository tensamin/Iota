use super::*;
use iota_identity::PrincipalStore as _;

// Maintenance may drop the entire flush on attempt cancellation. Retain the
// exact claim until the callback finishes, and release only that generation.
struct ClientDispatch(relay_queue::ClaimedPendingRelay);

impl Drop for ClientDispatch {
    fn drop(&mut self) {
        if let Err(error) = relay_queue::release_claim(&self.0) {
            log!(
                "Pending Relay {} claim release failed: {error}",
                self.0.pending.id
            );
        }
    }
}

impl OmikronConnection {
    pub(super) async fn dispatch_relay(self: Arc<Self>, frame: CommunicationValue) {
        let request = frame.clone();
        let Some(relay) = self.relay_service() else {
            log!("Rejecting Omikron Relay because the daemon relay service is unavailable");
            return;
        };
        let source = iota_connection::relay_service::IngressSource::Omikron {
            connection_id: self
                .bound_attempt
                .as_ref()
                .map(|attempt| format!("{}:{}", self.connection_id, attempt.generation))
                .unwrap_or_else(|| self.connection_id.to_string()),
        };
        // Signature/key resolution is disposable. Once acceptance starts, the
        // tracked handler owns the mutation until its durable continuation is
        // committed. Recovery then belongs to the process supervisor.
        let cancellation = self
            .bound_attempt
            .as_ref()
            .map(|attempt| &attempt.cancellation)
            .unwrap_or(&self.cancellation);
        let verified = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            result = relay.prepare_relay(&source, frame) => match result {
                Ok(verified) => verified,
                Err(error) => {
                    log!("Relay preparation failed: {error:?}");
                    let response = iota_connection::relay_service::relay_error_response(&request, &error);
                    tokio::select! { _ = cancellation.cancelled() => {}, _ = self.send_message(&response) => {} }
                    return;
                }
            },
        };
        match relay.accept_verified_relay(source, verified).await {
            Ok(outcome) => {
                let (ingress_response, local_deliveries) = outcome.into_parts();
                self.lifecycle_event(
                    LogLevel::Info,
                    "connector.durable.continuation_owned",
                    self.bound_attempt
                        .as_ref()
                        .map(|attempt| attempt.generation),
                    format_args!(
                        "owner=process local_delivery_attempts={}",
                        local_deliveries.len()
                    ),
                );
                if let Some(response) = ingress_response
                    && let Err(error) = self.send_message(&response).await
                {
                    log!("Relay outcome delivery failed: {error}");
                }
                if let Some(sink) = self.local_deliveries.get() {
                    for delivery in local_deliveries {
                        tokio::select! {
                            _ = cancellation.cancelled() => return,
                            _ = sink.deliver(delivery.recipient, delivery.frame) => {},
                        }
                    }
                }
            }
            Err(error) => {
                log!("Relay service rejected Omikron ingress: {error:?}");
                let response =
                    iota_connection::relay_service::relay_error_response(&request, &error);
                tokio::select! { _ = cancellation.cancelled() => {}, _ = self.send_message(&response) => {} }
            }
        }
    }
}

impl OmikronConnection {
    pub(super) async fn flush_pending_relays(&self) {
        self.flush_pending_relays_for_user(None).await;
    }

    pub(super) async fn flush_pending_relays_for_user(&self, destination_user_id: Option<i64>) {
        let cancellation = self.preparation_cancellation();
        let Some(sink) = self.pending_deliveries.get() else {
            return;
        };
        let Ok(_flush) = self.relay_flush.try_lock() else {
            return;
        };
        let Ok(records) = relay_queue::list_active(100) else {
            return;
        };
        // Listing supplies recipient hints only. It grants no delivery authority.
        // Every network attempt and durable write below uses a fresh scoped claim.
        for candidate in records.into_iter().filter(|record| {
            destination_user_id.is_none_or(|user_id| {
                matches!(record.target, relay_queue::RelayTarget::User(destination) if i64::try_from(destination).ok() == Some(user_id))
            })
        }) {
            if cancellation.is_cancelled() {
                break;
            }
            let relay_queue::RelayTarget::User(destination) = candidate.target else {
                // Remote delivery belongs to the process relay supervisor.
                continue;
            };
            let Some(recipient) = candidate.destination_principal else {
                continue;
            };
            match iota_storage::identity::SqliteLocalUserStore
                .local_user_for_principal(recipient)
            {
                Ok(Some(user)) if u64::try_from(user.0).ok() == Some(destination) => {},
                Ok(_) => {
                    log!(
                        "Retaining pending Relay {} with a recipient routing mismatch",
                        candidate.id
                    );
                    continue;
                }
                Err(error) => {
                    log!(
                        "Pending Relay {} recipient lookup failed: {}",
                        candidate.id,
                        error
                    );
                    continue;
                }
            };
            let Ok(user_id) = i64::try_from(destination) else {
                continue;
            };
            let dispatch = match relay_queue::claim_ready_for_user(user_id, recipient, 30_000) {
                Ok(Some(claimed)) => ClientDispatch(claimed),
                Ok(None) => continue,
                Err(error) => {
                    log!("Pending client Relay claim failed: {error}");
                    continue;
                }
            };
            let record = &dispatch.0.pending;
            if record.relay_message_id.is_none() || record.signer_principal.is_none() {
                let _ = relay_queue::quarantine_claimed(&dispatch.0, "missing_canonical_identity");
                continue;
            }
            let Some(version) = mtp::type_map::Version::parse(&record.type_map_version) else {
                log!(
                    "Retaining pending Relay {} with invalid type-map version {}",
                    record.id,
                    record.type_map_version
                );
                let _ = relay_queue::quarantine_claimed(&dispatch.0, "invalid_type_map");
                continue;
            };
            let type_map = mtp::codec::TypeMap::new(version);
            let Ok(frame) = CommunicationValue::from_bytes_with(&record.frame, &type_map) else {
                log!("Retaining pending Relay {} with invalid frame", record.id);
                let _ = relay_queue::quarantine_claimed(&dispatch.0, "invalid_frame");
                continue;
            };
            let identity_matches=(|| {
                let wire=iota_connection::federated_relay::parse_wire(&frame).ok()?;
                let signer=iota_storage::identity::SqlitePrincipalStore.get_principal(record.signer_principal?).ok()??;
                let recipient=iota_storage::identity::SqlitePrincipalStore.get_principal(record.destination_principal?).ok()??;
                Some(wire.message_id==*record.relay_message_id.as_ref()?
                    && wire.signer==iota_connection::federated_relay::protocol_principal(&signer.principal)
                    && wire.recipient==iota_connection::federated_relay::protocol_principal(&recipient.principal))
            })().unwrap_or(false);
            if !identity_matches {
                log!(
                    "Retaining pending Relay {} with a noncanonical frame",
                    record.id
                );
                let _ = relay_queue::quarantine_claimed(&dispatch.0, "noncanonical_frame");
                continue;
            }
            // Do not let an external callback continue sending after the lease
            // expires. The acknowledgement transaction independently checks it.
            let remaining = dispatch.0.claim.deadline.saturating_sub(now_millis_i64());
            if remaining <= 0 || !matches!(relay_queue::verify_current_claim(&dispatch.0), Ok(true)) {
                continue;
            }
                let response = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    response = tokio::time::timeout(Duration::from_millis(remaining as u64), sink(record.clone(), frame.with_id(record.frame_id))) => match response {
                        Ok(response) => response,
                        Err(_) => Err("client_delivery_timeout".into()),
                    },
                };
                match response {
                    Ok(response) if response.type_map().is_some()
                        && response.id() == Some(record.frame_id)
                        && response.is_type(CommunicationType::Success)
                        && response.get_data(DataType::RelayMessageId).as_str() == record.relay_message_id.as_deref() => {
                        if let Err(error) = client_relay_delivery::acknowledge_claimed_client_delivery(&dispatch.0) {
                            log!("Pending Relay {} acknowledgement failed: {error}", record.id);
                        }
                    }
                    Ok(_) => {},
                    Err(error) => {
                        log!("Pending Relay {} delivery failed: {error}", record.id);
                        if let Err(error) = relay_queue::record_retry_claimed(&dispatch.0, now_millis_i64(), "client_delivery_failed") {
                            log!("Pending Relay {} retry scheduling failed: {error}", record.id);
                        }
                    },
                }
        }
    }
}
