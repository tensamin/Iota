use super::*;

impl PeerManager {
    pub(super) async fn outgoing_read_loop(
        self: Arc<Self>,
        key: PublicKeyBundle,
        registration: OutgoingRegistration,
    ) {
        let node = &registration.node;
        let connection = &registration.connection;
        let shutdown = self.shutdown.child_token();
        let monitor = self.monitor_peer(node, &key, &shutdown);
        tokio::pin!(monitor);
        loop {
            let frame = tokio::select! {
                biased;
                _ = &mut monitor => break,
                frame = connection.receive() => match frame { Ok(frame) => frame, Err(_) => break },
            };
            let operation = self.process_incoming(node, &key, &shutdown, frame, |response| {
                let sender = connection.sender.clone();
                async move {
                    sender
                        .send(&response)
                        .await
                        .map_err(|error| error.to_string())
                }
            });
            tokio::pin!(operation);
            tokio::select! {
                _ = &mut operation => {},
                _ = &mut monitor => {
                    shutdown.cancel();
                    connection.sender.close_immediate();
                    operation.await;
                    break;
                },
            }
        }
    }

    pub(super) async fn process_incoming<F, Fut>(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
        shutdown: &tokio_util::sync::CancellationToken,
        frame: CommunicationValue,
        send: F,
    ) where
        F: FnOnce(CommunicationValue) -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        if !frame.is_type(mtp::codec::CommunicationType::Relay)
            || iota_connection::relay::message_security_class(&frame)
                != iota_connection::relay::MessageSecurityClass::AuthenticatedPeerControl
        {
            return;
        }
        let source = IngressSource::DirectPeer {
            node_id: node.clone(),
        };
        let request = frame.clone();
        let prepared = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = self.shutdown.cancelled() => return,
            verified = self.relay.prepare_relay(&source, frame) => verified,
        };
        let verified = match prepared {
            Ok(verified) => verified,
            Err(error) => {
                let response =
                    iota_connection::relay_service::relay_error_response(&request, &error);
                tokio::select! {
                    _ = shutdown.cancelled() => {},
                    _ = tokio::time::timeout(std::time::Duration::from_secs(5), send(response)) => {},
                }
                return;
            }
        };
        let trusted = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = self.shutdown.cancelled() => return,
            peer = self.validate_established_peer(node, key) => peer,
        };
        if trusted.is_err() {
            return;
        }
        let outcome = self.relay.accept_verified_relay(source, verified).await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let response =
                    iota_connection::relay_service::relay_error_response(&request, &error);
                tokio::select! {
                    _ = shutdown.cancelled() => {},
                    _ = tokio::time::timeout(std::time::Duration::from_secs(5), send(response)) => {},
                }
                return;
            }
        };
        let (response, deliveries) = outcome.into_parts();
        for delivery in deliveries {
            tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.deliveries.deliver(delivery.recipient, delivery.frame),
            ) => {},
            }
        }
        if let Some(response) = response {
            tokio::select! {
                _ = shutdown.cancelled() => {},
                _ = tokio::time::timeout(std::time::Duration::from_secs(5), send(response)) => {},
            }
        }
    }
}

pub(super) fn prefers_inbound(local: &IotaNodeId, remote: &IotaNodeId) -> bool {
    // The smaller node selects outbound; the larger selects inbound. Both ends
    // select the same transport when they dial simultaneously.
    local.as_str() > remote.as_str()
}

#[async_trait]
impl DirectPeerConnection for OutgoingPeer {
    fn authenticated_key(&self) -> Option<PublicKeyBundle> {
        Some(self.1.clone())
    }
    fn close(&self) {
        self.0.sender.close_immediate();
    }
    async fn send_relay(&self, frame: CommunicationValue) -> Result<RouteOutcome, RouteError> {
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.0.request(&frame, None),
        )
        .await
        .map_err(|_| RouteError::Delivery("peer relay request timed out".into()))?
        .map_err(|error| RouteError::Delivery(error.to_string()))?;
        RouteOutcome::from_relay_response(&frame, response)
    }
}

impl Drop for PendingPeerRequest {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().expect("peer response lock poisoned");
        if pending
            .get(&self.frame_id)
            .is_some_and(|(instance, _)| Arc::ptr_eq(instance, &self.instance))
        {
            pending.remove(&self.frame_id);
        }
    }
}

#[async_trait]
impl DirectPeerConnection for IncomingPeer {
    fn authenticated_key(&self) -> Option<PublicKeyBundle> {
        self.connection.client_public_key.clone()
    }
    fn close(&self) {
        self.pending
            .lock()
            .expect("peer response lock poisoned")
            .clear();
        self.connection.sender.close();
    }
    async fn send_relay(&self, frame: CommunicationValue) -> Result<RouteOutcome, RouteError> {
        let frame_id = frame
            .id()
            .filter(|frame_id| *frame_id != 0)
            .ok_or_else(|| RouteError::Delivery("relay request has no frame ID".into()))?;
        let (send, receive) = tokio::sync::oneshot::channel();
        let instance = Arc::new(());
        {
            let mut pending = self.pending.lock().expect("peer response lock poisoned");
            match pending.entry(frame_id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((instance.clone(), send));
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(RouteError::Delivery(
                        "relay request ID is already pending".into(),
                    ));
                }
            }
        }
        let _request = PendingPeerRequest {
            pending: self.pending.clone(),
            frame_id,
            instance,
        };
        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.connection.sender.send(&frame),
        )
        .await
        .map_err(|_| RouteError::Delivery("peer relay send timed out".into()))?;
        if let Err(error) = sent {
            return Err(RouteError::Delivery(error.to_string()));
        }
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), receive)
            .await
            .map_err(|_| RouteError::Delivery("peer relay request timed out".into()))?
            .map_err(|_| RouteError::Delivery("peer relay connection closed".into()))?;
        RouteOutcome::from_relay_response(&frame, response)
    }
}
