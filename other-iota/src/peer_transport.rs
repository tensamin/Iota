use super::*;

/// Scoped operations keep the reader running during reverse peer requests.
/// Dropping the peer loop cannot leave detached mutations running elsewhere.
#[derive(Default)]
pub(super) struct PeerOperations<'a> {
    operations: Vec<std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>>,
}

impl<'a> PeerOperations<'a> {
    pub(super) fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    pub(super) fn push(&mut self, operation: impl Future<Output = ()> + Send + 'a) -> bool {
        if self.operations.len() >= 16 {
            return false;
        }
        self.operations.push(Box::pin(operation));
        true
    }

    pub(super) async fn next(&mut self) {
        std::future::poll_fn(|context| {
            for index in 0..self.operations.len() {
                if self.operations[index].as_mut().poll(context).is_ready() {
                    drop(self.operations.swap_remove(index));
                    return std::task::Poll::Ready(());
                }
            }
            std::task::Poll::Pending
        })
        .await
    }

    pub(super) async fn drain(&mut self) {
        // An operation already inside acceptance must finish its commit. The
        // manager's shutdown supervisor reports an exceeded budget without
        // aborting or detaching these individual operations.
        while !self.is_empty() {
            self.next().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scoped_peer_operations_bound_work_and_drain_every_started_operation() {
        let mut operations = PeerOperations::default();
        let permits = Arc::new(tokio::sync::Semaphore::new(0));
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..16 {
            let permits = permits.clone();
            let completed = completed.clone();
            assert!(operations.push(async move {
                permits.acquire().await.unwrap().forget();
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        assert!(!operations.push(async {}));
        tokio::join!(operations.drain(), async {
            tokio::task::yield_now().await;
            permits.add_permits(16);
        });
        assert!(operations.is_empty());
        assert_eq!(completed.load(Ordering::SeqCst), 16);
    }
}

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
        let mut operations = PeerOperations::default();
        loop {
            let frame = tokio::select! {
                biased;
                _ = &mut monitor => break,
                _ = operations.next(), if !operations.is_empty() => continue,
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
            if !operations.push(operation) {
                iota_logger::log!("Peer request limit reached: node={}", node.as_str());
                break;
            }
        }
        shutdown.cancel();
        connection.sender.close_immediate();
        operations.drain().await;
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
        if frame.is_type(mtp::codec::CommunicationType::ChatSecretRecoveryRequest) {
            use iota_connection::chat_secret_recovery::{
                RecoveryError, RecoveryReply, decode_request, reply_frame,
            };
            let Ok(request) = decode_request(&frame) else {
                return;
            };
            if self.validate_established_peer(node, key).await.is_err() {
                return;
            }
            let handler = self
                .recovery
                .read()
                .ok()
                .and_then(|handler| handler.clone());
            let result = match handler {
                Some(handler) => tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = self.shutdown.cancelled() => return,
                    result = tokio::time::timeout(std::time::Duration::from_secs(15), handler.handle_peer_request(node, key, &request)) =>
                        result.unwrap_or(Err(RecoveryError::RetryablePeerUnavailable)),
                },
                None => Err(RecoveryError::RetryablePeerUnavailable),
            };
            if self.validate_established_peer(node, key).await.is_err()
                || shutdown.is_cancelled()
                || self.shutdown.is_cancelled()
            {
                return;
            }
            if let Ok(response) = reply_frame(&frame, &RecoveryReply { request, result }) {
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(5), send(response)).await;
            }
            return;
        }
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
    async fn send_peer_control(
        &self,
        frame: CommunicationValue,
    ) -> Result<CommunicationValue, RouteError> {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.0.request(&frame, None),
        )
        .await
        .map_err(|_| RouteError::Delivery("peer control request timed out".into()))?
        .map_err(|error| RouteError::Delivery(error.to_string()))
    }
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
        let response = self.send_peer_control(frame.clone()).await?;
        RouteOutcome::from_relay_response(&frame, response)
    }

    async fn send_peer_control(
        &self,
        frame: CommunicationValue,
    ) -> Result<CommunicationValue, RouteError> {
        let frame_id = frame
            .id()
            .filter(|frame_id| *frame_id != 0)
            .ok_or_else(|| RouteError::Delivery("relay request has no frame ID".into()))?;
        let (send, receive) = tokio::sync::oneshot::channel();
        let instance = Arc::new(());
        {
            let mut pending = self.pending.lock().expect("peer response lock poisoned");
            if pending.len() >= 256 {
                return Err(RouteError::Delivery(
                    "peer request concurrency limit".into(),
                ));
            }
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
        Ok(response)
    }
}
