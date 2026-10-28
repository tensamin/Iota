use super::*;

impl DirectPeerRouter {
    pub fn install_recovery(
        &self,
        recovery: Arc<dyn iota_connection::chat_secret_recovery::PeerRecoveryHandler>,
    ) {
        *self
            .recovery
            .write()
            .expect("recovery registry lock poisoned") = Some(Arc::downgrade(&recovery));
        if let Some(manager) = self
            .manager
            .read()
            .ok()
            .and_then(|manager| manager.as_ref().and_then(Weak::upgrade))
        {
            manager.install_recovery(recovery);
        }
    }
    pub fn register(
        &self,
        node: IotaNodeId,
        connection: Arc<dyn DirectPeerConnection>,
    ) -> Result<u64, RouteError> {
        Ok(self
            .register_selected(node, connection, true)?
            .expect("preferred route is published"))
    }

    pub(super) fn register_selected(
        &self,
        node: IotaNodeId,
        connection: Arc<dyn DirectPeerConnection>,
        preferred: bool,
    ) -> Result<Option<u64>, RouteError> {
        let mut peers = self
            .peers
            .write()
            .map_err(|_| RouteError::Delivery("peer route registry lock poisoned".into()))?;
        if !preferred && peers.get(&node).is_some_and(|current| current.2) {
            return Ok(None);
        }
        let registration = self.next_registration.fetch_add(1, Ordering::Relaxed) + 1;
        let replaced = peers
            .insert(node.clone(), (registration, connection, preferred))
            .is_some();
        iota_logger::log!(
            "Peer route publication: node={} generation={} replaced={}",
            node.as_str(),
            registration,
            replaced
        );
        Ok(Some(registration))
    }

    pub fn unregister(&self, node: &IotaNodeId, registration: u64) {
        if let Ok(mut peers) = self.peers.write()
            && peers
                .get(node)
                .is_some_and(|current| current.0 == registration)
        {
            peers.remove(node);
            iota_logger::log!(
                "Peer route removal: node={} generation={}",
                node.as_str(),
                registration
            );
        }
    }

    pub fn attach_manager(&self, manager: &Arc<PeerManager>) {
        manager.start_file_replication();
        if let Ok(mut current) = self.manager.write() {
            *current = Some(Arc::downgrade(manager));
        }
        if let Some(recovery) = self
            .recovery
            .read()
            .ok()
            .and_then(|recovery| recovery.as_ref().and_then(Weak::upgrade))
        {
            manager.install_recovery(recovery);
        }
    }

    pub fn has_connection(&self, node: &IotaNodeId) -> bool {
        self.peers
            .read()
            .is_ok_and(|peers| peers.contains_key(node))
    }
}

#[async_trait]
impl iota_connection::chat_secret_recovery::RecoveryTransport for DirectPeerRouter {
    async fn request(
        &self,
        node: &IotaNodeId,
        request: &iota_connection::chat_secret_recovery::RecoveryRequest,
    ) -> Result<
        iota_connection::chat_secret_recovery::AuthenticatedRecoveryReply,
        iota_connection::chat_secret_recovery::RecoveryError,
    > {
        use iota_connection::chat_secret_recovery::*;
        request.validate()?;
        let manager = self
            .manager
            .read()
            .ok()
            .and_then(|manager| manager.as_ref().and_then(Weak::upgrade))
            .ok_or(RecoveryError::RetryablePeerUnavailable)?;
        if !self.has_connection(node) {
            manager
                .connect_best(node)
                .await
                .map_err(|_| RecoveryError::RetryablePeerUnavailable)?;
        }
        let (generation, connection) = self
            .peers
            .read()
            .ok()
            .and_then(|peers| peers.get(node).map(|peer| (peer.0, peer.1.clone())))
            .ok_or(RecoveryError::RetryablePeerUnavailable)?;
        let key = connection
            .authenticated_key()
            .ok_or(RecoveryError::Unauthorized)?;
        if manager.validate_established_peer(node, &key).await.is_err() {
            self.unregister(node, generation);
            connection.close();
            return Err(RecoveryError::Unauthorized);
        }
        let frame = request_frame(request)?;
        let id = frame.id();
        let response = connection
            .send_peer_control(frame)
            .await
            .map_err(|_| RecoveryError::RetryablePeerUnavailable)?;
        if response.id() != id {
            return Err(RecoveryError::Conflict);
        }
        manager
            .validate_established_peer(node, &key)
            .await
            .map_err(|_| RecoveryError::Unauthorized)?;
        let reply = decode_reply(&response, request)?;
        Ok(AuthenticatedRecoveryReply {
            node: node.clone(),
            key,
            reply,
        })
    }
}

#[async_trait]
impl PeerRouter for DirectPeerRouter {
    async fn route(
        &self,
        destination: &RouteDestination,
        frame: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        let RouteDestination::Iota(node) = destination else {
            return Ok(RouteOutcome::Retryable {
                reason: "direct Iota router cannot route a legacy Omega destination".into(),
            });
        };
        let manager = self
            .manager
            .read()
            .ok()
            .and_then(|manager| manager.as_ref().and_then(Weak::upgrade));
        let mut connection = self
            .peers
            .read()
            .ok()
            .and_then(|peers| peers.get(node).map(|peer| (peer.0, peer.1.clone())));
        if connection.is_none()
            && let Some(manager) = manager.as_ref()
        {
            manager.connect_best(node).await?;
            connection = self
                .peers
                .read()
                .ok()
                .and_then(|peers| peers.get(node).map(|peer| (peer.0, peer.1.clone())));
        }
        let (generation, connection) =
            connection.ok_or_else(|| RouteError::NoRoute(node.clone()))?;
        if let Some(manager) = manager {
            if manager.shutdown.is_cancelled() {
                return Err(RouteError::Delivery("peer manager is shutting down".into()));
            }
            let key = connection.authenticated_key().ok_or_else(|| {
                RouteError::Delivery("peer route has no authenticated key".into())
            })?;
            if let Err(error) = manager.validate_established_peer(node, &key).await {
                self.unregister(node, generation);
                connection.close();
                return Err(RouteError::Delivery(error.to_string()));
            }
            if manager.shutdown.is_cancelled() {
                return Err(RouteError::Delivery("peer manager is shutting down".into()));
            }
        }
        let frame = if frame.payload().as_encrypted().is_some() {
            iota_connection::federated_relay::native_peer_frame(frame)
                .map_err(|error| RouteError::Delivery(error.to_string()))?
        } else {
            frame
        };
        connection.send_relay(frame).await
    }
}
