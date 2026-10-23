use super::*;

impl Drop for OutgoingRegistration {
    fn drop(&mut self) {
        if let Some(generation) = self.generation {
            self.router.unregister(&self.node, generation);
        }
        self.connection.sender.close_immediate();
    }
}

impl PeerManager {
    pub fn new(
        identity: iota_identity::LocalNodeIdentity,
        nodes: Arc<dyn NodeDirectory>,
        router: Arc<DirectPeerRouter>,
        relay: Arc<RelayService>,
        deliveries: Arc<dyn LocalDeliverySink>,
    ) -> Self {
        Self {
            identity,
            nodes,
            router,
            relay,
            deliveries,
            shutdown: tokio_util::sync::CancellationToken::new(),
            outgoing: std::sync::Mutex::new(Some(tokio::task::JoinSet::new())),
            outgoing_failed: AtomicBool::new(false),
            shutdown_join: tokio::sync::Mutex::new((None, None)),
            introducer: None,
            authority_resolver: None,
            last_authentication_error: std::sync::Mutex::new(None),
            dials: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub async fn connect(
        self: &Arc<Self>,
        node: IotaNodeId,
        endpoint: &AuthorityLocator,
        pinned_certificate: Option<Vec<u8>>,
    ) -> Result<(), RouteError> {
        if self.shutdown.is_cancelled() {
            return Err(RouteError::Delivery("peer manager is shutting down".into()));
        }
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.nodes.resolve_node(&node),
        )
        .await
        .map_err(|_| RouteError::Delivery("peer directory lookup timed out".into()))?
        .map_err(|error| RouteError::Delivery(error.to_string()))?;
        let host_key = resolved
            .public_keys
            .first()
            .ok_or_else(|| RouteError::Delivery("remote node has no trusted key".into()))?
            .clone();
        let mut config = mtp::client::ClientConfig::new(format!("https://{}/", endpoint.as_str()))
            .with_client_id(self.identity.node_id().mtp_authentication_hint())
            .with_description(format!("iota-peer:{}", self.identity.node_id().as_str()));
        if let Some(certificate) = pinned_certificate {
            config = config.with_pinned_pem(certificate);
        }
        let keyring = self.identity.keyring();
        let connection = tokio::select! {
            _ = self.shutdown.cancelled() => return Err(RouteError::Delivery("peer manager is shutting down".into())),
            connection = tokio::time::timeout(std::time::Duration::from_secs(15), mtp::client::MTPClient::auth_connect(config, &keyring, &host_key)) =>
                connection.map_err(|_| RouteError::Delivery("peer handshake timed out".into()))?
                    .map_err(|error| {
                        *self.last_authentication_error.lock().expect("peer diagnostics lock poisoned")=Some(error.to_string());
                        RouteError::Delivery(error.to_string())
                    })?,
        };
        if connection.auth_state != mtp::client::AuthState::Authenticated {
            connection.sender.close_immediate();
            return Err(RouteError::Delivery(
                "remote peer did not complete node authentication".into(),
            ));
        }
        let connection = Arc::new(connection);
        let mut registration = OutgoingRegistration {
            router: self.router.clone(),
            node: node.clone(),
            generation: None,
            connection: connection.clone(),
        };
        let admission = async {
            let candidate = self.validate_peer(&node, &host_key).await?;
            self.establish_peer(candidate, &host_key).await
        }
        .await;
        if let Err(error) = admission {
            connection.sender.close_immediate();
            return Err(RouteError::Delivery(error.to_string()));
        }
        self.nodes
            .pin_endpoint(endpoint, &node, now_millis())
            .map_err(|error| RouteError::Delivery(error.to_string()))?;
        let mut outgoing = self.outgoing.lock().expect("peer supervisor lock poisoned");
        let Some(tasks) = outgoing.as_mut().filter(|_| !self.shutdown.is_cancelled()) else {
            connection.sender.close_immediate();
            return Err(RouteError::Delivery("peer manager is shutting down".into()));
        };
        registration.generation = self.router.register_selected(
            node.clone(),
            Arc::new(OutgoingPeer(connection.clone(), host_key.clone())),
            !self.prefers_inbound(&node),
        )?;
        let manager = self.clone();
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                self.outgoing_failed.store(true, Ordering::Release);
                iota_logger::log!("Outbound peer task failed: {}", error);
            }
        }
        tasks.spawn(async move {
            manager.outgoing_read_loop(host_key, registration).await;
        });
        Ok(())
    }

    pub fn with_introducer(mut self, introducer: Arc<dyn introduction::PeerIntroducer>) -> Self {
        self.introducer = Some(introducer);
        self
    }

    pub fn with_authority_resolver(mut self, resolver: Arc<RemoteIotaResolver>) -> Self {
        self.authority_resolver = Some(resolver);
        self
    }

    /// Stop dials and signal both inbound and outbound peer handlers.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    /// Called after authoritative directory revocation. Remove the selected
    /// route and close its transport without affecting another node.
    pub fn revoke_peer(&self, node: &IotaNodeId) -> Result<(), RouteError> {
        self.nodes
            .revoke_peer_admission(node)
            .map_err(|e| RouteError::Delivery(e.to_string()))?;
        let removed = self
            .router
            .peers
            .write()
            .map_err(|_| RouteError::Delivery("peer route registry lock poisoned".into()))?
            .remove(node);
        if let Some((generation, connection, _)) = removed {
            connection.close();
            iota_logger::log!(
                "Peer revoked: node={} generation={}",
                node.as_str(),
                generation
            );
        }
        Ok(())
    }

    /// Retain the drain task across concurrent callers and cancelled waiters.
    /// Incomplete shutdown never treats an aborted mutation as successful cleanup.
    pub async fn shutdown(&self, budget: std::time::Duration) -> bool {
        self.stop();
        let mut join = self.shutdown_join.lock().await;
        if join.0.is_none() && join.1.is_none() {
            let tasks = self
                .outgoing
                .lock()
                .expect("peer supervisor lock poisoned")
                .take();
            let mut clean = !self.outgoing_failed.load(Ordering::Acquire);
            join.0 = Some(tokio::spawn(async move {
                let Some(mut tasks) = tasks else {
                    return clean;
                };
                if tokio::time::timeout(budget, async {
                    while let Some(result) = tasks.join_next().await {
                        if let Err(error) = result {
                            clean = false;
                            iota_logger::log!(
                                "Outbound peer task failed during shutdown: {}",
                                error
                            );
                        }
                    }
                })
                .await
                .is_err()
                {
                    iota_logger::log!(
                        "Outbound peer shutdown incomplete: remaining={} budget={:?}",
                        tasks.len(),
                        budget
                    );
                    tasks.detach_all();
                    return false;
                }
                clean
            }));
        }
        if let Some(task) = join.0.as_mut() {
            let result = task.await.unwrap_or(false);
            join.0.take();
            join.1 = Some(result);
        }
        join.1.expect("peer shutdown result retained")
    }

    pub async fn connect_best(self: &Arc<Self>, node: &IotaNodeId) -> Result<(), RouteError> {
        let mut receiver = {
            let mut dials = self.dials.lock().expect("peer dial lock poisoned");
            if let Some(receiver) = dials.get(node) {
                receiver.clone()
            } else {
                if dials.len() >= 256 {
                    return Err(RouteError::Delivery("peer dial concurrency limit".into()));
                }
                let (sender, receiver) = tokio::sync::watch::channel(DialState::Connecting);
                let mut outgoing = self.outgoing.lock().expect("peer supervisor lock poisoned");
                let tasks = outgoing
                    .as_mut()
                    .filter(|_| !self.shutdown.is_cancelled())
                    .ok_or_else(|| RouteError::Delivery("peer manager is shutting down".into()))?;
                dials.insert(node.clone(), receiver.clone());
                let manager = self.clone();
                let node = node.clone();
                tasks.spawn(async move {
                    let result = tokio::select! {
                        _ = manager.shutdown.cancelled() => Err(RouteError::Delivery("peer manager is shutting down".into())),
                        result = tokio::time::timeout(std::time::Duration::from_secs(45),manager.connect_best_inner(&node)) =>
                            result.unwrap_or_else(|_| Err(RouteError::Delivery("peer dial budget exhausted".into()))),
                    };
                    sender.send_replace(DialState::Finished(result));
                    tokio::select! { _ = manager.shutdown.cancelled() => {}, _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {} }
                    manager.dials.lock().expect("peer dial lock poisoned").remove(&node);
                });
                receiver
            }
        };
        loop {
            if let DialState::Finished(result) = receiver.borrow_and_update().clone() {
                return result;
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return Err(RouteError::Delivery("peer manager is shutting down".into())),
                changed = receiver.changed() => if changed.is_err() { return Err(RouteError::Delivery("peer dial task stopped".into())); },
            }
        }
    }

    pub(super) async fn connect_best_inner(
        self: &Arc<Self>,
        node: &IotaNodeId,
    ) -> Result<(), RouteError> {
        if self
            .router
            .peers
            .read()
            .ok()
            .is_some_and(|peers| peers.contains_key(node))
        {
            return Ok(());
        }
        let resolved = match self.nodes.resolve_node(node).await {
            Ok(resolved) => resolved,
            Err(IdentityError::Unavailable(_)) if self.authority_resolver.is_some() => {
                self.authority_resolver
                    .as_ref()
                    .expect("configured authority resolver")
                    .refresh_node_identity(node)
                    .await
                    .map_err(|e| RouteError::Delivery(e.to_string()))?;
                self.nodes
                    .resolve_node(node)
                    .await
                    .map_err(|e| RouteError::Delivery(e.to_string()))?
            }
            Err(error) => return Err(RouteError::Delivery(error.to_string())),
        };
        let mut endpoints = resolved.direct_endpoints;
        if let Some(last) = resolved.last_successful_endpoint {
            endpoints.retain(|endpoint| endpoint != &last);
            endpoints.insert(0, last);
        }
        let mut last_error = None;
        for endpoint in endpoints {
            if let Some(introducer) = &self.introducer {
                // HTTPS bootstrap is an explicit first-contact probe. Transport failures never trigger repinning.
                if let Err(error) = introducer.introduce(&self.identity, node, &endpoint).await {
                    last_error = Some(RouteError::Delivery(error.to_string()));
                    continue;
                }
            }
            let certificate = self
                .nodes
                .pinned_endpoint_certificate(&endpoint)
                .map_err(|error| RouteError::Delivery(error.to_string()))?;
            match self.connect(node.clone(), &endpoint, certificate).await {
                Ok(()) => {
                    let _ = self.nodes.record_successful_endpoint(node, &endpoint);
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| RouteError::NoRoute(node.clone())))
    }

    pub(super) fn prefers_inbound(&self, remote: &IotaNodeId) -> bool {
        prefers_inbound(self.identity.node_id(), remote)
    }
}
