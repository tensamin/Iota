use super::*;

impl PeerManager {
    /// Validate policy without changing it. The gateway separately authenticates
    /// the transport and explicitly establishes any provisional admission.
    pub async fn validate_peer(
        &self,
        node: &IotaNodeId,
        public_key: &PublicKeyBundle,
    ) -> Result<ValidatedPeer, IdentityError> {
        let result = self.validate_peer_inner(node, public_key).await;
        if let Err(error) = &result {
            *self
                .last_authentication_error
                .lock()
                .expect("peer diagnostics lock poisoned") = Some(error.to_string());
        }
        result
    }

    pub fn last_authentication_error(&self) -> Option<String> {
        self.last_authentication_error
            .lock()
            .expect("peer diagnostics lock poisoned")
            .clone()
    }

    /// Call only after binding this connection's verified MTP key, ID and role.
    /// Consuming a candidate is separate from validating public directory data.
    pub async fn establish_peer(
        &self,
        candidate: ValidatedPeer,
        key: &PublicKeyBundle,
    ) -> Result<ValidatedPeer, IdentityError> {
        if key
            .try_as_bytes()
            .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?
            != candidate.public_key
        {
            return Err(IdentityError::KeyPinMismatch);
        }
        let key_for_store = key.clone();
        let nodes = self.nodes.clone();
        let trust = candidate.trust.clone();
        let established = iota_storage::blocking::identity_lookup(move || {
            nodes.promote_peer(&trust, &key_for_store, now_millis())
        })
        .await?;
        let Some(trust) = established else {
            return self
                .validate_established_peer(candidate.trust.node(), key)
                .await;
        };
        if trust.node() != candidate.trust.node() || !trust.is_established_at(now_millis()) {
            return Err(IdentityError::KeyPinMismatch);
        }
        Ok(ValidatedPeer {
            trust,
            public_key: candidate.public_key,
        })
    }

    pub async fn validate_established_peer(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
    ) -> Result<ValidatedPeer, IdentityError> {
        let peer = self.validate_peer(node, key).await?;
        if !peer.trust.is_established_at(now_millis()) {
            return Err(IdentityError::Unavailable("peer is not established".into()));
        }
        Ok(peer)
    }

    /// Poll external writers, and react immediately to local revocation or a
    /// descriptor deadline, even while an incoming relay is resolving identities.
    pub(crate) async fn monitor_peer(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
        shutdown: &tokio_util::sync::CancellationToken,
    ) -> Result<(), IdentityError> {
        let mut changes = iota_storage::peer_admission::changes();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.tick().await;
        loop {
            let peer = tokio::select! {
                biased;
                _=shutdown.cancelled()=>return Ok(()),
                _=self.shutdown.cancelled()=>return Ok(()),
                result=self.validate_established_peer(node,key)=>result?,
            };
            let PeerTrust::Established { valid_until, .. } = peer.trust else {
                unreachable!()
            };
            let expiry = async {
                if let Some(until) = valid_until {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        until.saturating_sub(now_millis()).max(0) as u64,
                    ))
                    .await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                _=shutdown.cancelled()=>return Ok(()),
                _=self.shutdown.cancelled()=>return Ok(()),
                _=interval.tick()=>{},
                _=expiry=>{},
                _=changes.changed()=>{},
            }
        }
    }

    pub(super) async fn validate_peer_inner(
        &self,
        node: &IotaNodeId,
        public_key: &PublicKeyBundle,
    ) -> Result<ValidatedPeer, IdentityError> {
        if &IotaNodeId::from_public_keys(public_key)? != node {
            return Err(IdentityError::KeyPinMismatch);
        }
        let admission = {
            let node = node.clone();
            let key = public_key.clone();
            let nodes = self.nodes.clone();
            iota_storage::blocking::identity_lookup(move || {
                nodes.peer_admission(&node, &key, now_millis())
            })
            .await?
        };
        if let Some(trust) = admission {
            if trust.node() != node {
                return Err(IdentityError::KeyPinMismatch);
            }
            return Ok(ValidatedPeer {
                trust,
                public_key: public_key
                    .try_as_bytes()
                    .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?,
            });
        }
        let expected = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.nodes.resolve_node(node),
        )
        .await
        .map_err(|_| IdentityError::Unavailable("peer directory lookup timed out".into()))??;
        if &expected.node != node {
            return Err(IdentityError::KeyPinMismatch);
        }
        let actual = public_key
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        if !expected.public_keys.iter().any(|key| {
            key.try_as_bytes()
                .map(|trusted| trusted == actual)
                .unwrap_or(false)
        }) {
            return Err(IdentityError::KeyPinMismatch);
        }
        if expected
            .valid_until
            .is_some_and(|until| until <= now_millis())
        {
            return Err(IdentityError::Unavailable(
                "trusted peer descriptor expired".into(),
            ));
        }
        Ok(ValidatedPeer {
            trust: PeerTrust::Established {
                node: node.clone(),
                revision: expected.descriptor_revision,
                valid_until: expected.valid_until,
            },
            public_key: actual,
        })
    }

    pub async fn accept_validated(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        peer: ValidatedPeer,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<(), IdentityError> {
        let node = peer.trust.node().clone();
        if !peer.trust.is_established_at(now_millis()) {
            return Err(IdentityError::Unavailable(
                "provisional peers cannot publish routes".into(),
            ));
        }
        if shutdown.is_cancelled() || self.shutdown.is_cancelled() {
            return Ok(());
        }
        // The handoff cannot be reused with a transport authenticated by another key.
        if connection.auth_state != mtp::host::AuthState::Authenticated
            || connection.client_id != node.mtp_authentication_hint()
            || connection
                .description
                .as_deref()
                .and_then(|description| description.strip_prefix("iota-peer:"))
                .and_then(|description| IotaNodeId::new(description).ok())
                .as_ref()
                != Some(&node)
            || connection
                .client_public_key
                .as_ref()
                .and_then(|key| key.try_as_bytes().ok())
                .as_ref()
                != Some(&peer.public_key)
        {
            return Err(IdentityError::KeyPinMismatch);
        }
        let connection = Arc::new(connection);
        let key = connection
            .client_public_key
            .as_ref()
            .expect("validated transport has a key")
            .clone();
        self.validate_established_peer(&node, &key).await?;
        let pending: PendingPeerResponses = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registration = self
            .router
            .register_selected(
                node.clone(),
                Arc::new(IncomingPeer {
                    connection: connection.clone(),
                    pending: pending.clone(),
                }),
                self.prefers_inbound(&node),
            )
            .map_err(|error| IdentityError::Unavailable(error.to_string()))?;
        struct IncomingRegistration<'a> {
            router: &'a DirectPeerRouter,
            node: &'a IotaNodeId,
            registration: Option<u64>,
            pending: PendingPeerResponses,
            sender: mtp::webserver::WebMtpSender,
        }

        impl Drop for IncomingRegistration<'_> {
            fn drop(&mut self) {
                if let Some(registration) = self.registration {
                    self.router.unregister(self.node, registration);
                }
                self.pending
                    .lock()
                    .expect("peer response lock poisoned")
                    .clear();
                self.sender.close();
            }
        }

        let _registration = IncomingRegistration {
            router: &self.router,
            node: &node,
            registration,
            pending: pending.clone(),
            sender: connection.sender.clone(),
        };
        let shutdown = shutdown.child_token();
        let monitor = self.monitor_peer(&node, &key, &shutdown);
        tokio::pin!(monitor);
        loop {
            let frame = tokio::select! {
                biased;
                _ = &mut monitor => break,
                frame = connection.receive() => match frame { Ok(frame) => frame, Err(_) => break },
            };
            if let Some(frame_id) = frame.id()
                && let Some((_, response)) = pending
                    .lock()
                    .expect("peer response lock poisoned")
                    .remove(&frame_id)
            {
                let _ = response.send(frame);
                continue;
            }
            let operation = self.process_incoming(&node, &key, &shutdown, frame, |response| {
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
                    pending.lock().expect("peer response lock poisoned").clear();
                    connection.sender.close(); operation.await;
                    break;
                },
            }
        }
        Ok(())
    }
}

#[async_trait]
impl web_server::MtpConnectionHandler for PeerManager {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection) {
        self.accept_until_shutdown(connection, tokio_util::sync::CancellationToken::new())
            .await;
    }

    async fn accept_until_shutdown(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        let sender = connection.sender.clone();
        let result = async {
            if connection.auth_state != mtp::host::AuthState::Authenticated {
                return Err(IdentityError::KeyPinMismatch);
            }
            let key = connection
                .client_public_key
                .as_ref()
                .ok_or(IdentityError::KeyPinMismatch)?;
            let node = IotaNodeId::from_public_keys(key)?;
            if connection.client_id != node.mtp_authentication_hint()
                || connection.description.as_deref()
                    != Some(&format!("iota-peer:{}", node.as_str()))
            {
                return Err(IdentityError::KeyPinMismatch);
            }
            let validated = tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                peer = self.validate_peer(&node, key) => peer?,
            };
            let validated = self.establish_peer(validated, key).await?;
            self.accept_validated(connection, validated, shutdown).await
        }
        .await;
        if let Err(error) = result {
            iota_logger::log!("Peer compatibility handler rejected connection: {}", error);
        }
        sender.close();
    }
}
