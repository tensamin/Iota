use super::*;

impl ConnectionGateway {
    pub fn new(
        engine: tau::AdmissionEngine<IotaConnectionRole>,
        clients: Arc<ClientConnectionManager>,
        peers: Arc<other_iota::PeerManager>,
    ) -> Self {
        Self {
            engine,
            clients,
            peers,
        }
    }

    pub(super) async fn run(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        shutdown: CancellationToken,
    ) -> Result<(), GatewayError> {
        let (description, declared_peer) =
            crate::tau_gateway::parse_description(connection.description.as_deref())?;
        let mut facts = tau::ConnectionFacts::from_mtp(&connection);
        facts.description = Some(description);
        let admission = self.engine.admit(&facts)?;
        // Resolve outside Tau, carrying this admission's exact role, ID and key.
        let tau::TransportAuthentication::TransportAuthenticated {
            mtp_client_id,
            public_key,
        } = admission.transport()
        else {
            unreachable!()
        };
        let mut validated_peer = None;
        let identity = match admission.role() {
            IotaConnectionRole::HostedClient => tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                identity = self.clients.resolve_hosted_identity(*mtp_client_id, public_key) => identity?,
            },
            IotaConnectionRole::DirectPeer => {
                let node = crate::tau_gateway::peer_node(
                    *mtp_client_id,
                    public_key,
                    declared_peer.as_ref(),
                )?;
                let established = tokio::select! {
                    biased;
                    _=shutdown.cancelled()=>return Ok(()),
                    peer=async {
                        let candidate=self.peers.validate_peer(&node,public_key).await?;
                        self.peers.establish_peer(candidate,public_key).await
                    }=>peer.map_err(|error|match error {
                        iota_identity::IdentityError::KeyPinMismatch=>GatewayError::UntrustedPeerKey,
                        _=>GatewayError::PeerDirectoryLookup,
                    })?,
                };
                let identity = crate::tau_gateway::peer_identity(
                    *mtp_client_id,
                    public_key,
                    declared_peer.as_ref(),
                    established.trust().clone(),
                )?;
                validated_peer = Some(established);
                identity
            }
        };
        // Only the established, key-bound identity is handed to Tau. A provisional
        // lease never activates a session or reaches hosted-user handlers.
        let mut session = admission
            .into_session(|_, _, _| Ok::<_, tau::AdmissionError>(identity))
            .map_err(GatewayError::SessionCreation)?;
        let connection_id = session.connection_id().as_uuid();
        iota_logger::log!(
            "Connection identity bound: connection={} role={:?} origin=transport",
            connection_id,
            session.role()
        );
        let result = async {
            let identity = match session.authentication() {
                tau::ApplicationAuthentication::TransportAuthenticated { identity } => identity,
                _ => {
                    return Err(GatewayError::Admission(
                        tau::AdmissionError::RejectedActivation,
                    ));
                }
            };
            match identity {
                IotaConnectionIdentity::HostedClient {
                    local_user,
                    principal,
                    auth_generation,
                } => {
                    let (local_user, principal, auth_generation) =
                        (*local_user, *principal, *auth_generation);
                    if shutdown.is_cancelled() {
                        return Ok(());
                    }
                    session
                        .establish_transport_session()
                        .map_err(GatewayError::SessionCreation)?;
                    session
                        .activate()
                        .map_err(GatewayError::SessionActivation)?;
                    self.clients
                        .run_hosted(
                            connection,
                            session.connection_id().as_uuid(),
                            ValidatedHostedIdentity {
                                local_user,
                                principal,
                                auth_generation,
                            },
                            shutdown,
                        )
                        .await;
                }
                IotaConnectionIdentity::DirectPeer(trust) => {
                    let validated = validated_peer
                        .take()
                        .ok_or(GatewayError::PeerNotEstablished)?;
                    if validated.trust() != trust
                        || !trust.is_established_at(iota_storage::util::sync::now_millis())
                    {
                        return Err(GatewayError::PeerNotEstablished);
                    }
                    if shutdown.is_cancelled() {
                        return Ok(());
                    }
                    session
                        .establish_transport_session()
                        .map_err(GatewayError::SessionCreation)?;
                    session
                        .activate()
                        .map_err(GatewayError::SessionActivation)?;
                    self.peers
                        .accept_validated(connection, validated, shutdown)
                        .await
                        .map_err(|_| GatewayError::HandlerExecution)?;
                }
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            session.reject();
        }
        session.close();
        iota_logger::log!(
            "Connection terminated: connection={} role={:?} outcome={:?}",
            connection_id,
            session.role(),
            session.outcome()
        );
        result
    }
}

#[async_trait]
impl web_server::MtpConnectionHandler for ConnectionGateway {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection) {
        self.accept_until_shutdown(connection, CancellationToken::new())
            .await;
    }

    async fn accept_until_shutdown(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        shutdown: CancellationToken,
    ) {
        let sender = connection.sender.clone();
        let operation = self.run(connection, shutdown.clone());
        tokio::pin!(operation);
        let result = tokio::select! {
            result = &mut operation => result,
            _ = shutdown.cancelled() => {
                sender.close();
                operation.await
            }
        };
        if let Err(error) = result {
            iota_logger::log!("Rejected inbound connection: {}", error);
        }
        sender.close();
    }
}
