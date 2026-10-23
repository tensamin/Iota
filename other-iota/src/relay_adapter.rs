use super::*;

impl PeerRelayAdapter {
    pub fn new(relay: Arc<RelayService>) -> Self {
        Self { relay }
    }

    pub async fn accept_verified_relay(
        &self,
        authenticated_peer: IotaNodeId,
        relay: VerifiedRelayEnvelope,
    ) -> Result<RelayOutcome, RelayServiceError> {
        self.relay
            .accept_verified_relay(
                IngressSource::DirectPeer {
                    node_id: authenticated_peer,
                },
                relay,
            )
            .await
    }
}
