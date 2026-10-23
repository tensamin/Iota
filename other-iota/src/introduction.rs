use async_trait::async_trait;
use iota_identity::peer_introduction::{
    PeerAdmissionReceipt, PeerChallengeRequest, PeerChallengeResponse, PeerIntroductionLimits,
    PeerIntroductionRequest, PeerIntroductionService,
};
use iota_identity::{
    AuthorityLocator, IdentityError, IotaNodeId, LocalNodeIdentity, SignedNodeDescriptor,
};
use std::sync::Arc;

pub struct IntroductionService {
    node: IotaNodeId,
    resolver: Arc<crate::RemoteIotaResolver>,
    limits: PeerIntroductionLimits,
}

impl IntroductionService {
    pub fn new(
        node: IotaNodeId,
        resolver: Arc<crate::RemoteIotaResolver>,
        limits: PeerIntroductionLimits,
    ) -> Self {
        Self {
            node,
            resolver,
            limits,
        }
    }
}

#[async_trait]
impl PeerIntroductionService for IntroductionService {
    async fn challenge(
        &self,
        body: Vec<u8>,
        origin: std::net::IpAddr,
    ) -> Result<PeerChallengeResponse, IdentityError> {
        if body.len() > self.limits.max_request_bytes {
            return Err(IdentityError::InvalidDescriptor(
                "introduction request too large".into(),
            ));
        }
        let node = self.node.clone();
        let limits = self.limits.clone();
        iota_storage::blocking::identity_lookup(move || {
            let request: PeerChallengeRequest = serde_json::from_slice(&body)
                .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
            let descriptor = request.descriptor.parse()?;
            if descriptor.descriptor.node == node {
                return Err(IdentityError::KeyPinMismatch);
            }
            iota_storage::peer_admission::issue_challenge(
                &descriptor,
                &node,
                origin,
                request.authority_locator.as_ref(),
                &limits,
                crate::now_millis(),
            )
        })
        .await
    }

    async fn introduce(&self, body: Vec<u8>) -> Result<PeerAdmissionReceipt, IdentityError> {
        if body.len() > self.limits.max_request_bytes {
            return Err(IdentityError::InvalidDescriptor(
                "introduction request too large".into(),
            ));
        }
        let (request, locator) = iota_storage::blocking::identity_lookup(move || {
            let request: PeerIntroductionRequest = serde_json::from_slice(&body)
                .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
            let locator =
                iota_storage::peer_admission::proven_locator(&request, crate::now_millis())?;
            Ok((request, locator))
        })
        .await?;
        if let Some(locator) = locator {
            let verified = self.resolver.verify_authority_locator(&locator).await?;
            if verified != request.descriptor.node {
                return Err(IdentityError::KeyPinMismatch);
            }
        }
        let limits = self.limits.clone();
        iota_storage::blocking::identity_lookup(move || {
            iota_storage::peer_admission::redeem(request, &limits, crate::now_millis())
        })
        .await
    }
}

#[async_trait]
pub trait PeerIntroducer: Send + Sync {
    /// Bootstrap proactively through HTTPS, independently of transport error strings.
    async fn introduce(
        &self,
        identity: &LocalNodeIdentity,
        target: &IotaNodeId,
        endpoint: &AuthorityLocator,
    ) -> Result<(), IdentityError>;
}

pub struct HttpPeerIntroducer {
    descriptor: SignedNodeDescriptor,
    authority_locator: Option<AuthorityLocator>,
    allow_lan: bool,
    client: reqwest::Client,
    cache: std::sync::Mutex<
        std::collections::HashMap<(IotaNodeId, AuthorityLocator), CachedIntroduction>,
    >,
}

struct CachedIntroduction {
    until: i64,
    result: Result<(), IdentityError>,
}

impl HttpPeerIntroducer {
    pub fn new(
        descriptor: SignedNodeDescriptor,
        authority_locator: Option<AuthorityLocator>,
        allow_lan: bool,
    ) -> Result<Self, IdentityError> {
        let client = iota_util::federation_http::client_builder(allow_lan)
            .build()
            .map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        Ok(Self {
            descriptor,
            authority_locator,
            allow_lan,
            client,
            cache: Default::default(),
        })
    }

    pub fn with_pinned_certificate(mut self, certificate: &[u8]) -> Result<Self, IdentityError> {
        let certificate = reqwest::Certificate::from_pem(certificate)
            .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
        self.client = iota_util::federation_http::client_builder(self.allow_lan)
            .add_root_certificate(certificate)
            .build()
            .map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        Ok(self)
    }

    async fn post<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        endpoint: &AuthorityLocator,
        path: &str,
        request: &impl serde::Serialize,
    ) -> Result<T, IdentityError> {
        let url = iota_util::federation_http::url(endpoint, path, self.allow_lan)?;
        let response = self
            .client
            .post(url)
            .json(request)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        iota_util::federation_http::bounded_json(response).await
    }
}

#[async_trait]
impl PeerIntroducer for HttpPeerIntroducer {
    async fn introduce(
        &self,
        identity: &LocalNodeIdentity,
        target: &IotaNodeId,
        endpoint: &AuthorityLocator,
    ) -> Result<(), IdentityError> {
        let key = (target.clone(), endpoint.clone());
        {
            let mut cache = self.cache.lock().expect("introduction cache lock poisoned");
            cache.retain(|_, entry| entry.until > crate::now_millis());
            if let Some(entry) = cache.get(&key) {
                return entry.result.clone();
            }
            if cache.len() >= 1024 {
                return Err(IdentityError::Unavailable(
                    "introduction cache capacity reached".into(),
                ));
            }
        }
        let result = async {
            let challenge: PeerChallengeResponse = self
                .post(
                    endpoint,
                    "/federation/peer/challenge",
                    &PeerChallengeRequest {
                        descriptor: self.descriptor.to_wire_v1()?,
                        authority_locator: self.authority_locator.clone(),
                    },
                )
                .await?;
            if &challenge.responder_node != target
                || challenge.expires_at <= crate::now_millis()
                || challenge.expires_at > crate::now_millis().saturating_add(120_000)
                || challenge.challenge_id.len() != 43
                || challenge.nonce.len() != 43
            {
                return Err(IdentityError::KeyPinMismatch);
            }
            let proof = PeerIntroductionRequest::sign(&challenge, &self.descriptor, identity)?;
            let receipt: PeerAdmissionReceipt = self
                .post(endpoint, "/federation/peer/introduce", &proof)
                .await?;
            if receipt.node != *identity.node_id() || receipt.expires_at <= crate::now_millis() {
                return Err(IdentityError::KeyPinMismatch);
            }
            Ok(receipt.expires_at)
        }
        .await;
        let until = result
            .as_ref()
            .copied()
            .unwrap_or_else(|_| crate::now_millis().saturating_add(30_000));
        let result = result.map(|_| ());
        self.cache
            .lock()
            .expect("introduction cache lock poisoned")
            .insert(
                key,
                CachedIntroduction {
                    until,
                    result: result.clone(),
                },
            );
        result
    }
}
