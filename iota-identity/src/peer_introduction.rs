use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::crypto::SignatureScheme;
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityLocator, IdentityError, IotaNodeId, LocalNodeIdentity, NodeDescriptorWireV1,
    SignedNodeDescriptor,
};

/// Local authorization for a node key, separate from MTP's proof of possession.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerTrust {
    Established {
        node: IotaNodeId,
        revision: i64,
        valid_until: Option<i64>,
    },
    Provisional {
        node: IotaNodeId,
        revision: i64,
        admitted_at: i64,
        expires_at: i64,
    },
}

impl PeerTrust {
    pub fn node(&self) -> &IotaNodeId {
        match self {
            Self::Established { node, .. } | Self::Provisional { node, .. } => node,
        }
    }

    pub fn is_established_at(&self, now: i64) -> bool {
        matches!(self, Self::Established { valid_until, .. } if valid_until.is_none_or(|until| until > now))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerChallengeRequest {
    pub descriptor: NodeDescriptorWireV1,
    pub authority_locator: Option<AuthorityLocator>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerChallengeResponse {
    pub challenge_id: String,
    pub nonce: String,
    pub expires_at: i64,
    pub responder_node: IotaNodeId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIntroductionRequest {
    pub challenge_id: String,
    pub descriptor: NodeDescriptorWireV1,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAdmissionReceipt {
    pub node: IotaNodeId,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerIntroductionLimits {
    pub max_request_bytes: usize,
    pub max_concurrent_requests: usize,
    pub request_timeout_ms: u64,
    pub challenge_lifetime_ms: i64,
    pub admission_lifetime_ms: i64,
    pub max_pending_challenges: usize,
    pub max_challenges_per_origin: usize,
    pub max_admissions: usize,
}

impl Default for PeerIntroductionLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 64 * 1024,
            max_concurrent_requests: 8,
            request_timeout_ms: 15_000,
            challenge_lifetime_ms: 60_000,
            admission_lifetime_ms: 300_000,
            max_pending_challenges: 1024,
            max_challenges_per_origin: 8,
            max_admissions: 1024,
        }
    }
}

pub fn descriptor_digest(descriptor: &SignedNodeDescriptor) -> Result<[u8; 32], IdentityError> {
    let mut bytes = crate::node_descriptor_bytes(&descriptor.descriptor)?;
    crate::push_bytes(&mut bytes, &descriptor.node_signature)?;
    Ok(mtp::crypto::sha256(&bytes))
}

pub fn introduction_preimage(
    challenge: &PeerChallengeResponse,
    descriptor: &SignedNodeDescriptor,
) -> Result<Vec<u8>, IdentityError> {
    let mut bytes = b"tensamin-peer-introduction\0".to_vec();
    for field in [
        challenge.challenge_id.as_bytes(),
        challenge.nonce.as_bytes(),
        descriptor.descriptor.node.as_str().as_bytes(),
        challenge.responder_node.as_str().as_bytes(),
    ] {
        crate::push_bytes(&mut bytes, field)?;
    }
    bytes.extend_from_slice(&challenge.expires_at.to_be_bytes());
    bytes.extend_from_slice(&descriptor_digest(descriptor)?);
    Ok(bytes)
}

impl PeerIntroductionRequest {
    pub fn sign(
        challenge: &PeerChallengeResponse,
        descriptor: &SignedNodeDescriptor,
        identity: &LocalNodeIdentity,
    ) -> Result<Self, IdentityError> {
        if descriptor.descriptor.node != *identity.node_id() {
            return Err(IdentityError::KeyPinMismatch);
        }
        let key = identity.keyring();
        let signer = mtp::crypto::DualSigner::new(
            &key.sig_cl_secret_key,
            &key.sig_pq_secret_key,
            &key.sig_pq_public_key,
        )
        .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
        let signature = signer
            .sign(&introduction_preimage(challenge, descriptor)?)
            .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
        Ok(Self {
            challenge_id: challenge.challenge_id.clone(),
            descriptor: descriptor.to_wire_v1()?,
            signature: STANDARD.encode(signature),
        })
    }

    pub fn verify(
        &self,
        challenge: &PeerChallengeResponse,
    ) -> Result<SignedNodeDescriptor, IdentityError> {
        if self.challenge_id != challenge.challenge_id {
            return Err(IdentityError::KeyPinMismatch);
        }
        let descriptor = self.descriptor.clone().parse()?;
        let signature = STANDARD
            .decode(&self.signature)
            .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
        crate::verify_dual_signature(
            &descriptor.descriptor.public_keys,
            &introduction_preimage(challenge, &descriptor)?,
            &signature,
        )?;
        Ok(descriptor)
    }
}

#[async_trait::async_trait]
pub trait PeerIntroductionService: Send + Sync {
    async fn challenge(
        &self,
        body: Vec<u8>,
        origin: std::net::IpAddr,
    ) -> Result<PeerChallengeResponse, IdentityError>;
    async fn introduce(&self, body: Vec<u8>) -> Result<PeerAdmissionReceipt, IdentityError>;
}
