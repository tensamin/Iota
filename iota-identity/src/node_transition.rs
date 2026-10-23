use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::crypto::SignatureScheme;
use serde::{Deserialize, Serialize};

use crate::{IdentityError, IotaNodeId, LocalNodeIdentity, PublicKeyBundle};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeTransition {
    pub previous_node: IotaNodeId,
    pub replacement_node: IotaNodeId,
    pub previous_descriptor_revision: i64,
    pub effective_at: i64,
    pub expires_at: i64,
    pub old_key_signature: String,
    pub new_key_signature: String,
}

pub struct VerifiedNodeTransition {
    transition: NodeTransition,
}

impl NodeTransition {
    fn canonical_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let mut bytes = b"tensamin-node-transition\0".to_vec();
        crate::push_bytes(&mut bytes, self.previous_node.as_str().as_bytes())?;
        crate::push_bytes(&mut bytes, self.replacement_node.as_str().as_bytes())?;
        bytes.extend_from_slice(&self.previous_descriptor_revision.to_be_bytes());
        bytes.extend_from_slice(&self.effective_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(bytes)
    }

    pub fn sign(
        previous: &LocalNodeIdentity,
        replacement: &LocalNodeIdentity,
        previous_descriptor_revision: i64,
        effective_at: i64,
        expires_at: i64,
    ) -> Result<Self, IdentityError> {
        let mut transition = Self {
            previous_node: previous.node_id().clone(),
            replacement_node: replacement.node_id().clone(),
            previous_descriptor_revision,
            effective_at,
            expires_at,
            old_key_signature: String::new(),
            new_key_signature: String::new(),
        };
        let bytes = transition.canonical_bytes()?;
        let sign = |identity: &LocalNodeIdentity| {
            let key = identity.keyring();
            mtp::crypto::DualSigner::new(
                &key.sig_cl_secret_key,
                &key.sig_pq_secret_key,
                &key.sig_pq_public_key,
            )
            .and_then(|s| s.sign(&bytes))
            .map(|v| STANDARD.encode(v))
            .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))
        };
        transition.old_key_signature = sign(previous)?;
        transition.new_key_signature = sign(replacement)?;
        Ok(transition)
    }

    pub fn verify(
        self,
        previous_key: &PublicKeyBundle,
        replacement_key: &PublicKeyBundle,
        now: i64,
    ) -> Result<VerifiedNodeTransition, IdentityError> {
        if self.previous_node == self.replacement_node
            || self.previous_descriptor_revision < 0
            || self.effective_at > now
            || self.expires_at <= now
            || self.expires_at <= self.effective_at
            || self.expires_at.saturating_sub(self.effective_at) > 30 * 24 * 60 * 60 * 1000
            || self.previous_node != IotaNodeId::from_public_keys(previous_key)?
            || self.replacement_node != IotaNodeId::from_public_keys(replacement_key)?
        {
            return Err(IdentityError::InvalidDescriptor(
                "invalid node identity transition".into(),
            ));
        }
        let bytes = self.canonical_bytes()?;
        for (key, signature) in [
            (previous_key, &self.old_key_signature),
            (replacement_key, &self.new_key_signature),
        ] {
            if signature.len() > 16 * 1024 {
                return Err(IdentityError::InvalidDescriptor(
                    "transition signature too large".into(),
                ));
            }
            let signature = STANDARD
                .decode(signature)
                .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
            crate::verify_dual_signature(key, &bytes, &signature)?;
        }
        Ok(VerifiedNodeTransition { transition: self })
    }
}

impl VerifiedNodeTransition {
    pub fn transition(&self) -> &NodeTransition {
        &self.transition
    }
}
