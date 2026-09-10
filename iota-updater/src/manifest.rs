use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub product_version: String,
    pub channel: String,
    pub release_sequence: u64,
    pub published_at: String,
    pub expires_at: String,
    pub minimum_data_schema: u64,
    pub supported_ipc_min: u16,
    pub supported_ipc_max: u16,
    pub artifacts: Vec<Artifact>,
    pub release_signing_key_id: String,
    pub rollback_compatible: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub role: String,
    pub os: String,
    pub architecture: String,
    pub path: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

pub fn canonical_bytes(manifest: &ReleaseManifest) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(manifest)?)
}
pub fn verify_signature(
    manifest: &ReleaseManifest,
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key).context("invalid release public key")?;
    let signature = Signature::from_slice(signature).context("invalid release signature")?;
    key.verify(&canonical_bytes(manifest)?, &signature)
        .context("release manifest signature verification failed")
}
pub fn verify_artifact(path: &std::path::Path, artifact: &Artifact) -> Result<()> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() != artifact.size {
        bail!("artifact size mismatch for {}", artifact.path);
    }
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual != artifact.sha256.to_ascii_lowercase() {
        bail!("artifact hash mismatch for {}", artifact.path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_size_or_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iota-daemon");
        std::fs::write(&path, b"daemon").unwrap();
        let artifact = Artifact {
            role: "daemon".into(),
            os: "linux".into(),
            architecture: "x86_64".into(),
            path: "bin/iota-daemon".into(),
            url: "https://example.invalid".into(),
            sha256: "00".repeat(32),
            size: 6,
        };
        assert!(verify_artifact(&path, &artifact).is_err());
    }
}
