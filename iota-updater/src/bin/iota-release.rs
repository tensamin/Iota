use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signer, SigningKey};
use iota_updater::manifest::{ReleaseManifest, canonical_bytes, verify_signature};
use std::{fs, path::Path};

const SIGNING_KEY_ENV: &str = "IOTA_RELEASE_SIGNING_KEY";

fn main() -> Result<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        bail!("usage: iota-release sign MANIFEST.json MANIFEST.json.sig");
    };
    if command != "sign" {
        bail!("usage: iota-release sign MANIFEST.json MANIFEST.json.sig");
    }
    let manifest = arguments
        .next()
        .context("usage: iota-release sign MANIFEST.json MANIFEST.json.sig")?;
    let signature = arguments
        .next()
        .context("usage: iota-release sign MANIFEST.json MANIFEST.json.sig")?;
    if arguments.next().is_some() {
        bail!("usage: iota-release sign MANIFEST.json MANIFEST.json.sig");
    }
    let public_key = sign_manifest(Path::new(&manifest), Path::new(&signature))?;
    println!("{}", hex::encode(public_key));
    Ok(())
}

fn sign_manifest(manifest_path: &Path, signature_path: &Path) -> Result<[u8; 32]> {
    let manifest_bytes = fs::read(manifest_path)
        .with_context(|| format!("read release manifest {}", manifest_path.display()))?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).context("parse release manifest")?;
    let key_text =
        std::env::var(SIGNING_KEY_ENV).with_context(|| format!("{SIGNING_KEY_ENV} is required"))?;
    let key_bytes = hex::decode(key_text.trim()).context("decode release signing key hex")?;
    let signing_key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("release signing key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    let canonical = canonical_bytes(&manifest)?;
    let signature = signing_key.sign(&canonical);
    let public_key = signing_key.verifying_key().to_bytes();
    verify_signature(&manifest, &signature.to_bytes(), &public_key)?;
    fs::write(signature_path, hex::encode(signature.to_bytes()))
        .with_context(|| format!("write release signature {}", signature_path.display()))?;
    Ok(public_key)
}
