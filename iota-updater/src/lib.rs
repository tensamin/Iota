pub mod manifest;
pub mod transaction;

use anyhow::{Context, Result, bail};
use manifest::{Artifact, ReleaseManifest, verify_signature};
use std::{fs, path::Path};
use transaction::UpdateTransaction;

const MANIFEST_ENV: &str = "IOTA_UPDATE_MANIFEST";
const SIGNATURE_ENV: &str = "IOTA_UPDATE_SIGNATURE";
const PUBLIC_KEY_ENV: &str = "IOTA_UPDATE_PUBLIC_KEY";
const REQUIRED_HOST_ARTIFACTS: &str = include_str!("../artifacts.tsv");

/// Reads the configured signed release manifest and reports whether it differs
/// from the release currently selected by the installation's `current` link.
/// A configured manifest always requires `IOTA_UPDATE_PUBLIC_KEY` (32-byte hex)
/// and a hex signature, supplied by `IOTA_UPDATE_SIGNATURE` or `<manifest>.sig`.
pub async fn check_update() -> Result<bool> {
    let Some(release) = configured_release().await? else {
        return Ok(false);
    };
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(current_version(&paths.install_root)?.as_deref() != Some(&release.manifest.product_version))
}

/// Downloads, verifies, stages, and atomically activates the configured release.
/// Returns `false` when no manifest is configured or it already is current.
pub async fn apply_update() -> Result<bool> {
    let Some(release) = configured_release().await? else {
        return Ok(false);
    };
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    if current_version(&paths.install_root)?.as_deref() == Some(&release.manifest.product_version) {
        return Ok(false);
    }
    validate_manifest_compatibility(
        &release.manifest,
        &paths.database_file(),
        iota_ipc::MIN_PROTOCOL_VERSION,
        iota_ipc::PROTOCOL_VERSION,
    )?;

    let transaction = UpdateTransaction::from_paths(&paths)?;
    let _lock = transaction.acquire()?;
    if transaction.staging.exists() {
        fs::remove_dir_all(&transaction.staging).with_context(|| {
            format!(
                "remove stale update staging directory {}",
                transaction.staging.display()
            )
        })?;
    }
    for artifact in &release.artifacts {
        let source = download_to_temporary_file(&artifact.url).await?;
        transaction.stage_artifact(source.path(), artifact)?;
    }
    fs::write(
        transaction.staging.join("manifest.json"),
        serde_json::to_vec_pretty(&release.manifest)?,
    )
    .context("write staged release manifest")?;
    transaction.activate(&release.manifest.product_version)?;
    Ok(true)
}

/// Switches `current` to an already-installed release version.
pub fn rollback(version: &str) -> Result<()> {
    validate_version(version)?;
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    let transaction = UpdateTransaction::from_paths(&paths)?;
    let _lock = transaction.acquire()?;
    let release_dir = transaction.root.join("versions").join(version);
    if !release_dir.is_dir() {
        bail!(
            "installed release version does not exist: {}",
            release_dir.display()
        );
    }
    let active_manifest = read_installed_manifest(&transaction.root.join("current"))?;
    let target_manifest = read_installed_manifest(&release_dir)?;
    validate_rollback_manifests(&active_manifest, &target_manifest, version)?;
    validate_manifest_compatibility(
        &target_manifest,
        &paths.database_file(),
        iota_ipc::MIN_PROTOCOL_VERSION,
        iota_ipc::PROTOCOL_VERSION,
    )?;
    transaction.rollback(version)
}

struct ConfiguredRelease {
    manifest: ReleaseManifest,
    artifacts: Vec<Artifact>,
}

async fn configured_release() -> Result<Option<ConfiguredRelease>> {
    let Some(manifest_location) = std::env::var_os(MANIFEST_ENV) else {
        return Ok(None);
    };
    let manifest_location = manifest_location
        .into_string()
        .map_err(|_| anyhow::anyhow!("{MANIFEST_ENV} must be valid UTF-8"))?;
    if manifest_location.is_empty() {
        bail!("{MANIFEST_ENV} must not be empty");
    }
    let signature_location =
        std::env::var(SIGNATURE_ENV).unwrap_or_else(|_| format!("{manifest_location}.sig"));
    let key_text = std::env::var(PUBLIC_KEY_ENV)
        .with_context(|| format!("{PUBLIC_KEY_ENV} is required when {MANIFEST_ENV} is set"))?;
    configured_release_from_locations(&manifest_location, &signature_location, &key_text)
        .await
        .map(Some)
}

async fn configured_release_from_locations(
    manifest_location: &str,
    signature_location: &str,
    key_text: &str,
) -> Result<ConfiguredRelease> {
    let manifest_bytes = read_location(manifest_location).await?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).context("parse release manifest")?;
    validate_version(&manifest.product_version)?;
    let signature_text = String::from_utf8(read_location(signature_location).await?)
        .context("release signature must be UTF-8 hex")?;
    let signature = hex::decode(signature_text.trim()).context("decode release signature hex")?;
    let key = hex::decode(key_text.trim()).context("decode release public key hex")?;
    let public_key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("release public key must be 32 bytes"))?;
    verify_signature(&manifest, &signature, &public_key)?;
    let artifacts = select_host_artifacts(&manifest, std::env::consts::OS, std::env::consts::ARCH)?;
    Ok(ConfiguredRelease {
        manifest,
        artifacts,
    })
}

fn select_host_artifacts(
    manifest: &ReleaseManifest,
    operating_system: &str,
    architecture: &str,
) -> Result<Vec<Artifact>> {
    let requirements = required_host_artifacts()?;
    let artifacts: Vec<Artifact> = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.os == operating_system && artifact.architecture == architecture)
        .cloned()
        .collect();

    for artifact in &artifacts {
        if !requirements
            .iter()
            .any(|(role, path)| *role == artifact.role.as_str() && *path == artifact.path.as_str())
        {
            bail!(
                "release has unexpected artifact role/path for {operating_system}/{architecture}: {}/{}",
                artifact.role,
                artifact.path
            );
        }
    }
    for (role, path) in &requirements {
        let count = artifacts
            .iter()
            .filter(|artifact| artifact.role == *role && artifact.path == *path)
            .count();
        if count != 1 {
            bail!(
                "release must contain exactly one {role} artifact at {path} for {operating_system}/{architecture}; found {count}"
            );
        }
    }
    if artifacts.len() != requirements.len() {
        bail!(
            "release has an invalid artifact count for {operating_system}/{architecture}: expected {}, found {}",
            requirements.len(),
            artifacts.len()
        );
    }
    Ok(artifacts)
}

fn required_host_artifacts() -> Result<Vec<(&'static str, &'static str)>> {
    REQUIRED_HOST_ARTIFACTS
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split_once('\t')
                .context("invalid embedded updater artifact contract")
        })
        .collect()
}

async fn read_location(location: &str) -> Result<Vec<u8>> {
    if location.starts_with("https://") || location.starts_with("http://") {
        let response = reqwest::get(location)
            .await
            .with_context(|| format!("download {location}"))?
            .error_for_status()
            .with_context(|| format!("download {location}"))?;
        return Ok(response.bytes().await?.to_vec());
    }
    let path = location.strip_prefix("file://").unwrap_or(location);
    fs::read(path).with_context(|| format!("read update input {path}"))
}

async fn download_to_temporary_file(location: &str) -> Result<tempfile::NamedTempFile> {
    let file = tempfile::NamedTempFile::new().context("create temporary update artifact")?;
    fs::write(file.path(), read_location(location).await?)
        .with_context(|| format!("write downloaded update artifact from {location}"))?;
    Ok(file)
}

fn current_version(install_root: &Path) -> Result<Option<String>> {
    let manifest_path = install_root.join("current/manifest.json");
    if !manifest_path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "read installed release manifest {}",
            manifest_path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse installed release manifest {}",
            manifest_path.display()
        )
    })?;
    Ok(value
        .get("product_version")
        .and_then(|value| value.as_str())
        .map(str::to_owned))
}

fn read_installed_manifest(release_dir: &Path) -> Result<ReleaseManifest> {
    let manifest_path = release_dir.join("manifest.json");
    let bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "read installed release manifest {}",
            manifest_path.display()
        )
    })?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse installed release manifest {}",
            manifest_path.display()
        )
    })
}

fn validate_manifest_compatibility(
    manifest: &ReleaseManifest,
    database_path: &Path,
    installed_ipc_min: u16,
    installed_ipc_max: u16,
) -> Result<()> {
    if manifest.supported_ipc_min > manifest.supported_ipc_max {
        bail!(
            "release has an invalid IPC range: {}..={}",
            manifest.supported_ipc_min,
            manifest.supported_ipc_max
        );
    }
    if installed_ipc_min > installed_ipc_max {
        bail!("installed Iota has an invalid IPC compatibility range");
    }
    if manifest.supported_ipc_max < installed_ipc_min
        || manifest.supported_ipc_min > installed_ipc_max
    {
        bail!(
            "release IPC range {}..={} is incompatible with installed range {}..={}",
            manifest.supported_ipc_min,
            manifest.supported_ipc_max,
            installed_ipc_min,
            installed_ipc_max
        );
    }

    if let Some(installed_schema) = installed_data_schema(database_path)?
        && installed_schema < manifest.minimum_data_schema
    {
        bail!(
            "release requires data schema {} or newer, but installed database uses schema {}",
            manifest.minimum_data_schema,
            installed_schema
        );
    }
    Ok(())
}

fn validate_rollback_manifests(
    active: &ReleaseManifest,
    target: &ReleaseManifest,
    requested_version: &str,
) -> Result<()> {
    if !active.rollback_compatible {
        bail!(
            "active release {} does not permit rollback",
            active.product_version
        );
    }
    if target.product_version != requested_version {
        bail!(
            "rollback target manifest version {} does not match requested version {requested_version}",
            target.product_version
        );
    }
    Ok(())
}

fn installed_data_schema(database_path: &Path) -> Result<Option<u64>> {
    if !database_path.exists() {
        return Ok(None);
    }
    let connection = rusqlite::Connection::open_with_flags(
        database_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open installed database {}", database_path.display()))?;
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .with_context(|| format!("read data schema from {}", database_path.display()))?;
    let user_version = user_version.try_into().with_context(|| {
        format!(
            "installed database has a negative data schema: {}",
            database_path.display()
        )
    })?;
    Ok(Some(user_version))
}

fn validate_version(version: &str) -> Result<()> {
    let mut characters = version.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '+' | '_' | '-')
        })
    {
        bail!("release product_version contains unsupported characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn artifact(role: &str, path: &str, os: &str, architecture: &str) -> Artifact {
        Artifact {
            role: role.into(),
            os: os.into(),
            architecture: architecture.into(),
            path: path.into(),
            url: format!("file:///release/{}", path.replace('/', "-")),
            sha256: "00".repeat(32),
            size: 1,
        }
    }

    fn release_manifest(artifacts: Vec<Artifact>) -> ReleaseManifest {
        ReleaseManifest {
            product_version: "1.2.3".into(),
            channel: "stable".into(),
            published_at: "2026-09-10T00:00:00Z".into(),
            minimum_data_schema: 1,
            supported_ipc_min: 1,
            supported_ipc_max: 1,
            artifacts,
            release_signing_key_id: "test".into(),
            rollback_compatible: true,
        }
    }

    fn host_artifacts() -> Vec<Artifact> {
        required_host_artifacts()
            .unwrap()
            .into_iter()
            .map(|(role, path)| artifact(role, path, std::env::consts::OS, std::env::consts::ARCH))
            .collect()
    }

    #[tokio::test]
    async fn loads_a_signed_manifest_and_selects_complete_host_release() {
        let directory = tempfile::tempdir().unwrap();
        let mut artifacts = host_artifacts();
        artifacts.push(artifact("daemon", "bin/iota-daemon", "other", "other"));
        let manifest = release_manifest(artifacts);
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature = signing_key.sign(&manifest::canonical_bytes(&manifest).unwrap());
        let manifest_path = directory.path().join("manifest.json");
        let signature_path = directory.path().join("manifest.json.sig");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(&signature_path, hex::encode(signature.to_bytes())).unwrap();

        let release = configured_release_from_locations(
            manifest_path.to_str().unwrap(),
            signature_path.to_str().unwrap(),
            &hex::encode(signing_key.verifying_key().to_bytes()),
        )
        .await
        .unwrap();

        assert_eq!(release.manifest.product_version, "1.2.3");
        assert_eq!(release.artifacts.len(), 3);
        assert!(
            release
                .artifacts
                .iter()
                .all(|artifact| artifact.os == std::env::consts::OS)
        );
    }

    #[test]
    fn rejects_host_release_missing_an_executable() {
        let mut artifacts = host_artifacts();
        artifacts.retain(|artifact| artifact.path != "bin/iota-updater");
        let manifest = release_manifest(artifacts);

        let error = select_host_artifacts(&manifest, std::env::consts::OS, std::env::consts::ARCH)
            .unwrap_err();

        assert!(error.to_string().contains("bin/iota-updater"));
    }

    #[test]
    fn rejects_duplicate_or_unexpected_host_artifacts() {
        let mut duplicate = host_artifacts();
        duplicate.push(duplicate[0].clone());
        let duplicate_error = select_host_artifacts(
            &release_manifest(duplicate),
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
        .unwrap_err();
        assert!(duplicate_error.to_string().contains("exactly one"));

        let mut unexpected = host_artifacts();
        unexpected.push(artifact(
            "helper",
            "bin/iota-helper",
            std::env::consts::OS,
            std::env::consts::ARCH,
        ));
        let unexpected_error = select_host_artifacts(
            &release_manifest(unexpected),
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
        .unwrap_err();
        assert!(unexpected_error.to_string().contains("unexpected artifact"));
    }

    #[test]
    fn rejects_manifest_without_an_overlapping_ipc_range() {
        let directory = tempfile::tempdir().unwrap();
        let mut manifest = release_manifest(host_artifacts());
        manifest.supported_ipc_min = 5;
        manifest.supported_ipc_max = 6;

        let error =
            validate_manifest_compatibility(&manifest, &directory.path().join("missing.db"), 2, 4)
                .unwrap_err();

        assert!(error.to_string().contains("incompatible"));
    }

    #[test]
    fn rejects_manifest_requiring_a_newer_installed_data_schema() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("messages.sqlite3");
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection.pragma_update(None, "user_version", 25).unwrap();
        let mut manifest = release_manifest(host_artifacts());
        manifest.minimum_data_schema = 26;
        manifest.supported_ipc_min = 2;
        manifest.supported_ipc_max = 4;

        let error = validate_manifest_compatibility(&manifest, &database, 2, 4).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("installed database uses schema 25")
        );
    }

    #[test]
    fn accepts_compatible_manifest_when_no_database_exists() {
        let directory = tempfile::tempdir().unwrap();
        let mut manifest = release_manifest(host_artifacts());
        manifest.minimum_data_schema = 26;
        manifest.supported_ipc_min = 4;
        manifest.supported_ipc_max = 5;

        validate_manifest_compatibility(&manifest, &directory.path().join("missing.db"), 2, 4)
            .unwrap();
    }

    #[test]
    fn rejects_rollback_when_active_release_disallows_it() {
        let mut active = release_manifest(host_artifacts());
        active.rollback_compatible = false;
        let mut target = release_manifest(host_artifacts());
        target.product_version = "1.1.0".into();

        let error = validate_rollback_manifests(&active, &target, "1.1.0").unwrap_err();

        assert!(error.to_string().contains("does not permit rollback"));
    }
}
