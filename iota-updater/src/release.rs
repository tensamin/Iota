use super::*;

pub(super) async fn configured_release() -> Result<Option<ConfiguredRelease>> {
    let config = config::load()?;
    configured_release_from_locations(
        &config[MANIFEST_ENV],
        &config[SIGNATURE_ENV],
        &config[PUBLIC_KEY_ENV],
    )
    .await
    .map(Some)
}

pub(super) async fn configured_release_from_locations(
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

pub(super) fn select_host_artifacts(
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

pub(super) fn required_host_artifacts() -> Result<Vec<(&'static str, &'static str)>> {
    REQUIRED_HOST_ARTIFACTS
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split_once('\t')
                .context("invalid embedded updater artifact contract")
        })
        .collect()
}

pub(super) async fn read_location(location: &str) -> Result<Vec<u8>> {
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

pub(super) async fn download_to_temporary_file(location: &str) -> Result<tempfile::NamedTempFile> {
    let file = tempfile::NamedTempFile::new().context("create temporary update artifact")?;
    fs::write(file.path(), read_location(location).await?)
        .with_context(|| format!("write downloaded update artifact from {location}"))?;
    Ok(file)
}

pub(super) fn current_version(install_root: &Path) -> Result<Option<String>> {
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

pub(super) fn current_channel_version(
    install_root: &Path,
    channel: &str,
) -> Result<Option<String>> {
    let manifest = read_installed_manifest(&install_root.join("current"))?;
    Ok((manifest.channel == channel).then_some(manifest.product_version))
}

pub(super) fn read_installed_manifest(release_dir: &Path) -> Result<ReleaseManifest> {
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

pub(super) fn validate_manifest_compatibility(
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

pub(super) fn validate_rollback_manifests(
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

pub(super) fn installed_data_schema(database_path: &Path) -> Result<Option<u64>> {
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

pub(super) fn validate_version(version: &str) -> Result<()> {
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
