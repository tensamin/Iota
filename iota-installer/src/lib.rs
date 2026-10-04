use anyhow::{Context, Result, bail};
use std::{fs, io, path::Path, process::Command};
use tempfile::tempdir;
use zip::ZipArchive;

const REQUIRED: &str = include_str!("../bundle-files.txt");
const DAEMON_EXECUTABLE_PLACEHOLDER: &str = "@IOTA_SYSTEM_DAEMON_EXECUTABLE@";

pub fn validate_linux_bundle(bundle: &Path) -> Result<()> {
    let staging = tempdir().context("create bundle validation directory")?;
    extract_linux_bundle(bundle, staging.path())?;
    product_version(staging.path())?;
    validate_update_environment(staging.path())?;
    Ok(())
}

pub fn install_linux_bundle(bundle: &Path) -> Result<()> {
    install_linux_bundle_with_operator(bundle, None)
}

pub fn bootstrap_linux_bundle(bundle: &Path, operator: Option<&str>) -> Result<()> {
    install_linux_bundle_with_operator(bundle, operator)
}

pub fn install_linux_bundle_with_operator(bundle: &Path, operator: Option<&str>) -> Result<()> {
    if std::env::consts::OS != "linux" {
        bail!("Linux systemd bundles are not supported on this platform");
    }
    let staging = tempdir().context("create installer staging directory")?;
    extract_linux_bundle(bundle, staging.path())?;
    let product_version = product_version(staging.path())?;
    validate_update_environment(staging.path())?;

    for directory in ["/usr/local/lib/systemd/system", "/etc/systemd/system"] {
        let timer = Path::new(directory).join("iota-update.timer");
        if timer.exists() {
            run("systemctl", &["disable", "--now", "iota-update.timer"])?;
            fs::remove_file(timer).context("remove legacy unattended update timer")?;
        }
    }

    render_daemon_service(&staging.path().join("systemd/iota-daemon.service"))?;

    let version_dir = format!(
        "{}/versions/{product_version}",
        iota_paths::install_root().display()
    );
    install(
        &staging.path().join("bin/iota"),
        &format!("{version_dir}/bin/iota"),
        "0755",
    )?;
    install(
        &staging.path().join("bin/iota-daemon"),
        &format!("{version_dir}/bin/iota-daemon"),
        "0755",
    )?;
    if !Path::new(&format!("{version_dir}/bin/iota-daemon")).is_file() {
        bail!("installed daemon executable is missing: {version_dir}/bin/iota-daemon");
    }
    install(
        &staging.path().join("bin/iota-updater"),
        &format!("{version_dir}/bin/iota-updater"),
        "0755",
    )?;
    install(
        &staging.path().join("manifest.json"),
        &format!("{version_dir}/manifest.json"),
        "0644",
    )?;
    for unit in [
        "iota-daemon.service",
        "iota-daemon.socket",
        "iota-update.service",
        "iota-update.timer",
    ] {
        install(
            &staging.path().join("systemd").join(unit),
            &format!("/usr/local/lib/systemd/system/{unit}"),
            "0644",
        )?;
    }
    install(
        &staging.path().join("systemd/sysusers.d/iota.conf"),
        "/etc/sysusers.d/iota.conf",
        "0644",
    )?;
    install(
        &staging.path().join("systemd/update.env"),
        "/etc/iota/update.env",
        "0644",
    )?;
    run(
        "ln",
        &[
            "-sfn",
            &version_dir,
            &iota_paths::current_version_link().to_string_lossy(),
        ],
    )?;
    run(
        "ln",
        &[
            "-sfn",
            &format!("{}/current/bin/iota", iota_paths::install_root().display()),
            "/usr/local/bin/iota",
        ],
    )?;
    run(
        "ln",
        &[
            "-sfn",
            &format!(
                "{}/current/bin/iota-daemon",
                iota_paths::install_root().display()
            ),
            iota_paths::SYSTEM_DAEMON_EXECUTABLE,
        ],
    )?;
    run("systemd-sysusers", &[])?;
    for directory in ["/var/lib/iota", "/var/cache/iota", "/var/log/iota"] {
        run(
            "install",
            &["-d", "-m", "0750", "-o", "iota", "-g", "iota", directory],
        )?;
    }
    if let Some(operator) = operator {
        run("usermod", &["-aG", "iota-operators", operator])?;
    } else {
        eprintln!("To grant socket access, run: usermod -aG iota-operators USER");
        eprintln!(
            "A new login session is required before supplementary group membership is visible."
        );
    }
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", "iota-daemon.socket"])?;
    run("systemctl", &["enable", "--now", "iota-update.timer"])?;
    run("systemctl", &["is-active", "iota-daemon.socket"])?;
    run("systemctl", &["is-enabled", "iota-daemon.socket"])?;
    run("systemctl", &["is-enabled", "iota-update.timer"])?;
    let socket = iota_paths::socket_path(iota_paths::Scope::System);
    if !socket.exists() {
        bail!(
            "systemd socket is active but {} was not created",
            socket.display()
        );
    }
    Ok(())
}

fn extract_linux_bundle(bundle: &Path, staging: &Path) -> Result<()> {
    let file = fs::File::open(bundle).context("open release bundle")?;
    let mut archive = ZipArchive::new(file).context("read release bundle")?;
    for name in REQUIRED.lines().filter(|name| !name.is_empty()) {
        let mut entry = archive
            .by_name(name)
            .with_context(|| format!("bundle is missing {name}"))?;
        let output = staging.join(name);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&output)?;
        io::copy(&mut entry, &mut out)?;
    }
    Ok(())
}

fn render_daemon_service(path: &Path) -> Result<()> {
    let template = fs::read_to_string(path)
        .with_context(|| format!("read systemd unit template {}", path.display()))?;
    let placeholder_count = template.matches(DAEMON_EXECUTABLE_PLACEHOLDER).count();
    if placeholder_count != 1 {
        bail!(
            "systemd unit template {} must contain exactly one {DAEMON_EXECUTABLE_PLACEHOLDER} placeholder, found {placeholder_count}",
            path.display()
        );
    }
    fs::write(
        path,
        template.replace(
            DAEMON_EXECUTABLE_PLACEHOLDER,
            iota_paths::SYSTEM_DAEMON_EXECUTABLE,
        ),
    )
    .with_context(|| format!("render systemd unit {}", path.display()))
}

fn product_version(staging: &Path) -> Result<String> {
    let manifest_path = staging.join("manifest.json");
    let contents = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read bundle manifest {}", manifest_path.display()))?;
    let manifest: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parse bundle manifest {}", manifest_path.display()))?;
    for name in [
        "product_version",
        "channel",
        "published_at",
        "expires_at",
        "release_signing_key_id",
    ] {
        manifest
            .get(name)
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .with_context(|| format!("bundle manifest {name} must be a non-empty string"))?;
    }
    for name in [
        "release_sequence",
        "minimum_data_schema",
        "supported_ipc_min",
        "supported_ipc_max",
    ] {
        let value = manifest
            .get(name)
            .and_then(|value| value.as_u64())
            .with_context(|| format!("bundle manifest {name} must be an unsigned integer"))?;
        if name == "release_sequence" && value == 0 {
            bail!("bundle manifest release_sequence must be greater than zero");
        }
    }
    manifest
        .get("artifacts")
        .and_then(|value| value.as_array())
        .context("bundle manifest artifacts must be an array")?;
    manifest
        .get("rollback_compatible")
        .and_then(|value| value.as_bool())
        .context("bundle manifest rollback_compatible must be a boolean")?;
    let version = manifest
        .get("product_version")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .context("bundle manifest product_version must be a non-empty string")?;
    let mut characters = version.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '+' | '_' | '-')
        })
    {
        bail!("bundle manifest product_version contains unsupported characters");
    }
    Ok(version.to_owned())
}

fn validate_update_environment(staging: &Path) -> Result<()> {
    let path = staging.join("systemd/update.env");
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("read updater environment {}", path.display()))?;
    let mut entries = std::collections::BTreeMap::new();
    for line in contents.lines().filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once('=')
            .with_context(|| format!("invalid updater environment entry in {}", path.display()))?;
        if entries.insert(name, value).is_some() {
            bail!("duplicate updater environment variable {name}");
        }
    }
    for name in [
        "IOTA_UPDATE_MANIFEST",
        "IOTA_UPDATE_PUBLIC_KEY",
        "IOTA_UPDATE_SIGNATURE",
        "IOTA_UPDATE_CHANNEL",
        "IOTA_UPDATE_SIGNING_KEY_ID",
    ] {
        let value = entries
            .get(name)
            .filter(|value| !value.is_empty())
            .with_context(|| format!("updater environment is missing {name}"))?;
        if value.chars().any(char::is_whitespace) {
            bail!("updater environment variable {name} contains whitespace");
        }
    }
    if entries.len() != 5 {
        bail!("updater environment contains unexpected variables");
    }
    if !matches!(entries["IOTA_UPDATE_CHANNEL"], "stable" | "canary") {
        bail!("update channel must be stable or canary");
    }
    let public_key = entries
        .get("IOTA_UPDATE_PUBLIC_KEY")
        .context("updater environment is missing IOTA_UPDATE_PUBLIC_KEY")?;
    if public_key.len() != 64
        || !public_key
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("IOTA_UPDATE_PUBLIC_KEY must be 32-byte hex");
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(staging.join("manifest.json")).context("read bundle manifest")?,
    )
    .context("parse bundle manifest")?;
    for (environment_name, manifest_name) in [
        ("IOTA_UPDATE_CHANNEL", "channel"),
        ("IOTA_UPDATE_SIGNING_KEY_ID", "release_signing_key_id"),
    ] {
        let environment_value = entries
            .get(environment_name)
            .with_context(|| format!("updater environment is missing {environment_name}"))?;
        let manifest_value = manifest
            .get(manifest_name)
            .and_then(|value| value.as_str())
            .with_context(|| format!("bundle manifest is missing {manifest_name}"))?;
        if *environment_value != manifest_value {
            bail!(
                "updater environment {environment_name} does not match bundle manifest {manifest_name}"
            );
        }
    }
    Ok(())
}

fn install(source: &Path, destination: &str, mode: &str) -> Result<()> {
    run(
        "install",
        &["-D", "-m", mode, &source.to_string_lossy(), destination],
    )
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("run {program}"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{program} failed; run the installer as root")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn write_bundle(path: &Path, omitted: Option<&str>, product_version: &str) {
        let file = fs::File::create(path).unwrap();
        let mut archive = ZipWriter::new(file);
        for name in REQUIRED.lines().filter(|name| !name.is_empty()) {
            if omitted == Some(name) {
                continue;
            }
            archive
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            if name == "manifest.json" {
                let manifest = serde_json::json!({
                    "product_version": product_version,
                    "channel": "stable",
                    "release_sequence": 1,
                    "published_at": "2026-09-10T00:00:00Z",
                    "expires_at": "2026-10-10T00:00:00Z",
                    "minimum_data_schema": 1,
                    "supported_ipc_min": 2,
                    "supported_ipc_max": 4,
                    "artifacts": [],
                    "release_signing_key_id": "primary",
                    "rollback_compatible": true
                });
                archive
                    .write_all(&serde_json::to_vec(&manifest).unwrap())
                    .unwrap();
            } else if name == "systemd/update.env" {
                archive
                    .write_all(
                        b"IOTA_UPDATE_MANIFEST=https://example.invalid/manifest.json\nIOTA_UPDATE_PUBLIC_KEY=0707070707070707070707070707070707070707070707070707070707070707\nIOTA_UPDATE_SIGNATURE=https://example.invalid/manifest.json.sig\nIOTA_UPDATE_CHANNEL=stable\nIOTA_UPDATE_SIGNING_KEY_ID=primary\n",
                    )
                    .unwrap();
            } else {
                archive.write_all(b"bundle member").unwrap();
            }
        }
        archive.finish().unwrap();
    }

    #[test]
    fn daemon_service_uses_the_installed_daemon_entry_point() {
        let directory = tempfile::tempdir().unwrap();
        let unit = directory.path().join("iota-daemon.service");
        fs::write(&unit, include_str!("../../systemd/iota-daemon.service")).unwrap();

        render_daemon_service(&unit).unwrap();

        let rendered = fs::read_to_string(unit).unwrap();
        assert!(rendered.contains(&format!(
            "ExecStart={}",
            iota_paths::SYSTEM_DAEMON_EXECUTABLE
        )));
        assert!(!rendered.contains(DAEMON_EXECUTABLE_PLACEHOLDER));
    }

    #[test]
    fn validates_complete_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("release.zip");
        write_bundle(&bundle, None, "0.1.0-dev-abcdef0");

        validate_linux_bundle(&bundle).unwrap();
    }

    #[test]
    fn rejects_bundle_missing_contract_member() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("release.zip");
        write_bundle(&bundle, Some("systemd/iota-update.service"), "0.1.0");

        let error = validate_linux_bundle(&bundle).unwrap_err();
        assert!(error.to_string().contains("systemd/iota-update.service"));
    }

    #[test]
    fn rejects_unsafe_product_version() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("release.zip");
        write_bundle(&bundle, None, "../../outside");

        let error = validate_linux_bundle(&bundle).unwrap_err();
        assert!(error.to_string().contains("unsupported characters"));
    }

    #[test]
    fn rejects_bundle_without_complete_updater_environment() {
        let directory = tempfile::tempdir().unwrap();
        let systemd = directory.path().join("systemd");
        fs::create_dir_all(&systemd).unwrap();
        let environment = systemd.join("update.env");
        fs::write(
            &environment,
            "IOTA_UPDATE_MANIFEST=https://example.invalid/manifest.json\n",
        )
        .unwrap();

        let error = validate_update_environment(directory.path()).unwrap_err();

        assert!(error.to_string().contains("IOTA_UPDATE_PUBLIC_KEY"));
    }

    #[test]
    fn rejects_legacy_bundle_manifest_without_sequence_baseline() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("manifest.json"),
            br#"{"product_version":"1.0.0"}"#,
        )
        .unwrap();

        let error = product_version(directory.path()).unwrap_err();

        assert!(error.to_string().contains("channel"));
    }
}
