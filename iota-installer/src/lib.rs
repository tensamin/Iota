use anyhow::{Context, Result, bail};
use std::{fs, io, path::Path, process::Command};
use tempfile::tempdir;
use zip::ZipArchive;

const REQUIRED: &[&str] = &[
    "bin/iota",
    "bin/iota-daemon",
    "bin/iota-updater",
    "systemd/iota-daemon.service",
    "systemd/iota-daemon.socket",
    "systemd/sysusers.d/iota.conf",
    "systemd/iota-update.service",
    "systemd/iota-update.timer",
    "manifest.json",
];

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
    let file = fs::File::open(bundle).context("open release bundle")?;
    let mut archive = ZipArchive::new(file).context("read release bundle")?;
    for name in REQUIRED {
        let mut entry = archive
            .by_name(name)
            .with_context(|| format!("bundle is missing {name}"))?;
        let output = staging.path().join(name);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&output)?;
        io::copy(&mut entry, &mut out)?;
    }

    install(
        &staging.path().join("bin/iota"),
        &format!(
            "{}/versions/{}/bin/iota",
            iota_paths::install_root().display(),
            product_version(staging.path())
        ),
        "0755",
    )?;
    install(
        &staging.path().join("bin/iota-daemon"),
        &format!(
            "{}/versions/{}/bin/iota-daemon",
            iota_paths::install_root().display(),
            product_version(staging.path())
        ),
        "0755",
    )?;
    let version_dir = format!(
        "{}/versions/{}",
        iota_paths::install_root().display(),
        product_version(staging.path())
    );
    if !Path::new(&format!("{version_dir}/bin/iota-daemon")).is_file() {
        bail!("installed daemon executable is missing: {version_dir}/bin/iota-daemon");
    }
    install(
        &staging.path().join("bin/iota-updater"),
        &format!(
            "{}/versions/{}/bin/iota-updater",
            iota_paths::install_root().display(),
            product_version(staging.path())
        ),
        "0755",
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
            "/usr/local/libexec/iota/iota-daemon",
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
    run("systemctl", &["is-active", "iota-daemon.socket"])?;
    run("systemctl", &["is-enabled", "iota-daemon.socket"])?;
    let socket = iota_paths::socket_path(iota_paths::Scope::System);
    if !socket.exists() {
        bail!(
            "systemd socket is active but {} was not created",
            socket.display()
        );
    }
    Ok(())
}

fn product_version(staging: &Path) -> String {
    fs::read_to_string(staging.join("manifest.json"))
        .ok()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
        .and_then(|value| {
            value
                .get("product_version")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unversioned".into())
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
