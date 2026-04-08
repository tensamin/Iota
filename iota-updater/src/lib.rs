/* This file is used for the auto update function for the Iota.
 * It connects to the git server from methanium and checks if
 * the version has updated inside the cargo.toml file.
 * It is made by Yolokit and pasted in by AlexEmmet */

use anyhow::{Context, Result, anyhow};
use semver::Version;
use std::fs::File;
use std::io::copy;
use tempfile::NamedTempFile;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

const API_BASE: &str = "https://git.methanium.net/api/v1";
const OWNER: &str = "Tensamin";
const REPO: &str = "Iota";

#[derive(Debug)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Debug)]
struct Asset {
    name: String,
    browser_download_url: String,
}

async fn latest_release() -> Result<Release> {
    let url = format!("{API_BASE}/repos/{OWNER}/{REPO}/releases/latest");

    let response = reqwest::get(&url)
        .await
        .context("failed to query latest release.")?;

    if !response.status().is_success() {
        return Err(anyhow!("release API returned {}", response.status()));
    }

    let text = response
        .text()
        .await
        .context("failed to read response text")?;

    let parsed = json::parse(&text).map_err(|e| anyhow!("failed to parse JSON: {}", e))?;

    let tag_name = parsed["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow!("missing tag_name"))?
        .to_string();

    let assets_json = parsed["assets"].members().collect::<Vec<_>>();

    let mut assets = Vec::new();

    for asset in assets_json {
        let name = asset["name"]
            .as_str()
            .ok_or_else(|| anyhow!("missing asset name"))?
            .to_string();

        let browser_download_url = asset["browser_download_url"]
            .as_str()
            .ok_or_else(|| anyhow!("missing download url"))?
            .to_string();

        assets.push(Asset {
            name,
            browser_download_url,
        });
    }

    Ok(Release { tag_name, assets })
}

async fn parse_tag_version(tag: &str) -> Result<Version> {
    let normalized = tag.strip_prefix('v').unwrap_or(tag);
    Ok(Version::parse(normalized)?)
}

async fn current_version() -> Result<Version> {
    Ok(Version::parse(CURRENT_VERSION)?)
}

async fn asset_name_for_current_platform() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    match (os, arch) {
        ("linux", "x86_64") => "iota-linux-x86_64".to_string(),
        ("linux", "aarch64") => "iota-linux-aarch64".to_string(),
        ("windows", "x86_64") => "iota-windows-x86_64.exe".to_string(),
        ("macos", "x86_64") => "iota-macos-x86_64".to_string(),
        ("macos", "aarch64") => "iota-macos-aarch64".to_string(),
        _ => panic!("unsupported platform: {os}/{arch}"),
    }
}

async fn download_asset(url: &str) -> Result<NamedTempFile> {
    let mut response = reqwest::get(url)
        .await
        .context("failed to download asset")?;

    if !response.status().is_success() {
        return Err(anyhow!("asset download returned {}", response.status()));
    }

    let tmp = NamedTempFile::new().context("failed to create temp file")?;
    let mut out = File::create(tmp.path()).context("failed to open temp file")?;

    let bytes = response
        .bytes()
        .await
        .context("failed to read response bytes")?;

    std::fs::write(tmp.path(), &bytes).context("failed to write file")?;

    Ok(tmp)
}

async fn check_for_update() -> Result<Option<Release>> {
    let current = current_version().await?;
    let release = latest_release().await?;
    let latest = parse_tag_version(&release.tag_name).await?;

    if latest > current {
        Ok(Some(release))
    } else {
        Ok(None)
    }
}

async fn perform_update() -> Result<bool> {
    let Some(release) = check_for_update().await? else {
        return Ok(false);
    };

    let wanted_asset = asset_name_for_current_platform().await;

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == wanted_asset)
        .ok_or_else(|| anyhow!("no matching asset found: {}", wanted_asset))?;

    log!("Downloading update: {}", asset.name);

    let downloaded = download_asset(&asset.browser_download_url).await?;

    self_replace::self_replace(downloaded.path())
        .context("failed to replace current executable")?;

    Ok(true)
}

pub async fn check_update() -> Result<bool> {
    if perform_update().await? {
        return Ok(true);
    } else {
        return Ok(false);
    }
}
