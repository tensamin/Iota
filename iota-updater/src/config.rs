use anyhow::{Context, Result, bail};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

const CONFIG: &str = "/etc/iota/update.env";
const RELEASES: &str = "https://git.methanium.net/tensamin/prod-pins/releases/download";

pub fn manifest_url(channel: &str, architecture: &str) -> Result<String> {
    if !matches!(channel, "stable" | "canary") {
        bail!("update channel must be stable or canary");
    }
    if !matches!(architecture, "x86_64" | "aarch64") {
        bail!("unsupported update architecture: {architecture}");
    }
    Ok(format!(
        "{RELEASES}/{channel}/iota-update-linux-{architecture}.json"
    ))
}

pub(crate) fn load() -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(CONFIG).context("read /etc/iota/update.env")?;
    let mut entries = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').context("invalid update.env entry")?;
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            bail!("invalid update.env value for {name}");
        }
        if entries.insert(name.to_owned(), value.to_owned()).is_some() {
            bail!("duplicate update.env entry {name}");
        }
    }
    for name in [
        "IOTA_UPDATE_CHANNEL",
        "IOTA_UPDATE_PUBLIC_KEY",
        "IOTA_UPDATE_SIGNING_KEY_ID",
    ] {
        if !entries.contains_key(name) {
            bail!("update.env is missing {name}");
        }
    }
    let url = manifest_url(&entries["IOTA_UPDATE_CHANNEL"], std::env::consts::ARCH)?;
    if entries.get("IOTA_UPDATE_MANIFEST") != Some(&url)
        || entries.get("IOTA_UPDATE_SIGNATURE") != Some(&format!("{url}.sig"))
    {
        bail!("update.env URLs do not match the selected prod-pins channel");
    }
    Ok(entries)
}

pub fn selected_channel() -> Result<String> {
    Ok(load()?["IOTA_UPDATE_CHANNEL"].clone())
}

pub fn select_channel(channel: &str) -> Result<()> {
    let url = manifest_url(channel, std::env::consts::ARCH)?;
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    let transaction = crate::transaction::UpdateTransaction::from_paths(&paths)?;
    let _lock = transaction.acquire()?;
    let mut entries = load()?;
    entries.insert("IOTA_UPDATE_CHANNEL".into(), channel.into());
    entries.insert("IOTA_UPDATE_MANIFEST".into(), url.clone());
    entries.insert("IOTA_UPDATE_SIGNATURE".into(), format!("{url}.sig"));
    let path = Path::new(CONFIG);
    let parent = path.parent().context("update.env has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::metadata(path)?.permissions())?;
    for (name, value) in entries {
        writeln!(temporary, "{name}={value}")?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("save update channel")?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
