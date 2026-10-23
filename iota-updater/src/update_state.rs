use super::*;

pub(super) fn load_or_initialize_update_state(
    paths: &iota_paths::IotaPaths,
) -> Result<UpdateState> {
    let path = paths.update_status_file();
    if path.exists() {
        let bytes =
            fs::read(&path).with_context(|| format!("read update status {}", path.display()))?;
        return serde_json::from_slice(&bytes)
            .with_context(|| format!("parse update status {}", path.display()));
    }
    let installed = read_installed_manifest(&paths.install_root.join("current")).context(
        "initialize anti-rollback state from installed manifest; legacy installations require an installer migration",
    )?;
    if installed.release_sequence == 0 {
        bail!("installed release sequence must be greater than zero");
    }
    let mut state = UpdateState::default();
    state.channels.insert(
        installed.channel.clone(),
        ChannelState {
            highest_accepted_sequence: installed.release_sequence,
            highest_accepted_version: installed.product_version.clone(),
            active_version: installed.product_version,
            last_failed_sequence: None,
        },
    );
    save_update_state(&path, &state)?;
    Ok(state)
}

pub(super) fn save_update_state(path: &Path, state: &UpdateState) -> Result<()> {
    let parent = path.parent().context("update status path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("create temporary update status file")?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), state)
        .context("serialize update status")?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("flush update status")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("replace update status")?;
    fs::File::open(parent)
        .context("open update status directory")?
        .sync_all()
        .context("flush update status directory")?;
    Ok(())
}

pub(super) fn commit_update_state(
    paths: &iota_paths::IotaPaths,
    state: &mut UpdateState,
    manifest: &ReleaseManifest,
) -> Result<()> {
    let mut updated = state.clone();
    updated.channels.insert(
        manifest.channel.clone(),
        ChannelState {
            highest_accepted_sequence: manifest.release_sequence,
            highest_accepted_version: manifest.product_version.clone(),
            active_version: manifest.product_version.clone(),
            last_failed_sequence: None,
        },
    );
    updated.pending_activation = None;
    save_update_state(&paths.update_status_file(), &updated)?;
    *state = updated;
    Ok(())
}

pub(super) fn record_failed_release(
    paths: &iota_paths::IotaPaths,
    state: &mut UpdateState,
    manifest: &ReleaseManifest,
) -> Result<()> {
    record_failed_sequence(paths, state, &manifest.channel, manifest.release_sequence)
}

pub(super) fn record_failed_sequence(
    paths: &iota_paths::IotaPaths,
    state: &mut UpdateState,
    channel_name: &str,
    release_sequence: u64,
) -> Result<()> {
    let mut updated = state.clone();
    let active_version = current_version(&paths.install_root)?
        .context("active release has no product version while recording failed update")?;
    let channel = updated
        .channels
        .entry(channel_name.to_owned())
        .or_insert_with(|| ChannelState {
            highest_accepted_sequence: 0,
            highest_accepted_version: String::new(),
            active_version,
            last_failed_sequence: None,
        });
    channel.last_failed_sequence = Some(release_sequence);
    updated.pending_activation = None;
    save_update_state(&paths.update_status_file(), &updated)?;
    *state = updated;
    Ok(())
}
