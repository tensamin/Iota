use super::*;

impl DaemonSupervisor for SystemdSupervisor {
    fn is_active(&self) -> Result<bool> {
        let status = Command::new("systemctl")
            .args(["is-active", "--quiet", "iota-daemon.service"])
            .status()
            .context("query iota-daemon.service state")?;
        Ok(status.success())
    }

    fn restart(&self) -> Result<()> {
        let status = Command::new("systemctl")
            .args(["restart", "iota-daemon.service"])
            .status()
            .context("restart iota-daemon.service")?;
        if !status.success() {
            bail!("systemctl restart iota-daemon.service failed with {status}");
        }
        Ok(())
    }

    fn main_pid(&self) -> Result<u32> {
        let output = Command::new("systemctl")
            .args([
                "show",
                "--property=MainPID",
                "--value",
                "iota-daemon.service",
            ])
            .output()
            .context("query iota-daemon.service MainPID")?;
        if !output.status.success() {
            bail!("could not query iota-daemon.service MainPID");
        }
        let text =
            String::from_utf8(output.stdout).context("systemctl returned non-UTF-8 MainPID")?;
        text.trim()
            .parse()
            .context("parse iota-daemon.service MainPID")
    }
}

pub(super) async fn recover_interrupted_activation(
    paths: &iota_paths::IotaPaths,
    transaction: &UpdateTransaction,
    state: &mut UpdateState,
    supervisor: &impl DaemonSupervisor,
    policy: &ActivationPolicy,
) -> Result<()> {
    let Some(pending) = state.pending_activation.clone() else {
        return Ok(());
    };
    validate_pending_candidate(&pending, &transaction.root)?;
    let current_target = transaction.current_target()?;
    let candidate_was_selected = pending.selected || current_target == pending.new_target;
    if current_target == pending.new_target {
        transaction
            .restore_activation(&Activation {
                previous_target: pending.previous_target.clone(),
                new_target: pending.new_target.clone(),
            })
            .context("restore previous release after interrupted activation")?;
    } else if current_target != pending.previous_target {
        bail!(
            "cannot recover interrupted activation: current target {} matches neither {} nor {}",
            current_target.display(),
            pending.previous_target.display(),
            pending.new_target.display()
        );
    }
    if candidate_was_selected && pending.daemon_was_active {
        supervisor
            .restart()
            .context("restart previous daemon after interrupted activation")?;
        wait_for_ready_daemon(
            &iota_paths::socket_path(iota_paths::Scope::System),
            &activation_target_path(&paths.install_root, &pending.previous_target),
            supervisor,
            policy,
        )
        .await
        .context("previous daemon failed during interrupted update recovery")?;
    }
    if candidate_was_selected {
        record_failed_sequence(paths, state, &pending.channel, pending.release_sequence)?;
    } else {
        remove_unselected_candidate(state, &transaction.root)?;
        clear_pending_activation(paths, state)?;
    }
    Ok(())
}

pub(super) fn remove_unselected_candidate(state: &UpdateState, install_root: &Path) -> Result<()> {
    let Some(pending) = state.pending_activation.as_ref() else {
        return Ok(());
    };
    validate_pending_candidate(pending, install_root)?;
    if !pending.existing_target && pending.new_target.exists() {
        fs::remove_dir_all(&pending.new_target).with_context(|| {
            format!(
                "remove unselected candidate release {}",
                pending.new_target.display()
            )
        })?;
    }
    Ok(())
}

pub(super) fn validate_pending_candidate(
    pending: &PendingActivation,
    install_root: &Path,
) -> Result<()> {
    validate_version(&pending.product_version)?;
    let expected = install_root.join("versions").join(&pending.product_version);
    if pending.new_target != expected {
        bail!(
            "pending candidate path {} does not match expected path {}",
            pending.new_target.display(),
            expected.display()
        );
    }
    Ok(())
}

pub(super) fn begin_activation_state(
    paths: &iota_paths::IotaPaths,
    state: &mut UpdateState,
    transaction: &UpdateTransaction,
    manifest: &ReleaseManifest,
    daemon_was_active: bool,
) -> Result<()> {
    let new_target = transaction
        .root
        .join("versions")
        .join(&manifest.product_version);
    let existing_target = new_target.exists();
    if existing_target {
        let mut installed = read_installed_manifest(&new_target)?;
        // Refreshing signed expiry does not change the installed release contents.
        installed.published_at = manifest.published_at.clone();
        installed.expires_at = manifest.expires_at.clone();
        if manifest::canonical_bytes(&installed)? != manifest::canonical_bytes(manifest)? {
            bail!("existing release version has different signed metadata");
        }
        for artifact in
            select_host_artifacts(manifest, std::env::consts::OS, std::env::consts::ARCH)?
        {
            manifest::verify_artifact(&new_target.join(&artifact.path), &artifact)?;
        }
    }
    let mut updated = state.clone();
    updated.pending_activation = Some(PendingActivation {
        previous_target: transaction.current_target()?,
        new_target,
        channel: manifest.channel.clone(),
        release_sequence: manifest.release_sequence,
        product_version: manifest.product_version.clone(),
        daemon_was_active,
        selected: true,
        existing_target,
    });
    save_update_state(&paths.update_status_file(), &updated)?;
    *state = updated;
    Ok(())
}

pub(super) fn validate_activation_receipt(
    state: &UpdateState,
    activation: &Activation,
) -> Result<()> {
    let pending = state
        .pending_activation
        .as_ref()
        .context("activation has no persisted rollback receipt")?;
    if pending.previous_target != activation.previous_target
        || pending.new_target != activation.new_target
    {
        bail!("activation receipt does not match persisted rollback state");
    }
    Ok(())
}

pub(super) fn clear_pending_activation(
    paths: &iota_paths::IotaPaths,
    state: &mut UpdateState,
) -> Result<()> {
    let mut updated = state.clone();
    updated.pending_activation = None;
    save_update_state(&paths.update_status_file(), &updated)?;
    *state = updated;
    Ok(())
}

pub(super) async fn restore_previous_release(
    paths: &iota_paths::IotaPaths,
    transaction: &UpdateTransaction,
    activation: &Activation,
    daemon_was_active: bool,
    supervisor: &impl DaemonSupervisor,
    policy: &ActivationPolicy,
) -> Result<()> {
    transaction
        .restore_activation(activation)
        .context("restore previous release after failed activation")?;
    if daemon_was_active {
        supervisor
            .restart()
            .context("restart previous daemon after failed activation")?;
        wait_for_ready_daemon(
            &iota_paths::socket_path(iota_paths::Scope::System),
            &activation_target_path(&paths.install_root, &activation.previous_target),
            supervisor,
            policy,
        )
        .await
        .context("previous daemon failed after update rollback")?;
    }
    Ok(())
}

pub(super) fn activation_target_path(install_root: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_owned()
    } else {
        install_root.join(target)
    }
}

pub(super) async fn probe_daemon(socket: &Path) -> Result<iota_ipc::HelloAck> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect to {}", socket.display()))?;
    write_msg(
        &mut stream,
        &ClientMessage::Hello {
            supported_versions: (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).collect(),
        },
    )
    .await
    .context("send updater IPC hello")?;
    match read_msg::<_, DaemonMessage>(&mut stream).await? {
        DaemonMessage::HelloAck(ack) => Ok(ack),
        other => bail!("expected daemon HelloAck, received {other:?}"),
    }
}

pub(super) async fn wait_for_ready_daemon(
    socket: &Path,
    expected_release: &Path,
    supervisor: &impl DaemonSupervisor,
    policy: &ActivationPolicy,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + policy.timeout;
    loop {
        if let Ok(ack) = probe_daemon(socket).await
            && ack.startup_phase == StartupPhase::Ready
            && ack.health != HealthStatus::Failed
        {
            verify_running_executable(supervisor, expected_release)?;
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("updated daemon did not reach the required ready state");
        }
        tokio::time::sleep(policy.retry_interval).await;
    }
}

pub(super) fn verify_running_executable(
    supervisor: &impl DaemonSupervisor,
    expected_release: &Path,
) -> Result<()> {
    let pid = supervisor.main_pid()?;
    if pid == 0 {
        bail!("iota-daemon.service has no MainPID");
    }
    let actual = fs::canonicalize(format!("/proc/{pid}/exe"))
        .context("resolve running daemon executable")?;
    let expected = fs::canonicalize(expected_release.join("bin/iota-daemon"))
        .context("resolve expected daemon executable")?;
    if actual != expected {
        bail!(
            "running daemon executable mismatch: expected {}, got {}",
            expected.display(),
            actual.display()
        );
    }
    Ok(())
}

/// Switches `current` to an already-installed release version.
pub fn rollback(version: &str) -> Result<()> {
    validate_version(version)?;
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    let transaction = UpdateTransaction::from_paths(&paths)?;
    let _lock = transaction.acquire()?;
    let mut state = load_or_initialize_update_state(&paths)?;
    if state.pending_activation.is_some() {
        bail!("an interrupted update requires iota-updater apply recovery");
    }
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
    if active_manifest.channel != target_manifest.channel {
        bail!(
            "rollback target channel {} does not match active channel {}",
            target_manifest.channel,
            active_manifest.channel
        );
    }
    let previous_target = fs::read_link(transaction.root.join("current"))
        .context("read current release link before rollback")?;
    transaction.rollback(version)?;
    let activation = Activation {
        previous_target,
        new_target: release_dir,
    };
    if let Err(error) = set_active_version(&paths, &mut state, &target_manifest) {
        transaction
            .restore_activation(&activation)
            .context("restore active release after rollback state commit failed")?;
        return Err(error.context("persist rollback update state"));
    }
    Ok(())
}

pub(super) fn set_active_version(
    paths: &iota_paths::IotaPaths,
    state: &mut UpdateState,
    manifest: &ReleaseManifest,
) -> Result<()> {
    let mut updated = state.clone();
    let channel = updated
        .channels
        .get_mut(&manifest.channel)
        .context("rollback channel has no trusted baseline")?;
    channel.active_version = manifest.product_version.clone();
    save_update_state(&paths.update_status_file(), &updated)?;
    *state = updated;
    Ok(())
}
