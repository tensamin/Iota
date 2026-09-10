pub mod manifest;
pub mod transaction;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use iota_ipc::{
    ClientMessage, DaemonMessage, HealthStatus, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
    StartupPhase, read_msg, write_msg,
};
use manifest::{Artifact, ReleaseManifest, verify_signature};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio::net::UnixStream;
use transaction::{Activation, UpdateTransaction};

const MANIFEST_ENV: &str = "IOTA_UPDATE_MANIFEST";
const SIGNATURE_ENV: &str = "IOTA_UPDATE_SIGNATURE";
const PUBLIC_KEY_ENV: &str = "IOTA_UPDATE_PUBLIC_KEY";
const CHANNEL_ENV: &str = "IOTA_UPDATE_CHANNEL";
const SIGNING_KEY_ID_ENV: &str = "IOTA_UPDATE_SIGNING_KEY_ID";
const ACTIVATION_TIMEOUT_ENV: &str = "IOTA_UPDATE_ACTIVATION_TIMEOUT_SECONDS";
const ACTIVATION_RETRY_ENV: &str = "IOTA_UPDATE_ACTIVATION_RETRY_MILLISECONDS";
const DEFAULT_ACTIVATION_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_ACTIVATION_RETRY_MILLISECONDS: u64 = 250;
const REQUIRED_HOST_ARTIFACTS: &str = include_str!("../artifacts.tsv");

#[derive(Clone, Debug)]
pub struct ActivationPolicy {
    pub timeout: Duration,
    pub retry_interval: Duration,
}

impl ActivationPolicy {
    fn from_environment() -> Result<Self> {
        Ok(Self {
            timeout: Duration::from_secs(environment_u64(
                ACTIVATION_TIMEOUT_ENV,
                DEFAULT_ACTIVATION_TIMEOUT_SECONDS,
            )?),
            retry_interval: Duration::from_millis(environment_u64(
                ACTIVATION_RETRY_ENV,
                DEFAULT_ACTIVATION_RETRY_MILLISECONDS,
            )?),
        })
    }
}

#[derive(Clone, Debug)]
struct UpdatePolicy {
    channel: String,
    signing_key_id: String,
    activation: ActivationPolicy,
}

impl UpdatePolicy {
    fn from_environment() -> Result<Self> {
        Ok(Self {
            channel: required_environment(CHANNEL_ENV)?,
            signing_key_id: required_environment(SIGNING_KEY_ID_ENV)?,
            activation: ActivationPolicy::from_environment()?,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct UpdateState {
    #[serde(default)]
    channels: BTreeMap<String, ChannelState>,
    #[serde(default)]
    pending_activation: Option<PendingActivation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingActivation {
    previous_target: PathBuf,
    new_target: PathBuf,
    channel: String,
    release_sequence: u64,
    product_version: String,
    daemon_was_active: bool,
    selected: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ChannelState {
    highest_accepted_sequence: u64,
    highest_accepted_version: String,
    active_version: String,
    #[serde(default)]
    last_failed_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateDecision {
    NoUpdate,
    Install,
}

pub trait DaemonSupervisor {
    fn is_active(&self) -> Result<bool>;
    fn restart(&self) -> Result<()>;
    fn main_pid(&self) -> Result<u32>;
}

struct SystemdSupervisor;

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

pub async fn check_update() -> Result<bool> {
    let Some(release) = configured_release().await? else {
        return Ok(false);
    };
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    let policy = UpdatePolicy::from_environment()?;
    let transaction = UpdateTransaction::from_paths(&paths)?;
    let _lock = transaction.acquire()?;
    let state = load_or_initialize_update_state(&paths)?;
    if state.pending_activation.is_some() {
        bail!("an interrupted update requires iota-updater apply recovery");
    }
    let decision = evaluate_candidate(
        &release.manifest,
        current_version(&paths.install_root)?.as_deref(),
        state.channels.get(&policy.channel),
        &policy.channel,
        &policy.signing_key_id,
        Utc::now(),
    )?;
    Ok(decision == CandidateDecision::Install)
}

pub async fn apply_update() -> Result<bool> {
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    let policy = UpdatePolicy::from_environment()?;
    apply_update_with(&paths, &SystemdSupervisor, &policy).await
}

async fn apply_update_with(
    paths: &iota_paths::IotaPaths,
    supervisor: &impl DaemonSupervisor,
    policy: &UpdatePolicy,
) -> Result<bool> {
    let transaction = UpdateTransaction::from_paths(paths)?;
    let _lock = transaction.acquire()?;
    let mut state = load_or_initialize_update_state(paths)?;
    recover_interrupted_activation(
        paths,
        &transaction,
        &mut state,
        supervisor,
        &policy.activation,
    )
    .await?;
    let Some(release) = configured_release().await? else {
        return Ok(false);
    };
    let decision = evaluate_candidate(
        &release.manifest,
        current_version(&paths.install_root)?.as_deref(),
        state.channels.get(&policy.channel),
        &policy.channel,
        &policy.signing_key_id,
        Utc::now(),
    )?;
    if decision == CandidateDecision::NoUpdate {
        return Ok(false);
    }
    validate_manifest_compatibility(
        &release.manifest,
        &paths.database_file(),
        iota_ipc::MIN_PROTOCOL_VERSION,
        iota_ipc::PROTOCOL_VERSION,
    )?;

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
    let daemon_was_active = supervisor.is_active()?;
    begin_activation_state(
        paths,
        &mut state,
        &transaction,
        &release.manifest,
        daemon_was_active,
    )?;
    let activation = match transaction.activate(&release.manifest.product_version) {
        Ok(activation) => activation,
        Err(error) => {
            remove_unselected_candidate(&state, &transaction.root)?;
            clear_pending_activation(paths, &mut state)?;
            return Err(error);
        }
    };
    let activation_result = async {
        validate_activation_receipt(&state, &activation)?;
        if daemon_was_active {
            supervisor.restart()?;
            wait_for_ready_daemon(
                &iota_paths::socket_path(iota_paths::Scope::System),
                &activation.new_target,
                supervisor,
                &policy.activation,
            )
            .await?;
        }
        commit_update_state(paths, &mut state, &release.manifest)?;
        Ok::<_, anyhow::Error>(())
    }
    .await;

    if let Err(update_error) = activation_result {
        restore_previous_release(
            paths,
            &transaction,
            &activation,
            daemon_was_active,
            supervisor,
            &policy.activation,
        )
        .await?;
        record_failed_release(paths, &mut state, &release.manifest)?;
        return Err(
            update_error.context("candidate release failed runtime activation and was rolled back")
        );
    }
    Ok(true)
}

async fn recover_interrupted_activation(
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

fn remove_unselected_candidate(state: &UpdateState, install_root: &Path) -> Result<()> {
    let Some(pending) = state.pending_activation.as_ref() else {
        return Ok(());
    };
    validate_pending_candidate(pending, install_root)?;
    if pending.new_target.exists() {
        fs::remove_dir_all(&pending.new_target).with_context(|| {
            format!(
                "remove unselected candidate release {}",
                pending.new_target.display()
            )
        })?;
    }
    Ok(())
}

fn validate_pending_candidate(pending: &PendingActivation, install_root: &Path) -> Result<()> {
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

fn begin_activation_state(
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
    if new_target.exists() {
        bail!("release version already exists: {}", new_target.display());
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
    });
    save_update_state(&paths.update_status_file(), &updated)?;
    *state = updated;
    Ok(())
}

fn validate_activation_receipt(state: &UpdateState, activation: &Activation) -> Result<()> {
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

fn clear_pending_activation(paths: &iota_paths::IotaPaths, state: &mut UpdateState) -> Result<()> {
    let mut updated = state.clone();
    updated.pending_activation = None;
    save_update_state(&paths.update_status_file(), &updated)?;
    *state = updated;
    Ok(())
}

async fn restore_previous_release(
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

fn activation_target_path(install_root: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_owned()
    } else {
        install_root.join(target)
    }
}

async fn probe_daemon(socket: &Path) -> Result<iota_ipc::HelloAck> {
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

async fn wait_for_ready_daemon(
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

fn verify_running_executable(
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

fn evaluate_candidate(
    manifest: &ReleaseManifest,
    current_version: Option<&str>,
    channel_state: Option<&ChannelState>,
    expected_channel: &str,
    expected_key_id: &str,
    now: DateTime<Utc>,
) -> Result<CandidateDecision> {
    validate_manifest_identity(manifest, expected_channel, expected_key_id)?;
    validate_manifest_freshness(manifest, now)?;
    if manifest.release_sequence == 0 {
        bail!("release sequence must be greater than zero");
    }
    if let Some(state) = channel_state {
        if manifest.release_sequence < state.highest_accepted_sequence {
            bail!(
                "release sequence {} is older than trusted sequence {}",
                manifest.release_sequence,
                state.highest_accepted_sequence
            );
        }
        if manifest.release_sequence == state.highest_accepted_sequence
            && manifest.product_version != state.highest_accepted_version
        {
            bail!(
                "release sequence {} was already associated with version {}",
                manifest.release_sequence,
                state.highest_accepted_version
            );
        }
        if state.last_failed_sequence == Some(manifest.release_sequence) {
            bail!(
                "release sequence {} previously failed activation",
                manifest.release_sequence
            );
        }
        if manifest.release_sequence == state.highest_accepted_sequence {
            return Ok(CandidateDecision::NoUpdate);
        }
    }
    if current_version == Some(manifest.product_version.as_str()) {
        return Ok(CandidateDecision::NoUpdate);
    }
    Ok(CandidateDecision::Install)
}

fn validate_manifest_identity(
    manifest: &ReleaseManifest,
    expected_channel: &str,
    expected_key_id: &str,
) -> Result<()> {
    if manifest.channel != expected_channel {
        bail!(
            "release channel mismatch: expected {}, got {}",
            expected_channel,
            manifest.channel
        );
    }
    if manifest.release_signing_key_id != expected_key_id {
        bail!(
            "release signing key id mismatch: expected {}, got {}",
            expected_key_id,
            manifest.release_signing_key_id
        );
    }
    Ok(())
}

fn validate_manifest_freshness(manifest: &ReleaseManifest, now: DateTime<Utc>) -> Result<()> {
    let published_at = DateTime::parse_from_rfc3339(&manifest.published_at)
        .context("parse manifest published_at")?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .context("parse manifest expires_at")?
        .with_timezone(&Utc);
    if expires_at <= published_at {
        bail!("release manifest expires_at must be after published_at");
    }
    if now > expires_at {
        bail!("release manifest expired at {}", manifest.expires_at);
    }
    Ok(())
}

fn load_or_initialize_update_state(paths: &iota_paths::IotaPaths) -> Result<UpdateState> {
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

fn save_update_state(path: &Path, state: &UpdateState) -> Result<()> {
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

fn commit_update_state(
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

fn record_failed_release(
    paths: &iota_paths::IotaPaths,
    state: &mut UpdateState,
    manifest: &ReleaseManifest,
) -> Result<()> {
    record_failed_sequence(paths, state, &manifest.channel, manifest.release_sequence)
}

fn record_failed_sequence(
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

fn required_environment(name: &'static str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn environment_u64(name: &'static str, default: u64) -> Result<u64> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be an unsigned integer"))?,
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    };
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
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

fn set_active_version(
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

    struct CurrentProcessSupervisor;

    impl DaemonSupervisor for CurrentProcessSupervisor {
        fn is_active(&self) -> Result<bool> {
            Ok(true)
        }

        fn restart(&self) -> Result<()> {
            Ok(())
        }

        fn main_pid(&self) -> Result<u32> {
            Ok(std::process::id())
        }
    }

    fn test_paths(root: &Path) -> iota_paths::IotaPaths {
        let state_dir = root.join("state");
        iota_paths::IotaPaths {
            scope: iota_paths::Scope::User,
            config_dir: root.join("config"),
            config_file: root.join("config/config.yaml"),
            state_dir: state_dir.clone(),
            storage_dir: state_dir.join("storage"),
            identity_dir: state_dir.join("identity"),
            cache_dir: root.join("cache"),
            runtime_dir: Some(root.join("run")),
            log_dir: root.join("logs"),
            asset_dir: root.join("web"),
            install_root: root.join("install"),
            ipc_endpoint: iota_paths::IpcEndpoint::UnixSocket(root.join("run/iota.sock")),
        }
    }

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
            release_sequence: 12,
            published_at: "2026-09-10T00:00:00Z".into(),
            expires_at: "2030-09-10T00:00:00Z".into(),
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

    #[test]
    fn candidate_policy_rejects_replay_and_sequence_reuse() {
        let state = ChannelState {
            highest_accepted_sequence: 12,
            highest_accepted_version: "1.2.3".into(),
            active_version: "1.1.0".into(),
            last_failed_sequence: None,
        };
        let mut replay = release_manifest(host_artifacts());
        replay.release_sequence = 11;
        assert!(
            evaluate_candidate(
                &replay,
                Some("1.1.0"),
                Some(&state),
                "stable",
                "test",
                Utc::now(),
            )
            .unwrap_err()
            .to_string()
            .contains("older than trusted sequence")
        );

        let mut reused = release_manifest(host_artifacts());
        reused.product_version = "1.2.4".into();
        assert!(
            evaluate_candidate(
                &reused,
                Some("1.1.0"),
                Some(&state),
                "stable",
                "test",
                Utc::now(),
            )
            .unwrap_err()
            .to_string()
            .contains("already associated")
        );
    }

    #[test]
    fn accepted_sequence_is_not_reinstalled_after_explicit_rollback() {
        let state = ChannelState {
            highest_accepted_sequence: 12,
            highest_accepted_version: "1.2.3".into(),
            active_version: "1.1.0".into(),
            last_failed_sequence: None,
        };
        let decision = evaluate_candidate(
            &release_manifest(host_artifacts()),
            Some("1.1.0"),
            Some(&state),
            "stable",
            "test",
            Utc::now(),
        )
        .unwrap();
        assert_eq!(decision, CandidateDecision::NoUpdate);
    }

    #[test]
    fn candidate_policy_rejects_expired_wrong_channel_and_failed_release() {
        let mut expired = release_manifest(host_artifacts());
        expired.published_at = "2020-01-01T00:00:00Z".into();
        expired.expires_at = "2020-01-02T00:00:00Z".into();
        assert!(
            evaluate_candidate(&expired, None, None, "stable", "test", Utc::now(),)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );

        let manifest = release_manifest(host_artifacts());
        assert!(
            evaluate_candidate(&manifest, None, None, "dev", "test", Utc::now())
                .unwrap_err()
                .to_string()
                .contains("channel mismatch")
        );

        let state = ChannelState {
            highest_accepted_sequence: 11,
            highest_accepted_version: "1.2.2".into(),
            active_version: "1.2.2".into(),
            last_failed_sequence: Some(12),
        };
        assert!(
            evaluate_candidate(
                &manifest,
                Some("1.2.2"),
                Some(&state),
                "stable",
                "test",
                Utc::now(),
            )
            .unwrap_err()
            .to_string()
            .contains("previously failed activation")
        );
    }

    #[test]
    fn update_state_is_replaced_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("update-status.json");
        let mut state = UpdateState::default();
        state.channels.insert(
            "stable".into(),
            ChannelState {
                highest_accepted_sequence: 12,
                highest_accepted_version: "1.2.3".into(),
                active_version: "1.2.3".into(),
                last_failed_sequence: None,
            },
        );
        save_update_state(&path, &state).unwrap();
        let loaded: UpdateState = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(loaded.channels["stable"].highest_accepted_sequence, 12);
    }

    #[tokio::test]
    async fn readiness_probe_checks_ipc_state_and_running_executable() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("iota.sock");
        let release = directory.path().join("versions/1.2.3");
        fs::create_dir_all(release.join("bin")).unwrap();
        std::os::unix::fs::symlink(
            fs::canonicalize("/proc/self/exe").unwrap(),
            release.join("bin/iota-daemon"),
        )
        .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let hello = read_msg::<_, ClientMessage>(&mut stream).await.unwrap();
            assert!(matches!(hello, ClientMessage::Hello { .. }));
            write_msg(
                &mut stream,
                &DaemonMessage::HelloAck(iota_ipc::HelloAck {
                    protocol_version: PROTOCOL_VERSION,
                    daemon_version: "test".into(),
                    instance_id: "test".into(),
                    startup_phase: StartupPhase::Ready,
                    capabilities: Vec::new(),
                    lifecycle: iota_ipc::LifecyclePhase::Ready,
                    health: HealthStatus::Degraded,
                    deployment_mode: iota_ipc::DeploymentMode::default(),
                    supervisor: iota_ipc::SupervisorKind::default(),
                }),
            )
            .await
            .unwrap();
        });
        wait_for_ready_daemon(
            &socket,
            &release,
            &CurrentProcessSupervisor,
            &ActivationPolicy {
                timeout: Duration::from_secs(1),
                retry_interval: Duration::from_millis(10),
            },
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn interrupted_selected_candidate_is_restored_and_marked_failed() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        let transaction = UpdateTransaction::new(&paths.install_root);
        let old_release = paths.install_root.join("versions/1.0.0");
        let new_release = paths.install_root.join("versions/1.1.0");
        fs::create_dir_all(&old_release).unwrap();
        fs::create_dir_all(&new_release).unwrap();
        fs::write(
            old_release.join("manifest.json"),
            br#"{"product_version":"1.0.0"}"#,
        )
        .unwrap();
        fs::create_dir_all(&paths.install_root).unwrap();
        std::os::unix::fs::symlink(&new_release, paths.install_root.join("current")).unwrap();
        let mut state = UpdateState::default();
        state.channels.insert(
            "stable".into(),
            ChannelState {
                highest_accepted_sequence: 1,
                highest_accepted_version: "1.0.0".into(),
                active_version: "1.0.0".into(),
                last_failed_sequence: None,
            },
        );
        state.pending_activation = Some(PendingActivation {
            previous_target: old_release.clone(),
            new_target: new_release,
            channel: "stable".into(),
            release_sequence: 2,
            product_version: "1.1.0".into(),
            daemon_was_active: false,
            selected: true,
        });
        recover_interrupted_activation(
            &paths,
            &transaction,
            &mut state,
            &CurrentProcessSupervisor,
            &ActivationPolicy {
                timeout: Duration::from_secs(1),
                retry_interval: Duration::from_millis(10),
            },
        )
        .await
        .unwrap();
        assert_eq!(transaction.current_target().unwrap(), old_release);
        assert_eq!(state.channels["stable"].last_failed_sequence, Some(2));
        assert!(state.pending_activation.is_none());
    }
}
