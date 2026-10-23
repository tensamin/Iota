mod activation;
pub use activation::rollback;
use activation::{
    begin_activation_state, clear_pending_activation, recover_interrupted_activation,
    remove_unselected_candidate, restore_previous_release, validate_activation_receipt,
    wait_for_ready_daemon,
};
mod policy;
use policy::evaluate_candidate;
mod update_state;
use update_state::{
    commit_update_state, load_or_initialize_update_state, record_failed_release,
    record_failed_sequence, save_update_state,
};
mod release;
use release::{
    configured_release, current_channel_version, current_version, download_to_temporary_file,
    read_installed_manifest, select_host_artifacts, validate_manifest_compatibility,
    validate_rollback_manifests, validate_version,
};
#[cfg(test)]
use release::{configured_release_from_locations, required_host_artifacts};
pub mod config;
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

#[derive(Clone, Copy, Debug)]
pub enum UpdatePhase {
    CandidateEvaluated,
    ArtifactsStaged,
    ActivationStarted,
    DaemonRestarted,
    ActivationCommitted,
    RollbackStarted,
    RollbackCompleted,
}

pub trait UpdateObserver: Send + Sync {
    fn event(&self, phase: UpdatePhase, product_version: Option<&str>);
}

pub struct NoopUpdateObserver;
impl UpdateObserver for NoopUpdateObserver {
    fn event(&self, _phase: UpdatePhase, _product_version: Option<&str>) {}
}

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
        let config = config::load()?;
        Ok(Self {
            channel: config[CHANNEL_ENV].clone(),
            signing_key_id: config[SIGNING_KEY_ID_ENV].clone(),
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
    #[serde(default)]
    existing_target: bool,
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

pub async fn check_update() -> Result<bool> {
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    let transaction = UpdateTransaction::from_paths(&paths)?;
    let _lock = transaction.acquire()?;
    let policy = UpdatePolicy::from_environment()?;
    let Some(release) = configured_release().await? else {
        return Ok(false);
    };
    let state = load_or_initialize_update_state(&paths)?;
    if state.pending_activation.is_some() {
        bail!("an interrupted update requires iota-updater apply recovery");
    }
    let decision = evaluate_candidate(
        &release.manifest,
        current_channel_version(&paths.install_root, &policy.channel)?.as_deref(),
        state.channels.get(&policy.channel),
        &policy.channel,
        &policy.signing_key_id,
        Utc::now(),
    )?;
    Ok(decision == CandidateDecision::Install)
}

pub async fn apply_update() -> Result<bool> {
    apply_update_observed(&NoopUpdateObserver).await
}

pub async fn apply_update_observed(observer: &dyn UpdateObserver) -> Result<bool> {
    let paths = iota_paths::IotaPaths::resolve(iota_paths::Scope::System)
        .map_err(|error| anyhow::anyhow!(error))?;
    let policy = UpdatePolicy::from_environment()?;
    apply_update_with_observer(&paths, &SystemdSupervisor, &policy, observer).await
}

async fn apply_update_with_observer(
    paths: &iota_paths::IotaPaths,
    supervisor: &impl DaemonSupervisor,
    policy: &UpdatePolicy,
    observer: &dyn UpdateObserver,
) -> Result<bool> {
    let transaction = UpdateTransaction::from_paths(paths)?;
    let _lock = transaction.acquire()?;
    let configured_policy = UpdatePolicy::from_environment()?;
    if policy.channel != configured_policy.channel
        || policy.signing_key_id != configured_policy.signing_key_id
    {
        bail!("update configuration changed; retry apply");
    }
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
        current_channel_version(&paths.install_root, &policy.channel)?.as_deref(),
        state.channels.get(&policy.channel),
        &policy.channel,
        &policy.signing_key_id,
        Utc::now(),
    )?;
    observer.event(
        UpdatePhase::CandidateEvaluated,
        Some(&release.manifest.product_version),
    );
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
    observer.event(
        UpdatePhase::ArtifactsStaged,
        Some(&release.manifest.product_version),
    );
    let daemon_was_active = supervisor.is_active()?;
    begin_activation_state(
        paths,
        &mut state,
        &transaction,
        &release.manifest,
        daemon_was_active,
    )?;
    observer.event(
        UpdatePhase::ActivationStarted,
        Some(&release.manifest.product_version),
    );
    let activation = match if state
        .pending_activation
        .as_ref()
        .is_some_and(|pending| pending.existing_target)
    {
        let previous_target = transaction.current_target()?;
        transaction
            .rollback(&release.manifest.product_version)
            .map(|()| Activation {
                previous_target,
                new_target: transaction
                    .root
                    .join("versions")
                    .join(&release.manifest.product_version),
            })
    } else {
        transaction.activate(&release.manifest.product_version)
    } {
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
            observer.event(
                UpdatePhase::DaemonRestarted,
                Some(&release.manifest.product_version),
            );
        }
        commit_update_state(paths, &mut state, &release.manifest)?;
        observer.event(
            UpdatePhase::ActivationCommitted,
            Some(&release.manifest.product_version),
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;

    if let Err(update_error) = activation_result {
        observer.event(
            UpdatePhase::RollbackStarted,
            Some(&release.manifest.product_version),
        );
        restore_previous_release(
            paths,
            &transaction,
            &activation,
            daemon_was_active,
            supervisor,
            &policy.activation,
        )
        .await?;
        observer.event(
            UpdatePhase::RollbackCompleted,
            Some(&release.manifest.product_version),
        );
        record_failed_release(paths, &mut state, &release.manifest)?;
        return Err(
            update_error.context("candidate release failed runtime activation and was rolled back")
        );
    }
    Ok(true)
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

struct ConfiguredRelease {
    manifest: ReleaseManifest,
    artifacts: Vec<Artifact>,
}

#[cfg(test)]
mod tests;
