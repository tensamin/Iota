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

    let error =
        select_host_artifacts(&manifest, std::env::consts::OS, std::env::consts::ARCH).unwrap_err();

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

    validate_manifest_compatibility(&manifest, &directory.path().join("missing.db"), 2, 4).unwrap();
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
        existing_target: false,
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
