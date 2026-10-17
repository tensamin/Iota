use super::*;
use std::fs;

#[tokio::test]
async fn damaged_password_setup_does_not_invalidate_iota_identity() {
    let directory = test_path("password-isolation");
    fs::create_dir(&directory).unwrap();
    let identity_path = directory.join("identity.keyring");
    let identity = load_or_migrate_keyring_at(&identity_path, None).unwrap();
    fs::write(
        identity_path.with_file_name("password-auth.setup"),
        b"corrupt setup",
    )
    .unwrap();
    let connection = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    *connection.keyring.write().await = Some(identity.keyring());
    connection.initialize_password_auth(&identity_path);
    assert!(connection.keyring.read().await.is_some());
    assert!(connection.password_auth.setup().is_err());
    assert_eq!(
        fs::read(identity_path.with_file_name("password-auth.setup")).unwrap(),
        b"corrupt setup"
    );
    fs::remove_dir_all(directory).unwrap();
}

fn test_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "iota-identity-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ))
}

#[test]
fn generated_identity_is_unprotected_and_survives_reload() {
    let path = test_path("reload");
    let identity = load_or_migrate_keyring_at(&path, None).expect("identity saves");
    let reloaded = load_or_migrate_keyring_at(&path, None).expect("identity loads");
    assert_eq!(
        identity
            .keyring()
            .try_to_bytes()
            .expect("keyring serializes"),
        reloaded
            .keyring()
            .try_to_bytes()
            .expect("keyring serializes")
    );
    assert!(mtp::files::load_keyring_raw(&path).is_ok());
    let _ = fs::remove_file(path);
}

#[test]
fn corrupt_existing_identity_does_not_generate_a_replacement() {
    let path = test_path("corrupt");
    fs::write(&path, b"not a keyring").expect("corrupt fixture writes");
    let error = load_or_migrate_keyring_at(&path, None).expect_err("corrupt identity must fail");
    assert!(matches!(
        error,
        iota_identity::LocalNodeIdentityError::Storage { .. }
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn legacy_raw_identity_is_loaded_only_when_the_raw_format_is_valid() {
    let path = test_path("legacy");
    let keyring = crypto_helper::generate_keyring();
    let mut raw = b"MTMK".to_vec();
    raw.push(1);
    raw.extend_from_slice(&keyring.try_to_bytes().expect("keyring serializes"));
    fs::write(&path, raw).expect("legacy fixture writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("legacy fixture is owner-only");
    }

    let migrated = load_or_migrate_keyring_at(&path, None).expect("legacy identity loads");
    assert_eq!(
        migrated
            .keyring()
            .try_to_bytes()
            .expect("keyring serializes"),
        keyring.try_to_bytes().expect("keyring serializes")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn identity_directory_failure_is_returned() {
    let parent = test_path("parent-file");
    fs::write(&parent, b"not a directory").expect("parent fixture writes");
    let path = parent.join("iota.mk");
    let error =
        load_or_migrate_keyring_at(&path, None).expect_err("directory failure must be returned");
    assert!(matches!(
        error,
        iota_identity::LocalNodeIdentityError::Directory { .. }
    ));
    let _ = fs::remove_file(parent);
}

#[test]
fn reconnect_jitter_stays_bounded_by_the_exponential_delay_ceiling() {
    for _ in 0..32 {
        let delay = jittered_reconnect_delay(Duration::from_secs(5));
        assert!(delay >= Duration::from_secs(4));
        assert!(delay <= Duration::from_secs(6));
    }

    assert!(jittered_reconnect_delay(Duration::from_secs(600)) <= MAX_RECONNECT_DELAY);
}

#[test]
fn per_omikron_trust_paths_do_not_collide() {
    assert_ne!(omikron_public_key_path(1), omikron_public_key_path(2));
}

#[test]
fn not_found_response_is_preserved_for_callers() {
    let error = map_await_response_error(ConnectorRequestError::Rejected {
        kind: CommunicationType::ErrorNotFound,
        reason: "timed out; Request rejected kind=other".into(),
    });

    assert!(matches!(
        error,
        OmikronError::Rejected(CommunicationType::ErrorNotFound, _)
    ));
    assert!(matches!(
        map_await_response_error(ConnectorRequestError::Request(tau::RequestError::Timeout)),
        OmikronError::Timeout(_)
    ));
    assert!(matches!(
        map_await_response_error(ConnectorRequestError::Disconnected(
            "kind=not_found timed out".into()
        )),
        OmikronError::Disconnected(_)
    ));
}

#[test]
fn omega_invitation_snapshot_parser_requires_authoritative_fields() {
    let type_map = TypeMap::latest();
    let mut fields = Vec::new();
    for (kind, value) in [
        (
            DataType::InvitationAuthority,
            DataValue::Str("omega".into()),
        ),
        (DataType::InvitationId, DataValue::SignedNumber(7)),
        (DataType::IotaId, DataValue::SignedNumber(42)),
        (DataType::InvitationRevision, DataValue::SignedNumber(3)),
        (
            DataType::InvitationState,
            DataValue::Str("provisioning".into()),
        ),
        (DataType::InvitationCreatedAt, DataValue::SignedNumber(10)),
        (DataType::InvitationExpiresAt, DataValue::SignedNumber(20)),
        (
            DataType::InvitationPasswordProtected,
            DataValue::Bool(false),
        ),
    ] {
        fields.push((kind.try_to_id(&type_map).expect("type is mapped"), value));
    }
    let parsed = parse_omega_invitation(&fields, &type_map, 42, 20).expect("snapshot parses");
    assert_eq!(parsed.invitation_id, 7);
    assert_eq!(parsed.remote_revision, 3);
    assert_eq!(
        parsed.authority,
        iota_storage::users::invitations::InvitationAuthority::Omega
    );

    fields.retain(|(id, _)| Some(*id) != DataType::InvitationRevision.try_to_id(&type_map));
    assert!(parse_omega_invitation(&fields, &type_map, 42, 20).is_err());
}

#[test]
fn omega_control_target_requires_signed_local_iota_id() {
    let matching = CommunicationValue::new(CommunicationType::ProvisionIotaUser)
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(42));
    let wrong = CommunicationValue::new(CommunicationType::EraseHostedUserData)
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(43));
    let unsigned = CommunicationValue::new(CommunicationType::EraseHostedUserData)
        .add_typed_default(DataType::IotaId, DataValue::UnsignedNumber(42));
    assert!(targets_iota(&matching, Some(42)));
    assert!(!targets_iota(&wrong, Some(42)));
    assert!(!targets_iota(&unsigned, Some(42)));
    assert!(!targets_iota(&matching, None));
}

#[test]
fn omega_invitation_snapshot_parser_rejects_wrong_authority_or_iota() {
    let type_map = TypeMap::latest();
    let fields = [
        (DataType::InvitationAuthority, DataValue::Str("iota".into())),
        (DataType::InvitationId, DataValue::SignedNumber(7)),
        (DataType::IotaId, DataValue::SignedNumber(42)),
        (DataType::InvitationRevision, DataValue::SignedNumber(3)),
        (DataType::InvitationState, DataValue::Str("pending".into())),
        (DataType::InvitationCreatedAt, DataValue::SignedNumber(10)),
        (DataType::InvitationExpiresAt, DataValue::SignedNumber(20)),
        (
            DataType::InvitationPasswordProtected,
            DataValue::Bool(false),
        ),
    ]
    .into_iter()
    .map(|(kind, value)| (kind.try_to_id(&type_map).expect("type is mapped"), value))
    .collect::<Vec<_>>();

    assert!(parse_omega_invitation(&fields, &type_map, 42, 20).is_err());

    let mut fields = fields;
    let authority_id = DataType::InvitationAuthority
        .try_to_id(&type_map)
        .expect("type is mapped");
    let authority = fields
        .iter_mut()
        .find(|(id, _)| *id == authority_id)
        .expect("authority field exists");
    authority.1 = DataValue::Str("omega".into());
    assert!(parse_omega_invitation(&fields, &type_map, 43, 20).is_err());
}

#[test]
fn invitation_action_retry_delay_backs_off_and_caps() {
    assert_eq!(
        next_invitation_retry_delay(Duration::from_secs(5)),
        Duration::from_secs(10)
    );
    assert_eq!(
        next_invitation_retry_delay(Duration::from_secs(300)),
        Duration::from_secs(300)
    );
}

#[tokio::test]
async fn cancelled_preparation_does_not_publish_an_attempt() {
    let connector = Arc::new(OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    ));
    connector.cancellation.cancel();
    assert!(
        !connector
            .clone()
            .connect_once()
            .await
            .unwrap()
            .became_healthy
    );
    assert!(connector.active_attempt.read().await.is_none());
    assert!(connector.preparation_tasks.lock().await.is_empty());
}

#[tokio::test]
async fn idle_shutdown_is_complete_and_prevents_restart() {
    let connector = Arc::new(OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    ));
    assert_eq!(connector.stop().await.unwrap(), ShutdownOutcome::Complete);
    connector.clone().start().await;
    assert!(connector.connection_loop_handle.lock().await.is_none());
    assert!(
        *connector
            .shutdown_tx
            .lock()
            .await
            .as_ref()
            .unwrap()
            .borrow()
    );
}

#[tokio::test]
async fn nonterminal_drain_prevents_preparation_and_attempt_publication() {
    let connector = Arc::new(OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    ));
    assert_eq!(
        connector
            .drain(Duration::from_secs(1), false)
            .await
            .unwrap(),
        ShutdownOutcome::Complete
    );
    assert!(!connector.cancellation.is_cancelled());
    assert!(
        !connector
            .clone()
            .connect_once()
            .await
            .unwrap()
            .became_healthy
    );
    assert!(connector.active_attempt.read().await.is_none());
    assert_eq!(*connector.state.read().await, ConnectionState::Disconnected);
}

#[tokio::test]
async fn standalone_blocking_preparation_is_retained_and_joined() {
    let connector = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let (entered, running) = tokio::sync::oneshot::channel();
    let (release, blocked) = tokio::sync::oneshot::channel();
    let (finished, observed) = tokio::sync::oneshot::channel();
    connector.preparation_tasks.lock().await.spawn(async move {
        let value = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            blocked.blocking_recv().unwrap();
            42
        })
        .await
        .unwrap();
        finished.send(value).unwrap();
    });
    running.await.unwrap();
    assert!(matches!(
        connector.stop_with_timeout(Duration::ZERO).await.unwrap(),
        ShutdownOutcome::Incomplete { .. }
    ));
    assert!(connector.connection_loop_handle.lock().await.is_some());
    release.send(()).unwrap();
    assert_eq!(observed.await.unwrap(), 42);
    assert_eq!(connector.stop().await.unwrap(), ShutdownOutcome::Complete);
    assert!(connector.preparation_tasks.lock().await.is_empty());
}

#[tokio::test]
async fn concurrent_stop_respects_its_own_drain_deadline() {
    let connector = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let held_by_another_stop = connector.connection_loop_handle.lock().await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        connector.stop_with_timeout(Duration::ZERO),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(outcome, ShutdownOutcome::Incomplete { .. }));
    drop(held_by_another_stop);
    assert_eq!(connector.stop().await.unwrap(), ShutdownOutcome::Complete);
}

#[tokio::test]
async fn blocked_mutation_remains_supervised_until_drain_finishes() {
    let connector = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let (release, blocked) = tokio::sync::oneshot::channel();
    let (committed, observed) = tokio::sync::oneshot::channel();
    connector.pending_operations.store(1, Ordering::Release);
    let pending = connector.pending_operations.clone();
    *connector.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        blocked.await.unwrap();
        // A committed mutation finishes even after its reply transport closes.
        pending.store(0, Ordering::Release);
        committed.send(()).unwrap();
    }));
    assert_eq!(
        connector.stop_with_timeout(Duration::ZERO).await.unwrap(),
        ShutdownOutcome::Incomplete {
            pending_operations: 1
        }
    );
    assert!(connector.connection_loop_handle.lock().await.is_some());
    release.send(()).unwrap();
    observed.await.unwrap();
    assert_eq!(connector.stop().await.unwrap(), ShutdownOutcome::Complete);
    assert!(connector.connection_loop_handle.lock().await.is_none());
}

#[tokio::test]
async fn transaction_and_commit_before_reply_survive_bounded_shutdown() {
    let connector = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let (entered, in_transaction) = tokio::sync::oneshot::channel();
    let (release_transaction, transaction_gate) = tokio::sync::oneshot::channel();
    let (committed, after_commit) = tokio::sync::oneshot::channel();
    let (release_reply, reply_gate) = tokio::sync::oneshot::channel();
    let (finished, observed) = tokio::sync::oneshot::channel();
    connector.pending_operations.store(1, Ordering::Release);
    let pending = connector.pending_operations.clone();
    *connector.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        let connection = tokio::task::spawn_blocking(move || {
            let mut connection = rusqlite::Connection::open_in_memory().unwrap();
            connection
                .execute_batch("CREATE TABLE effects (id INTEGER PRIMARY KEY);")
                .unwrap();
            let transaction = connection.transaction().unwrap();
            transaction
                .execute("INSERT INTO effects VALUES (1)", [])
                .unwrap();
            entered.send(()).unwrap();
            transaction_gate.blocking_recv().unwrap();
            transaction.commit().unwrap();
            connection
        })
        .await
        .unwrap();
        committed.send(()).unwrap();
        reply_gate.await.unwrap();
        let effects: i64 = connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        pending.store(0, Ordering::Release);
        finished.send(effects).unwrap();
    }));
    in_transaction.await.unwrap();
    assert!(matches!(
        connector.stop_with_timeout(Duration::ZERO).await.unwrap(),
        ShutdownOutcome::Incomplete { .. }
    ));
    release_transaction.send(()).unwrap();
    after_commit.await.unwrap();
    assert!(matches!(
        connector.stop_with_timeout(Duration::ZERO).await.unwrap(),
        ShutdownOutcome::Incomplete { .. }
    ));
    release_reply.send(()).unwrap();
    assert_eq!(observed.await.unwrap(), 1);
    assert_eq!(connector.stop().await.unwrap(), ShutdownOutcome::Complete);
}

#[tokio::test]
async fn failed_supervisor_is_reported_instead_of_complete() {
    let connector = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    *connector.connection_loop_handle.lock().await = Some(tokio::spawn(async {
        panic!("unresolved mutation");
    }));
    assert!(matches!(
        connector.stop().await,
        Err(ConnectorShutdownError::Supervisor(_))
    ));
}

#[tokio::test]
async fn reconnect_isolates_waiters_and_old_handler_sends() {
    use mtp::host::{AuthenticationPolicy, HostConfig, MTPHost};
    use std::net::{IpAddr, Ipv4Addr};
    let keys = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&keys)
        .unwrap()
        .pem()
        .into_bytes();
    let mut host = MTPHost::new(
        HostConfig::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            cert.clone(),
            keys.serialize_pem().into_bytes(),
        )
        .with_authentication_policy(AuthenticationPolicy::AllowAuthentication),
    )
    .await
    .unwrap();
    let address = format!("https://127.0.0.1:{}", host.local_addr().port());
    let connect = || {
        Client::connect(
            ClientConfig::new(&address)
                .with_pinned_pem(cert.clone())
                .with_description("iota"),
        )
    };
    let (first, peer_a) = tokio::join!(connect(), host.accept());
    let first = Arc::new(first.unwrap());
    let peer_a = peer_a.unwrap().unwrap();
    let (second, peer_b) = tokio::join!(connect(), host.accept());
    let second = Arc::new(second.unwrap());
    let peer_b = peer_b.unwrap().unwrap();
    let connector = Arc::new(OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    ));
    let attempt = |generation, sender: Sender| {
        Arc::new(ConnectionAttempt {
            generation,
            sender: Arc::new(sender),
            responses: tau::ResponseCorrelator::new(),
            cancellation: CancellationToken::new(),
        })
    };
    let a = attempt(1, first.sender.clone());
    let b = attempt(2, second.sender.clone());
    let scoped = |attempt: &Arc<ConnectionAttempt>| {
        let mut connection = connector.as_ref().clone();
        connection.bound_attempt = Some(attempt.clone());
        Arc::new(connection)
    };
    let old_handler = scoped(&a);
    *connector.active_attempt.write().await = Some(a.clone());
    let waiting_a = tokio::spawn({
        let old = old_handler.clone();
        async move {
            old.await_response(
                &CommunicationValue::new(CommunicationType::GetUserData).with_id(42),
                None,
            )
            .await
        }
    });
    let outbound_a = peer_a.receive().await.unwrap();
    *connector.active_attempt.write().await = Some(b.clone());
    let waiting_b = tokio::spawn({
        let connector = connector.clone();
        async move {
            connector
                .await_response(
                    &CommunicationValue::new(CommunicationType::GetUserData).with_id(42),
                    None,
                )
                .await
        }
    });
    let outbound_b = peer_b.receive().await.unwrap();
    assert_eq!(outbound_a.id(), outbound_b.id());
    a.close();
    assert!(
        waiting_a
            .await
            .unwrap()
            .unwrap_err()
            .contains("connection closed")
    );
    assert_eq!(b.responses.len(), 1);
    assert!(
        old_handler
            .send_message(&CommunicationValue::new(CommunicationType::Success))
            .await
            .is_err()
    );
    assert!(!a.responses.complete(
        outbound_a.id().unwrap(),
        CommunicationValue::new(CommunicationType::Success)
    ));
    let read_b = tokio::spawn(scoped(&b).read_loop(second.clone()));
    assert!(!b.responses.complete(
        outbound_b.id().unwrap(),
        CommunicationValue::new(CommunicationType::Success)
    ));
    peer_b
        .sender
        .send(
            &CommunicationValue::new(CommunicationType::GetUserData)
                .with_id(outbound_b.id().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(waiting_b.await.unwrap().unwrap().id(), Some(42));
    b.close();
    // Both maintenance workers exit on attempt cancellation without waiting
    // for their periodic timer or starting invitation network work.
    let maintenance = tokio::spawn(scoped(&b).maintenance_loop(second));
    let invitations = tokio::spawn(scoped(&b).invitation_loop());
    tokio::time::timeout(Duration::from_secs(1), async {
        maintenance.await.unwrap();
        invitations.await.unwrap();
    })
    .await
    .unwrap();
    read_b.await.unwrap();
    assert!(a.responses.is_empty());
    assert!(b.responses.is_empty());
    first.sender.close().await;
    peer_b.sender.close().await;
    host.shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
        .await;
}
