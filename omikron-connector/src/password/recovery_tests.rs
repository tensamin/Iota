use super::*;
use iota_storage::{
    users::password_credentials::{self, PasswordCredential},
    util::db,
};
use mtp::{codec::InMemoryReplayGuard, crypto::Keyring};
use std::sync::Arc;

#[tokio::test]
async fn committed_password_receipts_and_health_survive_lost_responses() {
    // Isolate the process-global SQLite pool and configuration from other tests.
    if std::env::var_os("PASSWORD_RECEIPT_TEST_CHILD").is_none() {
        use base64::Engine as _;
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        let account = Keyring::generate();
        let account_key = account.public_key_bundle().try_to_base64().unwrap();
        let omega = Keyring::generate().public_key_bundle();
        let authority = iota_identity::AuthorityId::for_omega(&omega)
            .unwrap()
            .as_str()
            .to_owned();
        let discovery = serde_json::json!({"authority_id": authority, "public_key": omega.try_to_base64().unwrap()}).to_string();
        let profile =
            serde_json::json!({"user_id":7,"iota_id":11,"public_key": account_key}).to_string();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let shutdown = stopped.clone();
        let server = std::thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                let (mut stream, _) = listener.accept().unwrap();
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(byte[0]);
                    assert!(request.len() <= 8192);
                }
                let request = String::from_utf8(request).unwrap();
                let body = if request.starts_with("GET /.well-known/tensamin ") {
                    &discovery
                } else {
                    &profile
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            }
        });
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "password::recovery_tests::committed_password_receipts_and_health_survive_lost_responses"])
            .env("PASSWORD_RECEIPT_TEST_CHILD", "1")
            .env("PASSWORD_RECEIPT_ACCOUNT_KEY", base64::engine::general_purpose::STANDARD.encode(account.try_to_bytes().unwrap()))
            .env("PASSWORD_RECEIPT_OMEGA_AUTHORITY", authority)
            .env("OMEGA_API_URL", format!("http://{address}"))
            .status().unwrap();
        stopped.store(true, Ordering::Release);
        let _ = std::net::TcpStream::connect(address);
        server.join().unwrap();
        assert!(status.success());
        return;
    }
    let directory =
        std::path::Path::new("/tmp/opencode").join(format!("password-receipt-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    iota_util::file_util::configure_storage_directory(directory.clone());
    db::initialize_database().unwrap();
    let mut config = (**iota_storage::util::config_util::CONFIG.load()).clone();
    config.iota_id = Some(11);
    iota_storage::util::config_util::CONFIG.store(Arc::new(config));
    let node = Keyring::generate();
    use base64::Engine as _;
    let account = Keyring::from_bytes(
        &base64::engine::general_purpose::STANDARD
            .decode(std::env::var("PASSWORD_RECEIPT_ACCOUNT_KEY").unwrap())
            .unwrap(),
    )
    .unwrap();
    let public_key = account.public_key_bundle().try_to_base64().unwrap();
    db::with_db(|conn| {
        conn.execute(
            "INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'alice',?1,1)",
            [&public_key],
        )?;
        Ok(())
    })
    .unwrap();
    let connection = OmikronConnection::new(
        Arc::new(dashmap::DashSet::new()),
        Arc::new(std::sync::Mutex::new(iota_state::AppState::new())),
    );
    *connection.keyring.write().await = Some(Arc::new(node));
    let setup = opaque::generate_server_setup();
    let authority = std::env::var("PASSWORD_RECEIPT_OMEGA_AUTHORITY").unwrap();
    let principal_string = format!("{authority}#7");
    let principal = principal_string.as_str();
    let registration = opaque::client_registration_start(b"a recovery password").unwrap();
    let challenge =
        opaque::server_registration_start(&setup, &registration.request, principal.as_bytes())
            .unwrap();
    let upload = registration
        .state
        .finish(&challenge, principal, 11)
        .unwrap();
    let mut encrypted = b"TSCRED\0\0\0\x01".to_vec();
    encrypted.resize(50, 0);
    let mut credential = PasswordCredential {
        user_id: 7,
        opaque_profile: opaque::CURRENT_OPAQUE_PROFILE,
        opaque_record: opaque::server_registration_finish(&upload.upload).unwrap(),
        encrypted_tu_credential: encrypted,
        account_public_key_sha256: wire::key_fingerprint(&public_key).unwrap(),
        created_at: 1,
        updated_at: 1,
        setup_sha256: Some(
            Sha256::digest(opaque::serialize_server_setup(&setup).as_slice()).to_vec(),
        ),
        password_principal: Some(principal.into()),
        password_iota_id: Some(11),
    };
    connection
        .password_auth
        .setup
        .set(Arc::new(setup))
        .ok()
        .unwrap();
    connection
        .password_auth
        .omega_authority
        .set(authority)
        .unwrap();
    let node = connection.keyring.read().await.clone().unwrap();
    let enrollment_id = Uuid::new_v4();
    let original = connection
        .build_protected(
            &CommunicationValue::new(CommunicationType::PasswordEnrollmentFinish).with_id(42),
            CommunicationType::PasswordEnrollmentFinish,
            7,
            11,
            DataValue::Container(vec![
                typed(DataType::Uuid, DataValue::Str(enrollment_id.to_string())).unwrap(),
                typed(DataType::OpaqueMessage, DataValue::Bytes(upload.upload)).unwrap(),
                typed(
                    DataType::EncryptedCredential,
                    DataValue::Bytes(credential.encrypted_tu_credential.clone()),
                )
                .unwrap(),
            ]),
            node.public_key_bundle(),
            PASSWORD_MANAGEMENT_SIGNATURE,
            PASSWORD_MANAGEMENT_ENCRYPTION,
            &account,
        )
        .unwrap()
        .with_sender(7);
    let (opened, key, generation) = connection
        .open_password_command(
            &original,
            CommunicationType::PasswordEnrollmentFinish,
            false,
        )
        .await
        .unwrap();
    let operation = opened.message_id().to_string();
    let digest = Sha256::digest(original.clone().without_id().to_bytes().unwrap());
    let map = original.type_map().unwrap();
    let query =
        CommunicationValue::new_with_type_map(CommunicationType::PasswordEnrollmentStatus, map)
            .with_id(88)
            .with_sender(7)
            .add_typed_default(DataType::Version, DataValue::Str(map.version.to_string()))
            .add_typed_default(
                DataType::SecurePayload,
                DataValue::Bytes(original.clone().without_id().to_bytes().unwrap()),
            );
    assert!(
        connection
            .password_mutation_status(&query)
            .await
            .unwrap()
            .is_type(CommunicationType::ErrorInternal)
    );
    connection.password_auth.enrollments.insert(
        enrollment_id,
        runtime::PendingEnrollment {
            public_key: key.clone(),
            authorization_generation: generation,
            user_id: 7,
            created: Instant::now(),
            _permit: connection.password_auth.begin_enrollment().unwrap(),
        },
    );
    // Exercise the real mutation handler, then lose its already-built response.
    let lost_response = connection.enrollment_finish(&original).await.unwrap();
    drop(lost_response);
    credential = password_credentials::get(7).unwrap().unwrap();
    assert_eq!(
        password_credentials::mutation_outcome(7, &key, generation, (&operation, &digest)).unwrap(),
        Some(true)
    );
    // No acknowledgment was delivered. Retrying the mutation still fails;
    // the separately authenticated status query recovers its committed result.
    assert!(
        connection
            .open_password_command(&original, CommunicationType::PasswordEnrollmentFinish, true)
            .await
            .is_err()
    );
    let response = connection.password_mutation_status(&query).await.unwrap();
    assert_eq!(response.id(), Some(88));
    let opened = open_protected_with_checked(
        &response,
        &[&account],
        Some(11),
        |_| Some(vec![node.public_key_bundle()]),
        ProtectedOpenOptions::new(
            Some(7),
            purpose(app_protection::PASSWORD_RESPONSE_SIGNATURE),
            purpose(app_protection::PASSWORD_RESPONSE_ENCRYPTION),
            ProtectionPolicy::dual(),
        ),
        &mut InMemoryReplayGuard::default(),
    )
    .unwrap();
    assert_eq!(
        wire::field(opened.content(), DataType::Enabled)
            .unwrap()
            .as_bool(),
        Some(true)
    );
    assert!(
        connection
            .password_mutation_status(&query.clone().with_sender(8))
            .await
            .is_err()
    );
    assert_eq!(
        connection.password_health().credentials.unwrap().validated,
        1
    );
    let unknown_identity = PasswordAuthRuntime::default();
    unknown_identity
        .setup
        .set(connection.password_auth.setup().unwrap())
        .ok()
        .unwrap();
    unknown_identity.validate_storage().unwrap();
    assert_eq!(
        unknown_identity.health().readiness,
        PasswordReadiness::IdentityUnverified
    );
    assert_eq!(
        unknown_identity
            .health()
            .credentials
            .unwrap()
            .identity_unverified,
        1
    );

    // Complete real OPAQUE KE3 exchanges and deliver the protected credential
    // over MTP on both sides of the documented release/disable ordering.
    use mtp::{
        client::{Client, ClientConfig},
        host::{AuthenticationPolicy, HostConfig, MTPHost},
    };
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&tls_key)
        .unwrap()
        .pem()
        .into_bytes();
    let mut host = MTPHost::new(
        HostConfig::new(
            "127.0.0.1".parse().unwrap(),
            0,
            certificate.clone(),
            tls_key.serialize_pem().into_bytes(),
        )
        .with_authentication_policy(AuthenticationPolicy::AllowAuthentication),
    )
    .await
    .unwrap();
    let url = format!("https://127.0.0.1:{}", host.local_addr().port());
    let (transport, peer) = tokio::join!(
        Client::connect(ClientConfig::new(&url).with_pinned_pem(certificate)),
        host.accept()
    );
    let transport = transport.unwrap();
    let peer = peer.unwrap().unwrap();
    let contact = Keyring::generate();
    for disable_first in [true, false] {
        password_credentials::upsert_if_authorized(&credential, &key, generation).unwrap();
        let session = Uuid::new_v4();
        let contact_fingerprint =
            wire::public_key_fingerprint(&contact.public_key_bundle()).unwrap();
        let binding = PasswordLoginBindingV1 {
            principal,
            iota_id: 11,
            session_id: session,
            contact_key_sha256: &contact_fingerprint,
        };
        let login = opaque::client_login_start(b"a recovery password").unwrap();
        let ke2 = opaque::server_login_start(
            connection.password_auth.setup().unwrap().as_ref(),
            Some(&credential.opaque_record),
            &login.request,
            &binding,
        )
        .unwrap();
        let ke3 = login.state.finish(&ke2.response, &binding).unwrap();
        connection.password_auth.logins.insert(
            session,
            PendingLogin {
                connection_generation: connection.password_connection_generation(),
                user_id: 7,
                participant_id: 99,
                contact_key: contact.public_key_bundle(),
                advertised_account_key: Some(wire::key_fingerprint(&key).unwrap()),
                state: Some(ke2.state),
                real_record: true,
                record_hash: Some(Sha256::digest(&credential.opaque_record).to_vec()),
                created: Instant::now(),
                attempt: Some(connection.password_auth.begin_attempt(7).unwrap().0),
            },
        );
        let request = CommunicationValue::new(CommunicationType::PasswordProvisioningFinish)
            .with_id(123)
            .add_typed_default(DataType::Uuid, DataValue::Str(session.to_string()))
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(7))
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(11))
            .add_typed_default(
                DataType::ProvisioningParticipantId,
                DataValue::UnsignedNumber(99),
            )
            .add_typed_default(
                DataType::PublicKey,
                DataValue::Str(contact.public_key_bundle().try_to_base64().unwrap()),
            )
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(ke3.finalization));
        let prepared = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        if disable_first {
            *connection.password_auth.release_gate.lock().unwrap() =
                Some((prepared.clone(), release.clone()));
        }
        let finish = tokio::spawn({
            let connection = connection.clone();
            let request = request.clone();
            async move { connection.provisioning_finish(&request).await }
        });
        if disable_first {
            // The production handler has consumed and verified KE3 and built
            // the response, but has not reached its authorization transaction.
            tokio::time::timeout(Duration::from_secs(5), prepared.notified())
                .await
                .unwrap();
            password_credentials::commit_disable(
                7,
                &key,
                generation,
                ("disable-before-release", &[8; 32]),
            )
            .unwrap();
            release.notify_one();
            assert!(finish.await.unwrap().is_err());
            assert!(
                tokio::time::timeout(Duration::from_millis(50), peer.receive())
                    .await
                    .is_err()
            );
        } else {
            let protected = finish.await.unwrap().unwrap();
            password_credentials::commit_disable(
                7,
                &key,
                generation,
                ("disable-after-release", &[9; 32]),
            )
            .unwrap();
            transport.sender.send(&protected).await.unwrap();
            let delivered = tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap();
            let opened = open_protected_with_checked(
                &delivered,
                &[&contact],
                Some(11),
                |_| Some(vec![node.public_key_bundle()]),
                ProtectedOpenOptions::new(
                    Some(99),
                    purpose(app_protection::PROVISIONING_CREDENTIAL_SIGNATURE),
                    purpose(app_protection::PROVISIONING_CREDENTIAL_ENCRYPTION),
                    ProtectionPolicy::dual(),
                ),
                &mut InMemoryReplayGuard::default(),
            )
            .unwrap();
            assert_eq!(
                wire::field(opened.content(), DataType::EncryptedCredential)
                    .unwrap()
                    .as_bytes()
                    .unwrap(),
                credential.encrypted_tu_credential
            );
        }
        assert!(connection.provisioning_finish(&request).await.is_err());
    }
    transport.sender.close().await;
    host.shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    let mut invalid = credential.clone();
    invalid.encrypted_tu_credential[0] ^= 1;
    password_credentials::upsert_if_authorized(&invalid, &key, generation).unwrap();
    let health = connection.password_health();
    assert!(health.setup_available && health.storage_validated);
    assert_eq!(health.readiness, PasswordReadiness::CredentialsInvalid);
    assert_eq!(health.credentials.unwrap().invalid, 1);
    assert!(connection.password_auth.setup().is_ok());
    let mut legacy = credential.clone();
    legacy.setup_sha256 = None;
    legacy.password_principal = None;
    legacy.password_iota_id = None;
    password_credentials::upsert_if_authorized(&legacy, &key, generation).unwrap();
    let health = connection.password_health();
    assert_eq!(health.readiness, PasswordReadiness::LegacyUnverified);
    assert_eq!(health.credentials.unwrap().legacy_unverified, 1);
    assert_eq!(health.credentials.unwrap().validated, 0);
    let mut wrong_setup = credential.clone();
    wrong_setup.setup_sha256.as_mut().unwrap()[0] ^= 1;
    password_credentials::upsert_if_authorized(&wrong_setup, &key, generation).unwrap();
    let health = connection.password_health();
    assert!(health.storage_validated);
    assert_eq!(health.readiness, PasswordReadiness::SetupMismatch);
    assert_eq!(health.credentials.unwrap().invalid, 1);
    assert!(connection.password_auth.setup().is_err());
    db::with_db(|conn| {
        conn.execute("UPDATE user_password_credentials SET opaque_record = 'invalid storage type' WHERE user_id = 7", [])?;
        Ok(())
    }).unwrap();
    let health = connection.password_health();
    assert!(health.setup_available);
    assert!(!health.storage_validated);
    assert!(health.credentials.is_none());
    assert_eq!(
        health.readiness,
        PasswordReadiness::StorageValidationFailure
    );
    assert!(connection.password_auth.setup().is_err());
    // The receipt reports the historical commit, not a re-enrollment or a
    // claim that the current credential is still structurally valid.
    assert!(
        connection
            .password_mutation_status(&query)
            .await
            .unwrap()
            .payload()
            .as_encrypted()
            .is_some()
    );
    std::fs::remove_dir_all(directory).unwrap();
}
