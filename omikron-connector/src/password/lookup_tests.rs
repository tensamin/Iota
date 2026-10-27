use super::*;
use base64::Engine as _;
use iota_storage::util::db;
use mtp::crypto::Keyring;

#[tokio::test]
async fn omega_lookups_overlap_at_ke1_and_ke3_and_fail_closed() {
    if std::env::var_os("PASSWORD_LOOKUP_CHILD").is_none() {
        use std::{
            io::{Read, Write},
            sync::{
                Condvar, Mutex,
                atomic::{AtomicBool, Ordering},
            },
        };
        let account = Keyring::generate();
        let omega = Keyring::generate();
        let node = iota_identity::LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
        let authority = iota_identity::AuthorityId::for_omega(&omega.public_key_bundle())
            .unwrap()
            .as_str()
            .to_owned();
        let discovery = serde_json::json!({"authority_id":authority,"public_key":omega.public_key_bundle().try_to_base64().unwrap()}).to_string();
        let other = Keyring::generate().public_key_bundle();
        let changed_authority = serde_json::json!({"authority_id":iota_identity::AuthorityId::for_omega(&other).unwrap().as_str(),"public_key":other.try_to_base64().unwrap()}).to_string();
        let profile =
            super::super::password_identity_fixture(&omega, &node, account.public_key_bundle(), 1);
        let changed_key = super::super::password_identity_fixture(&omega, &node, other, 2);
        let other_node =
            iota_identity::LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
        let changed_iota = super::super::password_identity_fixture(
            &omega,
            &other_node,
            account.public_key_bundle(),
            2,
        );
        let responses = Arc::new((
            discovery,
            changed_authority,
            profile,
            changed_key,
            changed_iota,
        ));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let shutdown = stopped.clone();
        let pair = Arc::new((Mutex::new((String::from("ok"), 0u8)), Condvar::new()));
        let server = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !shutdown.load(Ordering::Acquire) {
                let (mut stream, _) = listener.accept().unwrap();
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                let pair = pair.clone();
                let responses = responses.clone();
                workers.push(std::thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        if stream.read(&mut byte).unwrap_or(0) == 0 { return; }
                        request.push(byte[0]);
                        assert!(request.len() < 8192);
                    }
                    let request = String::from_utf8(request).unwrap();
                    let path = request.split_whitespace().nth(1).unwrap();
                    let (status,body) = if let Some(mode) = path.strip_prefix("/test/") {
                        *pair.0.lock().unwrap() = (mode.to_owned(),0);
                        (200,"{}")
                    } else {
                        let authority = path == "/.well-known/tensamin";
                        let mut state = pair.0.lock().unwrap();
                        state.1 |= if authority { 1 } else { 2 };
                        pair.1.notify_all();
                        // Serial production requests fail this rendezvous. Both
                        // endpoints must be in flight before either returns.
                        let (state,timeout) = pair.1.wait_timeout_while(state,Duration::from_secs(2),|state| state.1 != 3).unwrap();
                        let mode = state.0.clone();
                        drop(state);
                        std::thread::sleep(Duration::from_millis(100));
                        let failed = timeout.timed_out() || (authority && mode == "authority_fail") || (!authority && mode == "account_fail");
                        let body = if authority {
                            if mode == "authority_changed" { &responses.1 } else { &responses.0 }
                        } else { match mode.as_str() { "key_changed"=>&responses.3,"iota_changed"=>&responses.4,_=>&responses.2 } };
                        (if failed { 503 } else { 200 },body.as_str())
                    };
                    let _ = write!(stream,"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","password::provisioning::lookup_tests::omega_lookups_overlap_at_ke1_and_ke3_and_fail_closed","--nocapture"])
            .env("PASSWORD_LOOKUP_CHILD","1")
            .env("PASSWORD_LOOKUP_ACCOUNT",base64::engine::general_purpose::STANDARD.encode(account.try_to_bytes().unwrap()))
            .env("PASSWORD_LOOKUP_NODE",base64::engine::general_purpose::STANDARD.encode(node.keyring().try_to_bytes().unwrap()))
            .env("PASSWORD_LOOKUP_AUTHORITY",authority)
            .env("OMEGA_API_URL",format!("http://{address}"))
            .status().unwrap();
        stopped.store(true, Ordering::Release);
        let _ = std::net::TcpStream::connect(address);
        server.join().unwrap();
        assert!(status.success());
        return;
    }
    let directory =
        std::path::Path::new("/tmp/opencode").join(format!("password-lookups-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    iota_util::file_util::configure_storage_directory(directory.clone());
    db::initialize_database().unwrap();
    iota_storage::identity::bind_omega_authority(
        &iota_identity::AuthorityId::new(std::env::var("PASSWORD_LOOKUP_AUTHORITY").unwrap())
            .unwrap(),
    )
    .unwrap();
    let mut config = (**iota_storage::util::config_util::CONFIG.load()).clone();
    config.iota_id = Some(11);
    iota_storage::util::config_util::CONFIG.store(Arc::new(config));
    let account = Keyring::from_bytes(
        &base64::engine::general_purpose::STANDARD
            .decode(std::env::var("PASSWORD_LOOKUP_ACCOUNT").unwrap())
            .unwrap(),
    )
    .unwrap();
    let public = account.public_key_bundle().try_to_base64().unwrap();
    db::with_db(|connection| {
        connection.execute(
            "INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'alice',?1,1)",
            [&public],
        )?;
        Ok(())
    })
    .unwrap();
    let connection = Arc::new(OmikronConnection::new(
        Arc::new(dashmap::DashSet::new()),
        Arc::new(std::sync::Mutex::new(iota_state::AppState::new())),
    ));
    *connection.keyring.write().await = Some(Arc::new(
        Keyring::from_bytes(
            &base64::engine::general_purpose::STANDARD
                .decode(std::env::var("PASSWORD_LOOKUP_NODE").unwrap())
                .unwrap(),
        )
        .unwrap(),
    ));
    let setup = opaque::generate_server_setup();
    let principal = format!("{}#7", std::env::var("PASSWORD_LOOKUP_AUTHORITY").unwrap());
    let registration = opaque::client_registration_start(b"password").unwrap();
    let response =
        opaque::server_registration_start(&setup, &registration.request, principal.as_bytes())
            .unwrap();
    let upload = registration
        .state
        .finish(&response, &principal, 11)
        .unwrap();
    let mut encrypted = b"TSCRED\0\0\0\x01".to_vec();
    encrypted.resize(50, 0);
    let credential = password_credentials::PasswordCredential {
        user_id: 7,
        opaque_profile: opaque::CURRENT_OPAQUE_PROFILE,
        opaque_record: opaque::server_registration_finish(&upload.upload).unwrap(),
        encrypted_tu_credential: encrypted,
        account_public_key_sha256: super::super::wire::key_fingerprint(&public).unwrap(),
        created_at: 1,
        updated_at: 1,
        setup_sha256: Some(Sha256::digest(opaque::serialize_server_setup(&setup)).to_vec()),
        password_principal: Some(principal.clone()),
        password_iota_id: Some(11),
    };
    let generation = password_credentials::authorization(7).unwrap().1;
    password_credentials::upsert_if_authorized(&credential, &public, generation).unwrap();
    connection
        .password_auth
        .setup
        .set(Arc::new(setup))
        .ok()
        .unwrap();
    let mode = |mode: &'static str| {
        let client = connection.http_client.clone();
        async move {
            client
                .get(format!(
                    "{}/test/{mode}",
                    crate::omega_discovery::api_base()
                ))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }
    };
    // KE1 endpoint failures run the production asynchronous cleanup path.
    for failure in ["authority_fail", "account_fail"] {
        mode(failure).await;
        let id = Uuid::new_v4();
        let login = opaque::client_login_start(b"password").unwrap();
        let request = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
            .with_id(1)
            .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(7))
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(11))
            .add_typed_default(
                DataType::ProvisioningParticipantId,
                DataValue::UnsignedNumber(99),
            )
            .add_typed_default(
                DataType::PublicKey,
                DataValue::Str(account.public_key_bundle().try_to_base64().unwrap()),
            )
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(login.request));
        connection
            .clone()
            .handle_password_provisioning_start(&request)
            .await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while connection.password_auth.logins.contains_key(&id) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            connection.password_auth.attempts.get(&7).unwrap().in_flight,
            0
        );
    }
    for failure in [
        "ok",
        "authority_fail",
        "account_fail",
        "key_changed",
        "iota_changed",
        "authority_changed",
    ] {
        mode("ok").await;
        let id = Uuid::new_v4();
        let contact = Keyring::generate();
        let login = opaque::client_login_start(b"password").unwrap();
        let request = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
            .with_id(1)
            .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
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
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(login.request));
        let prepared = connection
            .prepare_password_provisioning_start(&request)
            .unwrap();
        let ke2 = connection
            .execute_password_provisioning_start(prepared)
            .await
            .unwrap();
        let fingerprint = public_key_fingerprint(&contact.public_key_bundle()).unwrap();
        let binding = PasswordLoginBindingV1 {
            principal: &principal,
            iota_id: 11,
            session_id: id,
            contact_key_sha256: &fingerprint,
        };
        let finalization = login
            .state
            .finish(
                ke2.get_data(DataType::OpaqueMessage)
                    .unwrap()
                    .as_bytes_slice()
                    .unwrap(),
                &binding,
            )
            .unwrap();
        let mut finish =
            CommunicationValue::new(CommunicationType::PasswordProvisioningFinish).with_id(2);
        for (kind, value) in request.iter_typed_data() {
            finish = finish.add_typed_default(kind.unwrap(), value.clone());
        }
        let finish = finish.with_data(
            DataType::OpaqueMessage,
            DataValue::Bytes(finalization.finalization),
        );
        mode(failure).await;
        let result = connection.provisioning_finish(&finish).await;
        assert_eq!(result.is_ok(), failure == "ok", "{failure}");
        assert!(!connection.password_auth.logins.contains_key(&id));
        assert_eq!(
            connection.password_auth.attempts.get(&7).unwrap().in_flight,
            0
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}
