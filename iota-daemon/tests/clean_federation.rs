use iota_daemon_lib::accounts::{AccountAuthority, CreateUserRequest, LocalIotaAccountAuthority};
use iota_identity::LocalNodeIdentity;
use iota_storage::util::config_util::{FederationMode, IotaConfig, WebMode};
use iota_util::{mtp_compat::OptionalDataValueExt, tu::TuCredential};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(root: &Path, ca: &Path) -> Daemon {
    Daemon(
        Command::new(env!("CARGO_BIN_EXE_iota-daemon"))
            .env("IOTA_DATA_ROOT", root)
            .env("IOTA_DEPLOYMENT_MODE", "user")
            .env("SSL_CERT_FILE", ca)
            .env_remove("IOTA_SOCKET")
            .env_remove("IOTA_CONFIG_FILE")
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(root.join("stderr.log")).unwrap())
            .spawn()
            .unwrap(),
    )
}

async fn ready(daemon: &mut Daemon, client: &reqwest::Client, endpoint: &str, root: &Path) {
    for _ in 0..200 {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited: {}",
            std::fs::read_to_string(root.join("stderr.log")).unwrap()
        );
        if client
            .get(format!("https://{endpoint}/.well-known/tensamin"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "daemon HTTPS not ready: {}",
        std::fs::read_to_string(root.join("stderr.log")).unwrap()
    );
}

async fn hosted(
    endpoint: &str,
    certificate: &[u8],
    credential: &TuCredential,
    node: &LocalNodeIdentity,
) -> mtp::client::MTPConnection {
    mtp::client::MTPClient::auth_connect(
        mtp::client::ClientConfig::new(format!("https://{endpoint}/"))
            .with_client_id(credential.user_id as u64)
            .with_description("client")
            .with_pinned_pem(certificate.to_vec()),
        &credential.keyring,
        &node.public_keys(),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_daemons_introduce_resolve_deliver_and_restart_without_remote_key_seeding() {
    if let Ok(root) = std::env::var("TENSAMIN_BOOTSTRAP_SEED") {
        let root = Path::new(&root);
        iota_util::file_util::configure_storage_directory(root.join("state/storage"));
        iota_storage::util::db::initialize_database().unwrap();
        let identity =
            LocalNodeIdentity::load_or_create(&root.join("state/identity/iota.mk"), None).unwrap();
        let username = std::env::var("TENSAMIN_BOOTSTRAP_USERNAME").unwrap();
        LocalIotaAccountAuthority::new(identity)
            .create_user(CreateUserRequest {
                username: username.clone(),
            })
            .await
            .unwrap();
        let credential = iota_util::file_util::read_user_credential(&username)
            .unwrap()
            .unwrap();
        std::fs::write(root.join("user.tu"), credential).unwrap();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a");
    let b = root.path().join("b");
    let mut keys: Vec<_> = (0..2)
        .map(|_| {
            let key = mtp::crypto::Keyring::generate();
            (
                iota_identity::IotaNodeId::from_public_keys(&key.public_key_bundle())
                    .unwrap()
                    .as_str()
                    .to_owned(),
                key,
            )
        })
        .collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    for (home, (_, key)) in [&a, &b].into_iter().zip(keys) {
        LocalNodeIdentity::load_or_create(&home.join("state/identity/iota.mk"), Some(key)).unwrap();
    }
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&tls_key).unwrap();
    let certificate = cert.pem();
    let ca_path = root.path().join("ca.pem");
    std::fs::write(&ca_path, &certificate).unwrap();
    let mut endpoints = Vec::new();
    for (home, username) in [(&a, "alice"), (&b, "bob")] {
        std::fs::create_dir_all(home.join("config")).unwrap();
        std::fs::write(home.join("tls.pem"), &certificate).unwrap();
        std::fs::write(home.join("tls.key"), tls_key.serialize_pem()).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let endpoint = format!("127.0.0.1:{port}");
        let mut config = IotaConfig::default();
        config.web.mode = WebMode::Network;
        config.web.federation_mode = FederationMode::FederatedDirect;
        config.web.bind = "127.0.0.1".into();
        config.web.port = port;
        config.web.required = true;
        config.web.certificate = Some(home.join("tls.pem").to_str().unwrap().into());
        config.web.key = Some(home.join("tls.key").to_str().unwrap().into());
        config.web.authority_locator = Some(endpoint.clone());
        config.web.direct_endpoints = vec![endpoint.clone()];
        config.web.allow_lan_federation = true;
        config.web.allow_raw_ip_federation = true;
        std::fs::write(
            home.join("config/config.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        let accepted = Some(("backend-test".into(), "backend-test".into()));
        iota_terms::consent::save(
            &home.join("state"),
            &iota_terms::consent::ConsentRecord {
                eula: accepted.clone(),
                tos: accepted.clone(),
                privacy: accepted,
            },
        )
        .unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("clean_daemons_introduce_resolve_deliver_and_restart_without_remote_key_seeding")
            .env("TENSAMIN_BOOTSTRAP_SEED", home)
            .env("TENSAMIN_BOOTSTRAP_USERNAME", username)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "seed failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        endpoints.push(endpoint);
    }
    let alice = TuCredential::parse(&std::fs::read_to_string(a.join("user.tu")).unwrap()).unwrap();
    let bob = TuCredential::parse(&std::fs::read_to_string(b.join("user.tu")).unwrap()).unwrap();
    assert_eq!(alice.user_id, bob.user_id);
    assert_ne!(alice.principal().unwrap(), bob.principal().unwrap());
    let node_a =
        LocalNodeIdentity::load_or_create(&a.join("state/identity/iota.mk"), None).unwrap();
    let node_b =
        LocalNodeIdentity::load_or_create(&b.join("state/identity/iota.mk"), None).unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(certificate.as_bytes()).unwrap())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut daemon_a = start(&a, &ca_path);
    let mut daemon_b = start(&b, &ca_path);
    ready(&mut daemon_a, &http, &endpoints[0], &a).await;
    ready(&mut daemon_b, &http, &endpoints[1], &b).await;
    let connection = hosted(&endpoints[0], certificate.as_bytes(), &alice, &node_a).await;
    let query = CommunicationValue::new(CommunicationType::UserResolve)
        .with_id(1)
        .add_typed_default(
            DataType::UserAddress,
            DataValue::Str(format!("bob@{}", endpoints[1])),
        );
    let resolved = connection.request(&query, None).await.unwrap();
    assert!(
        resolved.is_type(CommunicationType::UserResolved),
        "{resolved:?}"
    );
    assert_eq!(
        resolved.get_data(DataType::Principal).as_str(),
        Some(
            serde_json::to_string(&bob.principal().unwrap())
                .unwrap()
                .as_str()
        )
    );
    let db_b = || rusqlite::Connection::open(b.join("state/storage/messages.sqlite3")).unwrap();
    assert_eq!(
        db_b()
            .query_row("SELECT COUNT(*) FROM federation_peer_admissions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    use iota_connection::federated_relay::{protocol, protocol_principal};
    let principals = [
        protocol_principal(&alice.principal().unwrap()),
        protocol_principal(&bob.principal().unwrap()),
    ];
    let chat = protocol::canonical_chat_id(&principals[0], &principals[1]);
    let secret = CommunicationValue::new(CommunicationType::SetChatSecret);
    let map = secret.type_map().unwrap();
    let copies = principals
        .iter()
        .map(|principal| {
            DataValue::Container(vec![
                (
                    DataType::UserId.try_to_id(map).unwrap(),
                    DataValue::Str(serde_json::to_string(principal).unwrap()),
                ),
                (
                    DataType::EncryptedSecret.try_to_id(map).unwrap(),
                    DataValue::Bytes(vec![1, 2, 3]),
                ),
                (
                    DataType::KemCiphertext.try_to_id(map).unwrap(),
                    DataValue::Bytes(vec![4, 5, 6]),
                ),
            ])
        })
        .collect();
    let secret = secret
        .add_typed_default(DataType::ChatId, DataValue::Str(chat.clone()))
        .add_typed_default(
            DataType::SecretId,
            DataValue::Str(protocol::chat_secret_id(&chat)),
        )
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1))
        .add_typed_default(
            DataType::WrappingScheme,
            DataValue::Str("backend-test".into()),
        )
        .add_typed_default(DataType::Recipients, DataValue::Array(copies));
    let secret = iota_connection::federated_relay::FederatedRelay::sign(
        alice.principal().unwrap(),
        bob.principal().unwrap(),
        node_b.node_id().clone(),
        "bootstrap-secret".into(),
        iota_storage::util::sync::now_millis() as u64,
        secret,
        &alice.keyring,
        vec![
            node_a.public_keys(),
            node_b.public_keys(),
            alice.public_key_bundle(),
            bob.public_key_bundle(),
        ],
    )
    .unwrap()
    .into_frame(4)
    .unwrap();
    let response = connection.request(&secret, None).await.unwrap();
    assert!(response.is_type(CommunicationType::Success), "{response:?}");
    let origin = rusqlite::Connection::open(a.join("state/storage/messages.sqlite3")).unwrap();
    for _ in 0..200 {
        if origin
            .query_row("SELECT COUNT(*) FROM chat_secrets", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
            == 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        origin
            .query_row("SELECT COUNT(*) FROM chat_secrets", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "secret not destination-acknowledged; A logs {:?}; B logs {:?}",
        std::fs::read_dir(a.join("logs"))
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect::<Vec<_>>(),
        std::fs::read_dir(b.join("logs"))
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect::<Vec<_>>()
    );
    let frame = iota_connection::federated_relay::FederatedRelay::sign(
        alice.principal().unwrap(),
        bob.principal().unwrap(),
        node_b.node_id().clone(),
        "clean-bootstrap".into(),
        iota_storage::util::sync::now_millis() as u64,
        CommunicationValue::new(CommunicationType::MessageSend)
            .add_typed_default(
                DataType::Content,
                DataValue::Str("backend encrypted content".into()),
            )
            .add_typed_default(DataType::SendTime, DataValue::SignedNumber(1))
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1)),
        &alice.keyring,
        vec![
            node_a.public_keys(),
            node_b.public_keys(),
            alice.public_key_bundle(),
            bob.public_key_bundle(),
        ],
    )
    .unwrap()
    .into_frame(2)
    .unwrap();
    let response = connection.request(&frame, None).await.unwrap();
    assert!(
        response.is_type(CommunicationType::Success),
        "{response:?}; logs: {:?}",
        std::fs::read_dir(a.join("logs"))
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect::<Vec<_>>()
    );
    let mut delivered = false;
    for _ in 0..300 {
        let count = db_b()
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap();
        if count == 1 {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        delivered,
        "no destination message; A: {}; B: {}",
        std::fs::read_to_string(a.join("stderr.log")).unwrap(),
        std::fs::read_to_string(b.join("stderr.log")).unwrap()
    );
    assert_eq!(
        db_b()
            .query_row(
                "SELECT status FROM federation_peer_admissions WHERE node_id=?1",
                [node_a.node_id().as_str()],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "established"
    );
    connection.sender.close_immediate();
    drop(daemon_a);
    rusqlite::Connection::open(a.join("state/storage/messages.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE principals SET last_resolved_at=0 WHERE authority_id=?1",
            [bob.principal().unwrap().authority.as_str()],
        )
        .unwrap();
    daemon_a = start(&a, &ca_path);
    ready(&mut daemon_a, &http, &endpoints[0], &a).await;
    let restarted = hosted(&endpoints[0], certificate.as_bytes(), &alice, &node_a).await;
    let canonical = CommunicationValue::new(CommunicationType::UserResolve)
        .with_id(3)
        .add_typed_default(
            DataType::UserAddress,
            DataValue::Str(serde_json::to_string(&bob.principal().unwrap()).unwrap()),
        );
    let resolved = restarted.request(&canonical, None).await.unwrap();
    assert!(
        resolved.is_type(CommunicationType::UserResolved),
        "canonical refresh after restart: {resolved:?}"
    );
    assert!(
        restarted
            .request(&frame, None)
            .await
            .unwrap()
            .is_type(CommunicationType::Success)
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        db_b()
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
