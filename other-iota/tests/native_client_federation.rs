//! Real authenticated MTP around the pinned unchanged Client assertions.
// The shared fixture also contains tests gated by its owning crate's feature.
#[allow(unexpected_cfgs)]
#[path = "../../iota-connection/tests/native_relay_ingress.rs"]
mod pinned;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_connection::{chat_secret_recovery::*, relay_service::RelayService};
use iota_identity::{AuthorityLocator, LocalNodeIdentity};
use iota_storage::{
    identity::{SqliteLocalUserStore, SqlitePrincipalStore},
    node_directory::SqliteNodeDirectory,
    util::db,
};
use mtp::{
    codec::CommunicationValue,
    crypto::Keyring,
    host::{AuthenticationPolicy, HostConfig},
    webserver::{MTPWebServer, WebServerConfig},
};
use other_iota::{DirectPeerRouter, LocalDeliverySink, PeerManager};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

struct NoSecretDelivery;
#[async_trait]
impl LocalDeliverySink for NoSecretDelivery {
    async fn deliver(&self, _: iota_identity::PrincipalHandle, _: CommunicationValue) {
        panic!(
            "SetChatSecret must notify through committed metadata, not raw Client relay delivery"
        );
    }
}

struct Runtime {
    manager: Arc<PeerManager>,
    shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    server: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn rendezvous() -> PathBuf {
    PathBuf::from(std::env::var_os("NATIVE_MTP_RENDEZVOUS").unwrap())
}

fn stage_hook(
    service: Arc<RelayService>,
    nodes: Vec<LocalNodeIdentity>,
    index: usize,
) -> pinned::StageFuture {
    Box::pin(async move {
        let directory = Arc::new(SqliteNodeDirectory);
        let now = iota_storage::util::sync::now_millis();
        for node in &nodes {
            directory
                .ensure_local_descriptor(node, vec![], vec![], now)
                .unwrap();
        }
        let router = Arc::new(DirectPeerRouter::default());
        let manager = Arc::new(PeerManager::new(
            nodes[index].clone(),
            directory.clone(),
            router.clone(),
            service.clone(),
            Arc::new(NoSecretDelivery),
        ));
        router.attach_manager(&manager);
        let recovery = Arc::new(RecoveryCoordinator::new(
            Arc::new(pinned::relay_support::Resolver),
            directory.clone(),
            Arc::new(SqlitePrincipalStore),
            Arc::new(SqliteLocalUserStore),
            nodes[index].node_id().clone(),
            router.clone(),
            Arc::new(OriginalOperationVerifier { relay: service }),
        ));
        router.install_recovery(recovery.clone());
        install_recovery(recovery);
        assert!(pinned::ROUTER.set(router).is_ok());
        if index == 0 {
            let ready: serde_json::Value =
                serde_json::from_slice(&std::fs::read(rendezvous().join("ready.json")).unwrap())
                    .unwrap();
            let endpoint = AuthorityLocator::new(ready["endpoint"].as_str().unwrap()).unwrap();
            let certificate = STANDARD
                .decode(ready["certificate"].as_str().unwrap())
                .unwrap();
            manager
                .connect(nodes[1].node_id().clone(), &endpoint, Some(certificate))
                .await
                .unwrap();
            assert!(
                RUNTIME
                    .set(Runtime {
                        manager,
                        shutdown: Mutex::new(None),
                        server: Mutex::new(None)
                    })
                    .is_ok()
            );
        } else {
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let certificate =
                rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap()
                    .self_signed(&key_pair)
                    .unwrap()
                    .pem()
                    .into_bytes();
            let client_key = nodes[0].public_keys();
            let client_hint = nodes[0].node_id().mtp_authentication_hint();
            let host = HostConfig::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
                certificate.clone(),
                key_pair.serialize_pem().into_bytes(),
            )
            .with_authentication(
                Keyring::from_bytes(&nodes[1].keyring().try_to_bytes().unwrap()).unwrap(),
                Box::new(move |id, _| {
                    let key = (id == client_hint).then(|| client_key.clone());
                    Box::pin(async move { key })
                }),
                Box::new(|_, _| Box::pin(async { 0 })),
            )
            .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
            let mut server = MTPWebServer::new(host, WebServerConfig::new())
                .await
                .unwrap();
            let endpoint = server.local_addr().to_string();
            let (shutdown, mut requested) = tokio::sync::oneshot::channel();
            let peer = manager.clone();
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut requested => { server.shutdown().await; break; },
                        accepted = server.accept() => match accepted {
                            Ok(Some(connection)) => { let peer = peer.clone(); tokio::spawn(async move {
                                web_server::MtpConnectionHandler::accept(peer.as_ref(), connection).await;
                            }); },
                            Ok(None) => break,
                            Err(error) => panic!("native peer accept failed: {error}"),
                        }
                    }
                }
            });
            assert!(
                RUNTIME
                    .set(Runtime {
                        manager,
                        shutdown: Mutex::new(Some(shutdown)),
                        server: Mutex::new(Some(task))
                    })
                    .is_ok()
            );
            std::fs::write(rendezvous().join("ready.json"), serde_json::to_vec(&serde_json::json!({ "endpoint": endpoint, "certificate": STANDARD.encode(certificate) })).unwrap()).unwrap();
            // PeerManager must commit the actual received request before the
            // reused fixture assertions inspect its durable duplicate and reads.
            tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    let accepted = db::with_db(|db| Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM relay_inbox WHERE state IN ('applied','queued','delivered'))", [], |row| row.get::<_,bool>(0))?)).unwrap();
                    if accepted { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("destination never committed native relay");
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_native_client_over_authenticated_mtp() {
    if std::env::var_os("NATIVE_RELAY_TEST_STAGE").is_none() {
        let temporary = tempfile::tempdir_in("/tmp/opencode").unwrap();
        let mut destination = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pinned_native_client_over_authenticated_mtp",
                "--nocapture",
            ])
            .env("NATIVE_RELAY_TEST_STAGE", "destination")
            .env("RELAY_NATIVE_CLIENT_FIXTURE", pinned::fixture_path())
            .env("NATIVE_MTP_RENDEZVOUS", temporary.path())
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            while !temporary.path().join("ready.json").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("native destination server did not start");
        let origin = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pinned_native_client_over_authenticated_mtp",
                "--nocapture",
            ])
            .env("NATIVE_RELAY_TEST_STAGE", "origin")
            .env("RELAY_NATIVE_CLIENT_FIXTURE", pinned::fixture_path())
            .env("NATIVE_MTP_RENDEZVOUS", temporary.path())
            .status()
            .unwrap();
        std::fs::write(temporary.path().join("finished"), []).unwrap();
        assert!(
            destination.wait().unwrap().success(),
            "destination assertions failed"
        );
        assert!(origin.success(), "origin assertions failed");
        return;
    }
    assert!(pinned::STAGE_HOOK.set(stage_hook).is_ok());
    pinned::run_native_stage().await;
    if std::env::var("NATIVE_RELAY_TEST_STAGE").unwrap() == "destination" {
        tokio::time::timeout(Duration::from_secs(45), async {
            while !rendezvous().join("finished").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    let runtime = RUNTIME.get().unwrap();
    runtime.manager.stop();
    let shutdown = runtime.shutdown.lock().unwrap().take();
    if let Some(shutdown) = shutdown {
        shutdown.send(()).ok();
    }
    let server = runtime.server.lock().unwrap().take();
    if let Some(server) = server {
        server.await.unwrap();
    }
    assert!(runtime.manager.shutdown(Duration::from_secs(3)).await);
}
