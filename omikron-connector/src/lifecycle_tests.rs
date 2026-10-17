use super::*;
use async_trait::async_trait;
use iota_connection::relay_service::{RelayNodeIdentity, RelayService};
use iota_identity::{
    IdentityError, IdentityResolver, IotaNodeId, LocalNodeIdentity, PrincipalHandle, PrincipalId,
    ResolutionContext, ResolvedPrincipal, UserAddress,
};
use mtp::host::{AuthenticationPolicy, HostConfig, MTPHost};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::Notify;
use tokio::time::timeout;

#[allow(dead_code)]
#[path = "../../iota-connection/tests/relay_support/mod.rs"]
mod relay_support;

const EXIT_BUDGET: Duration = Duration::from_secs(1);
const NETWORK_BUDGET: Duration = Duration::from_secs(5);

struct Loopback {
    host: MTPHost,
    client: Arc<MTPConnection>,
    peer: mtp::host::MTPConnection,
}

impl Loopback {
    async fn new() -> Self {
        let keys = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .self_signed(&keys)
            .unwrap()
            .pem()
            .into_bytes();
        let mut host = MTPHost::new(
            HostConfig::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
                certificate.clone(),
                keys.serialize_pem().into_bytes(),
            )
            .with_authentication_policy(AuthenticationPolicy::AllowAuthentication),
        )
        .await
        .unwrap();
        let address = format!("https://127.0.0.1:{}", host.local_addr().port());
        let (client, peer) = timeout(NETWORK_BUDGET, async {
            tokio::join!(
                Client::connect(
                    ClientConfig::new(&address)
                        .with_pinned_pem(certificate)
                        .with_description("iota"),
                ),
                host.accept(),
            )
        })
        .await
        .expect("MTP loopback handshake finishes");
        Self {
            host,
            client: Arc::new(client.unwrap()),
            peer: peer.unwrap().unwrap(),
        }
    }

    async fn connector(&self) -> Arc<OmikronConnection> {
        let mut connector = OmikronConnection::new(
            Arc::new(DashSet::new()),
            Arc::new(std::sync::Mutex::new(AppState::new())),
        );
        let attempt = Arc::new(ConnectionAttempt {
            generation: 1,
            sender: Arc::new(self.client.sender.clone()),
            responses: tau::ResponseCorrelator::new(),
            cancellation: connector.cancellation.child_token(),
        });
        *connector.active_attempt.write().await = Some(attempt.clone());
        connector.bound_attempt = Some(attempt);
        connector
            .set_state(ConnectionState::Connected { identified: true })
            .await;
        Arc::new(connector)
    }

    async fn start_reader(&self, connector: &Arc<OmikronConnection>) {
        *connector.connection_loop_handle.lock().await = Some(tokio::spawn(
            connector.clone().read_loop(self.client.clone()),
        ));
    }

    async fn close(mut self) {
        self.client.sender.close().await;
        self.peer.sender.close().await;
        self.host
            .shutdown(tokio::time::Instant::now() + EXIT_BUDGET)
            .await;
    }
}

// A dropped pending future proves cancellation reached the blocked operation,
// rather than merely closing its transport or returning from stop early.
#[derive(Default)]
struct BlockedCall {
    entered: Notify,
    dropped: Notify,
}

impl BlockedCall {
    async fn run(&self) {
        struct Dropped<'a>(&'a Notify);
        impl Drop for Dropped<'_> {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let _dropped = Dropped(&self.dropped);
        self.entered.notify_one();
        std::future::pending::<()>().await;
    }
}

struct BlockedResolver(Arc<BlockedCall>);

struct PanickingResolver;

#[async_trait]
impl IdentityResolver for PanickingResolver {
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }

    async fn resolve_principal(&self, _: &PrincipalId) -> Result<ResolvedPrincipal, IdentityError> {
        panic!("injected relay preparation panic");
    }

    async fn signing_keys(
        &self,
        _: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        unreachable!("principal resolution panics first")
    }
}

#[async_trait]
impl IdentityResolver for BlockedResolver {
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }

    async fn resolve_principal(&self, _: &PrincipalId) -> Result<ResolvedPrincipal, IdentityError> {
        self.0.run().await;
        unreachable!()
    }

    async fn signing_keys(
        &self,
        _: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        unreachable!("principal resolution stays blocked")
    }
}

struct Node(LocalNodeIdentity);

#[async_trait]
impl RelayNodeIdentity for Node {
    async fn keyring(&self) -> Option<Arc<Keyring>> {
        Some(self.0.keyring())
    }

    fn node_id(&self) -> Option<IotaNodeId> {
        Some(self.0.node_id().clone())
    }
}

async fn reader_stop_cancels_inflight_relay_identity_preparation() {
    let transport = Loopback::new().await;
    let connector = transport.connector().await;
    let node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let blocked = Arc::new(BlockedCall::default());
    let relay = RelayService::new(
        Arc::new(iota_storage::identity::SqliteLocalUserStore),
        Arc::new(relay_support::Router(true)),
    )
    .with_federation(
        Arc::new(BlockedResolver(blocked.clone())),
        Arc::new(Node(node.clone())),
    );
    assert!(connector.install_relay_service(Arc::new(relay)).is_ok());
    transport.start_reader(&connector).await;
    let frame = iota_connection::federated_relay::FederatedRelayV2::sign(
        PrincipalId {
            authority: node.authority_id().clone(),
            user_id: 1,
        },
        PrincipalId {
            authority: node.authority_id().clone(),
            user_id: 2,
        },
        node.node_id().clone(),
        "cancelled-preparation".into(),
        now_millis_i64() as u64,
        relay_support::send(1),
        &Keyring::generate(),
        vec![node.public_keys()],
    )
    .unwrap()
    .into_frame(7)
    .unwrap();
    transport.peer.sender.send(&frame).await.unwrap();
    timeout(NETWORK_BUDGET, blocked.entered.notified())
        .await
        .expect("real Relay dispatch enters identity preparation");
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 1);

    assert_eq!(
        connector.stop_with_timeout(EXIT_BUDGET).await.unwrap(),
        ShutdownOutcome::Complete
    );
    timeout(EXIT_BUDGET, blocked.dropped.notified())
        .await
        .expect("disposable resolver future is dropped");
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 0);
    assert!(connector.preparation_tasks.lock().await.is_empty());
    assert!(connector.connection_loop_handle.lock().await.is_none());
    assert!(!connector.worker_failed.load(Ordering::Acquire));
    transport.close().await;
}

struct BlockedLocalSink {
    blocked: Arc<BlockedCall>,
    recipient: PrincipalHandle,
    frame: Vec<u8>,
}

#[async_trait]
impl other_iota::LocalDeliverySink for BlockedLocalSink {
    async fn deliver(&self, recipient: PrincipalHandle, frame: CommunicationValue) {
        assert_eq!(recipient, self.recipient);
        assert_eq!(frame.to_bytes().unwrap(), self.frame);
        self.blocked.run().await;
    }
}

struct StorageDirectory(PathBuf);

impl Drop for StorageDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn committed_relay_survives_blocked_local_sink_and_cancelled_maintenance_retry() {
    // Only this test initializes process-global storage. Both delivery attempts
    // use the same durable queue, but separate real MTP connections.
    let directory = StorageDirectory(std::env::temp_dir().join(format!(
        "iota-connector-lifecycle-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    )));
    std::fs::create_dir_all(&directory.0).unwrap();
    relay_support::initialize(&directory.0);
    // Relay preparation now checks durable replay before identity discovery.
    // Keep all real Relay boundary checks under this one storage owner so they
    // cannot race process-global DB initialization or directory cleanup.
    reader_stop_cancels_inflight_relay_identity_preparation().await;
    real_relay_handler_panic_is_observed_and_shutdown_failure_stays_sticky().await;
    let fixture = relay_support::Fixture::new(true);
    relay_support::accepted(
        fixture
            .accept(0, "lifecycle-chat-secret", relay_support::secret(&fixture))
            .await,
    );
    for record in relay_queue::list_active(100).unwrap() {
        client_relay_delivery::acknowledge_pending_client_delivery(&record).unwrap();
    }
    let message_id = "committed-before-blocked-local-sink";
    let frame = fixture.frame(0, message_id, relay_support::send(1));
    let transport = Loopback::new().await;
    let connector = transport.connector().await;
    assert!(
        connector
            .install_relay_service(fixture.service.clone())
            .is_ok()
    );
    let blocked = Arc::new(BlockedCall::default());
    assert!(
        connector
            .install_local_delivery_sink(Arc::new(BlockedLocalSink {
                blocked: blocked.clone(),
                recipient: fixture.handles[1],
                frame: frame.to_bytes().unwrap(),
            }))
            .is_ok()
    );
    transport.start_reader(&connector).await;
    let page = CommunicationValue::new(CommunicationType::RelayReceiptPage)
        .with_id(88)
        .with_sender(1)
        .add_typed_default(DataType::ReceiptCursor, DataValue::SignedNumber(0))
        .add_typed_default(DataType::ReceiptUpper, DataValue::SignedNumber(0));
    transport.peer.sender.send(&page).await.unwrap();
    let response = timeout(NETWORK_BUDGET, transport.peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.is_type(CommunicationType::RelayReceiptPage),
        "{response:?}"
    );
    assert_eq!(response.id(), page.id());
    assert_eq!(response.receiver(), Some(1));
    assert_eq!(
        response.get_data(DataType::ReceiptComplete).as_bool(),
        Some(true)
    );
    transport.peer.sender.send(&frame).await.unwrap();
    timeout(NETWORK_BUDGET, blocked.entered.notified())
        .await
        .expect("Relay acceptance commits before local delivery blocks");
    let acknowledgement = timeout(NETWORK_BUDGET, transport.peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(acknowledgement.is_type(CommunicationType::Success));
    assert_eq!(acknowledgement.id(), frame.id());
    assert_eq!(
        acknowledgement.get_data(DataType::RelayMessageId).as_str(),
        Some(message_id)
    );
    assert_eq!(
        relay_support::count(
            "SELECT COUNT(*) FROM messages WHERE storage_owner = 2 AND relay_message_id = 'committed-before-blocked-local-sink'"
        ),
        1
    );
    assert_eq!(
        relay_support::count(
            "SELECT COUNT(*) FROM relay_inbox WHERE message_id = 'committed-before-blocked-local-sink' AND state = 'queued'"
        ),
        1
    );
    let pending = relay_queue::list_active(100)
        .unwrap()
        .into_iter()
        .find(|record| record.relay_message_id.as_deref() == Some(message_id))
        .expect("committed Relay has durable client delivery work");
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 1);

    assert_eq!(
        connector.stop_with_timeout(EXIT_BUDGET).await.unwrap(),
        ShutdownOutcome::Complete
    );
    timeout(EXIT_BUDGET, blocked.dropped.notified())
        .await
        .expect("blocked postcommit sink is disposable");
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 0);
    assert!(relay_queue::list_active(100).unwrap().contains(&pending));
    assert!(!connector.worker_failed.load(Ordering::Acquire));
    transport.close().await;

    maintenance_panic_preserves_claimed_delivery(&pending).await;

    let retry_transport = Loopback::new().await;
    let retry = retry_transport.connector().await;
    let blocked_retry = Arc::new(BlockedCall::default());
    retry
        .install_pending_delivery_sink({
            let blocked = blocked_retry.clone();
            let pending = pending.clone();
            move |record, frame| {
                let blocked = blocked.clone();
                let pending = pending.clone();
                async move {
                    assert_eq!(record, pending);
                    assert_eq!(frame.id(), Some(pending.frame_id));
                    blocked.run().await;
                    unreachable!()
                }
            }
        })
        .unwrap();
    let reader = retry.clone();
    let maintenance = retry.clone();
    let client = retry_transport.client.clone();
    *retry.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        tokio::join!(
            reader.read_loop(client.clone()),
            maintenance.maintenance_loop(client),
        );
    }));
    timeout(
        MAINTENANCE_INTERVAL + NETWORK_BUDGET,
        blocked_retry.entered.notified(),
    )
    .await
    .expect("actual maintenance worker starts a durable queue retry");
    let competing_dispatcher = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let duplicate_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    competing_dispatcher
        .install_pending_delivery_sink({
            let duplicate_attempts = duplicate_attempts.clone();
            move |_, _| {
                duplicate_attempts.fetch_add(1, Ordering::AcqRel);
                async { Err("duplicate dispatch must not start".into()) }
            }
        })
        .unwrap();
    competing_dispatcher.flush_pending_relays().await;
    assert_eq!(duplicate_attempts.load(Ordering::Acquire), 0);
    assert_eq!(
        retry.stop_with_timeout(EXIT_BUDGET).await.unwrap(),
        ShutdownOutcome::Complete
    );
    timeout(EXIT_BUDGET, blocked_retry.dropped.notified())
        .await
        .expect("maintenance drops its blocked external delivery");
    assert!(retry.relay_flush.try_lock().is_ok());
    assert!(retry.connection_loop_handle.lock().await.is_none());
    assert!(relay_queue::list_active(100).unwrap().contains(&pending));
    // Cancellation must release the lease, not merely drop the callback.
    let reclaimed = relay_queue::claim_ready_for_user(2, fixture.handles[1], 30_000)
        .unwrap()
        .expect("cancelled maintenance releases the claimed delivery");
    assert!(relay_queue::release_claim(&reclaimed).unwrap());
    assert_eq!(
        relay_support::count(
            "SELECT COUNT(*) FROM messages WHERE storage_owner = 2 AND relay_message_id = 'committed-before-blocked-local-sink'"
        ),
        1
    );
    assert_eq!(
        relay_support::count(
            "SELECT COUNT(*) FROM relay_inbox WHERE message_id = 'committed-before-blocked-local-sink' AND state = 'queued'"
        ),
        1
    );
    retry_transport.close().await;

    use iota_storage::util::message_storage_policy::{self, MessageHistoryMode, MessageRetention};
    message_storage_policy::set(
        2,
        MessageHistoryMode::DeleteAfterClientDelivery,
        MessageRetention::Forever,
    )
    .unwrap();
    let delivery = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    delivery
        .install_pending_delivery_sink({
            let callbacks = callbacks.clone();
            let pending = pending.clone();
            move |record, frame| {
                assert_eq!(record, pending);
                assert_eq!(frame.id(), Some(pending.frame_id));
                let callback = callbacks.fetch_add(1, Ordering::AcqRel);
                let response = CommunicationValue::new_with_type_map(
                    CommunicationType::Success,
                    frame.type_map().unwrap(),
                )
                .with_id(if callback == 0 {
                    pending.frame_id.wrapping_add(1)
                } else {
                    pending.frame_id
                })
                .add_typed_default(
                    DataType::RelayMessageId,
                    DataValue::Str(if callback == 1 {
                        "wrong-relay-message-id".into()
                    } else {
                        pending.relay_message_id.clone().unwrap()
                    }),
                );
                async move { Ok(response) }
            }
        })
        .unwrap();
    for _ in 0..2 {
        delivery.flush_pending_relays().await;
        assert!(relay_queue::list_active(100).unwrap().contains(&pending));
        assert_eq!(
            relay_support::count(
                "SELECT COUNT(*) FROM relay_inbox WHERE message_id = 'committed-before-blocked-local-sink' AND state = 'queued'"
            ),
            1
        );
        assert_eq!(
            relay_support::count(
                "SELECT COUNT(*) FROM messages WHERE storage_owner = 2 AND relay_message_id = 'committed-before-blocked-local-sink' AND history_deleted = 0 AND content = 'ciphertext'"
            ),
            1
        );
    }
    delivery.flush_pending_relays().await;
    assert_eq!(callbacks.load(Ordering::Acquire), 3);
    assert!(relay_queue::list_active(100).unwrap().is_empty());
    assert_eq!(
        relay_support::count(
            "SELECT COUNT(*) FROM relay_inbox WHERE message_id = 'committed-before-blocked-local-sink' AND state = 'delivered'"
        ),
        1
    );
    assert_eq!(
        relay_support::count(
            "SELECT COUNT(*) FROM messages WHERE storage_owner = 2 AND relay_message_id = 'committed-before-blocked-local-sink' AND history_deleted = 1 AND content = ''"
        ),
        1
    );
    assert_eq!(
        relay_support::count(
            "SELECT COUNT(*) FROM messages WHERE storage_owner = 1 AND relay_message_id = 'committed-before-blocked-local-sink' AND history_deleted = 0 AND content = 'ciphertext'"
        ),
        1
    );
    delivery.flush_pending_relays().await;
    assert_eq!(callbacks.load(Ordering::Acquire), 3);
}

#[tokio::test]
async fn stop_closes_blocked_external_request_and_running_invitation_worker() {
    let transport = Loopback::new().await;
    let connector = transport.connector().await;
    let reader = connector.clone();
    let maintenance = connector.clone();
    let invitations = connector.clone();
    let client = transport.client.clone();
    *connector.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        tokio::join!(
            reader.read_loop(client.clone()),
            maintenance.maintenance_loop(client),
            invitations.invitation_loop(),
        );
    }));
    let request = tokio::spawn({
        let connector = connector.clone();
        async move {
            connector
                .await_response_typed(
                    &CommunicationValue::new(CommunicationType::GetUserData).with_id(42),
                    Some(Duration::from_secs(60)),
                )
                .await
        }
    });
    // Do not answer either request. Receiving both on the peer proves both
    // workers reached their real network wait before shutdown begins.
    let first = timeout(NETWORK_BUDGET, transport.peer.receive())
        .await
        .unwrap()
        .unwrap();
    let second = timeout(NETWORK_BUDGET, transport.peer.receive())
        .await
        .unwrap()
        .unwrap();
    for kind in [
        CommunicationType::GetUserData,
        CommunicationType::ListUserInvitations,
    ] {
        assert!(first.is_type(kind) || second.is_type(kind));
    }
    let attempt = connector.bound_attempt.as_ref().unwrap();
    assert_eq!(attempt.responses.len(), 2);

    assert_eq!(
        connector.stop_with_timeout(EXIT_BUDGET).await.unwrap(),
        ShutdownOutcome::Complete
    );
    let error = timeout(EXIT_BUDGET, request)
        .await
        .expect("external request exits before its 60-second timeout")
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        map_await_response_error(error),
        OmikronError::Disconnected(_)
    ));
    assert!(attempt.responses.is_empty());
    assert!(connector.connection_loop_handle.lock().await.is_none());
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 0);
    assert!(!connector.worker_failed.load(Ordering::Acquire));
    transport.close().await;
}

#[tokio::test]
async fn reconnect_replaces_real_attempt_workers_and_stop_joins_both_generations() {
    let first = Loopback::new().await;
    let second = Loopback::new().await;
    let scoped = first.connector().await;
    let old = scoped.bound_attempt.as_ref().unwrap().clone();
    let mut root = scoped.as_ref().clone();
    root.bound_attempt = None;
    let root = Arc::new(root);
    let (entered, in_transaction) = tokio::sync::oneshot::channel();
    let (release, blocked) = tokio::sync::oneshot::channel();
    let (committed, observed) = tokio::sync::oneshot::channel();
    let pending = scoped.track_operation();
    // Retain an old mutation in the same draining owner used by run_attempt.
    // Its SQLite transaction must finish even while replacement traffic works.
    root.draining_attempts.lock().await.spawn(async move {
        let _pending = pending;
        let effects = tokio::task::spawn_blocking(move || {
            let mut db = rusqlite::Connection::open_in_memory().unwrap();
            db.execute_batch("CREATE TABLE effects (id INTEGER PRIMARY KEY)")
                .unwrap();
            let transaction = db.transaction().unwrap();
            transaction
                .execute("INSERT INTO effects VALUES (1)", [])
                .unwrap();
            entered.send(()).unwrap();
            blocked.blocking_recv().unwrap();
            transaction.commit().unwrap();
            db.query_row("SELECT COUNT(*) FROM effects", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        })
        .await
        .unwrap();
        committed.send(effects).unwrap();
    });
    timeout(EXIT_BUDGET, in_transaction).await.unwrap().unwrap();
    let replacement = Arc::new(ConnectionAttempt {
        generation: 2,
        sender: Arc::new(second.client.sender.clone()),
        responses: tau::ResponseCorrelator::new(),
        cancellation: root.cancellation.child_token(),
    });
    let supervisor = root.clone();
    let a = first.client.clone();
    let b = second.client.clone();
    let next = replacement.clone();
    let previous = old.clone();
    *root.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        supervisor.clone().run_attempt(a, previous).await.unwrap();
        // Supply a second authenticated loopback at the same boundary used by
        // connect_once, without invoking external Omega discovery in this test.
        *supervisor.active_attempt.write().await = Some(next.clone());
        supervisor
            .set_state(ConnectionState::Connected { identified: true })
            .await;
        supervisor.clone().run_attempt(b, next).await.unwrap();
        supervisor.join_draining_attempts().await;
    }));
    let first_invitation = timeout(NETWORK_BUDGET, first.peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(first_invitation.is_type(CommunicationType::ListUserInvitations));
    let waiting = tokio::spawn({
        let root = root.clone();
        async move {
            root.await_response(
                &CommunicationValue::new(CommunicationType::GetUserData).with_id(42),
                Some(Duration::from_secs(60)),
            )
            .await
        }
    });
    let request = timeout(NETWORK_BUDGET, first.peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(request.is_type(CommunicationType::GetUserData));
    root.reconnect().await;
    assert!(
        timeout(EXIT_BUDGET, waiting)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let second_invitation = timeout(NETWORK_BUDGET, second.peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(second_invitation.is_type(CommunicationType::ListUserInvitations));
    assert!(old.responses.is_empty());
    assert!(old.cancellation.is_cancelled());
    assert!(!replacement.cancellation.is_cancelled());
    assert!(
        scoped
            .send_message(&CommunicationValue::new(CommunicationType::Success))
            .await
            .is_err()
    );
    let page = CommunicationValue::new(CommunicationType::RelayReceiptPage)
        .with_id(99)
        .with_sender(1)
        .add_typed_default(DataType::ReceiptCursor, DataValue::SignedNumber(2))
        .add_typed_default(DataType::ReceiptUpper, DataValue::SignedNumber(1));
    // Invalid bounds exercise dispatch without global storage. An old account
    // handler must not send even its error reply on the replacement transport.
    scoped.handle_message(page.clone()).await;
    assert!(
        timeout(Duration::from_millis(50), second.peer.receive())
            .await
            .is_err()
    );
    second.peer.sender.send(&page).await.unwrap();
    let response = timeout(NETWORK_BUDGET, second.peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(response.is_type(CommunicationType::ErrorInvalidData));
    assert_eq!(response.id(), page.id());
    assert_eq!(root.pending_operations.load(Ordering::Acquire), 1);
    assert_eq!(
        root.active_attempt
            .read()
            .await
            .as_ref()
            .unwrap()
            .generation,
        2
    );
    assert_eq!(
        root.stop_with_timeout(Duration::ZERO).await.unwrap(),
        ShutdownOutcome::Incomplete {
            pending_operations: 1
        }
    );
    assert!(root.connection_loop_handle.lock().await.is_some());
    release.send(()).unwrap();
    assert_eq!(timeout(EXIT_BUDGET, observed).await.unwrap().unwrap(), 1);
    assert_eq!(
        root.stop_with_timeout(EXIT_BUDGET).await.unwrap(),
        ShutdownOutcome::Complete
    );
    assert!(root.connection_loop_handle.lock().await.is_none());
    assert!(root.draining_attempts.lock().await.is_empty());
    assert!(replacement.responses.is_empty());
    assert_eq!(root.pending_operations.load(Ordering::Acquire), 0);
    assert!(!root.worker_failed.load(Ordering::Acquire));
    first.close().await;
    second.close().await;
}

async fn real_relay_handler_panic_is_observed_and_shutdown_failure_stays_sticky() {
    let transport = Loopback::new().await;
    let connector = transport.connector().await;
    let node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let relay = RelayService::new(
        Arc::new(iota_storage::identity::SqliteLocalUserStore),
        Arc::new(relay_support::Router(true)),
    )
    .with_federation(Arc::new(PanickingResolver), Arc::new(Node(node.clone())));
    assert!(connector.install_relay_service(Arc::new(relay)).is_ok());
    let attempt = connector.bound_attempt.as_ref().unwrap().clone();
    let owner = connector.clone();
    let client = transport.client.clone();
    *connector.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        owner.clone().run_attempt(client, attempt).await.unwrap();
        owner.join_draining_attempts().await;
    }));
    let frame = iota_connection::federated_relay::FederatedRelayV2::sign(
        PrincipalId {
            authority: node.authority_id().clone(),
            user_id: 1,
        },
        PrincipalId {
            authority: node.authority_id().clone(),
            user_id: 2,
        },
        node.node_id().clone(),
        "panic-before-acceptance".into(),
        now_millis_i64() as u64,
        relay_support::send(1),
        &Keyring::generate(),
        vec![node.public_keys()],
    )
    .unwrap()
    .into_frame(7)
    .unwrap();
    transport.peer.sender.send(&frame).await.unwrap();
    timeout(NETWORK_BUDGET, async {
        while !connector.worker_failed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reader observes the real Relay handler's panic");
    for _ in 0..2 {
        assert!(matches!(
            connector.stop_with_timeout(EXIT_BUDGET).await,
            Err(ConnectorShutdownError::UnresolvedWorker)
        ));
    }
    assert!(connector.connection_loop_handle.lock().await.is_none());
    assert!(connector.draining_attempts.lock().await.is_empty());
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 0);
    assert!(
        connector
            .bound_attempt
            .as_ref()
            .unwrap()
            .responses
            .is_empty()
    );
    transport.close().await;
}

#[tokio::test]
async fn late_state_subscriber_and_clone_observe_the_same_connection_state() {
    let connector = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let clone = connector.clone();
    connector
        .set_state(ConnectionState::Connected { identified: true })
        .await;
    assert!(clone.connection_state().borrow().is_identified());
    clone.await_connection(Some(EXIT_BUDGET)).await.unwrap();
    assert_eq!(clone.stop().await.unwrap(), ShutdownOutcome::Complete);
    assert!(!connector.is_connected().await);
    assert_eq!(
        *connector.connection_state().borrow(),
        ConnectionState::Disconnected
    );
}

#[tokio::test]
async fn incomplete_stop_retains_blocking_worker_and_reports_its_later_panic() {
    let connector = OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    );
    let (entered, running) = tokio::sync::oneshot::channel();
    let (release, blocked) = tokio::sync::oneshot::channel();
    let pending = connector.track_operation();
    connector.preparation_tasks.lock().await.spawn(async move {
        let _pending = pending;
        tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            blocked.blocking_recv().unwrap();
            panic!("injected blocking worker failure after incomplete stop");
        })
        .await
        .unwrap();
    });
    timeout(EXIT_BUDGET, running).await.unwrap().unwrap();
    for _ in 0..2 {
        assert_eq!(
            timeout(EXIT_BUDGET, connector.stop_with_timeout(Duration::ZERO))
                .await
                .unwrap()
                .unwrap(),
            ShutdownOutcome::Incomplete {
                pending_operations: 1
            },
        );
        assert!(connector.connection_loop_handle.lock().await.is_some());
        assert_eq!(connector.pending_operations.load(Ordering::Acquire), 1);
    }
    release.send(()).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            connector.stop_with_timeout(EXIT_BUDGET).await,
            Err(ConnectorShutdownError::UnresolvedWorker)
        ));
    }
    assert!(connector.connection_loop_handle.lock().await.is_none());
    assert!(connector.preparation_tasks.lock().await.is_empty());
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 0);
}

async fn maintenance_panic_preserves_claimed_delivery(pending: &relay_queue::PendingRelay) {
    let transport = Loopback::new().await;
    let connector = transport.connector().await;
    let entered = Arc::new(Notify::new());
    connector
        .install_pending_delivery_sink({
            let entered = entered.clone();
            let pending = pending.clone();
            move |record, _| {
                let entered = entered.clone();
                let pending = pending.clone();
                async move {
                    assert_eq!(record, pending);
                    entered.notify_one();
                    panic!("injected maintenance delivery callback panic");
                }
            }
        })
        .unwrap();
    let attempt = connector.bound_attempt.as_ref().unwrap().clone();
    let owner = connector.clone();
    let client = transport.client.clone();
    *connector.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        owner.clone().run_attempt(client, attempt).await.unwrap();
        owner.join_draining_attempts().await;
    }));
    timeout(MAINTENANCE_INTERVAL + NETWORK_BUDGET, entered.notified())
        .await
        .unwrap();
    assert!(matches!(
        connector.stop_with_timeout(EXIT_BUDGET).await,
        Err(ConnectorShutdownError::UnresolvedWorker)
    ));
    assert!(connector.relay_flush.try_lock().is_ok());
    assert!(relay_queue::list_active(100).unwrap().contains(pending));
    let relay_queue::RelayTarget::User(user_id) = pending.target else {
        unreachable!()
    };
    let claim = relay_queue::claim_ready_for_user(
        user_id as i64,
        pending.destination_principal.unwrap(),
        30_000,
    )
    .unwrap()
    .expect("panic releases its dispatch generation");
    assert!(relay_queue::release_claim(&claim).unwrap());
    transport.close().await;
}

#[tokio::test]
async fn identity_rotation_during_incomplete_terminal_shutdown_cannot_replace_keys() {
    let connector = Arc::new(OmikronConnection::new(
        Arc::new(DashSet::new()),
        Arc::new(std::sync::Mutex::new(AppState::new())),
    ));
    let keys = Arc::new(Keyring::generate());
    *connector.keyring.write().await = Some(keys.clone());
    let (release, blocked) = tokio::sync::oneshot::channel();
    let pending = connector.track_operation();
    *connector.connection_loop_handle.lock().await = Some(tokio::spawn(async move {
        let _pending = pending;
        blocked.await.unwrap();
    }));
    assert!(matches!(
        connector.stop_with_timeout(Duration::ZERO).await.unwrap(),
        ShutdownOutcome::Incomplete { .. }
    ));
    assert!(matches!(
        connector.rotate_identity().await,
        Err(OmikronError::Disconnected(_))
    ));
    assert!(Arc::ptr_eq(
        connector.keyring.read().await.as_ref().unwrap(),
        &keys
    ));
    assert_eq!(connector.pending_operations.load(Ordering::Acquire), 1);
    release.send(()).unwrap();
    assert_eq!(
        connector.stop_with_timeout(EXIT_BUDGET).await.unwrap(),
        ShutdownOutcome::Complete
    );
    assert!(matches!(
        connector.rotate_identity().await,
        Err(OmikronError::Disconnected(_))
    ));
}
