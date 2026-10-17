use iota_daemon_lib::{
    DaemonRuntime, DaemonServices, IpcServer, ShutdownReason, StartupPhase, log_broadcaster,
    log_buffer::LogBuffer,
};
use iota_logger::{self as logger, log};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::CONFIG;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, watch};

const MESSAGE_RETENTION_INTERVAL: Duration = Duration::from_secs(60);
const SYNC_COMPACTION_INTERVAL: Duration = Duration::from_secs(60 * 60);
fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Cannot start daemon runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run());
    // A blocked storage closure cannot keep runtime destruction alive forever.
    // The web supervisor has already reported any incomplete connection work.
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

async fn run() -> ExitCode {
    let scope = match std::env::var("IOTA_DEPLOYMENT_MODE").ok().as_deref() {
        Some("system_socket_activated") | Some("system_always_on") => iota_paths::Scope::System,
        _ => iota_paths::Scope::User,
    };
    let paths = match iota_paths::IotaPaths::resolve(scope) {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("Cannot resolve Iota paths: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Bind a deliberately dormant IPC daemon before terms are accepted.  This
    // makes socket activation and `iota terms accept --system` usable, while
    // the router exposes status only and the inactive service cannot connect.
    if !iota_terms::consent::load(&paths.state_dir).has_all_required() {
        let socket = match &paths.ipc_endpoint {
            iota_paths::IpcEndpoint::UnixSocket(path) => path.clone(),
            iota_paths::IpcEndpoint::WindowsPipe(_) => {
                eprintln!("Windows named-pipe daemon transport is not implemented yet");
                return ExitCode::FAILURE;
            }
        };
        let runtime = Arc::new(DaemonRuntime::new());
        let (log_tx, _) = broadcast::channel(64);
        let log_buffer = Arc::new(Mutex::new(LogBuffer::new(64)));
        let (_, state_rx) = watch::channel(runtime.snapshot());
        let server = match IpcServer::bind(
            socket,
            runtime.clone(),
            DaemonServices::inactive(),
            log_tx,
            log_buffer,
            state_rx,
        )
        .await
        {
            Ok(server) => server,
            Err(error) => {
                eprintln!("Cannot bind dormant daemon IPC socket: {error}");
                return ExitCode::FAILURE;
            }
        };
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        eprintln!(
            "Iota daemon is awaiting terms acceptance. Run `iota terms accept{}` in an interactive terminal.",
            if paths.scope == iota_paths::Scope::System {
                " --system"
            } else {
                ""
            }
        );
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if iota_terms::consent::load(&paths.state_dir).has_all_required() {
                        // systemd restarts this daemon; a locally-launched daemon can
                        // simply be started again after accepting the documents.
                        return ExitCode::from(75);
                    }
                }
                _ = tokio::signal::ctrl_c() => return ExitCode::SUCCESS,
            }
        }
    }
    if let Err(error) = paths.migrate_legacy_layout() {
        eprintln!("Cannot migrate legacy Iota layout: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = paths.prepare_writable_directories() {
        eprintln!("Cannot prepare Iota directories: {error}");
        return ExitCode::FAILURE;
    }
    iota_util::file_util::configure_storage_directory(paths.storage_dir.clone());
    iota_storage::util::config_util::configure_config_path(paths.config_file.clone());
    if let Err(error) = iota_storage::util::config_util::load_config_from(&paths.config_file) {
        eprintln!("Cannot load Iota configuration: {error}");
        return ExitCode::FAILURE;
    }
    let node_identity =
        match iota_identity::LocalNodeIdentity::load_or_create(&paths.keyring_file(), None) {
            Ok(identity) => identity,
            Err(error) => {
                eprintln!("Cannot load Iota node identity: {error}");
                return ExitCode::FAILURE;
            }
        };
    omikron_connector::omikron_connection::configure_identity_path(paths.keyring_file());
    match paths.scope {
        iota_paths::Scope::User => logger::startup_with_log_dir(Some(paths.log_dir.clone())),
        iota_paths::Scope::System => logger::startup_with_log_dir(None),
    }

    let runtime = Arc::new(DaemonRuntime::new());
    // --- IPC infrastructure ---
    let (log_tx, _) = broadcast::channel(512);
    let log_buffer = Arc::new(Mutex::new(LogBuffer::new(1024)));
    log_broadcaster::spawn(log_tx.clone(), log_buffer.clone());
    let (state_tx, state_rx) = watch::channel(runtime.snapshot());

    runtime.set_startup_phase(StartupPhase::LoadingUsers);
    let storage_error = match iota_storage::util::db::verify_and_backup_database()
        .and_then(|()| iota_storage::util::db::initialize_database())
    {
        Ok(()) => tokio::task::spawn_blocking(user_manager::load_users_sync)
            .await
            .map_err(|error| format!("user storage task failed: {error}"))
            .and_then(|result| result.map_err(|error| error.to_string()))
            .err(),
        Err(error) => Some(error.to_string()),
    };
    if let Some(error) = storage_error {
        runtime.set_component_failed(
            iota_ipc::ComponentId::Storage,
            format!("user storage failed to load: {error}"),
        );
    } else {
        runtime.set_component_healthy(iota_ipc::ComponentId::Storage, None);
        iota_storage::util::call_envelopes::start_expiry_cleanup();
    }

    // Bind before migration and service startup: a successful bind is the
    // readiness boundary visible to clients and socket activation.
    let socket = match &paths.ipc_endpoint {
        iota_paths::IpcEndpoint::UnixSocket(path) => path.clone(),
        iota_paths::IpcEndpoint::WindowsPipe(_) => {
            eprintln!("Windows named-pipe daemon transport is not implemented yet");
            return ExitCode::FAILURE;
        }
    };
    let (services, omikron) = if CONFIG.load().omikron_host.is_some() {
        let omikron = Arc::new(omikron_connector::OmikronConnection::with_cancellation(
            runtime.cancellation.clone(),
            runtime.state.active_tasks.clone(),
            runtime.state.app.clone(),
        ));
        let services = match DaemonServices::new(omikron.clone(), node_identity.clone()) {
            Ok(services) => services,
            Err(error) => {
                eprintln!("Cannot initialize daemon identity services: {error}");
                return ExitCode::FAILURE;
            }
        };
        omikron.connect().await;
        if omikron
            .await_connection(Some(Duration::from_secs(45)))
            .await
            .is_err()
        {
            if omikron.has_auth_failure().await {
                runtime.set_component_failed(
                    iota_ipc::ComponentId::Omikron,
                    "Omikron authentication failed; inspect authenticated relay and Omega status before rotating Iota identity".into(),
                );
            } else {
                runtime.set_component_degraded(
                    iota_ipc::ComponentId::Omikron,
                    "Omikron connection unavailable; retrying".into(),
                );
            }
        }
        (services, Some(omikron))
    } else {
        let services = match DaemonServices::standalone(node_identity.clone()) {
            Ok(services) => services,
            Err(error) => {
                eprintln!("Cannot initialize standalone daemon services: {error}");
                return ExitCode::FAILURE;
            }
        };
        runtime.set_component_healthy(
            iota_ipc::ComponentId::Omikron,
            Some("disabled in standalone mode".into()),
        );
        (services, None)
    };
    let lifecycle_services = services.clone();
    let lifecycle_runtime = runtime.clone();
    let connector_shutdown = omikron.clone();
    {
        match services.relay.recover_incomplete(100) {
            Ok(report) => {
                log!("Initial relay recovery: {report:?}");
                if report.health.blocked > 0 || report.health.receipt_backfill_blocked > 0 {
                    runtime.set_component_degraded(
                        iota_ipc::ComponentId::Storage,
                        format!(
                            "{} relay operations and {} receipt backfills blocked",
                            report.health.blocked, report.health.receipt_backfill_blocked
                        ),
                    );
                }
            }
            Err(error) => runtime.set_component_failed(
                iota_ipc::ComponentId::Storage,
                format!("Relay recovery initialization failed: {error:?}"),
            ),
        }
        let relay_recovery = services.relay.clone();
        let recovery_runtime = runtime.clone();
        runtime
            .tasks
            .spawn_tracked("relay-application-recovery", async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = recovery_runtime.cancellation.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                    }
                    match relay_recovery.recover_incomplete(100) {
                        Ok(report) => {
                            log!("Relay recovery health: {report:?}");
                            if report.health.blocked > 0
                                || report.health.receipt_backfill_blocked > 0
                            {
                                recovery_runtime.set_component_degraded(
                                    iota_ipc::ComponentId::Storage,
                                    format!(
                                        "{} relay operations and {} receipt backfills blocked",
                                        report.health.blocked,
                                        report.health.receipt_backfill_blocked
                                    ),
                                );
                            } else {
                                recovery_runtime
                                    .set_component_healthy(iota_ipc::ComponentId::Storage, None);
                            }
                        }
                        Err(error) => {
                            log!("Relay application recovery failed: {error:?}");
                            recovery_runtime.set_component_failed(
                                iota_ipc::ComponentId::Storage,
                                format!("Relay recovery unavailable: {error:?}"),
                            );
                        }
                    }
                }
                Ok(())
            })
            .await;
        let dispatcher =
            iota_connection::relay_service::PendingRelayDispatcher::new(services.router.clone());
        let dispatcher_runtime = runtime.clone();
        runtime
            .tasks
            .spawn_tracked("pending-relay-dispatch", async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = dispatcher_runtime.cancellation.cancelled() => break,
                        result = dispatcher.dispatch_ready(100) => {
                            if let Err(error) = result { log!("Pending Relay dispatch failed: {error:?}"); }
                        }
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                        _ = dispatcher_runtime.cancellation.cancelled() => break,
                    }
                }
                Ok(())
            })
            .await;
    }
    if let Some(omikron_health) = omikron {
        let health_runtime = runtime.clone();
        runtime
            .tasks
            .spawn_tracked("omikron-health", async move {
                let mut states = omikron_health.connection_state();
                loop {
                    let state = *states.borrow();
                    match state {
                        omikron_connector::omikron_connection::ConnectionState::Connected {
                            ..
                        } => {
                            let ping_ms = *omikron_health.last_ping.lock().await;
                            let message = if ping_ms >= 0 {
                                format!("connected (RTT: {ping_ms} ms)")
                            } else {
                                "connected (waiting for RTT sample)".into()
                            };
                            health_runtime.set_component_healthy(
                                iota_ipc::ComponentId::Omikron,
                                Some(message),
                            );
                        }
                        omikron_connector::omikron_connection::ConnectionState::Connecting => {
                            health_runtime.set_component_degraded(
                                iota_ipc::ComponentId::Omikron,
                                "connecting to Omikron".into(),
                            );
                        }
                        omikron_connector::omikron_connection::ConnectionState::Disconnected => {
                            let message = omikron_health
                                .get_auth_failure()
                                .await
                                .unwrap_or_else(|| "disconnected; retrying".into());
                            if omikron_health.has_auth_failure().await {
                                health_runtime
                                    .set_component_failed(iota_ipc::ComponentId::Omikron, message);
                            } else {
                                health_runtime.set_component_degraded(
                                    iota_ipc::ComponentId::Omikron,
                                    message,
                                );
                            }
                        }
                    }
                    tokio::select! {
                        changed = states.changed() => if changed.is_err() { break },
                        // RTT is updated by MTP's heartbeat independently of a
                        // connection-state transition, so periodically refresh
                        // the component detail while connected.
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                        _ = health_runtime.cancellation.cancelled() => break,
                    }
                }
                Ok(())
            })
            .await;
    }
    runtime
        .tasks
        .spawn_tracked("user-lifecycle-reconciliation", async move {
            loop {
                match iota_storage::users::pending_operations::get_all() {
                    Ok(operations) => {
                        for operation in operations.into_iter().filter(|operation| {
                            operation.operation
                                == iota_storage::users::pending_operations::PendingUserOperationKind::Purge
                        }) {
                            if let Err(error) = user_manager::purge_user_data(operation.user_id) {
                                log!(
                                    "Pending purge reconciliation failed for {}: {}",
                                    operation.user_id,
                                    error
                                );
                            }
                        }
                    }
                    Err(error) => log!("Pending purge reconciliation could not read storage: {error}"),
                }
                if lifecycle_services.accounts.is_available().await
                    && let Err(error) = lifecycle_services.accounts.reconcile_managed_users().await
                {
                    log!("Managed user reconciliation failed: {error:?}");
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                    _ = lifecycle_runtime.cancellation.cancelled() => break,
                }
            }
            Ok(())
        })
        .await;
    let ipc_server = match IpcServer::bind(
        socket.clone(),
        runtime.clone(),
        services.clone(),
        log_tx.clone(),
        log_buffer.clone(),
        state_rx,
    )
    .await
    {
        Ok(server) => server,
        Err(error) => {
            eprintln!("Cannot bind daemon IPC socket: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("iota-daemon IPC listener ready at {}", socket.display());
    runtime.set_component_healthy(iota_ipc::ComponentId::Ipc, None);
    let listener_runtime = runtime.clone();
    runtime
        .tasks
        .spawn_tracked("ipc-server", async move {
            if let Err(error) = ipc_server.serve().await {
                eprintln!("iota-daemon IPC server failed: {error}");
                listener_runtime.shutdown(ShutdownReason::Fatal(format!(
                    "IPC listener stopped: {error}"
                )));
            }
            Ok(())
        })
        .await;
    log!("iota-daemon IPC server ready");

    log!(
        "iota-daemon paths (scope={:?}): config={} state={} storage={} identity={} cache={} log={} asset={} ipc={}",
        paths.scope,
        paths.config_file.display(),
        paths.state_dir.display(),
        paths.storage_dir.display(),
        paths.identity_dir.display(),
        paths.cache_dir.display(),
        paths.log_dir.display(),
        paths.asset_dir.display(),
        match &paths.ipc_endpoint {
            iota_paths::IpcEndpoint::UnixSocket(p) => p.display().to_string(),
            iota_paths::IpcEndpoint::WindowsPipe(n) => n.clone(),
        },
    );
    runtime.set_startup_phase(StartupPhase::StartingServices);

    // --- System monitor ---
    runtime.spawn_system_monitor().await;

    // --- State update publisher (watch-based, no full broadcast per tick) ---
    let state_publisher = runtime.clone();
    runtime
        .tasks
        .spawn_tracked("state-publisher", async move {
            loop {
                if state_publisher.is_shutting_down() {
                    break;
                }
                let snapshot = state_publisher.snapshot();
                let _ = state_tx.send(snapshot);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(())
        })
        .await;

    // --- Web server ---
    let config = CONFIG.load();
    let web = config.web.clone();
    let relay_router_settings = config.relay_routers.clone();
    drop(config);
    let direct_endpoints = match web
        .direct_endpoints
        .iter()
        .cloned()
        .map(iota_identity::AuthorityLocator::new)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(endpoints) => endpoints,
        Err(error) => {
            eprintln!("Cannot load federation direct endpoints: {error}");
            return ExitCode::FAILURE;
        }
    };
    let relay_hints = match web
        .relay_hints
        .iter()
        .cloned()
        .chain(
            relay_router_settings
                .iter()
                .map(|router| router.endpoint.clone()),
        )
        .map(iota_identity::AuthorityLocator::new)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(endpoints) => endpoints,
        Err(error) => {
            eprintln!("Cannot load federation relay hints: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut relay_hints = relay_hints;
    relay_hints.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    relay_hints.dedup();
    let node_descriptor = match iota_storage::node_directory::SqliteNodeDirectory
        .ensure_local_descriptor(
            &node_identity,
            direct_endpoints,
            relay_hints,
            iota_storage::util::sync::now_millis(),
        ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            eprintln!("Cannot publish Iota node descriptor: {error}");
            return ExitCode::FAILURE;
        }
    };
    if services.centralized.is_some()
        && let Some(iota_id) = CONFIG.load().iota_id
    {
        let omega = match iota_identity::AuthorityLocator::new(
            omikron_connector::omega_discovery::omega_host(),
        ) {
            Ok(omega) => omega,
            Err(error) => {
                eprintln!("Cannot load Omega federation endpoint: {error}");
                return ExitCode::FAILURE;
            }
        };
        let wire = match node_descriptor.to_wire_v1() {
            Ok(wire) => wire,
            Err(error) => {
                eprintln!("Cannot encode node descriptor for Omega: {error}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(error) = other_iota::publish_omega_node_descriptor(&omega, iota_id, &wire).await
        {
            log!("Omega node descriptor publication failed: {error}");
        }
    }
    let client_connections = Arc::new(client::ClientConnectionManager::new(
        services.identities.clone(),
        services.auth.hosted_accounts.clone(),
        services.sessions.clone(),
        services.relay.clone(),
    ));
    let authorization_clients = client_connections.clone();
    let authorization_shutdown = runtime.cancellation.clone();
    runtime
        .tasks
        .spawn_tracked("hosted-authorization", async move {
            authorization_clients
                .monitor_authorization(authorization_shutdown)
                .await;
            Ok(())
        })
        .await;
    if let Some(relay_routers) = &services.relay_routers {
        for router in &relay_router_settings {
            let endpoint = match iota_identity::AuthorityLocator::new(router.endpoint.clone()) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    eprintln!("Cannot load relay router endpoint: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let public_key = match iota_identity::PublicKeyBundle::from_base64(&router.public_key) {
                Ok(public_key) => public_key,
                Err(error) => {
                    eprintln!("Cannot load relay router public key: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let certificate_path =
                resolve_config_path(&paths.config_file, &router.certificate, &paths.config_dir);
            let certificate = match std::fs::read(&certificate_path) {
                Ok(certificate) if !certificate.is_empty() => certificate,
                Ok(_) => {
                    eprintln!(
                        "Cannot load relay router certificate {}: file is empty",
                        certificate_path.display()
                    );
                    return ExitCode::FAILURE;
                }
                Err(error) => {
                    eprintln!(
                        "Cannot load relay router certificate {}: {error}",
                        certificate_path.display()
                    );
                    return ExitCode::FAILURE;
                }
            };
            let router_runtime = runtime.clone();
            let relay_routers = relay_routers.clone();
            let relay = services.relay.clone();
            let identity = node_identity.clone();
            let deliveries: Arc<dyn other_iota::LocalDeliverySink> = client_connections.clone();
            runtime
                .tasks
                .spawn_tracked("relay-router", async move {
                    loop {
                        match other_iota::relay_router::RelayRouterClient::connect(
                            identity.clone(),
                            &endpoint,
                            certificate.clone(),
                            public_key.clone(),
                            relay.clone(),
                            deliveries.clone(),
                        )
                        .await
                        {
                            Ok(connected) => {
                                relay_routers.add(connected.clone());
                                tokio::select! {
                                    _ = connected.wait_disconnected() => {},
                                    _ = router_runtime.cancellation.cancelled() => break,
                                }
                            }
                            Err(error) => {
                                log!(
                                    "Relay router {} connection failed: {error}",
                                    endpoint.as_str()
                                );
                            }
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {},
                            _ = router_runtime.cancellation.cancelled() => break,
                        }
                    }
                    Ok(())
                })
                .await;
        }
    }
    let mut peer_manager = None;
    let mtp_handler: Arc<dyn web_server::MtpConnectionHandler> =
        if let Some(router) = services.direct_router.clone() {
            let nodes: Arc<dyn iota_identity::NodeDirectory> =
                Arc::new(iota_storage::node_directory::SqliteNodeDirectory);
            let deliveries: Arc<dyn other_iota::LocalDeliverySink> = client_connections.clone();
            let peers = Arc::new(other_iota::PeerManager::new(
                node_identity.clone(),
                nodes,
                router.clone(),
                services.relay.clone(),
                deliveries,
            ));
            router.attach_manager(&peers);
            peer_manager = Some(peers.clone());
            Arc::new(client::ConnectionGateway::new(
                client::tau_gateway::admission_engine(),
                client_connections.clone(),
                peers,
            ))
        } else {
            client_connections.clone()
        };
    let web_config = web_server::WebConfig {
        mode: match web.mode {
            iota_storage::util::config_util::WebMode::Disabled => web_server::WebMode::Disabled,
            iota_storage::util::config_util::WebMode::Loopback => web_server::WebMode::Loopback,
            iota_storage::util::config_util::WebMode::Network => web_server::WebMode::Network,
        },
        bind: web.bind.parse().expect("web.bind was validated at startup"),
        port: web.port,
        asset_dir: resolve_config_path(&paths.config_file, &web.asset_dir, &paths.asset_dir),
        tls: web
            .certificate
            .zip(web.key)
            .map(|(certificate, key)| web_server::TlsConfig {
                certificate: resolve_config_path(
                    &paths.config_file,
                    &certificate,
                    &paths.config_dir,
                ),
                key: resolve_config_path(&paths.config_file, &key, &paths.config_dir),
            }),
        required: web.required,
        max_mtp_sessions: web.max_mtp_sessions,
        max_mtp_sessions_per_user: web.max_mtp_sessions_per_user,
        shutdown_budget: Duration::from_secs(web.shutdown_budget_secs),
        authority_discovery: iota_identity::AuthorityDiscoveryDocument {
            version: 1,
            service: iota_identity::AuthorityKind::Iota,
            authority_id: node_identity.authority_id().clone(),
            node_id: Some(node_identity.node_id().clone()),
            public_key: match node_identity.public_keys().try_to_base64() {
                Ok(public_key) => public_key,
                Err(error) => {
                    eprintln!("Cannot encode Iota discovery identity: {error}");
                    return ExitCode::FAILURE;
                }
            },
            protocols: vec!["identity-http-v1".into(), "mtp-relay-v2".into()],
            node_descriptor: Some("/federation/v1/node".into()),
            direct_endpoints: Vec::new(),
            relay_hints: Vec::new(),
        },
        local_users: services.local_users.clone(),
        descriptor_publisher: Arc::new(
            iota_storage::identity::SqliteLocalDescriptorPublisher::new(node_identity.clone()),
        ),
        node_descriptor,
        node_identity: node_identity.clone(),
        client_keys: Arc::new(client::HostedAndPeerKeyResolver::new(
            services.local_users.clone(),
        )),
        mtp_handler,
    };
    let mut web_handle = None;
    match web_server::start(web_config, runtime.cancellation.clone()).await {
        Ok(None) => {
            runtime.set_component_healthy(iota_ipc::ComponentId::Web, Some("disabled".into()))
        }
        Ok(Some(handle)) => {
            web_handle = Some(handle.clone());
            runtime.set_component_healthy(iota_ipc::ComponentId::Web, None);
            runtime
                .tasks
                .spawn_tracked("web-server", async move {
                    handle.join().await;
                    Ok(())
                })
                .await;
        }
        Err(error) if web.required => {
            runtime.set_component_failed(iota_ipc::ComponentId::Web, error.to_string());
        }
        Err(error) => {
            runtime.set_component_degraded(iota_ipc::ComponentId::Web, error.to_string());
        }
    }

    runtime.set_startup_phase(StartupPhase::Ready);
    log!("iota-daemon started (phase: Ready)");

    let retention_runtime = runtime.clone();
    runtime
        .tasks
        .spawn_tracked("message-retention", async move {
            loop {
                let purge = tokio::task::spawn_blocking(|| {
                    iota_storage::util::message_retention::purge_expired_messages(
                        iota_storage::util::sync::now_millis(),
                    )
                })
                .await;
                match purge {
                    Ok(Ok(result)) if result.deleted_messages > 0 => {
                        log!("purged {} expired messages", result.deleted_messages);
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => log!("message retention cleanup failed: {}", error),
                    Err(error) => log!("message retention task failed: {}", error),
                }
                tokio::select! {
                    _ = tokio::time::sleep(MESSAGE_RETENTION_INTERVAL) => {},
                    _ = retention_runtime.cancellation.cancelled() => break,
                }
            }
            Ok(())
        })
        .await;

    let compaction_runtime = runtime.clone();
    runtime
        .tasks
        .spawn_tracked("sync-compaction", async move {
            loop {
                let compact =
                    tokio::task::spawn_blocking(iota_storage::util::sync::compact_all_sync_state)
                        .await;
                match compact {
                    Ok(Ok(result))
                        if result.removed_events > 0 || result.removed_blob_tombstones > 0 =>
                    {
                        log!(
                            "compacted {} sync events and {} blob tombstones",
                            result.removed_events,
                            result.removed_blob_tombstones
                        );
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => log!("sync compaction failed: {}", error),
                    Err(error) => log!("sync compaction task failed: {}", error),
                }
                tokio::select! {
                    _ = tokio::time::sleep(SYNC_COMPACTION_INTERVAL) => {},
                    _ = compaction_runtime.cancellation.cancelled() => break,
                }
            }
            Ok(())
        })
        .await;

    // --- Main lifecycle loop ---
    let signal = async {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => ShutdownReason::Stop, _ = term.recv() => ShutdownReason::Stop }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            ShutdownReason::Stop
        }
    };
    tokio::select! {
        _ = runtime.cancellation.cancelled() => {},
        reason = signal => runtime.shutdown(reason),
    }

    let reason = runtime.shutdown_reason().unwrap_or(ShutdownReason::Stop);
    log!("iota-daemon shutting down (reason: {:?})", reason);
    runtime.set_startup_phase(StartupPhase::Stopping);

    // Connection cleanup must finish before the generic task deadline can abort
    // other daemon work and before the Tokio runtime terminates.
    if let Some(peers) = peer_manager.as_ref() {
        peers.stop();
    }
    let (web_shutdown, peers_clean) = tokio::join!(
        async {
            if let Some(handle) = web_handle {
                handle.shutdown().await
            } else {
                web_server::ShutdownReport::Complete
            }
        },
        async {
            if let Some(peers) = peer_manager {
                peers
                    .shutdown(Duration::from_secs(web.shutdown_budget_secs))
                    .await
            } else {
                true
            }
        },
    );

    let connector_clean = if let Some(connector) = connector_shutdown {
        loop {
            match connector.stop().await {
                Ok(omikron_connector::omikron_connection::ShutdownOutcome::Complete) => break true,
                Ok(omikron_connector::omikron_connection::ShutdownOutcome::Incomplete {
                    pending_operations,
                }) => {
                    // The concrete supervisor keeps ownership. Ending Tokio here would abort its mutations.
                    log!(
                        "Connector shutdown is still supervised: {pending_operations} operations pending"
                    );
                }
                Err(error) => {
                    log!("Connector shutdown failed: {error}");
                    break false;
                }
            }
        }
    } else {
        true
    };

    let _ = runtime
        .tasks
        .join_with_timeout(Duration::from_secs(5))
        .await;

    let exit_code =
        if web_shutdown == web_server::ShutdownReport::Complete && peers_clean && connector_clean {
            reason.exit_code()
        } else {
            1
        };
    log!("iota-daemon exited (code: {})", exit_code);
    ExitCode::from(exit_code as u8)
}

fn resolve_config_path(
    config_file: &std::path::Path,
    value: &str,
    default: &std::path::Path,
) -> std::path::PathBuf {
    if value.is_empty() {
        return default.to_path_buf();
    }
    let path = std::path::PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        config_file
            .parent()
            .expect("absolute configuration file has a parent")
            .join(path)
    }
}
