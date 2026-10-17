use bytes::Bytes;
use http::Method;
use iota_identity::{LocalDescriptorPublisher, LocalUserId, LocalUserStore, SignedNodeDescriptor};
use iota_logger::log;
use mtp::host::HostConfig;
use mtp::webserver::{HttpRequest, HttpResponse, MTPWebServer, WebServerConfig};
use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

#[async_trait::async_trait]
pub trait ClientPublicKeyResolver: Send + Sync {
    async fn public_key(&self, client_id: u64) -> Option<mtp::crypto::PublicKeyBundle>;
}

#[async_trait::async_trait]
pub trait MtpConnectionHandler: Send + Sync {
    async fn accept(&self, connection: mtp::webserver::WebMTPConnection);

    /// Interrupt the transport on shutdown, then await the handler's cleanup.
    async fn accept_until_shutdown(
        &self,
        connection: mtp::webserver::WebMTPConnection,
        shutdown: CancellationToken,
    ) {
        let sender = connection.sender.clone();
        let handler = self.accept(connection);
        tokio::pin!(handler);
        tokio::select! {
            _ = &mut handler => {},
            _ = shutdown.cancelled() => {
                sender.close();
                handler.await;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebMode {
    Disabled,
    Loopback,
    Network,
}

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone)]
pub struct WebConfig {
    pub mode: WebMode,
    pub bind: IpAddr,
    pub port: u16,
    pub asset_dir: PathBuf,
    pub tls: Option<TlsConfig>,
    pub required: bool,
    pub max_mtp_sessions: usize,
    pub max_mtp_sessions_per_user: usize,
    pub shutdown_budget: std::time::Duration,
    pub authority_discovery: iota_identity::AuthorityDiscoveryDocument,
    pub local_users: Arc<dyn LocalUserStore>,
    pub descriptor_publisher: Arc<dyn LocalDescriptorPublisher>,
    pub node_descriptor: SignedNodeDescriptor,
    pub node_identity: iota_identity::LocalNodeIdentity,
    pub client_keys: Arc<dyn ClientPublicKeyResolver>,
    pub mtp_handler: Arc<dyn MtpConnectionHandler>,
}

#[derive(Debug)]
pub enum WebServerError {
    Disabled,
    MissingTls(String),
    Io(String),
    Startup(String),
}
impl std::fmt::Display for WebServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WebServerError {}

struct UserSessionGuard {
    sessions: Arc<StdMutex<HashMap<u64, usize>>>,
    user_id: u64,
}

impl Drop for UserSessionGuard {
    fn drop(&mut self) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(count) = sessions.get_mut(&self.user_id) {
            *count -= 1;
            if *count == 0 {
                sessions.remove(&self.user_id);
            }
        }
    }
}

pub struct WebServerHandle {
    cancellation: CancellationToken,
    join: Mutex<(Option<JoinHandle<ShutdownReport>>, Option<ShutdownReport>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownReport {
    Complete,
    Incomplete { remaining_handlers: usize },
    SupervisorFailed,
}

impl WebServerHandle {
    pub async fn shutdown(&self) -> ShutdownReport {
        self.cancellation.cancel();
        self.join().await
    }
    pub async fn join(&self) -> ShutdownReport {
        // Keep ownership in the handle until completion. A cancelled waiter must
        // not detach the supervisor or make another shutdown caller return early.
        let mut join = self.join.lock().await;
        if let Some(task) = join.0.as_mut() {
            let result = task.await.unwrap_or(ShutdownReport::SupervisorFailed);
            join.0.take();
            join.1 = Some(result);
        }
        join.1
            .expect("supervisor result retained for every shutdown caller")
    }
}

async fn root(asset_dir: PathBuf, _request: HttpRequest, response: HttpResponse) -> HttpResponse {
    static_file(asset_dir, "index.html".into(), response).await
}
async fn authority_discovery(body: Bytes, _: HttpRequest, response: HttpResponse) -> HttpResponse {
    response
        .status(http::StatusCode::OK)
        .header("content-type", "application/json")
        .body(body)
}

fn json_response<T: serde::Serialize>(value: &T, response: HttpResponse) -> HttpResponse {
    match serde_json::to_vec(value) {
        Ok(body) => response
            .status(http::StatusCode::OK)
            .header("content-type", "application/json")
            .body(Bytes::from(body)),
        Err(_) => response
            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .body("descriptor encoding failed"),
    }
}

fn descriptor_error(error: iota_identity::IdentityError, response: HttpResponse) -> HttpResponse {
    let status = match error {
        iota_identity::IdentityError::NotFound => http::StatusCode::NOT_FOUND,
        iota_identity::IdentityError::InvalidIdentifier(_) => http::StatusCode::BAD_REQUEST,
        _ => http::StatusCode::INTERNAL_SERVER_ERROR,
    };
    response.status(status).body(error.to_string())
}
async fn static_file(asset_dir: PathBuf, path: String, response: HttpResponse) -> HttpResponse {
    let file = path.trim_start_matches('/');
    let file = if file.is_empty() { "index.html" } else { file };
    if file.split('/').any(|component| component == "..") {
        return response
            .status(http::StatusCode::BAD_REQUEST)
            .body("invalid path");
    }
    let path = asset_dir.join(file);
    let body = match tokio::fs::read(&path).await {
        Ok(body) => body,
        Err(_) => {
            return response
                .status(http::StatusCode::NOT_FOUND)
                .body("not found");
        }
    };
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    response
        .status(http::StatusCode::OK)
        .header("content-type", content_type(name))
        .body(Bytes::from(body))
}
fn content_type(name: &str) -> &'static str {
    match std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
    {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

pub async fn start(
    config: WebConfig,
    parent: CancellationToken,
) -> Result<Option<Arc<WebServerHandle>>, WebServerError> {
    if config.mode == WebMode::Disabled {
        return Ok(None);
    }
    if config.mode == WebMode::Network && config.tls.is_none() {
        return Err(WebServerError::MissingTls(
            "network mode requires TLS".into(),
        ));
    }
    let tls = config
        .tls
        .ok_or_else(|| WebServerError::MissingTls("certificate and key are required".into()))?;
    let certificate = tokio::fs::read(&tls.certificate)
        .await
        .map_err(|e| WebServerError::Io(e.to_string()))?;
    let key = tokio::fs::read(&tls.key)
        .await
        .map_err(|e| WebServerError::Io(e.to_string()))?;
    let node_keyring = config.node_identity.keyring();
    let node_keyring = node_keyring
        .try_to_bytes()
        .map_err(|error| WebServerError::Startup(error.to_string()))
        .and_then(|bytes| {
            mtp::crypto::Keyring::from_bytes(&bytes)
                .map_err(|error| WebServerError::Startup(error.to_string()))
        })?;
    let client_keys = config.client_keys.clone();
    let host_config = HostConfig::new(config.bind, config.port, certificate, key)
        .with_authentication(
            node_keyring,
            Box::new(move |client_id, _| {
                let client_keys = client_keys.clone();
                Box::pin(async move { client_keys.public_key(client_id).await })
            }),
            Box::new(|_, _| Box::pin(async { 0 })),
        )
        .with_authentication_policy(mtp::host::AuthenticationPolicy::ForceAuthentication);
    let assets = config.asset_dir.clone();
    let discovery = serde_json::to_vec(&config.authority_discovery)
        .map(Bytes::from)
        .map_err(|error| WebServerError::Startup(error.to_string()))?;
    let node_descriptor = config
        .node_descriptor
        .to_wire_v1()
        .map_err(|error| WebServerError::Startup(error.to_string()))?;
    let local_users = config.local_users.clone();
    let descriptor_publisher = config.descriptor_publisher.clone();
    let mtp_handler = config.mtp_handler.clone();
    let web_config = WebServerConfig::new()
        .route("/", move |request, response| {
            root(assets.clone(), request, response)
        })
        .and_then(|web_config| {
            web_config.route("/.well-known/tensamin", move |request, response| {
                authority_discovery(discovery.clone(), request, response)
            })
        })
        .and_then(|web_config| {
            let descriptor = node_descriptor.clone();
            web_config.route_method(Method::GET, "/federation/v1/node", move |_, response| {
                let descriptor = descriptor.clone();
                async move { json_response(&descriptor, response) }
            })
        })
        .and_then(|web_config| {
            let publisher = descriptor_publisher.clone();
            web_config.route_pattern_method(
                Method::GET,
                "/federation/v1/users/id/{user_id}",
                move |_, response, params| {
                    let publisher = publisher.clone();
                    async move {
                        let user = params
                            .get("user_id")
                            .ok_or_else(|| {
                                iota_identity::IdentityError::InvalidIdentifier(
                                    "missing user ID".into(),
                                )
                            })
                            .and_then(|user| {
                                user.parse::<i64>().map(LocalUserId).map_err(|_| {
                                    iota_identity::IdentityError::InvalidIdentifier(
                                        "invalid user ID".into(),
                                    )
                                })
                            });
                        match user
                            .and_then(|user| publisher.principal_descriptor(user))
                            .and_then(|descriptor| descriptor.to_wire_v1())
                        {
                            Ok(descriptor) => json_response(&descriptor, response),
                            Err(error) => descriptor_error(error, response),
                        }
                    }
                },
            )
        })
        .and_then(|web_config| {
            let local_users = local_users.clone();
            let publisher = descriptor_publisher.clone();
            web_config.route_pattern_method(
                Method::GET,
                "/federation/v1/users/name/{username}",
                move |_, response, params| {
                    let local_users = local_users.clone();
                    let publisher = publisher.clone();
                    async move {
                        let descriptor = params
                            .get("username")
                            .ok_or_else(|| {
                                iota_identity::IdentityError::InvalidIdentifier(
                                    "missing username".into(),
                                )
                            })
                            .and_then(|username| local_users.get_local_user_by_username(username))
                            .and_then(|user| user.ok_or(iota_identity::IdentityError::NotFound))
                            .and_then(|user| publisher.principal_descriptor(user.id))
                            .and_then(|descriptor| descriptor.to_wire_v1());
                        match descriptor {
                            Ok(descriptor) => json_response(&descriptor, response),
                            Err(error) => descriptor_error(error, response),
                        }
                    }
                },
            )
        })
        .and_then(|web_config| {
            let assets = config.asset_dir.clone();
            web_config.fallback(move |request, response| {
                let path = request.uri.path().to_string();
                static_file(assets.clone(), path, response)
            })
        })
        .map_err(|e| WebServerError::Startup(e.to_string()))?;
    let mut server = MTPWebServer::new(host_config, web_config)
        .await
        .map_err(|e| WebServerError::Startup(e.to_string()))?;
    let cancellation = parent.child_token();
    let task_cancellation = cancellation.clone();
    let session_limit = Arc::new(tokio::sync::Semaphore::new(config.max_mtp_sessions));
    let user_sessions = Arc::new(StdMutex::new(HashMap::<u64, usize>::new()));
    let max_user_sessions = config.max_mtp_sessions_per_user;
    let shutdown_budget = config.shutdown_budget;
    let join = tokio::spawn(async move {
        let mut handlers = JoinSet::new();
        let mut handler_failed = false;
        loop {
            tokio::select! {
                biased;
                _ = task_cancellation.cancelled() => break,
                Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                    if let Err(error) = result { handler_failed = true; log!("MTP handler failed: {}", error); }
                },
                result = server.accept() => match result {
                    Ok(Some(connection)) => {
                        let Ok(permit) = session_limit.clone().try_acquire_owned() else {
                            log!("Rejected MTP connection: session limit reached");
                            connection.sender.close();
                            continue;
                        };
                        let user_guard = if connection.client_id & (1_u64 << 63) == 0 {
                            let mut sessions = user_sessions.lock().unwrap();
                            let count = sessions.get(&connection.client_id).copied().unwrap_or_default();
                            if count >= max_user_sessions {
                                log!("Rejected MTP connection: per-user session limit reached");
                                connection.sender.close();
                                continue;
                            }
                            sessions.insert(connection.client_id, count + 1);
                            Some(UserSessionGuard { sessions: user_sessions.clone(), user_id: connection.client_id })
                        } else {
                            None
                        };
                        let handler = mtp_handler.clone();
                        let shutdown = task_cancellation.child_token();
                        handlers.spawn(async move {
                            let _permit = permit;
                            let _user_guard = user_guard;
                            handler.accept_until_shutdown(connection, shutdown).await;
                        });
                    }
                    Ok(None) => break,
                    Err(error) => log!("MTP webserver connection failed: {}", error),
                },
            }
        }
        task_cancellation.cancel();
        let cleanup = async {
            server.shutdown().await;
            while let Some(result) = handlers.join_next().await {
                if let Err(error) = result {
                    handler_failed = true;
                    log!("MTP handler failed during shutdown: {}", error);
                }
            }
        };
        if tokio::time::timeout(shutdown_budget, cleanup)
            .await
            .is_err()
        {
            let remaining_handlers = handlers.len();
            log!(
                "MTP shutdown incomplete: {} handlers exceeded {:?}; connection state may require recovery, durable relay retries remain queued",
                remaining_handlers,
                shutdown_budget
            );
            // Do not abort a mutation-bearing handler. Permits remain owned by
            // detached tasks until termination. The daemon exits with failure;
            // SQLite transaction rollback and durable retries govern recovery.
            handlers.detach_all();
            return ShutdownReport::Incomplete { remaining_handlers };
        }
        if handler_failed {
            ShutdownReport::SupervisorFailed
        } else {
            ShutdownReport::Complete
        }
    });
    Ok(Some(Arc::new(WebServerHandle {
        cancellation,
        join: Mutex::new((Some(join), None)),
    })))
}
