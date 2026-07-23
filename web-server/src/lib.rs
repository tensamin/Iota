use bytes::Bytes;
use iota_logger::log;
use mtp::host::HostConfig;
use mtp::webserver::{HttpRequest, HttpResponse, MTPWebServer, WebServerConfig};
use std::{net::IpAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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

#[derive(Clone, Debug)]
pub struct WebConfig {
    pub mode: WebMode,
    pub bind: IpAddr,
    pub port: u16,
    pub asset_dir: PathBuf,
    pub tls: Option<TlsConfig>,
    pub required: bool,
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

pub struct WebServerHandle {
    cancellation: CancellationToken,
    join: Mutex<Option<JoinHandle<()>>>,
}
impl WebServerHandle {
    pub async fn shutdown(&self) {
        self.cancellation.cancel();
        self.join().await;
    }
    pub async fn join(&self) {
        if let Some(join) = self.join.lock().await.take() {
            let _ = join.await;
        }
    }
}

async fn root(asset_dir: PathBuf, _request: HttpRequest, response: HttpResponse) -> HttpResponse {
    static_file(asset_dir, "index.html".into(), response).await
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
    let host_config = HostConfig::new(config.bind, config.port, certificate, key);
    let assets = config.asset_dir.clone();
    let web_config = WebServerConfig::new()
        .route("/", move |request, response| {
            root(assets.clone(), request, response)
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
    let join = tokio::spawn(async move {
        loop {
            tokio::select! { result = server.accept() => match result { Ok(Some(_)) => {}, Ok(None) => break, Err(error) => log!("MTP webserver connection failed: {}", error) }, _ = task_cancellation.cancelled() => { server.shutdown().await; break; } }
        }
    });
    Ok(Some(Arc::new(WebServerHandle {
        cancellation,
        join: Mutex::new(Some(join)),
    })))
}
