use bytes::Bytes;
use iota_logger::log;
use iota_state::{ACTIVE_TASKS, SHUTDOWN};
use iota_util::file_util::load_file_vec;
use mtp::host::HostConfig;
use mtp::webserver::{Http3Request, Http3Response, MTPWebServer, WebServerConfig};
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::{Duration, sleep};

const CERT_PATH: &str = "certs/cert.pem";
const KEY_PATH: &str = "certs/cert.key";

async fn root(_request: Http3Request, response: Http3Response) -> Http3Response {
    static_file("index.html", response).await
}

async fn static_file(path: &str, response: Http3Response) -> Http3Response {
    let file = path.trim_start_matches('/');
    let file = if file.is_empty() { "index.html" } else { file };

    if file.split('/').any(|component| component == "..") {
        return response
            .status(http::StatusCode::BAD_REQUEST)
            .body("invalid path");
    }

    let path = std::path::Path::new("web").join(file);
    let Some(parent) = path.parent().and_then(|path| path.to_str()) else {
        return response
            .status(http::StatusCode::NOT_FOUND)
            .body("not found");
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return response
            .status(http::StatusCode::NOT_FOUND)
            .body("not found");
    };

    match load_file_vec(parent, name) {
        Ok(body) => response
            .status(http::StatusCode::OK)
            .header("content-type", content_type(name))
            .body(Bytes::from(body)),
        Err(_) => response
            .status(http::StatusCode::NOT_FOUND)
            .body("not found"),
    }
}

fn content_type(name: &str) -> &'static str {
    match std::path::Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
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

pub async fn start(port: u16) -> bool {
    let certificate = match tokio::fs::read(CERT_PATH).await {
        Ok(certificate) => certificate,
        Err(error) => {
            log!("MTP web server certificate load failed: {}", error);
            return false;
        }
    };
    let key = match tokio::fs::read(KEY_PATH).await {
        Ok(key) => key,
        Err(error) => {
            log!("MTP web server key load failed: {}", error);
            return false;
        }
    };

    let host_config = HostConfig::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, certificate, key);
    let web_config = match WebServerConfig::new().route("/", root).and_then(|config| {
        config.fallback(|request, response| async move {
            static_file(request.uri.path(), response).await
        })
    }) {
        Ok(config) => config,
        Err(error) => {
            log!("MTP web server route setup failed: {}", error);
            return false;
        }
    };

    let mut server = match MTPWebServer::new(host_config, web_config).await {
        Ok(server) => server,
        Err(error) => {
            log!("MTP web server startup failed: {}", error);
            return false;
        }
    };

    log!("MTP web server running on port {}", port);
    tokio::spawn(async move {
        ACTIVE_TASKS.insert("WebServer".into());
        loop {
            tokio::select! {
                result = server.accept() => {
                    match result {
                        Ok(Some(_connection)) => {}
                        Ok(None) => break,
                        Err(error) => log!("MTP webserver connection failed: {}", error),
                    }
                }
                _ = wait_for_shutdown() => {
                    server.shutdown().await;
                    break;
                }
            }
        }
        ACTIVE_TASKS.remove("WebServer");
    });
    true
}

async fn wait_for_shutdown() {
    loop {
        if *SHUTDOWN.read().await {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
}
