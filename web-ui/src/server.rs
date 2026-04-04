use crate::log;
use crate::server::api::api_config;
use crate::server::web_path_parser;
use crate::util::file_util::load_file_buf;
use crate::{ACTIVE_TASKS, SHUTDOWN};
use actix_web::{App, Error, HttpRequest, HttpServer, Responder, dev::ServerHandle, web};
use actix_web_actors::ws;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    error::Error as StdError,
    io::{self, BufReader, ErrorKind},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

async fn ws_handler(req: HttpRequest, stream: web::Payload) -> Result<impl Responder, Error> {
    let path = req.path().to_string();
    log!("WS connection from {:?}", req.peer_addr());
    let session = WsSession::new(path);
    ws::start(session, &req, stream)
}

use tokio::sync::oneshot;

pub async fn start(port: u16) -> bool {
    let (tx, rx) = oneshot::channel::<ServerHandle>();

    let _ = tokio::spawn(async move {
        let server = match load_tls_config() {
            Ok(Some(tls_config)) => {
                log!("HTTPS (HTTP/2) Server running on 0.0.0.0:{}", port);
                let _config = (*tls_config).clone();
                HttpServer::new(move || {
                    App::new()
                        .app_data(web::Data::new(true))
                        .configure(api_config)
                        .service(web::resource("/ws/{path:.*}").route(web::get().to(ws_handler)))
                        .default_service(web::to(web_path_parser::handle))
                })
                .bind(("0.0.0.0", port))
                .unwrap()
                .run()
            }
            Ok(_) => {
                log!("HTTP Server running on 0.0.0.0:{}", port);
                HttpServer::new(move || {
                    App::new()
                        .app_data(web::Data::new(false))
                        .configure(api_config)
                        .service(web::resource("/ws/{path:.*}").route(web::get().to(ws_handler)))
                        .default_service(web::to(web_path_parser::handle))
                })
                .bind(("0.0.0.0", port))
                .unwrap()
                .run()
            }
            Err(e) => {
                log!("TLS config error: {}", e);
                return;
            }
        };

        let server_handle = server.handle();
        tx.send(server_handle).unwrap();

        ACTIVE_TASKS.insert("WebServer".into());
        server.await.unwrap();
        ACTIVE_TASKS.remove("WebServer");
        log!("Web Server shutdown complete.");
    });

    if let Ok(server_handle) = rx.await {
        tokio::spawn(async move {
            wait_for_shutdown(server_handle).await;
        });
        true
    } else {
        false
    }
}

async fn wait_for_shutdown(server_handle: ServerHandle) {
    loop {
        if *SHUTDOWN.read().await {
            log!("Shutdown signal received.");
            server_handle.stop(true).await;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn load_tls_config() -> Result<Option<Arc<ServerConfig>>, Box<dyn StdError>> {
    let cert_file_res = load_file_buf("certs", "cert.pem");
    let key_file_res = load_file_buf("certs", "cert.key");

    let cert_file_buf = match cert_file_res {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            log!("TLS certificate 'certs/cert.pem' not found.");
            return Ok(None);
        }
        Err(e) => return Err(e.into()), // Other IO error
    };

    let key_file_buf = match key_file_res {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            log!("TLS key 'certs/cert.key' not found.");
            return Ok(None);
        }
        Err(e) => return Err(e.into()), // Other IO error
    };

    let cert_chain = rustls_pemfile::certs(&mut BufReader::new(cert_file_buf))
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    // PKCS8
    let mut key_reader = BufReader::new(key_file_buf);
    let mut key_ders = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map(|r| r.map(Into::into))
        .collect::<Result<Vec<PrivateKeyDer>, _>>()?;

    if key_ders.is_empty() {
        // RSA
        key_reader = BufReader::new(load_file_buf("certs", "cert.key")?); // Re-read key file
        key_ders = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .map(|r| r.map(Into::into))
            .collect::<Result<Vec<PrivateKeyDer>, _>>()?;
    }

    if key_ders.is_empty() {
        // EC
        key_reader = BufReader::new(load_file_buf("certs", "cert.key")?); // Re-read key file
        key_ders = rustls_pemfile::ec_private_keys(&mut key_reader)
            .map(|r| r.map(Into::into))
            .collect::<Result<Vec<PrivateKeyDer>, _>>()?;
    }

    if key_ders.is_empty() {
        return Err("No private keys found in key file. (Tried PKCS8, RSA, and EC)".into());
    }

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_ders.remove(0))
        .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;

    Ok(Some(Arc::new(config)))
}

pub fn is_local_network(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || v6.is_loopback()
        }
    }
}
