use crate::server::is_local_network;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use iota_state::DaemonState;
use iota_storage::util::config_util::{CONFIG, modify_config};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

pub fn api_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/shutdown/", web::post().to(shutdown))
            .route("/reload/", web::post().to(reload))
            .route("/users/add/", web::post().to(users_add))
            .route("/users/remove/", web::post().to(users_remove))
            .route("/users/get/", web::get().to(users_get))
            .route("/communities/add/", web::post().to(communities_add))
            .route("/communities/get/", web::get().to(communities_get))
            .route("/settings/set/", web::post().to(settings_set))
            .route("/settings/get/", web::get().to(settings_get)),
    );
}

async fn settings_set(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    let key = req.headers().get("key").and_then(|v| v.to_str().ok());
    let value = req.headers().get("value").and_then(|v| v.to_str().ok());

    match (key, value) {
        (Some(k), Some(v)) => {
            modify_config(|cfg| match k {
                "port" => {
                    if let Ok(port) = v.parse::<u16>() {
                        cfg.port = port;
                    }
                }
                "omikron_host" => {
                    cfg.omikron_host = Some(v.to_string());
                }
                "omikron_port" => {
                    if let Ok(port) = v.parse::<u16>() {
                        cfg.omikron_port = Some(port);
                    }
                }
                "read_receipts_enabled" => {
                    cfg.read_receipts_enabled = v == "true";
                }
                _ => {}
            });
            success()
        }
        _ => error(),
    }
}

async fn settings_get(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }
    let serde_config: Value = serde_json::to_value(&**CONFIG.load()).unwrap();
    HttpResponse::Ok().json(serde_config)
}

async fn communities_get(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    // let communities = decentralized::communities::community_manager::get_communities().await;

    let list: Vec<Value> = Vec::new();

    // for c in communities {
    //     let val = c.frontend().await.to_string();
    //     let s_val: Value = serde_json::from_str(&val).unwrap_or(Value::Null);
    //     list.push(s_val);
    // }
    HttpResponse::Ok().json(list)
}

async fn communities_add(
    req: HttpRequest,
    ssl: web::Data<bool>,
    _payload: web::Json<Value>,
) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    // let name = payload["name"].as_str().unwrap_or("").to_string();
    // let owner = payload["owner"].as_i64().unwrap_or(0);

    // let community =
    //     Arc::new(decentralized::communities::community::Community::create(name, owner).await);

    // decentralized::communities::community_manager::add_community(community).await;

    success()
}

async fn users_get(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    let users = iota_storage::users::user_manager::get_users();

    let list: Vec<_> = users
        .into_iter()
        .map(|u| {
            let val = u.frontend().to_string();
            serde_json::from_str(&val).unwrap_or(Value::Null)
        })
        .collect();

    HttpResponse::Ok().json(list)
}

async fn users_remove(
    req: HttpRequest,
    ssl: web::Data<bool>,
    payload: web::Json<Value>,
) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    let uuid = payload.get("uuid").and_then(|v| v.as_i64()).unwrap_or(0);

    iota_storage::users::user_manager::remove_user(uuid);
    iota_storage::users::user_manager::save_users();

    success()
}

async fn users_add(
    req: HttpRequest,
    ssl: web::Data<bool>,
    payload: web::Json<Value>,
) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    let username = match payload.get("username").and_then(|v| v.as_str()) {
        Some(u) => u,
        _ => return error(),
    };

    // The legacy web API is intentionally quarantined until it can use the
    // daemon's authenticated command/service boundary. It must not create a
    // second connector or mutate daemon storage directly.
    let _ = username;
    error()
}

async fn shutdown(
    req: HttpRequest,
    ssl: web::Data<bool>,
    state: web::Data<Arc<DaemonState>>,
) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    *state.shutdown.write().await = true;
    success()
}

async fn reload(
    req: HttpRequest,
    ssl: web::Data<bool>,
    state: web::Data<Arc<DaemonState>>,
) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    *state.shutdown.write().await = true;
    *state.reload.write().await = true;

    success()
}

fn forbidden() -> HttpResponse {
    HttpResponse::Forbidden().body("403 Forbidden")
}

fn success() -> HttpResponse {
    HttpResponse::Ok().json(json!({ "type": "success" }))
}

fn error() -> HttpResponse {
    HttpResponse::Ok().json(json!({ "type": "error" }))
}

fn is_allowed(addr: SocketAddr, ssl: bool) -> bool {
    is_local_network(addr.ip()) || ssl
}

fn is_allowed_req(req: &HttpRequest, ssl: bool) -> bool {
    if let Some(addr) = req.peer_addr() {
        is_allowed(addr, ssl)
    } else {
        false
    }
}
