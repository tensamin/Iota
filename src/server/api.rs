use crate::server::server::is_local_network;
use crate::util::config_util::CONFIG;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
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
            let _ = CONFIG
                .write()
                .await
                .config
                .insert(&k.to_string(), v.to_string());

            success()
        }
        _ => error(),
    }
}

async fn settings_get(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }
    let config = CONFIG.read().await.config.clone();
    let serde_config: Value = serde_json::to_value(config.to_string()).unwrap();
    HttpResponse::Ok().json(serde_config)
}

async fn communities_get(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    let communities = crate::communities::community_manager::get_communities().await;

    let mut list = Vec::new();

    for c in communities {
        let val = c.frontend().await;
        let s_val: Value = serde_json::to_value(val.to_string()).unwrap();
        list.push(s_val);
    }
    HttpResponse::Ok().json(list)
}

async fn communities_add(
    req: HttpRequest,
    ssl: web::Data<bool>,
    payload: web::Json<Value>,
) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    let name = payload["name"].as_str().unwrap_or("").to_string();
    let owner = payload["owner"].as_i64().unwrap_or(0);

    let community = Arc::new(crate::communities::community::Community::create(name, owner).await);

    crate::communities::community_manager::add_community(community).await;

    success()
}

async fn users_get(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    let users = crate::users::user_manager::get_users();

    let list: Vec<_> = users
        .into_iter()
        .map(|u| {
            let val = u.frontend();
            serde_json::to_value(val.to_string()).unwrap()
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

    crate::users::user_manager::remove_user(uuid);
    crate::users::user_manager::save_users();

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

    if let (Some(user), Some(_)) = crate::users::user_manager::create_user(username).await {
        let val = user.frontend();
        let s_val: Value = serde_json::to_value(val.to_string()).unwrap();
        HttpResponse::Ok().json(s_val)
    } else {
        error()
    }
}

async fn shutdown(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    *crate::SHUTDOWN.write().await = true;
    success()
}

async fn reload(req: HttpRequest, ssl: web::Data<bool>) -> impl Responder {
    if !is_allowed_req(&req, *ssl.get_ref()) {
        return forbidden();
    }

    *crate::SHUTDOWN.write().await = true;
    *crate::RELOAD.write().await = true;

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
