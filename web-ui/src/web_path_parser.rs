use actix_web::{HttpRequest, HttpResponse};
use std::path::{Path, PathBuf};

use crate::util::file_util::load_file_vec;

fn codec_for_ext(ext: &str) -> &'static str {
    match ext {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

pub async fn handle(req: HttpRequest) -> HttpResponse {
    let req_path = req.path().trim_start_matches('/');

    let mut fs_path = PathBuf::from("web");

    if req_path.is_empty() {
        fs_path.push("index.html");
    } else {
        fs_path.extend(req_path.split('/'));
    }

    if fs_path.is_dir() {
        fs_path.push("index.html");
    }

    let ext_opt = fs_path.extension().and_then(|e| e.to_str());
    let mut final_name = fs_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    if ext_opt.is_none() {
        if final_name.is_empty() {
            final_name = "index.html".to_string();
        } else {
            final_name.push_str(".html");
        }
    }

    let content_type = codec_for_ext(
        fs_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("html"),
    );

    let dir = fs_path.parent().unwrap_or(Path::new("web"));

    match load_file_vec(dir.to_str().unwrap_or("web"), &final_name) {
        Ok(content) => HttpResponse::Ok().content_type(content_type).body(content),

        Err(_) => {
            let ext = fs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "js" | "css" | "woff2") {
                return HttpResponse::NotFound()
                    .content_type("text/plain")
                    .body("Not found");
            }

            let fallback = load_file_vec("web", "404.html")
                .unwrap_or_else(|_| include_bytes!("../../static/web/404.html").to_vec());

            HttpResponse::NotFound()
                .content_type("text/html; charset=utf-8")
                .body(fallback)
        }
    }
}
