use dashmap::DashSet;
use once_cell::sync::Lazy;
use pnet::datalink::NetworkInterface;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

mod auth;
mod gui;
mod langu;
mod omikron;
mod terms;
mod users;
mod util;

use crate::gui::app_state;
use crate::gui::app_state::AppState;
use crate::gui::screens::main_screen::MainScreen;
use crate::gui::ui::start_tui;
use crate::langu::language_creator;
use crate::omikron::omikron_connection::OmikronConnection;
use crate::terms::consent_state;
use crate::users::user_manager;
use crate::util::config_util::CONFIG;
use crate::util::file_util::download_and_extract_zip;
use crate::util::file_util::has_dir;
use crate::util::logger;

pub static APP_STATE: LazyLock<Arc<Mutex<AppState>>> =
    LazyLock::new(|| Arc::new(Mutex::new(AppState::new())));

pub static SHUTDOWN: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));
pub static RELOAD: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(true));
pub static ACTIVE_TASKS: Lazy<DashSet<String>> = Lazy::new(|| DashSet::new());

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
#[allow(unused_must_use, dead_code)]
async fn main() {
    while *RELOAD.read().await {
        *RELOAD.write().await = false;
        *SHUTDOWN.write().await = false;

        let ui = start_tui();

        let (eula, tos_pp) = consent_state::check(ui.clone()).await;

        if !eula {
            *SHUTDOWN.write().await = true;
            loop {
                if ACTIVE_TASKS.is_empty() {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
            println!("You need to accept our End User Licence Agreement before launching!");
            println!("You can find this at 'agreements'!");
            return;
        }
        if !tos_pp {
            *SHUTDOWN.write().await = true;
            loop {
                if ACTIVE_TASKS.is_empty() {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
            println!(
                "Please accept our Privacy Policy & Terms of Serivce before using Tensamin Services!"
            );
            println!("In future releases this will be optional!");
            println!("You can find this at 'agreements'!");
            return;
        }
        app_state::setup();

        let main_screen = MainScreen::new(ui.clone()).await;
        ui.set_screen(Box::new(main_screen)).await;

        // LANGUAGE PACK
        if let Err(e) = language_creator::create_languages() {
            println!("Language pack creation failed: {}", e);
            return;
        }

        // UI
        logger::startup();

        // BASIC CONFIGURATION
        &CONFIG.write().await.load();

        // USER MANAGEMENT
        if let Err(_) = user_manager::load_users().await {
            log_t!("user_load_failed");
        }

        let mut sb = "".to_string();

        for up in user_manager::get_users() {
            sb = sb + "," + &up.user_id.to_string().as_str();
        }

        if !sb.is_empty() {
            {}
            sb.remove(0);
            sb = sb + ",";
        }
        log!(
            "IOTA ID:  {}",
            CONFIG.read().await.get_iota_id().to_string()
        );
        log!("User IDS: {}", sb);

        // COMMUNITY MANAGEMENT
        /*        registry::load_interactables().await;
        community_manager::load_communities().await;
        community_manager::save_communities().await;
        let mut sb1 = "".to_string();
        for cp in community_manager::get_communities().await {
            sb1 = sb1 + "," + &cp.get_name().to_string().as_str();
        }

        if !sb1.is_empty() {
            sb1.remove(0);
            sb1 = sb1 + ",";
        }
        log!("Community IDS: {}", sb1); */
        let port = CONFIG.read().await.get_port();
        let mut ip = "0.0.0.0".to_string();
        for iface in pnet::datalink::interfaces() {
            let iface: NetworkInterface = iface;
            if iface.ips.len() > 0 {
                let ipsv = format!("{}", iface.ips[0]);
                let ips: &str = ipsv.split('/').next().unwrap_or("");
                if format!("{}", ips).starts_with("10.") || format!("{}", ips).starts_with("192.") {
                    ip = ips.to_string();
                }
            }
        }
        /*
        if start(port).await {
            log_t!("community_active", ip, port.to_string());
        } else {
            if port < 1024 {
                log_t!("community_start_error_admin", port.to_string());
            } else {
                log_t!("community_start_error", port.to_string());
            }
        } */
        if !has_dir("web") {
            download_and_extract_zip(
                "https://omega.tensamin.net/api/download/iota_frontend",
                "web",
            )
            .await;
        }
        let _ = omikron::omikron_connection::get_omikron_connection().await;

        log_t!("setup_completed");
        loop {
            if *SHUTDOWN.read().await {
                break;
            }

            sleep(Duration::from_millis(100)).await;
        }
        if *RELOAD.read().await {
            loop {
                if ACTIVE_TASKS.is_empty() {
                    break;
                }
                sleep(Duration::from_secs(1)).await;
            }
            &CONFIG.write().await.clear();
            user_manager::clear();
            /*community_manager::clear();*/
            *APP_STATE.lock().unwrap() = AppState::new();
        }
        ui.terminal.lock().unwrap().clear();
        ui.terminal.lock().unwrap().flush();
    }
}
