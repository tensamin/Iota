mod consent_state;
use iota_updater::check_update;
use pnet::datalink::NetworkInterface;
use tokio::time::{Duration, sleep};

use iota_state::{AppState, DaemonState};

use iota_cli::screens::main_screen::MainScreen;
use iota_cli::{ipc_client::IpcClient, ui::start_tui};
use iota_logger::{self as logger, language_creator};
use iota_logger::{log, log_t};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::CONFIG;
use iota_util::file_util::{download_and_extract_zip, has_dir};
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
#[allow(unused_must_use, dead_code, unused_assignments)]
async fn main() {
    let state = Arc::new(DaemonState::new());

    while *state.reload.read().await {
        *state.reload.write().await = false;
        *state.shutdown.write().await = false;

        let socket = match iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
            .expect("resolve Iota user paths")
            .ipc_endpoint
        {
            iota_paths::IpcEndpoint::UnixSocket(path) => path,
            iota_paths::IpcEndpoint::WindowsPipe(_) => {
                panic!("Windows IPC client transport is not implemented yet")
            }
        };
        let ipc = IpcClient::connect(socket)
            .await
            .expect("iota-daemon must be running before starting iota-core");
        let session = start_tui(ipc.clone()).expect("interactive terminal initialization failed");
        let ui = session.ui();

        let consent = match consent_state::check(ui.clone()).await {
            Ok(v) => v,
            Err(e) => {
                *state.shutdown.write().await = true;
                loop {
                    if state.active_tasks.is_empty() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                println!("{}", e);
                return;
            }
        };

        if !consent.accepted_eula {
            *state.shutdown.write().await = true;
            loop {
                if state.active_tasks.is_empty() {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
            println!("You need to accept our End User Licence Agreement before launching!");
            println!("You can find this at 'agreements'!");
            return;
        }
        if !consent.accepted_services {
            *state.shutdown.write().await = true;
            loop {
                if state.active_tasks.is_empty() {
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
        check_update();
        iota_state::setup(&state);

        let main_screen = MainScreen::new(ipc);
        ui.set_screen(Box::new(main_screen)).await;

        // LANGUAGE PACK
        if let Err(e) = language_creator::create_languages() {
            println!("Language pack creation failed: {}", e);
            return;
        }

        // UI
        logger::startup();

        // BASIC CONFIGURATION
        if let Err(error) = iota_storage::util::config_util::load_config() {
            log!("Cannot load Iota configuration: {}", error);
            return;
        }

        // USER MANAGEMENT
        if let Err(error) = iota_storage::util::db::initialize_database() {
            log!("Failed to initialize user storage: {}", error);
            return;
        }
        iota_storage::util::call_envelopes::start_expiry_cleanup();
        if let Err(_) = user_manager::load_users_sync() {
            log_t!("user_load_failed");
        }
        if let Err(e) = iota_storage::util::settings::migrate_legacy_files() {
            log!("Failed to migrate legacy settings: {}", e);
        }

        let mut sb = "".to_string();

        let users = match user_manager::get_users() {
            Ok(users) => users,
            Err(error) => {
                log!("Failed to load users: {}", error);
                return;
            }
        };
        for up in users {
            sb = sb + "," + &up.user_id.to_string().as_str();
        }

        if !sb.is_empty() {
            {}
            sb.remove(0);
            sb = sb + ",";
        }
        log!(
            "IOTA ID:  {}",
            CONFIG
                .load()
                .iota_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "N/A".to_string())
        );
        log!("User IDS: {}", sb);

        // COMMUNITY MANAGEMENT
        // Reason for comment: Communities have not been implemented yet.
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
        let port = CONFIG.load().port;
        let mut _ip = "0.0.0.0".to_string();
        for iface in pnet::datalink::interfaces() {
            let iface: NetworkInterface = iface;
            if iface.ips.len() > 0 {
                let ipsv = format!("{}", iface.ips[0]);
                let ips: &str = ipsv.split('/').next().unwrap_or("");
                if format!("{}", ips).starts_with("10.") || format!("{}", ips).starts_with("192.") {
                    _ip = ips.to_string();
                }
            }
        }
        if !has_dir("web") {
            download_and_extract_zip(
                "https://omega.tensamin.net/api/download/iota_frontend",
                "web",
            )
            .await;
        }
        if !web_server::start(port).await {
            log!("Failed to start the MTP web server on port {}", port);
        }
        log_t!("setup_completed");
        loop {
            if *state.shutdown.read().await {
                break;
            }

            sleep(Duration::from_millis(500)).await;
        }
        if *state.reload.read().await {
            loop {
                if state.active_tasks.is_empty() {
                    break;
                }
                sleep(Duration::from_secs(1)).await;
            }
            iota_storage::util::config_util::clear_config();
            if let Err(error) = user_manager::clear() {
                log!("Failed to clear users: {}", error);
            }
            // Commhnities have not been implemented yet.
            /*community_manager::clear();*/
            *state.app.lock().unwrap() = AppState::new();
        }
        let _ = session.shutdown().await;
    }
}
