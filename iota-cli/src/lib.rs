pub mod elements {
    pub mod console_card;
    pub mod elements;
    pub mod graph_card;
    pub mod log_card;
}
pub mod screens {
    pub mod daemon_setup;
    pub mod main_screen;
    pub mod md_viewer;
    pub mod metrics;
    pub mod overview;
    pub mod screens;
    pub mod settings;
    pub mod terms_checker;
    pub mod terms_updater;
    pub mod users;
}
pub mod util {
    pub mod borders;
    pub mod buttons;
    pub mod terms_focus;
}
pub mod app_state;
pub mod controls;
pub mod help_overlay;
pub mod input_handler;
pub mod interaction_result;
pub mod ipc_client;
pub mod layout;
pub mod notification;
pub mod render_context;
pub mod theme;
pub mod ui;
pub use ui::TuiSession;
