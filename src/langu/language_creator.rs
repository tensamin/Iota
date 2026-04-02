use crate::util::file_util::save_file;
use json::{self, JsonError, JsonValue};

pub fn create_languages() -> Result<(), JsonError> {
    let mut frontend_messages = JsonValue::new_object();
    let mut omikron_messages = JsonValue::new_object();
    let mut button_texts = JsonValue::new_object();
    let mut general_texts = JsonValue::new_object();
    let mut debug_messages = JsonValue::new_object();

    frontend_messages.insert("error", "An error occurred")?;
    // FRONTEND
    frontend_messages.insert("get_chats", "User {} is loading conversations")?;
    frontend_messages.insert("message_get", "User {} is loading messages")?;
    frontend_messages.insert("get_communities", "User {} is loading communities")?;
    frontend_messages.insert("client_connected", "Client {} connected")?;
    frontend_messages.insert("add_conversation", "User {} added {}")?;
    frontend_messages.insert("message_send", "User {} sent a message")?;

    // OMIKRON
    omikron_messages.insert(
        "identification_response",
        "IOTA identified on Omikron, {} users!",
    )?;
    omikron_messages.insert(
        "send_message_failed",
        "Failed to send message to Omikron: {}",
    )?;
    omikron_messages.insert("connection_failed", "Failed to connect to Omikron: {}")?;

    // BUTTONS
    button_texts.insert("exit", "Exit")?;

    // GENERAL
    general_texts.insert("iota_id", "IOTA ID: {}-####-####-####-############")?;
    general_texts.insert("user_id", "USER ID: {}")?;
    general_texts.insert("user_ids", "USER IDS: {}")?;
    general_texts.insert("user_load_failed", "Failed to load user data")?;
    general_texts.insert("setup_completed", "Launched")?;
    general_texts.insert(
        "community_active",
        "Communities active on ws://{}:{}/community/...",
    )?;
    general_texts.insert(
        "community_start_error",
        "Failed to start community socket on port {}!",
    )?;
    general_texts.insert(
        "community_start_error_admin",
        "Failed to start community socket on port {}! Run with admin privileges",
    )?;
    // DEBUG
    debug_messages.insert("", "")?;
    save_file(
        "languages/en_INT",
        "frontend.json",
        &frontend_messages.to_string(),
    );
    save_file(
        "languages/en_INT",
        "omikron.json",
        &omikron_messages.to_string(),
    );
    save_file(
        "languages/en_INT",
        "buttons.json",
        &button_texts.to_string(),
    );
    save_file(
        "languages/en_INT",
        "debug.json",
        &debug_messages.to_string(),
    );
    save_file(
        "languages/en_INT",
        "general.json",
        &general_texts.to_string(),
    );
    Ok(())
}
