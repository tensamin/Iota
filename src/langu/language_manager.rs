use crate::util::file_util::{self};
use json::parse;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone)]
pub struct LanguagePack {
    language: HashMap<String, String>,
}

pub static LANGUAGE_PACK: Lazy<Mutex<LanguagePack>> =
    Lazy::new(|| Mutex::new(LanguagePack::new("en_INT")));

#[allow(dead_code)]
pub fn get_language() -> LanguagePack {
    LANGUAGE_PACK.lock().unwrap().clone()
}

#[allow(dead_code)]
pub fn get_languages() -> Vec<String> {
    file_util::get_children("languages")
}

#[allow(dead_code)]
pub fn set_language(language: &str) {
    LANGUAGE_PACK.lock().unwrap().language.clear();
    LANGUAGE_PACK.lock().unwrap().load_language(language);
}

pub fn from_key(key: &str) -> String {
    LANGUAGE_PACK
        .lock()
        .unwrap()
        .get_translation(key)
        .to_string()
}

pub fn format(key: &str, args: &[&str]) -> String {
    let message = from_key(key);
    let mut formatted = String::new();
    let parts = message.split("{}");
    for (i, part) in parts.enumerate() {
        formatted.push_str(part);
        if i < args.len() {
            formatted.push_str(args[i]);
        }
    }
    formatted
}

impl LanguagePack {
    pub fn new(language: &str) -> Self {
        let mut pack = LanguagePack {
            language: HashMap::new(),
        };
        pack.load_language(language);
        pack
    }

    pub fn load_language(&mut self, language: &str) {
        let path = format!("languages/{}/", language);

        let frontend_messages = file_util::load_file(&path, "frontend.json");
        let frontend_messages = parse(&frontend_messages).unwrap();
        for (key, value) in frontend_messages.entries() {
            self.language
                .insert(key.to_string(), value.as_str().unwrap().to_string());
        }

        let omikron_messages = file_util::load_file(&path, "omikron.json");
        let omikron_messages = parse(&omikron_messages).unwrap();
        for (key, value) in omikron_messages.entries() {
            self.language
                .insert(key.to_string(), value.as_str().unwrap().to_string());
        }

        let button_texts = file_util::load_file(&path, "buttons.json");
        let button_texts = parse(&button_texts).unwrap();
        for (key, value) in button_texts.entries() {
            self.language
                .insert(key.to_string(), value.as_str().unwrap().to_string());
        }

        let debug_messages = file_util::load_file(&path, "debug.json");
        let debug_messages = parse(&debug_messages).unwrap();
        for (key, value) in debug_messages.entries() {
            self.language
                .insert(key.to_string(), value.as_str().unwrap().to_string());
        }

        let general_messages = file_util::load_file(&path, "general.json");
        let general_messages = parse(&general_messages).unwrap();
        for (key, value) in general_messages.entries() {
            self.language
                .insert(key.to_string(), value.as_str().unwrap().to_string());
        }
    }
    pub fn get_translation(&self, key: &str) -> String {
        match self.language.get(key) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => key.to_uppercase(),
        }
    }
}
