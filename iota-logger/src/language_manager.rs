use iota_util::file_util::{self};
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
        let files = [
            "frontend.json",
            "omikron.json",
            "buttons.json",
            "debug.json",
            "general.json",
        ];

        // The daemon can initialize the logger before iota-core has created
        // the generated language files. Create the built-in pack on demand.
        if language == "en_INT"
            && files
                .iter()
                .any(|file| !file_util::has_file(&format!("languages/{language}/"), file))
        {
            let _ = crate::language_creator::create_languages();
        }

        let loaded = files
            .iter()
            .all(|file| self.load_file(&format!("languages/{language}/"), file));

        // A process may have been interrupted while an older version was
        // writing a language file. Regenerate the default pack once in that
        // case, and still leave custom language packs non-fatal.
        if !loaded && language == "en_INT" {
            self.language.clear();
            let _ = crate::language_creator::create_languages();
            for file in files {
                let _ = self.load_file(&format!("languages/{language}/"), file);
            }
        }
    }

    fn load_file(&mut self, path: &str, file: &str) -> bool {
        let contents = file_util::load_file(path, file);
        let Ok(messages) = parse(&contents) else {
            return false;
        };

        for (key, value) in messages.entries() {
            if let Some(value) = value.as_str() {
                self.language.insert(key.to_string(), value.to_string());
            }
        }
        true
    }
    pub fn get_translation(&self, key: &str) -> String {
        match self.language.get(key) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => key.to_uppercase(),
        }
    }
}
