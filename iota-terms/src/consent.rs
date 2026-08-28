//! Durable, deployment-scoped consent records.
//!
//! This deliberately contains no UI code.  Both the terminal client and the
//! daemon use the same record so a UI-local decision can never start services.

use crate::{Doc, TermsType as Type};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_NAME: &str = "terms-consent-v1";

#[derive(Clone, Debug, Default)]
pub struct ConsentRecord {
    pub eula: Option<(String, String)>,
    pub tos: Option<(String, String)>,
    pub privacy: Option<(String, String)>,
}

impl ConsentRecord {
    pub fn has_all_required(&self) -> bool {
        self.eula.is_some() && self.tos.is_some() && self.privacy.is_some()
    }

    pub fn accepts(&self, eula: &Doc, tos: &Doc, privacy: &Doc) -> bool {
        matches_doc(&self.eula, eula)
            && matches_doc(&self.tos, tos)
            && matches_doc(&self.privacy, privacy)
    }

    pub fn accept(&mut self, doc: &Doc) {
        let value = Some((doc.get_version(), doc.get_hash()));
        match doc.doc_type {
            Type::EULA => self.eula = value,
            Type::TOS => self.tos = value,
            Type::PP => self.privacy = value,
        }
    }
}

fn matches_doc(value: &Option<(String, String)>, doc: &Doc) -> bool {
    matches!(value, Some((_, hash)) if hash == &doc.get_hash())
}

pub fn load(state_dir: &Path) -> ConsentRecord {
    let Ok(text) = fs::read_to_string(state_dir.join(FILE_NAME)) else {
        return ConsentRecord::default();
    };
    let mut record = ConsentRecord::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some((version, hash)) = value.split_once(':') else {
            continue;
        };
        let value = Some((version.to_owned(), hash.to_owned()));
        match key {
            "eula" => record.eula = value,
            "tos" => record.tos = value,
            "privacy" => record.privacy = value,
            _ => {}
        }
    }
    record
}

pub fn save(state_dir: &Path, record: &ConsentRecord) -> io::Result<()> {
    fs::create_dir_all(state_dir)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut text = format!("# Iota terms consent record; accepted_at_unix={timestamp}\n");
    for (name, value) in [
        ("eula", &record.eula),
        ("tos", &record.tos),
        ("privacy", &record.privacy),
    ] {
        if let Some((version, hash)) = value {
            text.push_str(&format!("{name}={version}:{hash}\n"));
        }
    }
    iota_util::atomic_file::replace(&state_dir.join(FILE_NAME), text.as_bytes(), 3)
}
