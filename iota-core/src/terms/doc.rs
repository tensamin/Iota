use json::{JsonValue, object::Object};

use crate::{terms::terms_getter::Type, util::file_util::load_file};

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(unused)]
pub struct Doc {
    version: String,
    hash: String,
    pub doc_type: Type,
    timestamp: u64,
}

#[allow(dead_code)]
impl Doc {
    pub fn new(version: String, hash: String, doc_type: Type, timestamp: u64) -> Doc {
        Doc {
            version,
            hash,
            doc_type,
            timestamp,
        }
    }

    pub fn equals_some(&self, other: &Option<Self>) -> bool {
        if let Some(other) = other {
            self.get_version() == other.get_version() && self.get_hash() == other.get_hash()
        } else {
            false
        }
    }
    pub fn equals(&self, other: &Self) -> bool {
        self.get_version() == other.get_version() && self.get_hash() == other.get_hash()
    }

    pub fn get_version(&self) -> String {
        self.version.clone()
    }
    pub fn get_hash(&self) -> String {
        self.hash.clone()
    }
    pub fn get_time(&self) -> u64 {
        self.timestamp.clone()
    }
    pub fn get_content(&self) -> String {
        load_file(
            format!("docs/{}/", self.doc_type.to_str()).as_str(),
            format!("{}.md", self.version).as_str(),
        )
    }

    pub fn to_json(&self) -> JsonValue {
        let mut json = JsonValue::new_object();

        let _ = json.insert("version", self.version.clone());
        let _ = json.insert("hash", self.hash.clone());
        let _ = json.insert("unix", self.timestamp.clone());

        json
    }
    pub fn from_json(doc_type: Type, json: Object) -> Option<Self> {
        let hash = json.get("hash")?.as_str()?.to_string();
        let version = json.get("version")?.as_str()?.to_string();
        let timestamp = json.get("unix")?.as_u64()?;

        Some(Doc {
            version,
            hash,
            doc_type,
            timestamp,
        })
    }
}
