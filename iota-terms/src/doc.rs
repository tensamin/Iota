use crate::terms_getter::Type;
use iota_util::crypto_helper::hex_hash;

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

    pub fn from_raw(doc_type: Type, content: String, timestamp: u64) -> Doc {
        Doc::new(
            timestamp.to_string(),
            hex_hash(&content),
            doc_type,
            timestamp,
        )
    }

    pub fn equals_some(&self, other: &Option<Self>) -> bool {
        if let Some(other) = other {
            self.equals(other)
        } else {
            false
        }
    }
    pub fn equals(&self, other: &Self) -> bool {
        self.get_hash() == other.get_hash()
    }

    pub fn get_version(&self) -> String {
        self.version.clone()
    }
    pub fn get_hash(&self) -> String {
        self.hash.clone()
    }
    pub fn get_time(&self) -> u64 {
        self.timestamp
    }
    #[cfg(test)]
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::Doc;
    use crate::terms_getter::Type;
    use iota_util::crypto_helper::hex_hash;

    #[test]
    fn raw_documents_use_a_local_timestamp_and_content_hash() {
        let content = "# EULA\n".to_owned();
        let document = Doc::from_raw(Type::EULA, content.clone(), 123);

        assert_eq!(document.doc_type, Type::EULA);
        assert_eq!(document.get_version(), "123");
        assert_eq!(document.timestamp(), 123);
        assert_eq!(document.get_hash(), hex_hash(&content));
    }

    #[test]
    fn matching_documents_ignore_the_fetch_timestamp() {
        let earlier = Doc::from_raw(Type::EULA, "# EULA\n".to_owned(), 123);
        let later = Doc::from_raw(Type::EULA, "# EULA\n".to_owned(), 456);

        assert!(earlier.equals(&later));
    }
}
