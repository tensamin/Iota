use crate::doc::Doc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    EULA,
    TOS,
    PP,
}

impl Type {
    pub fn to_str(&self) -> &str {
        match self {
            Self::EULA => "eula",
            Self::TOS => "terms-of-service",
            Self::PP => "privacy-policy",
        }
    }
    pub fn to_string(&self) -> String {
        match self {
            Self::EULA => "End User License Agreement".to_string(),
            Self::TOS => "Terms of Service".to_string(),
            Self::PP => "Privacy Policy".to_string(),
        }
    }
}

pub fn get_link(terms_type: Type) -> String {
    format!(
        "https://legal.methanium.net/tensamin/{}",
        terms_type.to_str()
    )
}

/*
 * The legal service exposes only its latest raw documents. Keep this helper
 * for the dormant pre-emptive-acceptance UI until it has a source of future
 * document versions again.
 */
pub fn get_newest_link(terms_type: Type) -> String {
    get_link(terms_type)
}

pub async fn get_current_docs() -> Option<(Doc, Doc, Doc)> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let (eula, tos, privacy) = tokio::join!(
        get_terms(Type::EULA),
        get_terms(Type::TOS),
        get_terms(Type::PP),
    );

    Some((
        Doc::from_raw(Type::EULA, eula?, timestamp),
        Doc::from_raw(Type::TOS, tos?, timestamp),
        Doc::from_raw(Type::PP, privacy?, timestamp),
    ))
}

/*
 * Future documents are unavailable from the raw endpoint. Restore this API
 * with the pre-emptive-acceptance flow when the service provides them again.
 *
pub async fn get_newest_docs() -> Option<(Doc, Doc, Doc)> {
    None
}
*/

pub async fn get_terms(terms_type: Type) -> Option<String> {
    reqwest::get(format!(
        "https://legal.methanium.net/tensamin/{}/raw",
        terms_type.to_str()
    ))
    .await
    .ok()?
    .text()
    .await
    .ok()
}

#[cfg(test)]
mod tests {
    use super::{Type, get_link};

    #[test]
    fn maps_document_types_to_tensamin_raw_document_names() {
        assert_eq!(Type::EULA.to_str(), "eula");
        assert_eq!(Type::TOS.to_str(), "terms-of-service");
        assert_eq!(Type::PP.to_str(), "privacy-policy");
    }

    #[test]
    fn links_to_the_tensamin_document_page() {
        assert_eq!(
            get_link(Type::TOS),
            "https://legal.methanium.net/tensamin/terms-of-service"
        );
    }
}
