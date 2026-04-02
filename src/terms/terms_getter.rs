use json::JsonValue::Object;

use crate::terms::doc::Doc;

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
            Self::TOS => "tos",
            Self::PP => "privacy",
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
    format!("https://legal.tensamin.net/{}/", terms_type.to_str())
}
pub fn get_newest_link(terms_type: Type) -> String {
    format!("https://legal.tensamin.net/{}/newest/", terms_type.to_str())
}

pub async fn get_current_docs() -> Option<(Doc, Doc, Doc)> {
    let body = reqwest::get("https://legal.tensamin.net/api/current/")
        .await
        .ok()?
        .text()
        .await
        .ok()?;

    let json = json::parse(&body).ok()?;

    if let Object(eula) = &json["eula"] {
        if let Object(tos) = &json["tos"] {
            if let Object(pp) = &json["pp"] {
                Some((
                    Doc::from_json(Type::EULA, eula.clone())?,
                    Doc::from_json(Type::TOS, tos.clone())?,
                    Doc::from_json(Type::PP, pp.clone())?,
                ))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub async fn get_newest_docs() -> Option<(Doc, Doc, Doc)> {
    let body = reqwest::get("https://legal.tensamin.net/api/newest/")
        .await
        .ok()?
        .text()
        .await
        .ok()?;

    let json = json::parse(&body).ok()?;

    if let Object(eula) = &json["eula"] {
        if let Object(tos) = &json["tos"] {
            if let Object(pp) = &json["pp"] {
                Some((
                    Doc::from_json(Type::EULA, eula.clone())?,
                    Doc::from_json(Type::TOS, tos.clone())?,
                    Doc::from_json(Type::PP, pp.clone())?,
                ))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}
pub async fn get_terms(terms_type: Type) -> Option<String> {
    let body = reqwest::get(format!(
        "https://legal.tensamin.net/api/text/{}/",
        terms_type.to_str()
    ))
    .await
    .ok()?
    .text()
    .await
    .ok()?;

    Some(body)
}
