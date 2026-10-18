use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use iota_cli::screens::terms_checker::{TermsCheckerScreen, UserChoice};
use iota_cli::ui::UiHandle;
use iota_terms::{Doc, LegalDocument, TermsType as Type, get_current_docs};
use iota_util::file_util::{load_file, save_file};
use tokio::sync::oneshot;

pub struct ConsentCheck {
    pub accepted_eula: bool,
    pub accepted_services: bool,
    pub documents: [LegalDocument; 3],
}

pub async fn check(ui: Arc<UiHandle>) -> Result<ConsentCheck, String> {
    let mut state = ConsentState::load_state();

    let documents = ensure_initial_consent(ui.clone(), &mut state).await?;
    /*
     * The raw legal endpoint exposes only the current document. Restore this
     * flow when it provides future versions that users can accept early.
     */
    // ensure_updates(ui, &mut state).await?;

    state = state.sanitize();
    state.save_state();

    Ok(ConsentCheck {
        accepted_eula: state.accepted_eula,
        accepted_services: state.accepted_tos && state.accepted_pp,
        documents,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonInteractiveConsent {
    Accepted,
    RequiresInteractiveAcceptance,
}

pub fn non_interactive_consent() -> NonInteractiveConsent {
    let state = ConsentState::load_state();
    if state.accepted_eula && state.accepted_tos && state.accepted_pp {
        NonInteractiveConsent::Accepted
    } else {
        NonInteractiveConsent::RequiresInteractiveAcceptance
    }
}

async fn ensure_initial_consent(
    ui: Arc<UiHandle>,
    state: &mut ConsentState,
) -> Result<[LegalDocument; 3], String> {
    let (current_eula, current_tos, current_privacy) = get_current_docs().await.ok_or_else(|| {
        "Could not connect to the legal endpoint to fetch the current agreements. Please check your internet connection.".to_string()
    })?;

    let current_eula_doc = current_eula.metadata();
    let current_tos_doc = current_tos.metadata();
    let current_privacy_doc = current_privacy.metadata();
    let documents = [current_eula, current_tos, current_privacy];

    if state.accepts_current_docs(&current_eula_doc, &current_tos_doc, &current_privacy_doc) {
        return Ok(documents);
    }

    // A legacy consent file records the document hashes alongside its flags.
    // Do not carry a flag forward to the durable consent record when its
    // document has changed; the user must review and accept that revision.
    state.invalidate_mismatched_consent(&current_eula_doc, &current_tos_doc, &current_privacy_doc);

    let (tx, rx) = oneshot::channel();

    ui.set_screen(Box::new(TermsCheckerScreen::new(
        Some(tx),
        documents.clone(),
    )))
    .await;

    let result = rx.await.unwrap_or(UserChoice::Deny);

    match result {
        UserChoice::AcceptEULA | UserChoice::AcceptAll => {
            state.accepted_eula = true;
            state.eula = Some(current_eula_doc);

            if matches!(result, UserChoice::AcceptAll) {
                state.accepted_tos = true;
                state.accepted_pp = true;
                state.tos = Some(current_tos_doc);
                state.privacy = Some(current_privacy_doc);
            }

            let _ = &state.save_state();
            Ok(documents)
        }
        UserChoice::Deny => Ok(documents),
    }
}
/*
async fn ensure_updates(ui: Arc<UiHandle>, state: &mut ConsentState) -> Result<(), String> {
    let Some((eula_update, tos_update, privacy_update)) = get_updates().await else {
        return Ok(());
    };

    let is_forced = matches!(eula_update, UpdateDecision::Forced(_))
        || matches!(tos_update, UpdateDecision::Forced(_))
        || matches!(privacy_update, UpdateDecision::Forced(_));

    let (tx, rx) = oneshot::channel();

    ui.set_screen(Box::new(TermsUpdaterScreen::new(
        eula_update.clone(),
        tos_update.clone(),
        privacy_update.clone(),
        Some(tx),
    )))
    .await;

    let result = rx.await.unwrap_or(UserChoice::Deny);

    if is_forced {
        match result {
            UserChoice::AcceptAll => {
                state.accepted_eula = true;
                state.accepted_tos = true;
                state.accepted_pp = true;
            }
            UserChoice::AcceptEULA => {
                state.accepted_eula = true;
            }
            UserChoice::Deny => {
                return Err("Consent update was denied for a mandatory document.".to_string());
            }
        }
    } else {
        apply_future_updates(state, result, eula_update, tos_update, privacy_update);
    }

    state.save_state();
    Ok(())
}
*/
/*
fn apply_future_updates(
    state: &mut ConsentState,
    result: UserChoice,
    eula_update: UpdateDecision,
    tos_update: UpdateDecision,
    privacy_update: UpdateDecision,
) {
    match result {
        UserChoice::AcceptAll => {
            if let UpdateDecision::Future { newest } = eula_update {
                state.future_eula = Some(newest);
            }
            if let UpdateDecision::Future { newest } = tos_update {
                state.future_tos = Some(newest);
            }
            if let UpdateDecision::Future { newest } = privacy_update {
                state.future_privacy = Some(newest);
            }
        }
        UserChoice::AcceptEULA => {
            if let UpdateDecision::Future { newest } = eula_update {
                state.future_eula = Some(newest);
            }
        }
        UserChoice::Deny => {}
    }
}

async fn get_updates() -> Option<(
    // Ok(None) indicates no update
    // Ok(Some) Indicates a future update
    // Err indicates a update that has to be accepted before the programm can continue
    UpdateDecision,
    UpdateDecision,
    UpdateDecision,
)> {
    if let (
        Some((current_eula, current_tos, current_privacy)),
        Some((newest_eula, newest_tos, newest_privacy)),
    ) = (get_current_docs().await, get_newest_docs().await)
    {
        let file = load_file("", "agreements");
        let accepted_state = ConsentState::from_str(&file).sanitize();
        save_file("", "agreements", &accepted_state.serialize());

        let eula_update: UpdateDecision = if current_eula.equals_some(&accepted_state.eula) {
            if current_eula.equals(&newest_eula) {
                UpdateDecision::NoChange
            } else {
                if newest_eula.equals_some(&accepted_state.future_eula) {
                    UpdateDecision::NoChange
                } else {
                    UpdateDecision::Future {
                        newest: newest_eula,
                    }
                }
            }
        } else if newest_eula.equals_some(&accepted_state.eula) {
            UpdateDecision::NoChange
        } else {
            UpdateDecision::Forced(current_eula)
        };

        let tos_update: UpdateDecision =
            if !accepted_state.accepted_tos || newest_tos.equals_some(&accepted_state.tos) {
                UpdateDecision::NoChange
            } else if accepted_state.accepted_tos && current_tos.equals_some(&accepted_state.tos) {
                if current_tos.equals(&newest_tos) {
                    UpdateDecision::NoChange
                } else {
                    if newest_tos.equals_some(&accepted_state.future_tos) {
                        UpdateDecision::NoChange
                    } else {
                        UpdateDecision::Future { newest: newest_tos }
                    }
                }
            } else {
                UpdateDecision::Forced(current_tos)
            };

        let privacy_update: UpdateDecision = if !accepted_state.accepted_pp
            || newest_privacy.equals_some(&accepted_state.privacy)
        {
            UpdateDecision::NoChange
        } else if accepted_state.accepted_pp && current_privacy.equals_some(&accepted_state.privacy)
        {
            if current_privacy.equals(&newest_privacy) {
                UpdateDecision::NoChange
            } else {
                if newest_privacy.equals_some(&accepted_state.future_privacy) {
                    UpdateDecision::NoChange
                } else {
                    UpdateDecision::Future {
                        newest: newest_privacy,
                    }
                }
            }
        } else {
            UpdateDecision::Forced(current_privacy)
        };
        match (&eula_update, &tos_update, &privacy_update) {
            (&UpdateDecision::NoChange, &UpdateDecision::NoChange, &UpdateDecision::NoChange) => {
                None
            }
            _ => Some((eula_update, tos_update, privacy_update)),
        }
    } else {
        None
    }
}
*/

#[derive(Debug, Clone)]
pub struct ConsentState {
    pub eula: Option<Doc>,
    pub accepted_eula: bool,
    pub future_eula: Option<Doc>,

    pub tos: Option<Doc>,
    pub accepted_tos: bool,
    pub future_tos: Option<Doc>,

    pub privacy: Option<Doc>,
    pub accepted_pp: bool,
    pub future_privacy: Option<Doc>,
}

impl ConsentState {
    fn accepts_current_docs(&self, eula: &Doc, tos: &Doc, privacy: &Doc) -> bool {
        self.accepted_eula
            && self.accepted_tos
            && self.accepted_pp
            && eula.equals_some(&self.eula)
            && tos.equals_some(&self.tos)
            && privacy.equals_some(&self.privacy)
    }

    fn invalidate_mismatched_consent(&mut self, eula: &Doc, tos: &Doc, privacy: &Doc) {
        self.accepted_eula &= eula.equals_some(&self.eula);
        self.accepted_tos &= tos.equals_some(&self.tos);
        self.accepted_pp &= privacy.equals_some(&self.privacy);
        *self = self.clone().sanitize();
    }

    fn sanitize(mut self) -> Self {
        let current_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(future_eula) = self.future_eula.clone()
            && future_eula.get_time() < current_secs
        {
            self.eula = Some(future_eula);
            self.future_eula = None;
        }
        if let Some(future_tos) = self.future_tos.clone()
            && future_tos.get_time() < current_secs
        {
            self.tos = Some(future_tos);
            self.future_tos = None;
        }
        if let Some(future_privacy) = self.future_privacy.clone()
            && future_privacy.get_time() < current_secs
        {
            self.privacy = Some(future_privacy);
            self.future_privacy = None;
        }

        if !self.accepted_eula {
            self.accepted_tos = false;
            self.accepted_pp = false;
        }
        self
    }

    pub fn load_state() -> ConsentState {
        let file = load_file("", "agreements");
        ConsentState::from_str(&file).sanitize()
    }

    pub fn save_state(&self) {
        save_file("", "agreements", &self.serialize());
    }

    fn serialize(&self) -> String {
        let current_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut file_out: String = format!(
            "This file reflects the current consent state used by the application.\
        \nIt may be regenerated or overwritten by the application.\
        \nThis file was last edited by Tensamin at:\
        \nUNIX-SECOND={}",
            current_secs
        );

        if let Some(eula) = &self.eula {
            file_out.push_str(&format!("\
            \n\"EULA=true\" indicates that you read, understood and accepted Tensamin's End User Licence agreement. You can find our EULA at https://legal.nonanium.net/tensamin/eula\
            \nEULA={}\
            \nEULA-VERSION={}\
            \nEULA-HASH={}\
            ", self.accepted_eula, eula.get_version(), eula.get_hash()));

            if self.accepted_tos
                && let Some(tos) = &self.tos
            {
                file_out.push_str(&format!("\
                \n\"Terms-of-Service=true\" indicates that you read, understood and accepted Tensamin's Terms of Service. You can find our Terms of Serivce at https://legal.nonanium.net/tensamin/terms-of-service\
                \nTerms-of-Service={}\
                \nTerms-of-Service-VERSION={}\
                \nTerms-of-Service-HASH={}\
                ", self.accepted_tos, tos.get_version(), tos.get_hash()));
            }
            if self.accepted_pp
                && let Some(pp) = &self.privacy
            {
                file_out.push_str(&format!("\
                \n\"Privacy-Policy=true\" indicates that you read, understood and accepted Tensamin's Privacy Policy. You can find our Privacy Policy at https://legal.nonanium.net/tensamin/privacy-policy\
                \nPrivacy-Policy={}\
                \nPrivacy-Policy-VERSION={}\
                \nPrivacy-Policy-HASH={}\
                ", self.accepted_pp, pp.get_version(), pp.get_hash()));
            }
        } else {
            file_out.push_str("\
                \n\"EULA=true\" indicates that you read, understood and accepted Tensamin's End User Licence Agreement. You can find Tensamin's EULA at https://legal.nonanium.net/tensamin/eula\
                \nEULA=false\
                ");
        }

        if let Some(eula) = &self.future_eula {
            file_out.push_str(&format!(
                "\
                \nFUTURE-EULA-VERSION={}\
                \nFUTURE-EULA-HASH={}\
                \nFUTURE-EULA-TIME={}\
                ",
                eula.get_version(),
                eula.get_hash(),
                eula.get_time()
            ));
        }
        if let Some(tos) = &self.future_tos {
            file_out.push_str(&format!(
                "\
                \nFUTURE-Terms-of-Service-VERSION={}\
                \nFUTURE-Terms-of-Service-HASH={}\
                \nFUTURE-Terms-of-Service-TIME={}\
                ",
                tos.get_version(),
                tos.get_hash(),
                tos.get_time()
            ));
        }
        if let Some(pp) = &self.future_privacy {
            file_out.push_str(&format!(
                "\
                \nFUTURE-Privacy-Policy-VERSION={}\
                \nFUTURE-Privacy-Policy-HASH={}\
                \nFUTURE-Privacy-Policy-TIME={}\
                ",
                pp.get_version(),
                pp.get_hash(),
                pp.get_time()
            ));
        }

        file_out
    }

    fn from_str(s: &str) -> Self {
        let mut eula = false;
        let mut eula_version = String::new();
        let mut eula_hash = String::new();
        let mut pp = false;
        let mut pp_version = String::new();
        let mut pp_hash = String::new();
        let mut tos = false;
        let mut tos_version = String::new();
        let mut tos_hash = String::new();

        let mut future_eula_version = String::new();
        let mut future_eula_hash = String::new();
        let mut future_eula_time = String::new();

        let mut future_tos_version = String::new();
        let mut future_tos_hash = String::new();
        let mut future_tos_time = String::new();

        let mut future_pp_version = String::new();
        let mut future_pp_hash = String::new();
        let mut future_pp_time = String::new();

        let mut unix = String::new();

        for line in s.lines() {
            if let Some(v) = line.strip_prefix("EULA=") {
                eula = v == "true";
            } else if let Some(v) = line.strip_prefix("EULA-VERSION=") {
                eula_version = v.to_string();
            } else if let Some(v) = line.strip_prefix("EULA-HASH=") {
                eula_hash = v.to_string();
            } else if let Some(v) = line.strip_prefix("Terms-of-Service=") {
                tos = v == "true";
            } else if let Some(v) = line.strip_prefix("Terms-of-Service-VERSION=") {
                tos_version = v.to_string();
            } else if let Some(v) = line.strip_prefix("Terms-of-Service-HASH=") {
                tos_hash = v.to_string();
            } else if let Some(v) = line.strip_prefix("Privacy-Policy=") {
                pp = v == "true";
            } else if let Some(v) = line.strip_prefix("Privacy-Policy-VERSION=") {
                pp_version = v.to_string();
            } else if let Some(v) = line.strip_prefix("Privacy-Policy-HASH=") {
                pp_hash = v.to_string();
            } else if let Some(v) = line.strip_prefix("UNIX-SECOND=") {
                unix = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-EULA-VERSION=") {
                future_eula_version = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-EULA-HASH=") {
                future_eula_hash = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-EULA-TIME=") {
                future_eula_time = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-Terms-of-Service-VERSION=") {
                future_tos_version = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-Terms-of-Service-HASH=") {
                future_tos_hash = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-Terms-of-Service-TIME=") {
                future_tos_time = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-Privacy-Policy-VERSION=") {
                future_pp_version = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-Privacy-Policy-HASH=") {
                future_pp_hash = v.to_string();
            } else if let Some(v) = line.strip_prefix("FUTURE-Privacy-Policy-TIME=") {
                future_pp_time = v.to_string();
            }
        }
        let unix: u64 = unix.parse::<u64>().unwrap_or(0);
        let future_eula_time = future_eula_time.parse::<u64>().unwrap_or(0);
        let future_tos_time = future_tos_time.parse::<u64>().unwrap_or(0);
        let future_pp_time = future_pp_time.parse::<u64>().unwrap_or(0);

        Self {
            accepted_eula: eula,
            eula: Some(Doc::new(eula_version, eula_hash, Type::EULA, unix)),
            accepted_pp: pp,
            privacy: Some(Doc::new(pp_version, pp_hash, Type::PP, unix)),
            accepted_tos: tos,
            tos: Some(Doc::new(tos_version, tos_hash, Type::TOS, unix)),
            future_eula: if !future_eula_version.is_empty() {
                Some(Doc::new(
                    future_eula_version,
                    future_eula_hash,
                    Type::EULA,
                    future_eula_time,
                ))
            } else {
                None
            },
            future_tos: if !future_tos_version.is_empty() {
                Some(Doc::new(
                    future_tos_version,
                    future_tos_hash,
                    Type::TOS,
                    future_tos_time,
                ))
            } else {
                None
            },
            future_privacy: if !future_pp_version.is_empty() {
                Some(Doc::new(
                    future_pp_version,
                    future_pp_hash,
                    Type::PP,
                    future_pp_time,
                ))
            } else {
                None
            },
        }
        .sanitize()
    }
}

#[cfg(test)]
mod tests {
    use super::ConsentState;
    use iota_terms::{Doc, TermsType as Type};

    fn doc(doc_type: Type, hash: &str) -> Doc {
        Doc::new("1".to_owned(), hash.to_owned(), doc_type, 0)
    }

    #[test]
    fn accepts_current_docs_requires_each_accepted_hash_to_match() {
        let eula = doc(Type::EULA, "eula-hash");
        let tos = doc(Type::TOS, "tos-hash");
        let privacy = doc(Type::PP, "privacy-hash");
        let state = ConsentState {
            eula: Some(eula.clone()),
            accepted_eula: true,
            future_eula: None,
            tos: Some(tos.clone()),
            accepted_tos: true,
            future_tos: None,
            privacy: Some(privacy.clone()),
            accepted_pp: true,
            future_privacy: None,
        };

        assert!(state.accepts_current_docs(&eula, &tos, &privacy));
        assert!(!state.accepts_current_docs(&doc(Type::EULA, "new-eula-hash"), &tos, &privacy));
        assert!(!state.accepts_current_docs(&eula, &doc(Type::TOS, "new-tos-hash"), &privacy));
        assert!(!state.accepts_current_docs(&eula, &tos, &doc(Type::PP, "new-privacy-hash")));
    }

    #[test]
    fn invalidating_a_mismatched_eula_revokes_dependent_consent() {
        let eula = doc(Type::EULA, "old-eula-hash");
        let tos = doc(Type::TOS, "tos-hash");
        let privacy = doc(Type::PP, "privacy-hash");
        let mut state = ConsentState {
            eula: Some(eula),
            accepted_eula: true,
            future_eula: None,
            tos: Some(tos.clone()),
            accepted_tos: true,
            future_tos: None,
            privacy: Some(privacy.clone()),
            accepted_pp: true,
            future_privacy: None,
        };

        state.invalidate_mismatched_consent(&doc(Type::EULA, "new-eula-hash"), &tos, &privacy);

        assert!(!state.accepted_eula);
        assert!(!state.accepted_tos);
        assert!(!state.accepted_pp);
    }
}
