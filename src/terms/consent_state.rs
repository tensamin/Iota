use tokio::sync::oneshot;

use crate::{
    gui::{
        screens::{terms_checker::TermsCheckerScreen, terms_updater::TermsUpdaterScreen},
        ui::UI,
    },
    terms::{
        doc::Doc,
        terms_getter::{Type, get_current_docs, get_newest_docs},
    },
    util::file_util::{load_file, save_file},
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check(ui: Arc<UI>) -> (bool, bool) {
    let mut state = ConsentState::load_state();

    if ensure_initial_consent(ui.clone(), &mut state)
        .await
        .is_err()
    {
        return (false, false);
    }
    if ensure_updates(ui, &mut state).await.is_err() {
        return (false, false);
    };

    state = state.sanitize();
    state.save_state();

    (state.accepted_eula, state.accepted_tos && state.accepted_pp)
}

async fn ensure_initial_consent(ui: Arc<UI>, state: &mut ConsentState) -> Result<(), ()> {
    if state.accepted_eula {
        return Ok(());
    }

    let (tx, rx) = oneshot::channel();

    ui.set_screen(Box::new(TermsCheckerScreen::new(ui.clone(), Some(tx))))
        .await;

    let result = rx.await.unwrap_or(UserChoice::Deny);

    match result {
        UserChoice::AcceptEULA | UserChoice::AcceptAll => {
            if let Some((eula, tos, privacy)) = get_current_docs().await {
                state.accepted_eula = true;
                state.eula = Some(eula);

                if matches!(result, UserChoice::AcceptAll) {
                    state.accepted_tos = true;
                    state.accepted_pp = true;
                    state.tos = Some(tos);
                    state.privacy = Some(privacy);
                }
            }

            let _ = &state.save_state();
            Ok(())
        }
        UserChoice::Deny => Err(()),
    }
}
async fn ensure_updates(ui: Arc<UI>, state: &mut ConsentState) -> Result<(), ()> {
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
            UserChoice::Deny => return Err(()),
        }
    } else {
        apply_future_updates(state, result, eula_update, tos_update, privacy_update);
    }

    state.save_state();
    Ok(())
}
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
        save_file("", "agreements", &accepted_state.to_string());

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserChoice {
    Deny,
    AcceptEULA,
    AcceptAll,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateDecision {
    NoChange,
    Future { newest: Doc },
    Forced(Doc),
}

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
    fn sanitize(mut self) -> Self {
        let current_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(future_eula) = self.future_eula.clone() {
            if future_eula.get_time() < current_secs {
                self.eula = Some(future_eula);
                self.future_eula = None;
            }
        }
        if let Some(future_tos) = self.future_tos.clone() {
            if future_tos.get_time() < current_secs {
                self.tos = Some(future_tos);
                self.future_tos = None;
            }
        }
        if let Some(future_privacy) = self.future_privacy.clone() {
            if future_privacy.get_time() < current_secs {
                self.privacy = Some(future_privacy);
                self.future_privacy = None;
            }
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
        save_file("", "agreements", &self.to_string());
    }

    fn to_string(&self) -> String {
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
            \n\"EULA=true\" indicates that you read, understood and accepted Tensamin's End User Licence agreement. You can find our EULA at https://legal.tensamin.net/eula/\
            \nEULA={}\
            \nEULA-VERSION={}\
            \nEULA-HASH={}\
            ", self.accepted_eula, eula.get_version(), eula.get_hash()));

            if self.accepted_tos
                && let Some(tos) = &self.tos
            {
                file_out.push_str(&format!("\
                \n\"Terms-of-Service=true\" indicates that you read, understood and accepted Tensamin's Terms of Service. You can find our Terms of Serivce at https://legal.tensamin.net/tos/\
                \nTerms-of-Service={}\
                \nTerms-of-Service-VERSION={}\
                \nTerms-of-Service-HASH={}\
                ", self.accepted_tos, tos.get_version(), tos.get_hash()));
            }
            if self.accepted_pp
                && let Some(pp) = &self.privacy
            {
                file_out.push_str(&format!("\
                \n\"Privacy-Policy=true\" indicates that you read, understood and accepted Tensamin's Privacy Policy. You can find our Privacy Policy at https://legal.tensamin.net/privacy/\
                \nPrivacy-Policy={}\
                \nPrivacy-Policy-VERSION={}\
                \nPrivacy-Policy-HASH={}\
                ", self.accepted_pp, pp.get_version(), pp.get_hash()));
            }
        } else {
            file_out.push_str("\
                \n\"EULA=true\" indicates that you read, understood and accepted Tensamin's End User Licence Agreement. You can find Tensamin's EULA at https://legal.tensamin.net/eula/\
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
        let state = Self {
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
        .sanitize();

        state
    }
}
