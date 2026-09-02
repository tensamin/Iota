use super::{UserEntry, model::UserAction};
#[derive(Debug, Clone)]
pub struct UserConfirmation {
    pub user: UserEntry,
    pub action: UserAction,
}
impl UserConfirmation {
    pub fn title(&self) -> &'static str {
        match self.action {
            UserAction::Release => "Release user",
            UserAction::PurgeData => "Purge hosted data",
            UserAction::ExportTu => "Export TU",
            UserAction::DeleteAccount => "Delete Tensamin account",
            UserAction::Reconcile => "Reconcile with Omega",
            UserAction::Diagnostics => "User diagnostics",
            UserAction::ForceDetach => "Force local detach",
            UserAction::ForgetResidency => "Forget residency record",
        }
    }
    pub fn message(&self) -> String {
        match self.action {
            UserAction::Release => format!(
                "Stop managing {} on this Iota?\nHosted data is retained. Local credentials are removed.",
                self.user.username
            ),
            UserAction::PurgeData => format!(
                "Delete hosted data for {}?\nThe account and Iota assignment are retained.",
                self.user.username
            ),
            UserAction::ExportTu => format!("Export the local TU for {}?", self.user.username),
            UserAction::DeleteAccount => format!(
                "Delete the Tensamin account {}?\nHosted data erasure is requested.",
                self.user.username
            ),
            UserAction::Reconcile => {
                format!("Compare {} with its Omega assignment?", self.user.username)
            }
            UserAction::Diagnostics => {
                format!("Load local diagnostics for {}?", self.user.username)
            }
            UserAction::ForceDetach => format!(
                "Force local detach for {}?\nOmega assignment will not be changed. Hosted data is retained.",
                self.user.username
            ),
            UserAction::ForgetResidency => format!(
                "Forget the released residency record for {}?\nThis is allowed only when hosted data is empty.",
                self.user.username
            ),
        }
    }

    pub fn confirm_label(&self) -> &'static str {
        self.action.confirmation_label()
    }
}
