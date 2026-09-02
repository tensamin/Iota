#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusZone {
    Toolbar,
    Search,
    UserList,
    UserActions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAdminTab {
    Users,
    Invitations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserActionGroup {
    Hosting,
    Data,
    Credential,
    Account,
    Repair,
    Record,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAction {
    Release,
    PurgeData,
    ExportTu,
    DeleteAccount,
    Reconcile,
    Diagnostics,
    ForceDetach,
    ForgetResidency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionGroupEntry {
    pub group: UserActionGroup,
    pub actions: Vec<UserAction>,
}

use super::UserEntry;

/* Maps local daemon facts into the operator actions that are safe to present. */
pub fn available_action_groups(user: &UserEntry) -> Vec<ActionGroupEntry> {
    let mut groups = Vec::new();
    if user.state == iota_ipc::LocalUserState::Managed {
        groups.push(ActionGroupEntry {
            group: UserActionGroup::Hosting,
            actions: vec![UserAction::Release],
        });
    }
    groups.push(ActionGroupEntry {
        group: UserActionGroup::Repair,
        actions: if user.state == iota_ipc::LocalUserState::Managed {
            vec![
                UserAction::Reconcile,
                UserAction::Diagnostics,
                UserAction::ForceDetach,
            ]
        } else {
            vec![UserAction::Reconcile, UserAction::Diagnostics]
        },
    });
    if user.state == iota_ipc::LocalUserState::Released && !user.data_present {
        groups.push(ActionGroupEntry {
            group: UserActionGroup::Record,
            actions: vec![UserAction::ForgetResidency],
        });
    }
    if user.data_present {
        groups.push(ActionGroupEntry {
            group: UserActionGroup::Data,
            actions: vec![UserAction::PurgeData],
        });
    }
    if user.state == iota_ipc::LocalUserState::Managed
        && user.credential_status == iota_ipc::CredentialStatus::LocalPresent
    {
        groups.push(ActionGroupEntry {
            group: UserActionGroup::Credential,
            actions: vec![UserAction::ExportTu],
        });
    }
    if user.state == iota_ipc::LocalUserState::Managed {
        groups.push(ActionGroupEntry {
            group: UserActionGroup::Account,
            actions: vec![UserAction::DeleteAccount],
        });
    }
    groups
}

impl UserActionGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Hosting => "Hosting",
            Self::Data => "Data",
            Self::Credential => "Credential",
            Self::Account => "Account",
            Self::Repair => "Repair",
            Self::Record => "Record",
        }
    }
}
impl UserAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Release => "Release from this Iota",
            Self::PurgeData => "Purge hosted data",
            Self::ExportTu => "Export TU",
            Self::DeleteAccount => "Delete Tensamin account",
            Self::Reconcile => "Reconcile with Omega",
            Self::Diagnostics => "Diagnostics",
            Self::ForceDetach => "Force local detach",
            Self::ForgetResidency => "Forget residency record",
        }
    }

    pub fn requires_confirmation(self) -> bool {
        matches!(
            self,
            Self::Release
                | Self::PurgeData
                | Self::DeleteAccount
                | Self::ForceDetach
                | Self::ForgetResidency
        )
    }

    pub fn confirmation_label(self) -> &'static str {
        match self {
            Self::Release => "Release user",
            Self::PurgeData => "Purge data",
            Self::DeleteAccount => "Delete account",
            Self::ForceDetach => "Force detach",
            Self::ForgetResidency => "Forget record",
            Self::ExportTu => "Export TU",
            Self::Reconcile => "Reconcile",
            Self::Diagnostics => "Load diagnostics",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user(state: iota_ipc::LocalUserState, data_present: bool) -> UserEntry {
        UserEntry {
            user_id: 1,
            username: "alice".into(),
            state,
            data_present,
            credential_status: iota_ipc::CredentialStatus::LocalPresent,
            pending_operation: None,
        }
    }
    #[test]
    fn released_users_cannot_be_released() {
        assert!(
            !available_action_groups(&user(iota_ipc::LocalUserState::Released, true))
                .iter()
                .any(|entry| entry.actions.contains(&UserAction::Release))
        );
    }
    #[test]
    fn empty_data_does_not_offer_purge() {
        assert!(
            !available_action_groups(&user(iota_ipc::LocalUserState::Managed, false))
                .iter()
                .any(|entry| entry.actions.contains(&UserAction::PurgeData))
        );
    }

    #[test]
    fn released_empty_user_can_forget_but_cannot_force_detach() {
        let actions = available_action_groups(&user(iota_ipc::LocalUserState::Released, false));
        assert!(
            actions
                .iter()
                .any(|entry| entry.actions.contains(&UserAction::ForgetResidency))
        );
        assert!(
            !actions
                .iter()
                .any(|entry| entry.actions.contains(&UserAction::ForceDetach))
        );
    }

    #[test]
    fn external_credential_does_not_offer_export() {
        let mut external = user(iota_ipc::LocalUserState::Managed, true);
        external.credential_status = iota_ipc::CredentialStatus::External;

        assert!(
            !available_action_groups(&external)
                .iter()
                .any(|entry| entry.actions.contains(&UserAction::ExportTu))
        );
    }

    #[test]
    fn local_credential_offers_export_only_in_credential_group() {
        let groups = available_action_groups(&user(iota_ipc::LocalUserState::Managed, true));

        assert!(groups.iter().any(|entry| {
            entry.group == UserActionGroup::Credential
                && entry.actions.contains(&UserAction::ExportTu)
        }));
        assert!(
            groups
                .iter()
                .filter(|entry| entry.group != UserActionGroup::Credential)
                .all(|entry| !entry.actions.contains(&UserAction::ExportTu))
        );
    }

    #[test]
    fn only_lifecycle_mutations_require_confirmation() {
        assert!(UserAction::Release.requires_confirmation());
        assert!(UserAction::PurgeData.requires_confirmation());
        assert!(UserAction::DeleteAccount.requires_confirmation());
        assert!(UserAction::ForceDetach.requires_confirmation());
        assert!(UserAction::ForgetResidency.requires_confirmation());
        assert!(!UserAction::Reconcile.requires_confirmation());
        assert!(!UserAction::Diagnostics.requires_confirmation());
        assert!(!UserAction::ExportTu.requires_confirmation());
    }
}
