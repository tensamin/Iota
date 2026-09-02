use super::{UserEntry, model::UserActionGroup};
pub fn state_label(user: &UserEntry) -> &'static str {
    match user.state {
        iota_ipc::LocalUserState::Managed => "Managed",
        iota_ipc::LocalUserState::Released => "Released",
    }
}
pub fn group_label(group: UserActionGroup) -> &'static str {
    group.label()
}

pub fn credential_status_label(status: iota_ipc::CredentialStatus) -> &'static str {
    match status {
        iota_ipc::CredentialStatus::LocalPresent => "Local",
        iota_ipc::CredentialStatus::External => "External",
        iota_ipc::CredentialStatus::Missing => "Missing",
        iota_ipc::CredentialStatus::None => "None",
    }
}

pub fn pending_operation_label(operation: &iota_ipc::UserOperationSummary) -> String {
    let kind = match operation.operation {
        iota_ipc::UserOperationKind::Create => "Create",
        iota_ipc::UserOperationKind::Attach => "Attach",
        iota_ipc::UserOperationKind::Release => "Release",
        iota_ipc::UserOperationKind::Purge => "Purge",
    };
    format!("{kind} ({})", operation.phase)
}
