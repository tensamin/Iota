use crate::controls::{
    menu::{MenuItem, MenuState},
    text_input::TextInput,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddUserMethod {
    Invitation,
    CreateLocal,
    ImportTu,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddUserPhase {
    ChooseMethod,
    ConfigureCreate,
    ConfigureImport,
    ConfigureInvitation,
    InspectingTu,
    ReviewImport,
    Pending,
    Result,
}

#[derive(Debug, Clone)]
pub struct AddUserFlow {
    pub phase: AddUserPhase,
    pub methods: MenuState<AddUserMethod>,
    pub username: TextInput,
    pub import_path: TextInput,
    pub credential: Option<iota_ipc::SecretString>,
    pub preview: Option<iota_ipc::TuCredentialPreview>,
    pub error: Option<String>,
}

impl AddUserFlow {
    pub fn new(invitation_supported: bool, tu_inspection_supported: bool) -> Self {
        Self {
            phase: AddUserPhase::ChooseMethod,
            methods: MenuState::new(vec![
                MenuItem {
                    label: "Share an invitation".into(),
                    description: Some("Not supported by the connected daemon".into()),
                    value: AddUserMethod::Invitation,
                    enabled: invitation_supported,
                    disabled_reason: Some("Not supported by the connected daemon".into()),
                },
                MenuItem {
                    label: "Create user on this Iota".into(),
                    description: None,
                    value: AddUserMethod::CreateLocal,
                    enabled: true,
                    disabled_reason: None,
                },
                MenuItem {
                    label: "Import existing user from TU".into(),
                    description: None,
                    value: AddUserMethod::ImportTu,
                    enabled: tu_inspection_supported,
                    disabled_reason: (!tu_inspection_supported)
                        .then(|| "TU inspection is not supported by the connected daemon".into()),
                },
            ]),
            username: TextInput::new("Username"),
            import_path: TextInput::new("TU path"),
            credential: None,
            preview: None,
            error: None,
        }
    }
    pub fn choose(&mut self) {
        self.phase = match self.methods.selected_item().map(|item| item.value) {
            Some(AddUserMethod::CreateLocal) => AddUserPhase::ConfigureCreate,
            Some(AddUserMethod::ImportTu) => AddUserPhase::ConfigureImport,
            Some(AddUserMethod::Invitation) => AddUserPhase::ConfigureInvitation,
            None => AddUserPhase::ChooseMethod,
        };
    }
    pub fn inspection_succeeded(&mut self, preview: iota_ipc::TuCredentialPreview) {
        self.preview = Some(preview);
        self.error = None;
        self.phase = AddUserPhase::ReviewImport;
    }
    pub fn inspection_failed(&mut self, error: String) {
        self.preview = None;
        self.error = Some(error);
        self.phase = AddUserPhase::ConfigureImport;
    }
    pub fn attachment_started(&mut self) {
        self.phase = AddUserPhase::Pending;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invitation_is_disabled_without_capability() {
        let flow = AddUserFlow::new(false, false);
        assert!(!flow.methods.items()[0].enabled);
    }

    #[test]
    fn create_and_import_have_distinct_configuration_phases() {
        let mut flow = AddUserFlow::new(false, true);
        flow.choose();
        assert_eq!(flow.phase, AddUserPhase::ConfigureCreate);
        flow.phase = AddUserPhase::ChooseMethod;
        flow.methods.move_next();
        flow.choose();
        assert_eq!(flow.phase, AddUserPhase::ConfigureImport);
    }

    #[test]
    fn inspection_result_controls_import_review() {
        let mut flow = AddUserFlow::new(false, true);
        flow.inspection_succeeded(iota_ipc::TuCredentialPreview {
            user_id: 42,
            username: "alice".into(),
            assigned_iota_id: None,
        });
        assert_eq!(flow.phase, AddUserPhase::ReviewImport);
        flow.inspection_failed("invalid credential".into());
        assert_eq!(flow.phase, AddUserPhase::ConfigureImport);
        assert_eq!(flow.error.as_deref(), Some("invalid credential"));
    }
}
