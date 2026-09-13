use super::model::{UserAction, UserActionGroup};
use ratatool::{MenuItem, MenuState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserActionMenu {
    pub group: UserActionGroup,
    pub menu: MenuState<UserAction>,
}
impl UserActionMenu {
    pub fn new(
        group: UserActionGroup,
        actions: Vec<UserAction>,
        credential_export_supported: bool,
    ) -> Self {
        Self {
            group,
            menu: MenuState::new(
                actions
                    .into_iter()
                    .map(|action| {
                        let enabled = action != UserAction::ExportTu || credential_export_supported;
                        MenuItem {
                            label: action.label().into(),
                            description: None,
                            value: action,
                            enabled,
                            disabled_reason: (!enabled)
                                .then(|| "Not supported by connected daemon".into()),
                        }
                    })
                    .collect(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_is_disabled_without_daemon_capability() {
        let menu = UserActionMenu::new(
            UserActionGroup::Credential,
            vec![UserAction::ExportTu],
            false,
        );

        assert!(menu.menu.selected_item().is_none());
        assert!(!menu.menu.items()[0].enabled);
    }

    #[test]
    fn export_is_enabled_with_daemon_capability() {
        let menu = UserActionMenu::new(
            UserActionGroup::Credential,
            vec![UserAction::ExportTu],
            true,
        );

        assert_eq!(
            menu.menu.selected_item().map(|item| item.value),
            Some(UserAction::ExportTu)
        );
    }
}
