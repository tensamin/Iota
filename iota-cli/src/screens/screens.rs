use std::{fmt, path::PathBuf};

use ratatui::{Frame, layout::Rect};

use crate::theme::{CliOutputFormat, ResolvedTheme, TerminalPolicy, ThemeName};

#[derive(Debug, Clone)]
pub enum AppEvent {
    ThemeSaved(Result<(), String>),
    UsersLoaded(Result<Vec<crate::screens::users::UserEntry>, String>),
    TuInspected(Result<iota_ipc::TuCredentialPreview, String>),
    UserOperationFinished(Result<String, String>),
    CredentialExportFinished(Result<String, String>),
    KeysRegenerated(Result<(), String>),
    TermsLoaded {
        kind: iota_terms::TermsType,
        result: Result<String, String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAction {
    OpenOverview,
    OpenUsers,
    OpenSettings,
    OpenMetrics,
    ToggleMetrics,
    AddUser,
    OpenUserGroup(crate::screens::users::model::UserActionGroup),
    SetUserAdminTab(crate::screens::users::model::UserAdminTab),
    ActivateUserAction(crate::screens::users::model::UserAction),
    Back,
    Quit,
    FocusLogs,
    FocusConsole,
    FocusMetrics,
    OpenMain,
    SelectUser(i64),
    ConfirmDialog,
    CancelDialog,
    RegenerateKeys,
}

#[derive(Clone, Debug)]
pub enum IotaEffect {
    OpenUsers,
    OpenMetrics,
    OpenOverview,
    ApplyTheme {
        theme: ThemeName,
        persist: bool,
    },
    SaveSettings {
        theme: ThemeName,
        color: TerminalPolicy,
        unicode: TerminalPolicy,
        cli_output: CliOutputFormat,
        cli_require_confirmation: bool,
    },
    RegenerateKeys,
    InspectTu {
        credential: iota_ipc::SecretString,
    },
    AttachUserFromTu {
        credential: iota_ipc::SecretString,
    },
    RunUserOperation {
        action: crate::screens::users::model::UserAction,
        user_id: i64,
    },
    ExportCredential {
        user_id: i64,
        destination: PathBuf,
    },
    CreateUser {
        username: String,
    },
    CreateInvitation {
        authority: iota_ipc::InvitationAuthority,
    },
    RefreshUsers,
    LoadNewestTerms {
        kind: iota_terms::TermsType,
    },
}

#[derive(Clone, Debug)]
pub enum IotaMessage {
    Action(AppAction),
    Effect(IotaEffect),
    Event(AppEvent),
    Invalidate,
}

pub type UiEvent = ratatool::UiEvent<IotaMessage>;
pub type HitMap = ratatool::HitMap<IotaMessage>;
pub type NavDirection = ratatool::Direction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHint {
    pub keys: &'static str,
    pub action: &'static str,
}

pub enum IotaInteraction {
    Unhandled,
    Changed,
    Push {
        screen: Box<dyn IotaScreen>,
        presentation: ratatool::ScreenPresentation,
    },
    Pop,
    Effect(IotaEffect),
    Exit,
}

impl fmt::Debug for IotaInteraction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unhandled => formatter.write_str("Unhandled"),
            Self::Changed => formatter.write_str("Changed"),
            Self::Push { presentation, .. } => {
                formatter.debug_tuple("Push").field(presentation).finish()
            }
            Self::Pop => formatter.write_str("Pop"),
            Self::Effect(effect) => formatter.debug_tuple("Effect").field(effect).finish(),
            Self::Exit => formatter.write_str("Exit"),
        }
    }
}

pub trait IotaScreen: Send {
    fn render(
        &mut self,
        ui: &mut ratatool::UiFrame<'_, '_, IotaMessage>,
        area: Rect,
        theme: &ResolvedTheme,
    ) {
        let mut hits = HitMap::new();
        self.render_legacy(ui.frame(), area, theme, &mut hits);
        for region in hits.regions() {
            ui.hit_map().register(region.area, region.action.clone());
        }
    }

    fn render_legacy(
        &self,
        frame: &mut Frame,
        area: Rect,
        theme: &ResolvedTheme,
        hits: &mut HitMap,
    );

    fn handle_event(&mut self, event: &UiEvent) -> IotaInteraction;

    fn handle_action(&mut self, _action: AppAction) -> IotaInteraction {
        IotaInteraction::Unhandled
    }

    fn key_hints(&self) -> Vec<KeyHint> {
        vec![
            KeyHint {
                keys: "Tab",
                action: "Move focus",
            },
            KeyHint {
                keys: "Enter",
                action: "Activate",
            },
            KeyHint {
                keys: "Esc",
                action: "Back",
            },
            KeyHint {
                keys: "F6",
                action: "Header",
            },
        ]
    }
}

pub fn action_message(action: AppAction) -> IotaMessage {
    IotaMessage::Action(action)
}
