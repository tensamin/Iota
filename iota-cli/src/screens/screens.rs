use std::any::Any;

use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::{Frame, layout::Rect};

use crate::{interaction_result::InteractionResult, render_context::RenderContext};

/// All terminal input that can affect the UI. Keeping this as one type makes
/// it impossible for screens to accidentally ignore a newly supported event.
#[derive(Debug, Clone)]
pub enum UiEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Paste(String),
    Resize(u16, u16),
    App(AppEvent),
}

/// Completion of background UI work. Keeping it in the regular event stream
/// gives screens an explicit success/failure path instead of detached tasks.
#[derive(Debug, Clone)]
pub enum AppEvent {
    OpenUsers,
    OpenMetrics,
    ApplyTheme {
        theme: crate::theme::ThemeName,
        persist: bool,
    },
    SaveSettings {
        theme: crate::theme::ThemeName,
        color: crate::theme::TerminalPolicy,
        unicode: crate::theme::TerminalPolicy,
    },
    ThemeSaved(Result<(), String>),
    UsersLoaded(Result<Vec<crate::screens::users::UserEntry>, String>),
    UserCreated(Result<crate::screens::users::UserEntry, String>),
    UserRemoved {
        user_id: i64,
        result: Result<(), String>,
    },
    RegenerateKeysRequested,
    KeysRegenerated(Result<(), String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAction {
    OpenOverview,
    OpenUsers,
    OpenSettings,
    OpenMetrics,
    ToggleMetrics,
    AddUser,
    RemoveUser,
    Back,
    Quit,
    FocusLogs,
    FocusConsole,
    FocusMetrics,
    OpenMain,
    SelectUser(usize),
    ConfirmDialog,
    CancelDialog,
    RegenerateKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHint {
    pub keys: &'static str,
    pub action: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HitRegion {
    pub area: Rect,
    pub action: AppAction,
}

#[derive(Debug, Default, Clone)]
pub struct HitMap {
    regions: Vec<HitRegion>,
}

impl HitMap {
    pub fn register(&mut self, area: Rect, action: AppAction) {
        self.regions.push(HitRegion { area, action });
    }
    pub fn action_at(&self, column: u16, row: u16) -> Option<AppAction> {
        self.regions
            .iter()
            .rev()
            .find(|region| {
                column >= region.area.x
                    && column < region.area.x.saturating_add(region.area.width)
                    && row >= region.area.y
                    && row < region.area.y.saturating_add(region.area.height)
            })
            .map(|region| region.action)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavDirection {
    Up,
    Down,
    Left,
    Right,

    Next,
    Prev,
}

pub trait Screen: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn render(&self, f: &mut Frame, rect: Rect, context: &RenderContext<'_>, hits: &mut HitMap);
    fn handle_event(&mut self, event: UiEvent) -> InteractionResult;
    fn handle_action(&mut self, _action: AppAction) -> InteractionResult {
        InteractionResult::Unhandled
    }
    fn app_title(&self) -> String {
        "IOTA".to_owned()
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
