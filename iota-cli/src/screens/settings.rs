use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::theme::ResolvedTheme;
use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    screens::screens::{
        AppAction, AppEvent, HitMap, IotaEffect, IotaInteraction, IotaMessage, IotaScreen, KeyHint,
        UiEvent,
    },
    theme::{CliOutputFormat, TerminalPolicy, ThemeName, UiConfig},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Theme,
    CliOutput,
    CliConfirm,
    RegenerateKeys,
    Back,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialog {
    ConfirmRegenerateKeys,
}

pub struct SettingsScreen {
    selected: usize,
    saved: ThemeName,
    message: String,
    color: TerminalPolicy,
    unicode: TerminalPolicy,
    cli_output: CliOutputFormat,
    cli_require_confirmation: bool,
    focus: Focus,
    dialog: Option<Dialog>,
    pending: bool,
}

impl SettingsScreen {
    pub fn new(current: ThemeName) -> Self {
        let selected = ThemeName::ALL
            .iter()
            .position(|theme| *theme == current)
            .unwrap_or(0);
        let config = UiConfig::load_or_default();
        Self {
            selected,
            saved: current,
            message: "Left/Right previews. Enter saves.".into(),
            color: config.color,
            unicode: config.unicode,
            cli_output: config.cli_output,
            cli_require_confirmation: config.cli_require_confirmation,
            focus: Focus::Theme,
            dialog: None,
            pending: false,
        }
    }

    fn selected_theme(&self) -> ThemeName {
        ThemeName::ALL[self.selected]
    }

    fn apply(&self, persist: bool) -> IotaInteraction {
        let theme = self.selected_theme();
        IotaInteraction::Effect(IotaEffect::ApplyTheme { theme, persist })
    }

    fn next_policy(policy: TerminalPolicy) -> TerminalPolicy {
        match policy {
            TerminalPolicy::Auto => TerminalPolicy::Always,
            TerminalPolicy::Always => TerminalPolicy::Never,
            TerminalPolicy::Never => TerminalPolicy::Auto,
        }
    }

    fn next_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Theme => Focus::CliOutput,
            Focus::CliOutput => Focus::CliConfirm,
            Focus::CliConfirm => Focus::RegenerateKeys,
            Focus::RegenerateKeys => Focus::Back,
            Focus::Back => Focus::Theme,
        };
    }

    fn prev_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Theme => Focus::Back,
            Focus::Back => Focus::RegenerateKeys,
            Focus::RegenerateKeys => Focus::CliConfirm,
            Focus::CliConfirm => Focus::CliOutput,
            Focus::CliOutput => Focus::Theme,
        };
    }

    fn activate(&mut self) -> IotaInteraction {
        if self.pending {
            return IotaInteraction::Changed;
        }
        if let Some(dialog) = self.dialog.take() {
            match dialog {
                Dialog::ConfirmRegenerateKeys => {
                    self.pending = true;
                    self.message = "Regenerating keys…".into();
                    return IotaInteraction::Effect(IotaEffect::RegenerateKeys);
                }
            }
        }
        match self.focus {
            Focus::Theme => {
                self.message = "Saving theme…".into();
            }
            Focus::CliOutput => {
                self.message = "Output format updated.".into();
                return IotaInteraction::Changed;
            }
            Focus::CliConfirm => {
                self.cli_require_confirmation = !self.cli_require_confirmation;
                self.message = format!(
                    "Confirm: {}",
                    if self.cli_require_confirmation {
                        "On"
                    } else {
                        "Off"
                    },
                );
                return IotaInteraction::Changed;
            }
            Focus::RegenerateKeys => {
                self.dialog = Some(Dialog::ConfirmRegenerateKeys);
                return IotaInteraction::Changed;
            }
            Focus::Back => return IotaInteraction::Pop,
        }
        let theme = self.selected_theme();
        let color = self.color;
        let unicode = self.unicode;
        let cli_output = self.cli_output;
        let cli_require_confirmation = self.cli_require_confirmation;
        IotaInteraction::Effect(IotaEffect::SaveSettings {
            theme,
            color,
            unicode,
            cli_output,
            cli_require_confirmation,
        })
    }
}

impl IotaScreen for SettingsScreen {
    fn render_legacy(
        &self,
        frame: &mut Frame,
        area: Rect,
        theme: &ResolvedTheme,
        hits: &mut HitMap,
    ) {
        let header_block = Block::default()
            .title(" Settings ")
            .borders(Borders::ALL)
            .border_style(theme.borders.focused);
        let inner = header_block.inner(area);
        frame.render_widget(header_block, area);

        let sections = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).split(inner);

        frame.render_widget(
            Paragraph::new(format!(
                "Theme: < {} >{}\nColor: {:?} (C)   Unicode: {:?} (U)",
                self.selected_theme(),
                if self.selected_theme() == self.saved {
                    "  [saved]"
                } else {
                    "  [preview]"
                },
                self.color,
                self.unicode,
            ))
            .style(theme.text.heading),
            sections[0],
        );

        let cli_line = format!(
            "CLI output: {:?} (L)   Confirm: {} (K)",
            self.cli_output,
            if self.cli_require_confirmation {
                "required"
            } else {
                "disabled"
            },
        );

        let bottom_rows =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(sections[1]);

        let lines = vec![
            Line::from(Span::styled(&self.message, theme.text.normal)),
            Line::from(Span::styled(&cli_line, theme.text.normal)),
            Line::from("Preview"),
            Line::from("[OK] Healthy"),
            Line::from("[WARN] Degraded"),
            Line::from("[FAIL] Failed"),
            Line::from("> Focused action <"),
        ];
        frame.render_widget(
            Paragraph::new(lines).style(theme.text.normal),
            bottom_rows[0],
        );

        let buttons_area = Layout::horizontal([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(bottom_rows[1]);

        render_button(
            frame,
            buttons_area[0],
            ActionButton {
                label: "Back",
                intent: ButtonIntent::Cancel,
                focused: self.focus == Focus::Back && self.dialog.is_none(),
                enabled: true,
            },
            theme,
        );
        hits.register(buttons_area[0], IotaMessage::Action(AppAction::Back));

        render_button(
            frame,
            buttons_area[1],
            ActionButton {
                label: "Regenerate Keys",
                intent: ButtonIntent::Destructive,
                focused: self.focus == Focus::RegenerateKeys && self.dialog.is_none(),
                enabled: !self.pending,
            },
            theme,
        );
        hits.register(
            buttons_area[1],
            IotaMessage::Action(AppAction::RegenerateKeys),
        );

        if self.dialog.is_some() {
            frame.render_widget(Block::default().style(theme.surfaces.overlay), area);
            let popup = ratatool::layout::centered_rect(
                area,
                ratatool::layout::RequiredSize {
                    width: 42,
                    height: 7,
                },
            );
            let block = Block::default()
                .title(" Confirm ")
                .borders(Borders::ALL)
                .border_style(theme.borders.focused)
                .style(theme.surfaces.overlay);
            let popup_inner = block.inner(popup);
            frame.render_widget(block, popup);
            let dialog_rows =
                Layout::vertical([Constraint::Min(2), Constraint::Length(1)]).split(popup_inner);
            frame.render_widget(
                Paragraph::new("Regenerate the identity key pair?\nThis will rotate keys and reconnect to Omikron.").style(theme.text.normal),
                dialog_rows[0],
            );
            let dialog_buttons =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(dialog_rows[1]);
            render_button(
                frame,
                dialog_buttons[0],
                ActionButton {
                    label: "Cancel",
                    intent: ButtonIntent::Cancel,
                    focused: false,
                    enabled: true,
                },
                theme,
            );
            render_button(
                frame,
                dialog_buttons[1],
                ActionButton {
                    label: "Regenerate",
                    intent: ButtonIntent::Destructive,
                    focused: true,
                    enabled: true,
                },
                theme,
            );
            hits.register(
                dialog_buttons[0],
                IotaMessage::Action(AppAction::CancelDialog),
            );
            hits.register(
                dialog_buttons[1],
                IotaMessage::Action(AppAction::ConfirmDialog),
            );
        }
    }

    fn handle_event(&mut self, event: &UiEvent) -> IotaInteraction {
        let event = event.clone();
        let event = match event {
            UiEvent::Message(IotaMessage::Event(AppEvent::ThemeSaved(result))) => {
                match result {
                    Ok(()) => {
                        self.saved = self.selected_theme();
                        self.message = "Theme saved to ui.yaml.".into();
                    }
                    Err(error) => self.message = error,
                }
                return IotaInteraction::Changed;
            }
            UiEvent::Message(IotaMessage::Event(AppEvent::KeysRegenerated(result))) => {
                self.pending = false;
                self.dialog = None;
                match result {
                    Ok(()) => self.message = "Keys regenerated successfully.".into(),
                    Err(error) => self.message = error,
                }
                return IotaInteraction::Changed;
            }
            event => event,
        };

        if self.dialog.is_some() {
            let UiEvent::Key(key) = event else {
                return IotaInteraction::Unhandled;
            };
            return match key.code {
                KeyCode::Esc => {
                    self.dialog = None;
                    IotaInteraction::Changed
                }
                KeyCode::Enter => self.activate(),
                _ => IotaInteraction::Changed,
            };
        }

        let UiEvent::Key(key) = event else {
            return IotaInteraction::Unhandled;
        };
        match key.code {
            KeyCode::Left => {
                if self.focus == Focus::Theme {
                    self.selected = self.selected.saturating_sub(1);
                    self.apply(false)
                } else {
                    IotaInteraction::Changed
                }
            }
            KeyCode::Right => {
                if self.focus == Focus::Theme {
                    self.selected = (self.selected + 1).min(ThemeName::ALL.len() - 1);
                    self.apply(false)
                } else {
                    IotaInteraction::Changed
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate(),
            KeyCode::Tab => {
                self.next_focus();
                IotaInteraction::Changed
            }
            KeyCode::BackTab => {
                self.prev_focus();
                IotaInteraction::Changed
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.color = Self::next_policy(self.color);
                IotaInteraction::Changed
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                self.unicode = Self::next_policy(self.unicode);
                IotaInteraction::Changed
            }
            KeyCode::Char('l') | KeyCode::Char('L') => {
                self.cli_output = self.cli_output.next();
                self.message = format!("CLI output: {:?}", self.cli_output);
                IotaInteraction::Changed
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                self.cli_require_confirmation = !self.cli_require_confirmation;
                self.message = format!(
                    "CLI confirm: {}",
                    if self.cli_require_confirmation {
                        "On"
                    } else {
                        "Off"
                    },
                );
                IotaInteraction::Changed
            }
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => IotaInteraction::Pop,
            _ => IotaInteraction::Unhandled,
        }
    }

    fn handle_action(&mut self, action: AppAction) -> IotaInteraction {
        match action {
            AppAction::Back => IotaInteraction::Pop,
            AppAction::RegenerateKeys => {
                self.focus = Focus::RegenerateKeys;
                self.activate()
            }
            AppAction::ConfirmDialog if self.dialog.is_some() => self.activate(),
            AppAction::CancelDialog if self.dialog.is_some() => {
                self.dialog = None;
                IotaInteraction::Changed
            }
            _ => IotaInteraction::Unhandled,
        }
    }

    fn key_hints(&self) -> Vec<KeyHint> {
        if self.dialog.is_some() {
            vec![
                KeyHint {
                    keys: "Enter",
                    action: "Confirm",
                },
                KeyHint {
                    keys: "Esc",
                    action: "Cancel",
                },
            ]
        } else {
            vec![
                KeyHint {
                    keys: "Left/Right",
                    action: "Preview theme",
                },
                KeyHint {
                    keys: "Enter",
                    action: "Save/Activate",
                },
                KeyHint {
                    keys: "Tab",
                    action: "Move focus",
                },
                KeyHint {
                    keys: "C/U",
                    action: "Color/Unicode",
                },
                KeyHint {
                    keys: "L/K",
                    action: "CLI Out/Confirm",
                },
                KeyHint {
                    keys: "Esc/B",
                    action: "Back",
                },
            ]
        }
    }
}
