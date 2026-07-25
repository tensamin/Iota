use crate::{
    controls::{
        button::{ActionButton, ButtonIntent, render_button},
        choice::{ChoiceKind, render_choice_line},
        radio_group::{RadioGroup, RadioItem},
    },
    interaction_result::InteractionResult,
    render_context::RenderContext,
    screens::screens::{HitMap, Screen, UiEvent},
};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::any::Any;
use tokio::sync::oneshot;

/// Kept on screen while the launcher waits for the daemon's IPC hello.  The
/// setup choice screen is intentionally closed before its decision is sent,
/// so without this the terminal would otherwise be blank during startup.
pub struct DaemonStartingScreen;
impl Screen for DaemonStartingScreen {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn render(&self, frame: &mut Frame, area: Rect, context: &RenderContext<'_>, _hits: &mut HitMap) {
        let popup = crate::layout::fit::centered_rect(
            area,
            crate::layout::fit::RequiredSize {
                width: 48,
                height: 5,
            },
        );
        frame.render_widget(
            Paragraph::new(
                "Starting iota-daemon…\nWaiting for its IPC handshake.\nPress Ctrl+C to cancel.",
            )
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .title(" Iota daemon ")
                    .borders(Borders::ALL)
                    .border_style(context.theme.borders.normal),
            ),
            popup,
        );
    }
    fn handle_event(&mut self, _: UiEvent) -> InteractionResult {
        InteractionResult::Handled
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonLaunchMode {
    Once,
    WithUi,
    WithSystem,
}
#[derive(Debug, Clone)]
pub struct LaunchOption {
    pub mode: DaemonLaunchMode,
    pub enabled: bool,
    pub reason: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonSetupDecision {
    Start(DaemonLaunchMode),
    Exit,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Options,
    Exit,
    Action,
}

/// The launcher owns the actual side effects.  This screen only presents the
/// capabilities discovered for this machine, keeping disabled choices visible.
pub struct DaemonSetupScreen {
    choices: RadioGroup<DaemonLaunchMode>,
    focus: Focus,
    sender: Option<oneshot::Sender<DaemonSetupDecision>>,
    message: String,
}
impl DaemonSetupScreen {
    pub fn new(
        options: Vec<LaunchOption>,
        message: impl Into<String>,
        sender: oneshot::Sender<DaemonSetupDecision>,
    ) -> Result<Self, crate::controls::radio_group::RadioGroupError> {
        let items: Vec<RadioItem<DaemonLaunchMode>> = options
            .into_iter()
            .map(|o| RadioItem {
                value: o.mode,
                label: match o.mode {
                    DaemonLaunchMode::Once => "Start once",
                    DaemonLaunchMode::WithUi => "Start with Iota UI",
                    DaemonLaunchMode::WithSystem => "Start with the system",
                }
                .into(),
                description: o.reason,
                enabled: o.enabled,
                disabled_reason: None,
            })
            .collect();
        let default = items
            .iter()
            .find(|item| item.enabled)
            .map(|item| item.value)
            .ok_or(crate::controls::radio_group::RadioGroupError::NoEnabledItems)?;
        let mut choices = RadioGroup::new(items, None, default)?;
        choices.set_focus_policy(crate::controls::navigation::DisabledFocusPolicy::Include);
        Ok(Self {
            choices,
            focus: Focus::Options,
            sender: Some(sender),
            message: message.into(),
        })
    }
    fn complete(&mut self, d: DaemonSetupDecision) {
        if let Some(tx) = self.sender.take() {
            let _ = tx.send(d);
        }
    }
    fn activate(&mut self) -> InteractionResult {
        match self.focus {
            Focus::Options => {
                self.choices.select_focused();
                InteractionResult::Handled
            }
            Focus::Exit => {
                self.complete(DaemonSetupDecision::Exit);
                InteractionResult::CloseScreen
            }
            Focus::Action => {
                let choice = *self.choices.selected();
                if self
                    .choices
                    .items()
                    .iter()
                    .find(|i| i.value == choice)
                    .is_some_and(|i| i.enabled)
                {
                    self.complete(DaemonSetupDecision::Start(choice));
                    InteractionResult::CloseScreen
                } else {
                    InteractionResult::Handled
                }
            }
        }
    }
    fn next(&mut self) {
        self.focus = match self.focus {
            Focus::Options => {
                self.choices.focus_next();
                if self.choices.focused_item().value == DaemonLaunchMode::Once {
                    Focus::Exit
                } else {
                    Focus::Options
                }
            }
            Focus::Exit => Focus::Action,
            Focus::Action => Focus::Options,
        };
    }
    fn previous(&mut self) {
        self.focus = match self.focus {
            Focus::Options => {
                self.choices.focus_previous();
                if self.choices.focused_item().value == DaemonLaunchMode::WithSystem {
                    Focus::Action
                } else {
                    Focus::Options
                }
            }
            Focus::Exit => Focus::Options,
            Focus::Action => Focus::Exit,
        };
    }
}
impl Screen for DaemonSetupScreen {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn render(&self, frame: &mut Frame, area: Rect, context: &RenderContext<'_>, _hits: &mut HitMap) {
        let popup = crate::layout::fit::centered_rect(
            area,
            crate::layout::fit::RequiredSize {
                width: 68,
                height: 16,
            },
        );
        let mut lines = vec![Line::from(self.message.as_str()), Line::from("")];
        for item in self.choices.items() {
            lines.push(render_choice_line(
                &item.label,
                ChoiceKind::Radio,
                self.choices.visual_state(&item.value),
                context.theme,
            ));
            if let Some(reason) = &item.description {
                lines.push(Line::styled(
                    format!("    {reason}"),
                    context.theme.text.muted,
                ));
            }
        }
        let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(popup);
        frame.render_widget(
            Paragraph::new(Text::from(lines))
                .wrap(Wrap { trim: true })
                .block(
                    Block::default()
                        .title(" Iota daemon setup ")
                        .borders(Borders::ALL),
                ),
            rows[0],
        );
        let b = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);
        render_button(
            frame,
            b[0],
            ActionButton {
                label: "Exit",
                intent: ButtonIntent::Cancel,
                focused: self.focus == Focus::Exit,
                enabled: true,
            },
            context.theme,
        );
        let selected = *self.choices.selected();
        let enabled = self
            .choices
            .items()
            .iter()
            .find(|i| i.value == selected)
            .is_some_and(|i| i.enabled);
        let label = match selected {
            DaemonLaunchMode::Once => "Start once",
            DaemonLaunchMode::WithUi => "Save and start",
            DaemonLaunchMode::WithSystem => "Configure and start",
        };
        render_button(
            frame,
            b[1],
            ActionButton {
                label,
                intent: if enabled {
                    ButtonIntent::Primary
                } else {
                    ButtonIntent::Destructive
                },
                focused: self.focus == Focus::Action,
                enabled,
            },
            context.theme,
        );
    }
    fn handle_event(&mut self, event: UiEvent) -> InteractionResult {
        let UiEvent::Key(event) = event else { return InteractionResult::Unhandled; };
        match event.code {
            KeyCode::Esc => {
                self.complete(DaemonSetupDecision::Exit);
                InteractionResult::CloseScreen
            }
            KeyCode::Down | KeyCode::Right | KeyCode::Tab => {
                self.next();
                InteractionResult::Handled
            }
            KeyCode::Up | KeyCode::Left | KeyCode::BackTab => {
                self.previous();
                InteractionResult::Handled
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate(),
            _ => InteractionResult::Unhandled,
        }
    }
}
