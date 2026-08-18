use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    interaction_result::InteractionResult,
    render_context::RenderContext,
    screens::screens::{HitMap, KeyHint, Screen, UiEvent},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogButton {
    Cancel,
    Confirm,
    Custom(usize),
}

pub struct ConfirmDialog {
    title: String,
    message: Vec<String>,
    buttons: Vec<DialogButtonConfig>,
    focused_button: usize,
    on_confirm: Option<Box<dyn Fn() -> InteractionResult + Send + Sync>>,
    on_cancel: Option<Box<dyn Fn() -> InteractionResult + Send + Sync>>,
}

struct DialogButtonConfig {
    label: String,
    intent: ButtonIntent,
    enabled: bool,
}

impl ConfirmDialog {
    pub fn new(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            message: vec![message.into()],
            buttons: vec![
                DialogButtonConfig {
                    label: "Cancel".to_owned(),
                    intent: ButtonIntent::Cancel,
                    enabled: true,
                },
                DialogButtonConfig {
                    label: "Confirm".to_owned(),
                    intent: ButtonIntent::Primary,
                    enabled: true,
                },
            ],
            focused_button: 0,
            on_confirm: None,
            on_cancel: None,
        }
    }

    pub fn destructive(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            message: vec![message.into()],
            buttons: vec![
                DialogButtonConfig {
                    label: "Cancel".to_owned(),
                    intent: ButtonIntent::Cancel,
                    enabled: true,
                },
                DialogButtonConfig {
                    label: "Delete".to_owned(),
                    intent: ButtonIntent::Destructive,
                    enabled: true,
                },
            ],
            focused_button: 0,
            on_confirm: None,
            on_cancel: None,
        }
    }

    pub fn with_message_line(mut self, line: impl Into<String>) -> Self {
        self.message.push(line.into());
        self
    }

    pub fn with_button(mut self, label: impl Into<String>, intent: ButtonIntent) -> Self {
        self.buttons.push(DialogButtonConfig {
            label: label.into(),
            intent,
            enabled: true,
        });
        self
    }

    pub fn with_confirm_action<F: Fn() -> InteractionResult + Send + Sync + 'static>(
        mut self,
        action: F,
    ) -> Self {
        self.on_confirm = Some(Box::new(action));
        self
    }

    pub fn with_cancel_action<F: Fn() -> InteractionResult + Send + Sync + 'static>(
        mut self,
        action: F,
    ) -> Self {
        self.on_cancel = Some(Box::new(action));
        self
    }

    fn activate(&self) -> InteractionResult {
        match self.focused_button {
            0 => {
                if let Some(action) = &self.on_cancel {
                    action()
                } else {
                    InteractionResult::CloseScreen
                }
            }
            1 => {
                if let Some(action) = &self.on_confirm {
                    action()
                } else {
                    InteractionResult::CloseScreen
                }
            }
            _ => InteractionResult::CloseScreen,
        }
    }

    fn next_button(&mut self) {
        self.focused_button = (self.focused_button + 1) % self.buttons.len();
    }

    fn prev_button(&mut self) {
        if self.focused_button == 0 {
            self.focused_button = self.buttons.len() - 1;
        } else {
            self.focused_button -= 1;
        }
    }
}

impl Screen for ConfirmDialog {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn render(&self, f: &mut Frame, rect: Rect, context: &RenderContext<'_>, _hits: &mut HitMap) {
        let area = crate::layout::fit::centered_rect(
            rect,
            crate::layout::fit::RequiredSize {
                width: 50,
                height: (self.message.len() + 8) as u16,
            },
        );

        f.render_widget(Clear, area);
        let block = Block::default()
            .title(format!(" {} ", self.title))
            .borders(Borders::ALL)
            .border_style(context.theme.borders.focused)
            .style(context.theme.surfaces.overlay);

        let inner = block.inner(area);
        f.render_widget(block, area);

        let rows = Layout::vertical([
            Constraint::Min(self.message.len() as u16),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

        let lines: Vec<Line> = self
            .message
            .iter()
            .map(|line| Line::from(Span::styled(line.as_str(), context.theme.text.normal)))
            .collect();
        f.render_widget(Paragraph::new(lines), rows[0]);

        let buttons_area = rows[2];
        let button_widths: Vec<u16> = self
            .buttons
            .iter()
            .map(|b| crate::controls::button::button_minimum_width(&b.label))
            .collect();

        let total_width: u16 = button_widths.iter().sum();
        let spacing = self.buttons.len().saturating_sub(1) as u16;
        let available = buttons_area.width;
        let start_x = buttons_area.x + available.saturating_sub(total_width + spacing) / 2;

        let mut x = start_x;
        for (i, (button_config, &width)) in self.buttons.iter().zip(&button_widths).enumerate() {
            let button_area = Rect {
                x,
                y: buttons_area.y,
                width,
                height: 1,
            };
            x = x.saturating_add(width + 1);

            render_button(
                f,
                button_area,
                ActionButton {
                    label: &button_config.label,
                    intent: button_config.intent,
                    focused: self.focused_button == i,
                    enabled: button_config.enabled,
                },
                context.theme,
            );
        }
    }

    fn handle_event(&mut self, event: UiEvent) -> InteractionResult {
        let UiEvent::Key(key) = event else {
            return InteractionResult::Unhandled;
        };
        match key.code {
            KeyCode::Esc => InteractionResult::CloseScreen,
            KeyCode::Tab => {
                self.next_button();
                InteractionResult::Handled
            }
            KeyCode::BackTab => {
                self.prev_button();
                InteractionResult::Handled
            }
            KeyCode::Left => {
                self.prev_button();
                InteractionResult::Handled
            }
            KeyCode::Right => {
                self.next_button();
                InteractionResult::Handled
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate(),
            _ => InteractionResult::Unhandled,
        }
    }

    fn key_hints(&self) -> Vec<KeyHint> {
        vec![
            KeyHint {
                keys: "Tab",
                action: "Switch button",
            },
            KeyHint {
                keys: "Enter",
                action: "Confirm",
            },
            KeyHint {
                keys: "Esc",
                action: "Cancel",
            },
        ]
    }
}
