use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use std::{
    any::Any,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

use crate::{
    elements::elements::{Element, InteractableElement, JoinableElement},
    interaction_result::InteractionResult,
    ipc_client::IpcClient,
    util::borders::draw_block_joins,
};

pub struct ConsoleCard {
    ipc: Arc<IpcClient>,
    focused: bool,
    pub title: String,
    pub content: String,
    pub cursor_position: usize,

    borders: Borders,
    joins: Borders,

    cursor: Arc<Mutex<bool>>,
    last_swap: Arc<Mutex<Instant>>,
    pending_restore: Arc<Mutex<Option<String>>>,
}

impl ConsoleCard {
    pub fn new(title: &str, content: &str, ipc: Arc<IpcClient>) -> Self {
        ConsoleCard {
            ipc,
            focused: false,
            title: title.to_string(),
            content: content.to_string(),
            cursor_position: content.chars().count(),
            borders: Borders::ALL,
            joins: Borders::NONE,
            cursor: Arc::new(Mutex::new(true)),
            last_swap: Arc::new(Mutex::new(Instant::now())),
            pending_restore: Arc::new(Mutex::new(None)),
        }
    }

    fn byte_index(&self) -> usize {
        self.content
            .char_indices()
            .nth(self.cursor_position)
            .map(|(i, _)| i)
            .unwrap_or(self.content.len())
    }

    fn cursor_visible(&self) -> bool {
        if !self.focused {
            return false;
        }

        let mut visible = self.cursor.lock().unwrap();
        let mut last = self.last_swap.lock().unwrap();
        let now = Instant::now();

        if now.duration_since(*last) >= Duration::from_millis(500) {
            *visible = !*visible;
            *last = now;
        }

        *visible
    }

    fn current_prefix(&self) -> Option<&str> {
        if self.content.starts_with('/') {
            Some("/")
        } else {
            None
        }
    }

    fn cursor_spans(&self) -> Vec<Span<'static>> {
        let cursor_visible = self.cursor_visible();
        let cursor_style = Style::default().fg(Color::White).bg(Color::DarkGray);
        let mut spans = Vec::new();

        if self.content.is_empty() {
            if self.focused {
                if cursor_visible {
                    spans.push(Span::styled(" ", cursor_style));
                } else {
                    spans.push(Span::styled(" ", Style::default().fg(Color::White)));
                }
                spans.push(Span::styled(
                    "send command (/help for info)",
                    Style::default().fg(Color::DarkGray),
                ));
            } else {
                spans.push(Span::styled(
                    " send command (/help for info)",
                    Style::default().fg(Color::DarkGray),
                ));
            }
            return spans;
        }

        let byte_index = self.byte_index();
        let before = self.content[..byte_index].to_string();
        let after = self.content[byte_index..].to_string();

        let prefix_len = self.current_prefix().map(|s| s.len()).unwrap_or(0);

        if prefix_len > 0 && before.len() >= prefix_len {
            let prefix = &before[..prefix_len];
            let rest = &before[prefix_len..];
            spans.push(Span::styled(
                prefix.to_string(),
                Self::style_for_part(true, false, false),
            ));
            if !rest.is_empty() {
                spans.push(Span::styled(
                    rest.to_string(),
                    Style::default().fg(Color::White),
                ));
            }
        } else if !before.is_empty() {
            spans.push(Span::styled(
                before.clone(),
                Style::default().fg(Color::White),
            ));
        }

        if cursor_visible {
            spans.push(Span::styled(" ", cursor_style));
        }

        if !after.is_empty() {
            spans.push(Span::styled(after, Style::default().fg(Color::White)));
        }

        spans
    }

    fn style_for_part(is_prefix: bool, is_hint: bool, is_error: bool) -> Style {
        if is_error {
            return Style::default().fg(Color::Red);
        }

        if is_hint {
            return Style::default().fg(Color::DarkGray);
        }

        if is_prefix {
            return Style::default().fg(Color::DarkGray);
        }

        Style::default().fg(Color::White)
    }

    fn render_cursor_spans(&self) -> Vec<Span<'static>> {
        self.cursor_spans()
    }

    fn move_cursor_left(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
        }
    }

    fn move_cursor_right(&mut self) {
        let len = self.content.chars().count();
        if self.cursor_position < len {
            self.cursor_position += 1;
        }
    }

    fn delete_at_cursor(&mut self) {
        if self.content.is_empty() || self.cursor_position == 0 {
            return;
        }

        let start = self
            .content
            .char_indices()
            .nth(self.cursor_position.saturating_sub(1))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let end = self.byte_index();
        self.content.replace_range(start..end, "");
        self.cursor_position -= 1;
    }

    fn insert_at_cursor(&mut self, c: char) {
        let idx = self.byte_index();
        self.content.insert(idx, c);
        self.cursor_position += 1;
    }
}

impl Element for ConsoleCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, r: Rect) {
        let block = Block::default()
            .borders(self.borders)
            .title(self.title.clone())
            .title_style(Style::default().fg(Color::White))
            .border_style(if self.focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            })
            .style(if self.focused {
                Style::default().fg(Color::White)
            } else {
                Style::default()
            });

        let spans = self.render_cursor_spans();
        let par = Paragraph::new(Line::from(spans))
            .block(block)
            .scroll((0, 0));
        f.render_widget(par, r);
        draw_block_joins(f, r, self.borders, self.joins);
    }
}

impl JoinableElement for ConsoleCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_element(&self) -> &(dyn Element + 'static) {
        self
    }

    fn as_element_mut(&mut self) -> &mut (dyn Element + 'static) {
        self
    }

    fn set_borders(&mut self, borders: Borders) {
        self.borders = borders;
    }

    fn set_joins(&mut self, joins: Borders) {
        self.joins = joins;
    }
}

impl InteractableElement for ConsoleCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_element(&self) -> &(dyn Element + 'static) {
        self
    }

    fn as_element_mut(&mut self) -> &mut (dyn Element + 'static) {
        self
    }

    fn interact(&mut self, key: KeyEvent) -> InteractionResult {
        // Check if a previously failed command should be restored.
        if let Some(restored) = self.pending_restore.lock().unwrap().take() {
            self.content = restored;
            self.cursor_position = self.content.chars().count();
        }

        match key.code {
            KeyCode::Enter => {
                if self.content.is_empty() {
                    return InteractionResult::Handled;
                }

                let command = self.content.clone();
                let ipc = self.ipc.clone();
                let restore = self.pending_restore.clone();
                tokio::spawn(async move {
                    if ipc.send_command(0, command.clone()).await.is_err() {
                        *restore.lock().unwrap() = Some(command);
                    }
                });

                self.content.clear();
                self.cursor_position = 0;
                InteractionResult::Handled
            }
            KeyCode::Backspace => {
                self.delete_at_cursor();
                InteractionResult::Handled
            }
            KeyCode::Delete => {
                let len = self.content.chars().count();
                if self.cursor_position < len {
                    let start = self.byte_index();
                    let end = self
                        .content
                        .char_indices()
                        .nth(self.cursor_position + 1)
                        .map(|(i, _)| i)
                        .unwrap_or(self.content.len());
                    self.content.replace_range(start..end, "");
                }
                InteractionResult::Handled
            }
            KeyCode::Left => {
                self.move_cursor_left();
                InteractionResult::Handled
            }
            KeyCode::Right => {
                self.move_cursor_right();
                InteractionResult::Handled
            }
            KeyCode::Home => {
                self.cursor_position = 0;
                InteractionResult::Handled
            }
            KeyCode::End => {
                self.cursor_position = self.content.chars().count();
                InteractionResult::Handled
            }
            KeyCode::Tab | KeyCode::BackTab => InteractionResult::Unhandled,
            _ => {
                if let Some(c) = key.code.as_char() {
                    self.insert_at_cursor(c);
                    InteractionResult::Handled
                } else {
                    InteractionResult::Unhandled
                }
            }
        }
    }

    fn can_focus(&self) -> bool {
        true
    }

    fn is_focused(&self) -> bool {
        self.focused
    }

    fn focus(&mut self, f: bool) {
        self.focused = f;
    }
}
