use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use ttp_core::{CommunicationType, CommunicationValue};
use uuid::Uuid;

use crate::{
    ACTIVE_TASKS, RELOAD, SHUTDOWN,
    gui::{
        elements::elements::{Element, InteractableElement, JoinableElement},
        interaction_result::InteractionResult,
        ui::FPS,
        util::borders::draw_block_joins,
    },
    log, log_command, log_cv,
    omikron::omikron_connection::OMIKRON_CONNECTION,
    users::{user_manager, user_profile::UserProfile},
    util::file_util,
};
use std::{
    any::Any,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

pub struct ConsoleCard {
    focused: bool,
    pub title: String,
    pub content: String,
    pub cursor_position: usize,

    borders: Borders,
    joins: Borders,

    cursor: Arc<Mutex<bool>>,
    last_swap: Arc<Mutex<Instant>>,
    tab_index: usize,
}

impl ConsoleCard {
    pub fn new(title: &str, content: &str) -> Self {
        ConsoleCard {
            focused: false,
            title: title.to_string(),
            content: content.to_string(),
            cursor_position: content.chars().count(),
            borders: Borders::ALL,
            joins: Borders::NONE,
            cursor: Arc::new(Mutex::new(true)),
            last_swap: Arc::new(Mutex::new(Instant::now())),
            tab_index: 0,
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
                    "send command (<help> for info)",
                    Style::default().fg(Color::DarkGray),
                ));
            } else {
                spans.push(Span::styled(
                    " send command (<help> for info)",
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
        match key.code {
            KeyCode::Enter => {
                if self.content.is_empty() {
                    log!("");
                    return InteractionResult::Handled;
                }

                let command = self.content.clone();
                let id = Uuid::new_v4();
                let id = id.to_string();
                let id = id.split_at(8).0;
                let task_id = format!("command_{}_{}", command, id);
                ACTIVE_TASKS.insert(task_id.clone());

                log_command!("{}", command);

                tokio::spawn(async move {
                    run_command(&command).await;
                    ACTIVE_TASKS.remove(&task_id);
                });

                self.content.clear();
                self.cursor_position = 0;
                self.tab_index = 0;
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
            KeyCode::Tab => {
                if let Some(prefix) = self.current_prefix() {
                    if prefix == "/" {
                        self.tab_index = self.tab_index.saturating_add(1);
                    }
                }
                InteractionResult::Handled
            }
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

pub async fn run_command(command: &str) {
    let parts = command.split(" ").collect::<Vec<&str>>();

    match parts.as_slice() {
        ["tasks"] => {
            let active_tasks: Vec<String> =
                ACTIVE_TASKS.clone().iter().map(|v| v.to_string()).collect();
            let info = if *SHUTDOWN.read().await && *RELOAD.read().await {
                "Rebooting, "
            } else if *SHUTDOWN.read().await {
                "Shutting , "
            } else {
                ""
            };
            log!("{}Active tasks: {:?}", info, active_tasks);
        }
        ["fps"] => {
            let (fps, skips) = *FPS.read().await;
            log!("{:.1} FPS with {:.1}% of attempts skipped", fps, skips);
        }

        ["help"] => {
            log!("Available commands: tasks, fps, ping, user");
        }

        ["help", "tasks"] => {
            log!("Tasks command usage: tasks");
        }
        ["help", "fps"] => {
            log!("FPS command usage: fps");
        }
        ["help", "ping"] => {
            log!("Ping command usage: ping [time]");
        }
        ["help", "user"] => {
            log!("User command usage: user add <username> | user remove <username> | user list");
        }

        ["ping"] => {
            ping(20).await;
        }
        ["ping", time] => {
            let time = time.parse::<u64>().unwrap_or(20);
            ping(time).await;
        }
        ["user", "add", username] => {
            if let (Some(user), Some(_)) = user_manager::create_user(username).await {
                log!("Created user {}", user.user_id);
            } else {
                log!("Failed to create user");
            }
        }
        ["user", "remove", username] => {
            if let Some(user) = user_manager::get_user_by_username(username) {
                user_manager::remove_user(user.user_id);
                log!("Removed user {}", user.user_id);
            } else {
                log!("Failed to find user");
            }
        }
        ["user", "list"] => {
            let users: Vec<UserProfile> = user_manager::get_users();
            for user in users {
                let storage = file_util::get_designed_storage(user.user_id);
                log!(
                    "> Username: {}, ID: {}, created at: {}, storage: {}",
                    user.username,
                    user.user_id,
                    user.created_at,
                    storage
                );
            }
        }
        ["user", "info", username] => {
            if let Some(user) = user_manager::get_user_by_username(username) {
                user_manager::remove_user(user.user_id);
                log!("Removed user {}", user.user_id);
            } else {
                log!("Failed to find user");
            }
        }
        ["reload"] | ["restart"] => {
            log!("Restarting");
            *RELOAD.write().await = true;
            *SHUTDOWN.write().await = true;
        }
        ["shutdown"] | ["stop"] => {
            log!("Shutting down");
            *SHUTDOWN.write().await = true;
        }
        _ => {
            log!("Unknown command");
        }
    }
}

pub async fn ping(time: u64) {
    let conn = OMIKRON_CONNECTION.clone();

    let response_cv = conn
        .await_response(
            &CommunicationValue::new(CommunicationType::ping),
            Some(Duration::from_secs(time)),
        )
        .await;
    match response_cv {
        Ok(response) => log_cv!(response),
        Err(err) => log!("Ping error: {:?}", err),
    }
}
