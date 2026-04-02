use crate::APP_STATE;
use crate::gui::elements::elements::{Element, InteractableElement, JoinableElement};
use crate::gui::interaction_result::InteractionResult;
use crate::gui::util::borders::draw_block_joins;
use crate::util::logger::PrintType;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::any::Any;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct UiLogEntry {
    pub timestamp_ms: u128,
    pub sender: PrintType,
    pub message: String,
    pub is_error: bool,
}

impl UiLogEntry {
    pub fn format_timestamp(&self) -> String {
        let secs = (self.timestamp_ms / 1000) as i64;
        let hours = (secs / 3600) % 24;
        let minutes = (secs / 60) % 60;
        let seconds = secs % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

impl From<LogEntry> for UiLogEntry {
    fn from(entry: LogEntry) -> Self {
        Self {
            timestamp_ms: entry.timestamp_ms,
            sender: entry.sender,
            message: entry.message,
            is_error: entry.is_error,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp_ms: u128,
    pub sender: PrintType,
    pub message: String,
    pub is_error: bool,
}

impl LogEntry {
    pub fn new(sender: PrintType, message: String, is_error: bool) -> Self {
        Self {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            sender,
            message,
            is_error,
        }
    }
}

pub struct LogCard {
    focused: bool,
    selected: bool,
    scroll_offset: usize,
    last_total_lines: usize,
    last_visible_height: usize,
    pub borders: Borders,
    pub joins: Borders,
}

impl LogCard {
    pub fn new() -> Self {
        Self {
            focused: false,
            selected: false,
            scroll_offset: 0,
            last_total_lines: 0,
            last_visible_height: 10,
            borders: Borders::ALL,
            joins: Borders::NONE,
        }
    }

    fn get_logs(&self) -> Vec<UiLogEntry> {
        let state = APP_STATE.lock().unwrap();
        state.get_logs().iter().cloned().collect()
    }

    fn find_split_point(s: &str, max_width: usize) -> usize {
        if max_width == 0 {
            return s.len();
        }

        let mut current_width = 0usize;
        let mut last_boundary = 0usize;

        for (idx, ch) in s.char_indices() {
            let char_width = if ch.is_ascii() { 1 } else { 2 };
            if current_width + char_width > max_width {
                if last_boundary == 0 {
                    return idx + ch.len_utf8();
                }
                return last_boundary;
            }
            current_width += char_width;
            last_boundary = idx + ch.len_utf8();
        }

        s.len()
    }

    fn wrap_entry(entry: &UiLogEntry, available_width: usize) -> Vec<(String, Color, bool)> {
        let mut result = Vec::new();

        let timestamp = entry.format_timestamp();
        let first_prefix = "┌ ";
        let default_prefix = "│ ";
        let last_prefix = "└ ";

        let prefix_width = 2;
        let first_line_width = available_width.saturating_sub(prefix_width + 1);
        let continuation_width = available_width.saturating_sub(prefix_width);

        let segments: Vec<&str> = entry.message.split('\n').collect();

        let mut raw_lines = Vec::new();

        for segment in segments {
            let mut remaining = segment;
            if remaining.is_empty() {
                raw_lines.push(String::new());
                continue;
            }

            let mut is_first_part = true;
            while !remaining.is_empty() {
                let current_width = if is_first_part {
                    first_line_width
                } else {
                    continuation_width
                };

                let split_point = Self::find_split_point(remaining, current_width);
                let line_content = remaining[..split_point].to_string();
                raw_lines.push(line_content);
                remaining = &remaining[split_point..];
                is_first_part = false;
            }
        }

        if raw_lines.is_empty() {
            raw_lines.push(String::new());
        }

        for (idx, content) in raw_lines.iter().enumerate() {
            let is_last = idx + 1 == raw_lines.len();
            let is_single = raw_lines.len() == 1;
            let is_first = idx == 0;
            let prefix = if is_first {
                first_prefix
            } else if is_last && !is_single {
                last_prefix
            } else {
                default_prefix
            };

            let mut line = String::from(prefix);
            line.push_str(content);

            if is_last && !timestamp.is_empty() {
                line.push(' ');
                line.push_str(&timestamp);
            }

            result.push((line, entry.sender.prefix_color(), entry.is_error));
        }

        result
    }

    fn build_all_lines(
        &self,
        entries: Vec<UiLogEntry>,
        width: usize,
    ) -> Vec<(String, Color, bool)> {
        let mut lines = Vec::new();

        for entry in entries {
            let wrapped = Self::wrap_entry(&entry, width);
            lines.extend(wrapped);
        }

        lines
    }

    fn calculate_view_window(&self, total_lines: usize, visible_height: usize) -> (usize, usize) {
        if total_lines <= visible_height {
            return (0, total_lines);
        }

        let max_offset = total_lines - visible_height;
        let clamped_offset = self.scroll_offset.min(max_offset);

        let end = total_lines - clamped_offset;
        let start = end.saturating_sub(visible_height);

        (start, end)
    }

    fn get_title_hints(&self) -> (bool, bool) {
        if self.last_total_lines == 0 || self.last_total_lines <= self.last_visible_height {
            return (false, false);
        }

        let max_offset = self.last_total_lines - self.last_visible_height;
        let can_scroll_up = self.scroll_offset < max_offset;
        let can_scroll_down = self.scroll_offset > 0;

        (can_scroll_up, can_scroll_down)
    }

    fn build_title(&self) -> String {
        if !self.focused {
            return "Logs".to_string();
        }

        let (can_up, can_down) = self.get_title_hints();

        if !can_up && !can_down {
            return "Logs".to_string();
        }

        let nav_symbol = if self.selected { "↑" } else { "j" };
        let down_symbol = if self.selected { "↓" } else { "k" };

        match (can_up, can_down) {
            (true, true) => format!("Logs ({} older {} newer)", nav_symbol, down_symbol),
            (true, false) => format!("Logs ({} older)", nav_symbol),
            (false, true) => format!("Logs ({} newer)", down_symbol),
            (false, false) => "Logs".to_string(),
        }
    }

    fn scroll_up(&mut self) {
        let max_offset = self
            .last_total_lines
            .saturating_sub(self.last_visible_height);
        self.scroll_offset = (self.scroll_offset + 1).min(max_offset);
    }

    fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    fn split_line_prefix(line: &str) -> (&str, &str) {
        if let Some(rest) = line.strip_prefix("└ ") {
            ("└ ", rest)
        } else if let Some(rest) = line.strip_prefix("│ ") {
            ("│ ", rest)
        } else if let Some(rest) = line.strip_prefix("┌ ") {
            ("┌ ", rest)
        } else {
            ("", line)
        }
    }

    fn split_timestamp_suffix(line: &str) -> (&str, &str) {
        if let Some(idx) = line.rfind(' ') {
            let possible_timestamp = &line[idx + 1..];
            if possible_timestamp.len() == 8
                && possible_timestamp.as_bytes()[2] == b':'
                && possible_timestamp.as_bytes()[5] == b':'
            {
                let (content, timestamp_with_space) = line.split_at(idx);
                return (content.trim_end(), timestamp_with_space);
            }
        }
        (line, "")
    }
}

impl Element for LogCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, area: Rect) {
        let entries = self.get_logs();

        let block = Block::default()
            .title(self.build_title())
            .borders(self.borders)
            .border_style(if self.focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            });

        let inner_area = block.inner(area);
        f.render_widget(block, area);

        if inner_area.width == 0 || inner_area.height == 0 {
            draw_block_joins(f, area, self.borders, self.joins);
            return;
        }

        let all_lines = self.build_all_lines(entries, inner_area.width as usize);
        let total_lines = all_lines.len();
        let visible_height = inner_area.height as usize;

        let (start, end) = self.calculate_view_window(total_lines, visible_height);
        let visible_lines = &all_lines[start..end];

        let rendered_lines: Vec<Line> = visible_lines
            .iter()
            .map(|(line, prefix_color, is_error)| {
                let mut spans = Vec::new();

                let (prefix, rest) = Self::split_line_prefix(line);

                if !prefix.is_empty() {
                    spans.push(Span::styled(
                        prefix.to_string(),
                        Style::default().fg(*prefix_color),
                    ));
                }

                let (content, timestamp) = Self::split_timestamp_suffix(rest);
                let text_color = if *is_error { Color::Red } else { Color::White };

                if !content.is_empty() {
                    spans.push(Span::styled(
                        content.to_string(),
                        Style::default().fg(text_color),
                    ));
                }

                if !timestamp.is_empty() {
                    spans.push(Span::styled(
                        timestamp.to_string(),
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                Line::from(spans)
            })
            .collect();

        for (idx, line) in rendered_lines.iter().enumerate() {
            let line_area = Rect {
                x: inner_area.x,
                y: inner_area.y + idx as u16,
                width: inner_area.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(line.clone()), line_area);
        }

        draw_block_joins(f, area, self.borders, self.joins);
    }
}

impl JoinableElement for LogCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_element(&self) -> &(dyn Element + 'static) {
        &*self
    }

    fn as_element_mut(&mut self) -> &mut (dyn Element + 'static) {
        &mut *self
    }

    fn set_borders(&mut self, borders: Borders) {
        self.borders = borders;
    }

    fn set_joins(&mut self, joins: Borders) {
        self.joins = joins;
    }
}

impl InteractableElement for LogCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_element(&self) -> &(dyn Element + 'static) {
        &*self
    }

    fn as_element_mut(&mut self) -> &mut (dyn Element + 'static) {
        &mut *self
    }

    fn interact(&mut self, key: KeyEvent) -> InteractionResult {
        let entries = self.get_logs();
        let estimated_width = 80usize;
        let all_lines = self.build_all_lines(entries, estimated_width);

        self.last_total_lines = all_lines.len();
        let visible_height = self.last_visible_height.max(1);

        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.selected = !self.selected;
                InteractionResult::Handled
            }
            KeyCode::Char('j') | KeyCode::Char('J') => {
                let (can_up, _) = self.get_title_hints();
                if can_up {
                    self.scroll_up();
                }
                InteractionResult::Handled
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                let (_, can_down) = self.get_title_hints();
                if can_down {
                    self.scroll_down();
                }
                InteractionResult::Handled
            }
            KeyCode::Up if self.selected => {
                let (can_up, _) = self.get_title_hints();
                if can_up {
                    self.scroll_up();
                }
                InteractionResult::Handled
            }
            KeyCode::Down if self.selected => {
                let (_, can_down) = self.get_title_hints();
                if can_down {
                    self.scroll_down();
                }
                InteractionResult::Handled
            }
            KeyCode::Home => {
                if self.last_total_lines > visible_height {
                    self.scroll_offset = self.last_total_lines - visible_height;
                }
                InteractionResult::Handled
            }
            KeyCode::End => {
                self.scroll_offset = 0;
                InteractionResult::Handled
            }
            _ => InteractionResult::Unhandled,
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
