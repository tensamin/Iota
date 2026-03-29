use crate::APP_STATE;
use crate::gui::elements::elements::{Element, InteractableElement, JoinableElement};
use crate::gui::interaction_result::InteractionResult;
use crate::gui::util::borders::draw_block_joins;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::any::Any;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    User,
    System,
}

impl Sender {
    pub fn prefix_color(self) -> Color {
        match self {
            Sender::User => Color::Magenta,
            Sender::System => Color::Blue,
        }
    }
}

impl Sender {
    pub fn color(self) -> Color {
        match self {
            Sender::User => Color::Magenta,
            Sender::System => Color::Blue,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp_ms: u128,
    pub sender: Sender,
    pub message: String,
    pub is_error: bool,
}

impl LogEntry {
    pub fn new(sender: Sender, message: String, is_error: bool) -> Self {
        Self {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            sender,
            message,
            is_error,
        }
    }

    pub fn format_timestamp(&self) -> String {
        let secs = (self.timestamp_ms / 1000) as i64;
        let hours = (secs / 3600) % 24;
        let minutes = (secs / 60) % 60;
        let seconds = secs % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

#[derive(Clone)]
pub struct UiLogEntry {
    pub sender: Sender,
    pub message: String,
    pub timestamp_ms: u128,
    pub is_error: bool,
    pub color: Color,
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

struct RenderedLine {
    prefix: String,
    sender: Sender,
    timestamp: String,
    content: String,
    is_error: bool,
    is_first: bool,
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

    fn wrap_entry(entry: &UiLogEntry, available_width: usize) -> Vec<(bool, String)> {
        let mut result = Vec::new();
        let continuation_prefix_width = 2;
        let first_line_width = available_width.saturating_sub(continuation_prefix_width);
        let continuation_content_width = available_width.saturating_sub(continuation_prefix_width);

        let paragraphs: Vec<&str> = entry.message.split('\n').collect();

        for (para_idx, paragraph) in paragraphs.iter().enumerate() {
            if paragraph.is_empty() {
                if para_idx == 0 {
                    result.push((true, String::new()));
                } else {
                    result.push((false, String::new()));
                }
                continue;
            }

            let mut remaining = *paragraph;
            let mut is_first_line = para_idx == 0;

            while !remaining.is_empty() {
                let current_width = if is_first_line {
                    first_line_width
                } else {
                    continuation_content_width
                };

                let split_point = Self::find_split_point(remaining, current_width);
                let line_content = &remaining[..split_point];

                result.push((is_first_line, line_content.to_string()));

                remaining = &remaining[split_point..];
                is_first_line = false;
            }
        }

        if result.is_empty() {
            result.push((true, String::new()));
        }

        result
    }

    fn build_all_lines(&self, entries: Vec<UiLogEntry>, width: usize) -> Vec<RenderedLine> {
        let mut lines = Vec::new();

        for entry in entries {
            let wrapped = Self::wrap_entry(&entry, width);
            let timestamp = {
                let secs = (entry.timestamp_ms / 1000) as i64;
                let hours = (secs / 3600) % 24;
                let minutes = (secs / 60) % 60;
                let seconds = secs % 60;
                format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
            };

            for (is_first, content) in wrapped {
                lines.push(RenderedLine {
                    prefix: "│ ".to_string(),
                    sender: entry.sender,
                    timestamp: if is_first {
                        timestamp.clone()
                    } else {
                        String::new()
                    },
                    content,
                    is_error: entry.is_error,
                    is_first,
                });
            }
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

        let lines: Vec<Line> = visible_lines
            .iter()
            .map(|rl| {
                let mut spans = Vec::new();

                spans.push(Span::styled(
                    &rl.prefix,
                    Style::default().fg(rl.sender.prefix_color()),
                ));

                if !rl.content.is_empty() {
                    let content_color = if rl.is_error {
                        Color::Red
                    } else {
                        Color::White
                    };
                    spans.push(Span::styled(
                        &rl.content,
                        Style::default().fg(content_color),
                    ));
                }

                if rl.is_first {
                    spans.push(Span::styled(
                        format!(" {}", rl.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                Line::from(spans)
            })
            .collect();

        for (idx, line) in lines.iter().enumerate() {
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

impl InteractableElement for LogCard {
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
