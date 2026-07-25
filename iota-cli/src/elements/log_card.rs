use crate::elements::elements::{Element, InteractableElement, JoinableElement};
use crate::util::borders::draw_block_joins;
use crate::{interaction_result::InteractionResult, render_context::RenderContext};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use iota_state::{ClientState, UiLogEntry};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::{
    any::Any,
    sync::atomic::{AtomicUsize, Ordering},
};
use unicode_width::UnicodeWidthChar;

#[derive(Clone, Copy)]
enum LogSource {
    Call,
    Client,
    Iota,
    Omikron,
    Omega,
    Command,
    Other,
}

impl LogSource {
    fn from_sender(sender: &str) -> Self {
        match sender {
            "Call" => Self::Call,
            "Client" => Self::Client,
            "Iota" => Self::Iota,
            "Omikron" => Self::Omikron,
            "Omega" => Self::Omega,
            "Command" => Self::Command,
            _ => Self::Other,
        }
    }

    fn style(self, theme: &crate::theme::ResolvedTheme) -> Style {
        match self {
            Self::Call => theme.logs.call,
            Self::Client => theme.logs.client,
            Self::Iota => theme.logs.iota,
            Self::Omikron => theme.logs.omikron,
            Self::Omega => theme.logs.omega,
            Self::Command => theme.logs.command,
            Self::Other => theme.logs.other,
        }
    }
}

pub struct LogCard {
    state: ClientState,
    focused: bool,
    selected: bool,
    scroll_offset: usize,
    last_total_lines: AtomicUsize,
    last_visible_height: AtomicUsize,
    last_width: AtomicUsize,
    filter: String,
    filtering: bool,
    pub borders: Borders,
    pub joins: Borders,
}

impl LogCard {
    pub fn new(state: ClientState) -> Self {
        Self {
            state,
            focused: false,
            selected: false,
            scroll_offset: 0,
            last_total_lines: AtomicUsize::new(0),
            last_visible_height: AtomicUsize::new(1),
            last_width: AtomicUsize::new(1),
            filter: String::new(),
            filtering: false,
            borders: Borders::ALL,
            joins: Borders::NONE,
        }
    }

    fn get_logs(&self) -> Vec<UiLogEntry> {
        let state = match self.state.app.try_lock() {
            Ok(state) => state,
            Err(_) => return Vec::new(),
        };
        let needle = self.filter.to_ascii_lowercase();
        state
            .get_logs()
            .iter()
            .filter(|entry| {
                needle.is_empty()
                    || entry.sender.to_ascii_lowercase().contains(&needle)
                    || entry.message.to_ascii_lowercase().contains(&needle)
            })
            .map(|e| UiLogEntry {
                timestamp_ms: e.timestamp_ms,
                sender: e.sender.clone(),
                message: e.message.clone(),
                is_error: e.is_error,
            })
            .collect()
    }

    fn find_split_point(s: &str, max_width: usize) -> usize {
        if max_width == 0 {
            return s.len();
        }

        let mut current_width = 0usize;
        let mut last_boundary = 0usize;

        for (idx, ch) in s.char_indices() {
            let char_width = UnicodeWidthChar::width(ch).unwrap_or(0);
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

    fn wrap_entry(entry: &UiLogEntry, available_width: usize) -> Vec<(String, LogSource, bool)> {
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

            result.push((line, LogSource::from_sender(&entry.sender), entry.is_error));
        }

        result
    }

    fn build_all_lines(
        &self,
        entries: Vec<UiLogEntry>,
        width: usize,
    ) -> Vec<(String, LogSource, bool)> {
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
        let total_lines = self.last_total_lines.load(Ordering::Relaxed);
        let visible_height = self.last_visible_height.load(Ordering::Relaxed);
        if total_lines == 0 || total_lines <= visible_height {
            return (false, false);
        }

        let max_offset = total_lines - visible_height;
        let can_scroll_up = self.scroll_offset < max_offset;
        let can_scroll_down = self.scroll_offset > 0;

        (can_scroll_up, can_scroll_down)
    }

    fn build_title(&self) -> String {
        if self.filtering {
            return format!("Logs filter: {}_", self.filter);
        }
        if !self.filter.is_empty() {
            return format!("Logs [filter: {}]", self.filter);
        }
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
            .load(Ordering::Relaxed)
            .saturating_sub(self.last_visible_height.load(Ordering::Relaxed));
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

    fn render(&self, f: &mut Frame, area: Rect, context: &RenderContext<'_>) {
        let entries = self.get_logs();

        let inner_area = if matches!(context.theme.chrome, crate::theme::ChromeMode::Surfaces) {
            crate::controls::panel::render_panel(f, area, &self.build_title(), self.focused, context.theme)
        } else {
            let block = Block::default().title(self.build_title()).borders(self.borders).border_style(if self.focused { context.theme.logs.focused_border } else { context.theme.logs.border });
            let inner = block.inner(area);
            f.render_widget(block, area);
            inner
        };

        if inner_area.width == 0 || inner_area.height == 0 {
            draw_block_joins(
                f,
                area,
                self.borders,
                self.joins,
                if self.focused {
                    context.theme.borders.focused
                } else {
                    context.theme.borders.normal
                },
            );
            return;
        }

        let all_lines = self.build_all_lines(entries, inner_area.width as usize);
        let total_lines = all_lines.len();
        let visible_height = inner_area.height as usize;
        self.last_width
            .store(inner_area.width as usize, Ordering::Relaxed);
        self.last_total_lines.store(total_lines, Ordering::Relaxed);
        self.last_visible_height
            .store(visible_height, Ordering::Relaxed);

        let (start, end) = self.calculate_view_window(total_lines, visible_height);
        let visible_lines = &all_lines[start..end];

        let rendered_lines: Vec<Line> = visible_lines
            .iter()
            .map(|(line, source, is_error)| {
                let mut spans = Vec::new();

                let (prefix, rest) = Self::split_line_prefix(line);
                let prefix = if matches!(context.theme.chrome, crate::theme::ChromeMode::Surfaces) { "" } else { prefix };

                if !prefix.is_empty() {
                    spans.push(Span::styled(
                        prefix.to_string(),
                        source.style(context.theme),
                    ));
                }

                let (content, timestamp) = Self::split_timestamp_suffix(rest);
                let text_style = if *is_error {
                    context.theme.logs.error
                } else {
                    context.theme.logs.text
                };

                if !content.is_empty() {
                    spans.push(Span::styled(content.to_string(), text_style));
                }

                if !timestamp.is_empty() {
                    spans.push(Span::styled(
                        timestamp.to_string(),
                        context.theme.logs.timestamp,
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

        if !matches!(context.theme.chrome, crate::theme::ChromeMode::Surfaces) { draw_block_joins(
            f,
            area,
            self.borders,
            self.joins,
            if self.focused {
                context.theme.borders.focused
            } else {
                context.theme.borders.normal
            },
        ); }
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
        if self.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.filtering = false;
                    self.filter.clear();
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.filter.push(c);
                }
                _ => {}
            }
            self.scroll_offset = 0;
            return InteractionResult::Handled;
        }
        let entries = self.get_logs();
        let width = self.last_width.load(Ordering::Relaxed).max(1);
        let all_lines = self.build_all_lines(entries, width);

        self.last_total_lines
            .store(all_lines.len(), Ordering::Relaxed);
        let total_lines = all_lines.len();
        let visible_height = self.last_visible_height.load(Ordering::Relaxed).max(1);

        match key.code {
            KeyCode::Char('/') => {
                self.filtering = true;
                self.filter.clear();
                self.scroll_offset = 0;
                InteractionResult::Handled
            }
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
                if total_lines > visible_height {
                    self.scroll_offset = total_lines - visible_height;
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
