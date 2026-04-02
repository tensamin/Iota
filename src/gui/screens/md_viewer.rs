use crossterm::event::{self, Event, KeyCode, KeyEvent};
use ratatui::{
    DefaultTerminal,
    prelude::*,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{any::Any, time::Duration};

use crate::gui::{interaction_result::InteractionResult, screens::screens::Screen};

pub struct FileViewer {
    title: String,
    text: Vec<DisplayLine>,
    scroll: u16,
    scroll_x: u16,
}

impl Screen for FileViewer {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, rect: Rect) {
        self.draw(f, rect);
    }

    fn handle_input(&mut self, event: KeyEvent) -> InteractionResult {
        match event.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                return InteractionResult::CloseScreen;
            }

            KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Right => self.scroll_x = self.scroll_x.saturating_add(2),
            KeyCode::Left => self.scroll_x = self.scroll_x.saturating_sub(2),

            _ => {}
        }

        InteractionResult::Unhandled
    }
}

impl FileViewer {
    pub fn new(title: String, content: &str) -> Self {
        Self {
            title,
            text: parse_document(content.to_owned()),
            scroll: 0,
            scroll_x: 0,
        }
    }
    pub fn force_popup(mut self, mut terminal: DefaultTerminal) -> DefaultTerminal {
        loop {
            terminal
                .draw(|f| {
                    let area = f.area();
                    self.draw(f, area);
                })
                .unwrap();

            if event::poll(Duration::from_millis(100)).unwrap() {
                let ev = event::read().unwrap();
                self.handle_event(&ev);

                if matches!(ev, Event::Key(k) if k.code == KeyCode::Char('q')) {
                    break;
                }
            }
        }
        terminal
    }
    fn draw(&self, f: &mut Frame, area: Rect) {
        use ratatui::text::Text;

        let mut rendered_lines = Vec::new();

        for display_line in &self.text {
            if display_line.scrollable {
                let content: String = display_line
                    .line
                    .spans
                    .iter()
                    .map(|s| s.content.clone())
                    .collect();

                let start = self.scroll_x as usize;
                let width = area.width as usize - 2;

                let visible = if start < content.chars().count() {
                    content.chars().skip(start).take(width).collect()
                } else {
                    String::new()
                };

                let mut chars: Vec<char> = visible.chars().collect();

                if start > 0 && !chars.is_empty() {
                    chars[0] = '<';
                }

                if start + width < content.chars().count() && !chars.is_empty() {
                    let last = chars.len() - 1;
                    chars[last] = '>';
                }

                let visible: String = chars.into_iter().collect();

                rendered_lines.push(Line::from(Span::styled(
                    visible,
                    display_line
                        .line
                        .spans
                        .first()
                        .map(|s| s.style)
                        .unwrap_or_default(),
                )));
            } else {
                rendered_lines.push(display_line.line.clone());
            }
        }

        let paragraph = Paragraph::new(Text::from(rendered_lines))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("{} - [Q to close]", self.title.as_str(),)),
            )
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));

        f.render_widget(paragraph, area);
    }

    pub fn handle_event(&mut self, event: &Event) {
        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
                KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
                KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
                KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
                KeyCode::Right => self.scroll_x = self.scroll_x.saturating_add(2),
                KeyCode::Left => self.scroll_x = self.scroll_x.saturating_sub(2),
                _ => {}
            }
        }
    }
}
fn parse_document(input: String) -> Vec<DisplayLine> {
    let mut lines_vec = Vec::new();
    let mut in_code_block = false;
    let liness: Vec<String> = input.lines().map(String::from).collect();
    let mut i = 0;

    while i < liness.len() {
        let raw = &liness[i];

        if raw.trim().starts_with("```") {
            in_code_block = !in_code_block;
            let code: String = if raw.trim().replace("```", "").is_empty() {
                "──".to_string()
            } else {
                raw.trim().replace("```", "")
            };
            lines_vec.push(DisplayLine {
                line: Line::from(Span::styled(
                    format!("────────{}────────", code),
                    Style::default().fg(Color::DarkGray),
                )),
                scrollable: false,
            });
            i += 1;
            continue;
        }

        if in_code_block {
            lines_vec.push(DisplayLine {
                line: Line::from(Span::styled(
                    raw.to_string(),
                    Style::default().fg(Color::Yellow),
                )),
                scrollable: false,
            });
            i += 1;
            continue;
        }
        if raw.starts_with("### ") {
            lines_vec.push(DisplayLine {
                line: Line::from(Span::styled(
                    raw.trim_start_matches("### ").to_string(),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                scrollable: false,
            });
            i += 1;
            continue;
        }
        if raw.starts_with("## ") {
            lines_vec.push(DisplayLine {
                line: Line::from(Span::styled(
                    raw.trim_start_matches("## ").to_string(),
                    Style::default()
                        .fg(Color::LightCyan)
                        .add_modifier(Modifier::BOLD),
                )),
                scrollable: false,
            });
            i += 1;
            continue;
        }
        if raw.starts_with("# ") {
            lines_vec.push(DisplayLine {
                line: Line::from(Span::styled(
                    raw.trim_start_matches("# ").to_string(),
                    Style::default()
                        .fg(Color::Gray)
                        .add_modifier(Modifier::BOLD),
                )),
                scrollable: false,
            });
            i += 1;
            continue;
        }

        if raw.trim_start().starts_with("- ") {
            let indent = raw.chars().take_while(|c| *c == ' ').count();
            lines_vec.push(DisplayLine {
                line: Line::from(Span::raw(format!(
                    "{}• {}",
                    " ".repeat(indent),
                    raw.trim_start_matches("- ")
                ))),
                scrollable: false,
            });
            i += 1;
            continue;
        }

        if raw.trim().starts_with('|') && raw.contains('|') {
            let mut table_lines = vec![raw.clone()];
            let mut j = i + 1;
            while j < liness.len() && liness[j].trim().starts_with('|') {
                table_lines.push(liness[j].clone());
                j += 1;
            }

            let table = parse_table(&table_lines.iter().map(|s| s.as_str()).collect::<Vec<_>>());
            lines_vec.extend(table_to_lines(table));
            i = j;
            continue;
        }

        lines_vec.push(DisplayLine {
            line: Line::from(parse_inline(raw.as_str())),
            scrollable: false,
        });
        i += 1;
    }

    lines_vec
}

fn parse_inline(input: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut buf = String::new();

    let mut bold = false;
    let mut underline = false;
    let mut code = false;

    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        let toggle = match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                Some("bold")
            }
            '_' if chars.peek() == Some(&'_') => {
                chars.next();
                Some("underline")
            }
            '`' => Some("code"),
            _ => None,
        };

        if let Some(kind) = toggle {
            flush_span(&mut spans, &mut buf, current_style(bold, underline, code));

            match kind {
                "bold" => bold = !bold,
                "underline" => underline = !underline,
                "code" => code = !code,
                _ => {}
            }
            continue;
        }

        buf.push(c);
    }

    flush_span(&mut spans, &mut buf, current_style(bold, underline, code));
    spans
}

fn current_style(bold: bool, underline: bool, code: bool) -> Style {
    let mut style = Style::default();

    if bold {
        style = style.add_modifier(Modifier::BOLD);
    }
    if underline {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    if code {
        style = style.fg(Color::Yellow);
    }

    style
}
#[derive(Clone)]
pub struct DisplayLine {
    line: Line<'static>,
    scrollable: bool,
}

fn table_to_lines(table: Vec<Vec<String>>) -> Vec<DisplayLine> {
    if table.len() < 2 {
        return vec![];
    }

    let header = &table[0];
    let mut column_heights = vec![0; table[0].len()];

    for row in table.iter().skip(1) {
        for (i, cell) in row.iter().enumerate() {
            let lines = cell.lines().count().max(1);
            column_heights[i] += lines;
        }
    }

    let widths: Vec<usize> = header
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let h_len = h.chars().count().max(1);
            if i == 0 {
                table
                    .iter()
                    .map(|row| row.get(i).map(|c| c.chars().count()).unwrap_or(0))
                    .max()
                    .unwrap_or(h_len)
            } else {
                let max = (3 * h_len) as usize;
                max.max(h_len)
            }
        })
        .collect();

    let mut lines = Vec::new();

    for (row_idx, row) in table.iter().enumerate() {
        if row_idx == 1 {
            let divider = widths
                .iter()
                .map(|w| "─".repeat(*w))
                .collect::<Vec<_>>()
                .join("─┼─");

            lines.push(DisplayLine {
                line: Line::from(Span::styled(divider, Style::default().fg(Color::DarkGray))),
                scrollable: true,
            });
            continue;
        }

        let wrapped_cells: Vec<Vec<String>> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| wrap_cell(cell, widths[i]))
            .collect();

        let row_height = wrapped_cells.iter().map(|c| c.len()).max().unwrap_or(1);

        for line_idx in 0..row_height {
            let mut line = String::new();

            for (i, cell) in wrapped_cells.iter().enumerate() {
                let content = cell.get(line_idx).map(String::as_str).unwrap_or("");
                line.push_str(&format!("{:width$}", content, width = widths[i]));
                if i < wrapped_cells.len() - 1 {
                    line.push_str(" │ ");
                }
            }

            let style = if row_idx == 0 {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            };

            lines.push(DisplayLine {
                line: Line::from(Span::styled(line, style)),
                scrollable: true,
            });
        }
    }

    lines
}
fn wrap_cell(cell: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in cell.split_whitespace() {
        let word_len = word.chars().count();
        let current_len = current.chars().count();

        if current_len == 0 {
            if word_len <= width {
                current.push_str(word);
            } else {
                for chunk in word.chars().collect::<Vec<_>>().chunks(width) {
                    lines.push(chunk.iter().collect());
                }
            }
        } else if current_len + 1 + word_len <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = String::new();

            if word_len <= width {
                current.push_str(word);
            } else {
                for chunk in word.chars().collect::<Vec<_>>().chunks(width) {
                    lines.push(chunk.iter().collect());
                }
            }
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn flush_span(spans: &mut Vec<Span>, buf: &mut String, style: Style) {
    if !buf.is_empty() {
        spans.push(Span::styled(buf.clone(), style));
        buf.clear();
    }
}

fn parse_table(lines: &[&str]) -> Vec<Vec<String>> {
    let mut table = Vec::new();

    for &line in lines {
        if !line.starts_with('|') || !line.contains('|') {
            break;
        }
        let row: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|s| s.trim().to_string())
            .collect();
        table.push(row);
    }

    table
}
