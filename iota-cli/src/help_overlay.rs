use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::{
    screens::screens::{HitMap, IotaInteraction, IotaScreen, UiEvent},
    theme::ResolvedTheme,
};

pub struct HelpOverlay {
    scroll: usize,
}

impl HelpOverlay {
    pub fn new() -> Self {
        Self { scroll: 0 }
    }

    fn build_lines(&self, theme: &ResolvedTheme) -> Vec<Line<'static>> {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "Global Keyboard Shortcuts",
                theme.text.heading,
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  F6", theme.text.link),
                Span::styled("        Toggle header navigation", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Tab", theme.text.link),
                Span::styled("      Move focus to next panel", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Shift+Tab", theme.text.link),
                Span::styled("  Move focus to previous panel", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Esc", theme.text.link),
                Span::styled("        Go back / Close dialog", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl+C", theme.text.link),
                Span::styled("      Quit the application", theme.text.normal),
            ]),
            Line::from(""),
            Line::from(Span::styled("Dashboard Navigation", theme.text.heading)),
            Line::from(""),
            Line::from(vec![
                Span::styled("  o/O", theme.text.link),
                Span::styled("        Open Overview screen", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  u/U", theme.text.link),
                Span::styled("        Open Users screen", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  m/M", theme.text.link),
                Span::styled("        Open Metrics screen", theme.text.normal),
            ]),
            Line::from(""),
            Line::from(Span::styled("Log Panel", theme.text.heading)),
            Line::from(""),
            Line::from(vec![
                Span::styled("  j/Down", theme.text.link),
                Span::styled("     Scroll down", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  k/Up", theme.text.link),
                Span::styled("       Scroll up", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Enter", theme.text.link),
                Span::styled("      Lock/unlock scroll", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  /", theme.text.link),
                Span::styled("          Filter logs", theme.text.normal),
            ]),
            Line::from(""),
            Line::from(Span::styled("Console Panel", theme.text.heading)),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Enter", theme.text.link),
                Span::styled("      Send command", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Up/Down", theme.text.link),
                Span::styled("    Command history", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Tab", theme.text.link),
                Span::styled("        Auto-complete", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  /help", theme.text.link),
                Span::styled("       List available commands", theme.text.normal),
            ]),
            Line::from(""),
            Line::from(Span::styled("List Navigation", theme.text.heading)),
            Line::from(""),
            Line::from(vec![
                Span::styled("  j/Down", theme.text.link),
                Span::styled("     Next item", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  k/Up", theme.text.link),
                Span::styled("       Previous item", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  PgUp/PgDn", theme.text.link),
                Span::styled("  Page up/down", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  Home", theme.text.link),
                Span::styled("       First item", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  End", theme.text.link),
                Span::styled("        Last item", theme.text.normal),
            ]),
            Line::from(vec![
                Span::styled("  /", theme.text.link),
                Span::styled("          Filter list", theme.text.normal),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Press ? or Esc to close this overlay",
                theme.text.muted,
            )),
        ]
    }
}

impl IotaScreen for HelpOverlay {
    fn render_legacy(&self, f: &mut Frame, rect: Rect, theme: &ResolvedTheme, _hits: &mut HitMap) {
        let area = ratatool::layout::centered_rect(
            rect,
            ratatool::layout::RequiredSize {
                width: 52,
                height: 40,
            },
        );

        f.render_widget(Clear, area);
        let block = Block::default()
            .title(" Keyboard Shortcuts (?) ")
            .borders(Borders::ALL)
            .border_style(theme.borders.focused)
            .style(theme.surfaces.overlay);

        let inner = block.inner(area);
        f.render_widget(block, area);

        let lines = self.build_lines(theme);
        let paragraph = Paragraph::new(lines)
            .scroll((self.scroll as u16, 0))
            .style(theme.text.normal);
        f.render_widget(paragraph, inner);
    }

    fn handle_event(&mut self, event: &UiEvent) -> IotaInteraction {
        let event = event.clone();
        let UiEvent::Key(key) = event else {
            return IotaInteraction::Unhandled;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => IotaInteraction::Pop,
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                IotaInteraction::Changed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                IotaInteraction::Changed
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(10);
                IotaInteraction::Changed
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(10);
                IotaInteraction::Changed
            }
            _ => IotaInteraction::Unhandled,
        }
    }

    fn key_hints(&self) -> Vec<crate::screens::screens::KeyHint> {
        vec![
            crate::screens::screens::KeyHint {
                keys: "Up/Down",
                action: "Scroll",
            },
            crate::screens::screens::KeyHint {
                keys: "Esc/?",
                action: "Close",
            },
        ]
    }
}
