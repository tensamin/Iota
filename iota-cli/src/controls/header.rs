use crate::theme::ResolvedTheme;
use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    screens::screens::{AppAction, HitMap},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::Span,
    widgets::Paragraph,
};

/// Shared application bar. The brand cell is deliberately an action so it is
/// a reliable way home from every screen.
pub fn render_header(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    theme: &ResolvedTheme,
    hits: &mut HitMap,
    focused_action: Option<usize>,
) {
    let cells = Layout::horizontal([
        Constraint::Min(28),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(8),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(Span::styled(format!(" {title}"), theme.surfaces.toolbar)),
        cells[0],
    );
    hits.register(cells[0], AppAction::OpenMain);
    for (index, (area, label, action)) in [
        (cells[1], "Overview", AppAction::OpenOverview),
        (cells[2], "Users", AppAction::OpenUsers),
        (cells[3], "Settings", AppAction::OpenSettings),
        (cells[4], "Quit", AppAction::Quit),
    ]
    .into_iter()
    .enumerate()
    {
        render_button(
            frame,
            area,
            ActionButton {
                label,
                intent: if action == AppAction::Quit {
                    ButtonIntent::Destructive
                } else {
                    ButtonIntent::Neutral
                },
                focused: focused_action == Some(index),
                enabled: true,
            },
            theme,
        );
        hits.register(area, action);
    }
}
