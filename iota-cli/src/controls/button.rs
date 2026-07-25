use crate::theme::ResolvedTheme;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    text::Span,
    widgets::Paragraph,
};
use unicode_width::UnicodeWidthStr;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonIntent {
    Primary,
    Neutral,
    Cancel,
    Destructive,
}
pub struct ActionButton<'a> {
    pub label: &'a str,
    pub intent: ButtonIntent,
    pub focused: bool,
    pub enabled: bool,
}
pub fn render_button(
    frame: &mut Frame,
    area: Rect,
    button: ActionButton<'_>,
    theme: &ResolvedTheme,
) {
    let style = if !button.enabled {
        theme.buttons.disabled
    } else {
        match (button.intent, button.focused) {
            (ButtonIntent::Primary, true) => theme.buttons.primary_focused,
            (ButtonIntent::Primary, false) => theme.buttons.primary,
            (ButtonIntent::Neutral, true) => theme.buttons.neutral_focused,
            (ButtonIntent::Neutral, false) => theme.buttons.neutral,
            (ButtonIntent::Cancel, true) => theme.buttons.cancel_focused,
            (ButtonIntent::Cancel, false) => theme.buttons.cancel,
            (ButtonIntent::Destructive, _) => theme.buttons.destructive,
        }
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            if button.focused {
                format!("› {}", button.label)
            } else {
                button.label.to_owned()
            },
            style,
        ))
        .alignment(Alignment::Center),
        area,
    );
}
pub fn horizontal_button_widths(available: u16, minimums: &[u16]) -> Option<Vec<u16>> {
    let required = minimums
        .iter()
        .try_fold(0u16, |total, width| total.checked_add(*width))?;
    if required > available {
        return None;
    }
    if minimums.is_empty() {
        return Some(Vec::new());
    }
    let extra = available - required;
    let count = minimums.len() as u16;
    Some(
        minimums
            .iter()
            .enumerate()
            .map(|(index, width)| width + extra / count + u16::from((index as u16) < extra % count))
            .collect(),
    )
}
pub fn button_minimum_width(label: &str) -> u16 {
    UnicodeWidthStr::width(label)
        .saturating_add(2)
        .min(u16::MAX as usize) as u16
}
