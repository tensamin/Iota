use crate::theme::ResolvedTheme;
use ratatui::text::{Line, Span};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChoiceKind {
    Checkbox,
    Radio,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChoiceVisualState {
    pub selected: bool,
    pub focused: bool,
    pub enabled: bool,
}
pub fn render_choice_line<'a>(
    label: &'a str,
    kind: ChoiceKind,
    state: ChoiceVisualState,
    theme: &'a ResolvedTheme,
) -> Line<'a> {
    let item = match (state.selected, state.focused, state.enabled) {
        (_, true, false) => &theme.choices.focused_disabled,
        (true, false, false) => &theme.choices.selected_disabled,
        (false, false, false) => &theme.choices.disabled,
        (true, true, true) => &theme.choices.focused_selected,
        (true, false, true) => &theme.choices.selected,
        (false, true, true) => &theme.choices.focused,
        (false, false, true) => &theme.choices.normal,
    };
    let marker = match (kind, state.selected) {
        (ChoiceKind::Checkbox, false) => theme.markers.checkbox_unselected,
        (ChoiceKind::Checkbox, true) => theme.markers.checkbox_selected,
        (ChoiceKind::Radio, false) => theme.markers.radio_unselected,
        (ChoiceKind::Radio, true) => theme.markers.radio_selected,
    };
    Line::from(vec![
        Span::styled(item.prefix, item.label),
        Span::styled(marker, item.marker),
        Span::raw(" "),
        Span::styled(label, item.label),
        Span::styled(item.suffix, item.label),
    ])
}
