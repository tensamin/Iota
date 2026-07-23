use iota_cli::{
    controls::choice::{ChoiceKind, ChoiceVisualState, render_choice_line},
    theme::{ThemeName, resolve},
};
use ratatui::style::{Color, Modifier};

#[test]
fn ansi_checkbox_matches_the_existing_focused_and_disabled_styles() {
    let theme = resolve(ThemeName::Ansi);
    let line = render_choice_line(
        "Terms",
        ChoiceKind::Checkbox,
        ChoiceVisualState {
            selected: false,
            focused: true,
            enabled: true,
        },
        &theme,
    );
    assert_eq!(
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>(),
        "[ ] Terms"
    );
    assert_eq!(line.spans[1].style.fg, Some(Color::Yellow));
    assert!(line.spans[1].style.add_modifier.contains(Modifier::BOLD));

    let disabled = render_choice_line(
        "Terms",
        ChoiceKind::Checkbox,
        ChoiceVisualState {
            selected: false,
            focused: true,
            enabled: false,
        },
        &theme,
    );
    assert_eq!(disabled.spans[1].style.fg, Some(Color::DarkGray));
    assert_eq!(disabled.spans[3].style.fg, Some(Color::Red));
}

#[test]
fn colourless_themes_keep_state_and_focus_visible() {
    for name in [ThemeName::Monospace, ThemeName::Binary] {
        let theme = resolve(name);
        let line = render_choice_line(
            "Mode",
            ChoiceKind::Radio,
            ChoiceVisualState {
                selected: true,
                focused: true,
                enabled: true,
            },
            &theme,
        );
        assert_eq!(
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>(),
            "> (x) Mode <"
        );
        assert!(
            line.spans
                .iter()
                .all(|span| span.style.fg.is_none() && span.style.bg.is_none())
        );
    }
}
