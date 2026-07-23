use ratatui::layout::Rect;

use crate::{
    controls::button::{
        ActionButton, ButtonIntent, button_minimum_width, horizontal_button_widths, render_button,
    },
    theme::ResolvedTheme,
    util::terms_focus::Focus,
};

pub fn draw_buttons(
    frame: &mut ratatui::Frame,
    area: Rect,
    current_focus: Focus,
    state: (bool, bool),
    update_needed: bool,
    downgrade_scenario: bool,
    tos_or_privacy: bool,
    theme: &ResolvedTheme,
) {
    let cancel_text = if update_needed {
        "[Q] Quit"
    } else {
        "[Q] Not now"
    };
    let continue_text = if downgrade_scenario {
        "Downgrade"
    } else {
        "Continue"
    };
    let mut buttons = vec![
        (cancel_text, Focus::Cancel),
        (continue_text, Focus::Continue),
    ];
    if tos_or_privacy {
        buttons.push(("Continue with Tensamin Services", Focus::ContinueAll));
    }

    let minimums = buttons
        .iter()
        .map(|(label, _)| button_minimum_width(label))
        .collect::<Vec<_>>();
    let Some(widths) = horizontal_button_widths(area.width, &minimums) else {
        return;
    };

    let mut x = area.x;
    for ((label, focus), width) in buttons.iter().zip(widths) {
        let button_area = Rect {
            x,
            y: area.y,
            width,
            height: area.height,
        };
        x = x.saturating_add(width);

        let (intent, enabled) = match focus {
            Focus::Cancel => (ButtonIntent::Cancel, true),
            Focus::Continue => (ButtonIntent::Primary, state.0),
            Focus::ContinueAll => (ButtonIntent::Primary, state.1),
            _ => (ButtonIntent::Neutral, false),
        };
        render_button(
            frame,
            button_area,
            ActionButton {
                label,
                intent,
                focused: current_focus == *focus,
                enabled,
            },
            theme,
        );
    }
}
