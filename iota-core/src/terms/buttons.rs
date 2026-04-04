use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::terms::focus::Focus;

#[allow(mismatched_lifetime_syntaxes)]
pub fn checkbox(label: &str, checked: bool, active: bool, allowed: bool) -> Line {
    let box_char = if checked { "[x]" } else { "[ ]" };
    let (box_style, text_style) = if active {
        if allowed {
            (
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(Color::Gray),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )
        }
    } else {
        (Style::default(), Style::default())
    };
    Line::from(vec![
        Span::styled(box_char, box_style),
        Span::raw(" "),
        Span::styled(label, text_style),
    ])
}

pub fn draw_button(f: &mut ratatui::Frame, area: Rect, label: &str, style: Style) {
    let p = Paragraph::new(Span::styled(label, style))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}
pub fn draw_buttons(
    f: &mut ratatui::Frame,
    area: Rect,
    current_focus: Focus,
    state: (bool, bool),
    update_needed: bool,
    downgrade_scenario: bool,
    tos_or_privacy: bool,
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

    let padding = 2;
    let min_widths: Vec<u16> = buttons
        .iter()
        .map(|(label, _)| label.len() as u16 + padding)
        .collect();

    let widths = compute_widths(area.width, &min_widths);

    let mut x = area.x;

    for ((label, focus), width) in buttons.iter().zip(widths) {
        let chunk = Rect {
            x,
            y: area.y,
            width,
            height: area.height,
        };
        x += width;

        let is_focused = current_focus == *focus;

        let style = match focus {
            Focus::Cancel => {
                if is_focused {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Red)
                }
            }

            Focus::Continue => {
                if is_focused && state.0 {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else if state.0 {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            }

            Focus::ContinueAll => {
                if is_focused && state.1 {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else if state.1 {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            }

            _ => Style::default().fg(Color::DarkGray),
        };

        draw_button(f, chunk, label, style);
    }
}
pub fn compute_widths(area_width: u16, min_widths: &[u16]) -> Vec<u16> {
    let mut widths = vec![0; min_widths.len()];
    let mut remaining: Vec<usize> = (0..min_widths.len()).collect();

    let mut remaining_width = area_width;

    while !remaining.is_empty() {
        let count = remaining.len() as u16;
        let equal = remaining_width / count;

        let mut clamped = Vec::new();

        for &i in &remaining {
            if min_widths[i] > equal {
                widths[i] = min_widths[i];
                remaining_width -= min_widths[i];
                clamped.push(i);
            }
        }

        if clamped.is_empty() {
            let mut remainder = remaining_width % count;
            for &i in &remaining {
                widths[i] = equal
                    + if remainder > 0 {
                        remainder -= 1;
                        1
                    } else {
                        0
                    };
            }
            break;
        }

        remaining.retain(|i| !clamped.contains(i));
    }

    widths
}
