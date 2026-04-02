use ratatui::layout::Rect;
use ratatui::prelude::*;
use ratatui::style::Style;
use ratatui::widgets::Borders;

fn set_join_char(frame: &mut Frame, x: u16, y: u16, c: char) {
    frame
        .buffer_mut()
        .set_string(x, y, c.to_string(), Style::default());
}

pub fn draw_block_joins(frame: &mut Frame, area: Rect, borders: Borders, joins: Borders) {
    let x0 = area.x;
    let y0 = area.y;
    let x1 = area.x + area.width - 1;
    let y1 = area.y + area.height - 1;

    if borders.contains(Borders::TOP) && borders.contains(Borders::LEFT) {
        let top_left = match (joins.contains(Borders::TOP), joins.contains(Borders::LEFT)) {
            (true, true) => '┼',
            (true, false) => '├',
            (false, true) => '┬',
            (false, false) => '┌',
        };
        set_join_char(frame, x0, y0, top_left);
    }

    if borders.contains(Borders::TOP) && borders.contains(Borders::RIGHT) {
        let top_right = match (joins.contains(Borders::TOP), joins.contains(Borders::RIGHT)) {
            (true, true) => '┼',
            (true, false) => '┤',
            (false, true) => '┬',
            (false, false) => '┐',
        };
        set_join_char(frame, x1, y0, top_right);
    }

    if borders.contains(Borders::BOTTOM) && borders.contains(Borders::LEFT) {
        let bottom_left = match (
            joins.contains(Borders::BOTTOM),
            joins.contains(Borders::LEFT),
        ) {
            (true, true) => '┼',
            (true, false) => '├',
            (false, true) => '┴',
            (false, false) => '└',
        };
        set_join_char(frame, x0, y1, bottom_left);
    }

    if borders.contains(Borders::BOTTOM) && borders.contains(Borders::RIGHT) {
        let bottom_right = match (
            joins.contains(Borders::BOTTOM),
            joins.contains(Borders::RIGHT),
        ) {
            (true, true) => '┼',
            (true, false) => '┤',
            (false, true) => '┴',
            (false, false) => '┘',
        };
        set_join_char(frame, x1, y1, bottom_right);
    }
}
