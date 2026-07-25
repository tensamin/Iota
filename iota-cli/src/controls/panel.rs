use crate::theme::{ChromeMode, ResolvedTheme};
use ratatui::{Frame, layout::Rect, widgets::{Block, Borders, Paragraph}};

/// Draw a conventional outlined panel or a filled surface from the same call
/// site.  Screens can migrate without embedding theme branches in layouts.
pub fn render_panel(frame: &mut Frame, area: Rect, title: &str, focused: bool, theme: &ResolvedTheme) -> Rect {
    match theme.chrome {
        ChromeMode::Bordered => {
            let block = Block::default().title(title).borders(Borders::ALL).border_style(if focused { theme.borders.focused } else { theme.borders.normal });
            let inner = block.inner(area);
            frame.render_widget(block, area);
            inner
        }
        ChromeMode::Surfaces => {
            frame.render_widget(Block::default().style(if focused { theme.surfaces.panel_focused } else { theme.surfaces.panel }), area);
            let header = Rect { x: area.x, y: area.y, width: area.width, height: area.height.min(1) };
            frame.render_widget(Paragraph::new(format!("  {title}")).style(theme.surfaces.panel_alternate), header);
            // Surface panels use a single header row. A one-cell inset keeps
            // compact controls such as the console usable at height three.
            Rect { x: area.x.saturating_add(1), y: area.y.saturating_add(1), width: area.width.saturating_sub(2), height: area.height.saturating_sub(1) }
        }
    }
}
