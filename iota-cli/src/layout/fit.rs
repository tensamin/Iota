use ratatui::layout::Rect;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredSize {
    pub width: u16,
    pub height: u16,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FitLevel {
    Preferred,
    Compact,
    Fallback,
}
pub fn select_fit_level(area: Rect, preferred: RequiredSize, compact: RequiredSize) -> FitLevel {
    if area.width >= preferred.width && area.height >= preferred.height {
        FitLevel::Preferred
    } else if area.width >= compact.width && area.height >= compact.height {
        FitLevel::Compact
    } else {
        FitLevel::Fallback
    }
}
pub fn centered_rect(area: Rect, maximum: RequiredSize) -> Rect {
    let width = area.width.min(maximum.width);
    let height = area.height.min(maximum.height);
    Rect {
        x: area.x.saturating_add(area.width.saturating_sub(width) / 2),
        y: area
            .y
            .saturating_add(area.height.saturating_sub(height) / 2),
        width,
        height,
    }
}
pub fn reserve_vertical(area: Rect, top: u16, bottom: u16) -> Option<Rect> {
    let height = area.height.checked_sub(top)?.checked_sub(bottom)?;
    Some(Rect {
        x: area.x,
        y: area.y.checked_add(top)?,
        width: area.width,
        height,
    })
}
pub fn inset_checked(area: Rect, horizontal: u16, vertical: u16) -> Option<Rect> {
    let width = area.width.checked_sub(horizontal.checked_mul(2)?)?;
    let height = area.height.checked_sub(vertical.checked_mul(2)?)?;
    Some(Rect {
        x: area.x.checked_add(horizontal)?,
        y: area.y.checked_add(vertical)?,
        width,
        height,
    })
}
