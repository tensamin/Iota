use iota_cli::layout::fit::{
    FitLevel, RequiredSize, centered_rect, inset_checked, reserve_vertical, select_fit_level,
};
use ratatui::layout::Rect;

#[test]
fn selects_fit_by_both_dimensions() {
    let preferred = RequiredSize {
        width: 80,
        height: 20,
    };
    let compact = RequiredSize {
        width: 50,
        height: 12,
    };
    assert_eq!(
        select_fit_level(Rect::new(0, 0, 80, 20), preferred, compact),
        FitLevel::Preferred
    );
    assert_eq!(
        select_fit_level(Rect::new(0, 0, 50, 12), preferred, compact),
        FitLevel::Compact
    );
    assert_eq!(
        select_fit_level(Rect::new(0, 0, 80, 11), preferred, compact),
        FitLevel::Fallback
    );
}

#[test]
fn rectangle_helpers_do_not_underflow() {
    let zero = Rect::new(4, 5, 0, 0);
    assert_eq!(
        centered_rect(
            zero,
            RequiredSize {
                width: 10,
                height: 10
            }
        ),
        zero
    );
    assert_eq!(reserve_vertical(zero, 1, 0), None);
    assert_eq!(inset_checked(zero, 1, 1), None);
}
