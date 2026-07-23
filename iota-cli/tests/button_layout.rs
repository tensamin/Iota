use iota_cli::controls::button::{button_minimum_width, horizontal_button_widths};

#[test]
fn width_allocation_handles_exact_spare_and_insufficient_space() {
    assert_eq!(horizontal_button_widths(7, &[3, 4]), Some(vec![3, 4]));
    assert_eq!(horizontal_button_widths(10, &[3, 4]), Some(vec![5, 5]));
    assert_eq!(horizontal_button_widths(6, &[3, 4]), None);
    assert_eq!(horizontal_button_widths(10, &[]), Some(Vec::new()));
}

#[test]
fn minimum_width_uses_terminal_columns() {
    assert_eq!(button_minimum_width("é"), 3);
    assert_eq!(button_minimum_width("界"), 4);
}
