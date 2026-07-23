use iota_cli::controls::{
    checkbox_group::{CheckboxChange, CheckboxGroup, CheckboxItem},
    navigation::DisabledFocusPolicy,
    radio_group::{DisabledSelectionPolicy, RadioChange, RadioGroup, RadioGroupError, RadioItem},
};

fn checkbox(value: u8, enabled: bool) -> CheckboxItem<u8> {
    CheckboxItem {
        value,
        label: value.to_string(),
        description: None,
        enabled,
        disabled_reason: None,
    }
}

fn radio(value: u8, enabled: bool) -> RadioItem<u8> {
    RadioItem {
        value,
        label: value.to_string(),
        description: None,
        enabled,
        disabled_reason: None,
    }
}

#[test]
fn checkbox_selection_and_disabled_focus_are_independent() {
    let mut group = CheckboxGroup::new(
        vec![checkbox(1, true), checkbox(2, false), checkbox(3, true)],
        [1, 99],
    )
    .unwrap();
    assert_eq!(
        group.selected().iter().copied().collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(group.toggle_focused(), CheckboxChange::Deselected(1));
    group.focus_next();
    assert_eq!(group.focused_item().unwrap().value, 3);
    group.set_focus_policy(DisabledFocusPolicy::Include);
    group.focus_previous();
    assert_eq!(group.focused_item().unwrap().value, 2);
    assert_eq!(group.toggle_focused(), CheckboxChange::IgnoredDisabled(2));
}

#[test]
fn checkbox_non_wrapping_navigation_stops_at_the_edge() {
    let mut group = CheckboxGroup::new(vec![checkbox(1, true), checkbox(2, true)], []).unwrap();
    group.set_wrap_navigation(false);
    group.focus_previous();
    assert_eq!(group.focused_item().unwrap().value, 1);
}

#[test]
fn radio_validates_default_and_preserves_one_selection() {
    assert!(matches!(
        RadioGroup::new(Vec::<RadioItem<u8>>::new(), None, 1),
        Err(RadioGroupError::Empty)
    ));
    assert!(matches!(
        RadioGroup::new(vec![radio(1, true)], None, 2),
        Err(RadioGroupError::DefaultMissing)
    ));
    assert!(matches!(
        RadioGroup::new(vec![radio(1, false)], None, 1),
        Err(RadioGroupError::DefaultDisabled)
    ));

    let mut group = RadioGroup::new(vec![radio(1, true), radio(2, true)], Some(2), 1).unwrap();
    assert_eq!(group.selected(), &2);
    group.focus_next();
    assert_eq!(group.selected(), &2);
    assert_eq!(group.select_focused(), RadioChange::Unchanged(2));
    group.focus_previous();
    assert_eq!(
        group.select_focused(),
        RadioChange::Changed {
            previous: 2,
            selected: 1
        }
    );
    assert_eq!(group.selected(), &1);
}

#[test]
fn groups_initially_focus_the_first_enabled_item() {
    let checkboxes = CheckboxGroup::new(vec![checkbox(1, false), checkbox(2, true)], []).unwrap();
    assert_eq!(checkboxes.focused_item().unwrap().value, 2);
    let radios = RadioGroup::new(vec![radio(1, false), radio(2, true)], None, 2).unwrap();
    assert_eq!(radios.focused_item().value, 2);
}

#[test]
fn disabling_a_selected_radio_obeys_the_configured_policy() {
    let mut group = RadioGroup::new(vec![radio(1, true), radio(2, true)], Some(2), 1).unwrap();
    group.set_enabled(&2, false).unwrap();
    assert_eq!(group.selected(), &1);

    group.set_enabled(&2, true).unwrap();
    group.focus_next();
    group.select_focused();
    group.set_disabled_selection_policy(DisabledSelectionPolicy::ReturnError);
    assert_eq!(
        group.set_enabled(&2, false),
        Err(RadioGroupError::SelectedItemDisabled)
    );
    assert_eq!(group.selected(), &2);
}
