use super::{choice::ChoiceVisualState, navigation::DisabledFocusPolicy};

pub struct RadioItem<T> {
    pub value: T,
    pub label: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
}
pub struct RadioGroup<T: Clone + Eq> {
    items: Vec<RadioItem<T>>,
    selected: T,
    default: T,
    focused_index: usize,
    focus_policy: DisabledFocusPolicy,
    wrap_navigation: bool,
    disabled_selection_policy: DisabledSelectionPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadioGroupError {
    Empty,
    DefaultMissing,
    DefaultDisabled,
    NoEnabledItems,
    SelectedItemDisabled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadioChange<T> {
    Changed { previous: T, selected: T },
    Unchanged(T),
    IgnoredDisabled(T),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledSelectionPolicy {
    UseConfiguredDefault,
    UseFirstEnabled,
    ReturnError,
}
impl<T: Clone + Eq> RadioGroup<T> {
    pub fn new(
        items: Vec<RadioItem<T>>,
        observed: Option<T>,
        default: T,
    ) -> Result<Self, RadioGroupError> {
        if items.is_empty() {
            return Err(RadioGroupError::Empty);
        }
        let default_item = items
            .iter()
            .find(|item| item.value == default)
            .ok_or(RadioGroupError::DefaultMissing)?;
        if !default_item.enabled {
            return Err(RadioGroupError::DefaultDisabled);
        }
        let focused_index = items
            .iter()
            .position(|item| item.enabled)
            .ok_or(RadioGroupError::NoEnabledItems)?;
        let selected = observed
            .filter(|value| {
                items
                    .iter()
                    .any(|item| item.enabled && item.value == *value)
            })
            .unwrap_or_else(|| default.clone());
        Ok(Self {
            items,
            selected,
            default,
            focused_index,
            focus_policy: DisabledFocusPolicy::Skip,
            wrap_navigation: true,
            disabled_selection_policy: DisabledSelectionPolicy::UseConfiguredDefault,
        })
    }
    pub fn items(&self) -> &[RadioItem<T>] {
        &self.items
    }
    pub fn selected(&self) -> &T {
        &self.selected
    }
    pub fn focused_item(&self) -> &RadioItem<T> {
        &self.items[self.focused_index]
    }
    pub fn focus_next(&mut self) {
        self.move_focus(true);
    }
    pub fn focus_previous(&mut self) {
        self.move_focus(false);
    }
    fn move_focus(&mut self, forward: bool) {
        for step in 1..=self.items.len() {
            let raw = self.focused_index as isize
                + if forward {
                    step as isize
                } else {
                    -(step as isize)
                };
            let next = if self.wrap_navigation {
                raw.rem_euclid(self.items.len() as isize) as usize
            } else if raw < 0 || raw >= self.items.len() as isize {
                return;
            } else {
                raw as usize
            };
            if self.focus_policy == DisabledFocusPolicy::Include || self.items[next].enabled {
                self.focused_index = next;
                return;
            }
        }
    }
    pub fn select_focused(&mut self) -> RadioChange<T> {
        let item = self.focused_item();
        let enabled = item.enabled;
        let value = item.value.clone();
        if !enabled {
            return RadioChange::IgnoredDisabled(value);
        }
        if value == self.selected {
            RadioChange::Unchanged(self.selected.clone())
        } else {
            let previous = std::mem::replace(&mut self.selected, value);
            RadioChange::Changed {
                previous,
                selected: self.selected.clone(),
            }
        }
    }
    pub fn visual_state(&self, value: &T) -> ChoiceVisualState {
        let item = self.items.iter().position(|item| &item.value == value);
        ChoiceVisualState {
            selected: &self.selected == value,
            focused: item == Some(self.focused_index),
            enabled: item
                .and_then(|index| self.items.get(index))
                .is_some_and(|item| item.enabled),
        }
    }
    pub fn set_disabled_selection_policy(&mut self, policy: DisabledSelectionPolicy) {
        self.disabled_selection_policy = policy;
    }
    pub fn set_focus_policy(&mut self, policy: DisabledFocusPolicy) {
        self.focus_policy = policy;
    }
    pub fn set_wrap_navigation(&mut self, wrap: bool) {
        self.wrap_navigation = wrap;
    }
    pub fn set_enabled(&mut self, value: &T, enabled: bool) -> Result<(), RadioGroupError> {
        let Some(index) = self.items.iter().position(|item| &item.value == value) else {
            return Ok(());
        };
        if self.items[index].enabled == enabled {
            return Ok(());
        }
        if !enabled
            && self
                .items
                .iter()
                .enumerate()
                .all(|(other, item)| other == index || !item.enabled)
        {
            return Err(RadioGroupError::NoEnabledItems);
        }
        if !enabled && self.selected == *value {
            let replacement = match self.disabled_selection_policy {
                DisabledSelectionPolicy::UseConfiguredDefault if self.default != *value => self
                    .items
                    .iter()
                    .find(|item| item.enabled && item.value == self.default)
                    .map(|item| item.value.clone()),
                DisabledSelectionPolicy::UseConfiguredDefault => None,
                DisabledSelectionPolicy::UseFirstEnabled => self
                    .items
                    .iter()
                    .enumerate()
                    .find(|(other, item)| *other != index && item.enabled)
                    .map(|(_, item)| item.value.clone()),
                DisabledSelectionPolicy::ReturnError => {
                    return Err(RadioGroupError::SelectedItemDisabled);
                }
            };
            self.selected = replacement.ok_or(RadioGroupError::SelectedItemDisabled)?;
        }
        self.items[index].enabled = enabled;
        if !enabled && self.focused_index == index && self.focus_policy == DisabledFocusPolicy::Skip
        {
            self.focus_next();
        }
        Ok(())
    }
    pub fn default(&self) -> &T {
        &self.default
    }
}
