use super::{choice::ChoiceVisualState, navigation::DisabledFocusPolicy};
use std::{collections::HashSet, hash::Hash};

pub struct CheckboxItem<T> {
    pub value: T,
    pub label: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
}
pub struct CheckboxGroup<T: Clone + Eq + Hash> {
    items: Vec<CheckboxItem<T>>,
    selected: HashSet<T>,
    focused_index: usize,
    focus_policy: DisabledFocusPolicy,
    wrap_navigation: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckboxGroupError {
    Empty,
    DuplicateValue,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckboxChange<T> {
    Selected(T),
    Deselected(T),
    IgnoredDisabled(T),
    NoItem,
}
impl<T: Clone + Eq + Hash> CheckboxGroup<T> {
    pub fn new(
        items: Vec<CheckboxItem<T>>,
        selected: impl IntoIterator<Item = T>,
    ) -> Result<Self, CheckboxGroupError> {
        let mut values = HashSet::new();
        if items.iter().any(|item| !values.insert(item.value.clone())) {
            return Err(CheckboxGroupError::DuplicateValue);
        }
        let selected = selected
            .into_iter()
            .filter(|value| values.contains(value))
            .collect();
        let focused_index = items.iter().position(|item| item.enabled).unwrap_or(0);
        Ok(Self {
            items,
            selected,
            focused_index,
            focus_policy: DisabledFocusPolicy::Skip,
            wrap_navigation: true,
        })
    }
    pub fn items(&self) -> &[CheckboxItem<T>] {
        &self.items
    }
    pub fn selected(&self) -> &HashSet<T> {
        &self.selected
    }
    pub fn focused_item(&self) -> Option<&CheckboxItem<T>> {
        self.items.get(self.focused_index)
    }
    pub fn set_focus_policy(&mut self, policy: DisabledFocusPolicy) {
        self.focus_policy = policy;
    }
    pub fn set_wrap_navigation(&mut self, wrap: bool) {
        self.wrap_navigation = wrap;
    }
    pub fn focus_next(&mut self) {
        self.move_focus(true);
    }
    pub fn focus_previous(&mut self) {
        self.move_focus(false);
    }
    fn move_focus(&mut self, forward: bool) {
        if self.items.is_empty() {
            return;
        }
        for step in 1..=self.items.len() {
            let current = self.focused_index as isize;
            let delta = if forward {
                step as isize
            } else {
                -(step as isize)
            };
            let raw = current + delta;
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
    pub fn toggle_focused(&mut self) -> CheckboxChange<T> {
        let Some(item) = self.items.get(self.focused_index) else {
            return CheckboxChange::NoItem;
        };
        let value = item.value.clone();
        if !item.enabled {
            return CheckboxChange::IgnoredDisabled(value);
        }
        if self.selected.remove(&value) {
            CheckboxChange::Deselected(value)
        } else {
            self.selected.insert(value.clone());
            CheckboxChange::Selected(value)
        }
    }
    pub fn set_enabled(&mut self, value: &T, enabled: bool) {
        if let Some(item) = self.items.iter_mut().find(|item| &item.value == value) {
            item.enabled = enabled;
        }
    }
    pub fn set_selected(&mut self, value: T, selected: bool) {
        if selected {
            self.selected.insert(value);
        } else {
            self.selected.remove(&value);
        }
    }
    pub fn visual_state(&self, value: &T) -> ChoiceVisualState {
        let item = self.items.iter().position(|item| &item.value == value);
        ChoiceVisualState {
            selected: self.selected.contains(value),
            focused: item == Some(self.focused_index),
            enabled: item
                .and_then(|index| self.items.get(index))
                .is_some_and(|item| item.enabled),
        }
    }
}
