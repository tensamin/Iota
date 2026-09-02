use crossterm::event::KeyCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem<T> {
    pub label: String,
    pub description: Option<String>,
    pub value: T,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuState<T> {
    items: Vec<MenuItem<T>>,
    selected: Option<usize>,
}

impl<T> MenuState<T> {
    pub fn new(items: Vec<MenuItem<T>>) -> Self {
        let selected = items.iter().position(|item| item.enabled);
        Self { items, selected }
    }

    pub fn items(&self) -> &[MenuItem<T>] {
        &self.items
    }
    pub fn selected_index(&self) -> Option<usize> {
        self.selected
    }
    pub fn selected_item(&self) -> Option<&MenuItem<T>> {
        self.selected.and_then(|index| self.items.get(index))
    }

    pub fn move_next(&mut self) {
        self.move_by(1);
    }
    pub fn move_previous(&mut self) {
        self.move_by(-1);
    }
    pub fn first(&mut self) {
        self.selected = self.items.iter().position(|item| item.enabled);
    }
    pub fn last(&mut self) {
        self.selected = self.items.iter().rposition(|item| item.enabled);
    }

    pub fn handle_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Up => self.move_previous(),
            KeyCode::Down => self.move_next(),
            KeyCode::Home => self.first(),
            KeyCode::End => self.last(),
            _ => return false,
        }
        true
    }

    fn move_by(&mut self, delta: isize) {
        let Some(current) = self.selected else {
            return;
        };
        for offset in 1..=self.items.len() {
            let next = (current as isize + delta * offset as isize)
                .rem_euclid(self.items.len() as isize) as usize;
            if self.items[next].enabled {
                self.selected = Some(next);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_skips_disabled_items() {
        let mut menu = MenuState::new(vec![
            MenuItem {
                label: "A".into(),
                description: None,
                value: 1,
                enabled: true,
                disabled_reason: None,
            },
            MenuItem {
                label: "B".into(),
                description: None,
                value: 2,
                enabled: false,
                disabled_reason: Some("Unavailable".into()),
            },
            MenuItem {
                label: "C".into(),
                description: None,
                value: 3,
                enabled: true,
                disabled_reason: None,
            },
        ]);
        menu.move_next();
        assert_eq!(menu.selected_index(), Some(2));
    }

    #[test]
    fn empty_enabled_set_is_safe() {
        let mut menu = MenuState::new(vec![MenuItem {
            label: "A".into(),
            description: None,
            value: (),
            enabled: false,
            disabled_reason: None,
        }]);
        menu.move_next();
        menu.last();
        assert_eq!(menu.selected_index(), None);
    }
}
