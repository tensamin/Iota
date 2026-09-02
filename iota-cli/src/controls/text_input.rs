use crossterm::event::KeyCode;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextInput {
    value: String,
    cursor: usize,
    label: Option<String>,
    placeholder: Option<String>,
    validation: Option<String>,
    secret: bool,
}

impl TextInput {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: Some(label.into()),
            ..Self::default()
        }
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn display_value(&self) -> String {
        if self.secret {
            "•".repeat(self.value.chars().count())
        } else {
            self.value.clone()
        }
    }
    pub fn set_placeholder(&mut self, value: impl Into<String>) {
        self.placeholder = Some(value.into());
    }
    pub fn placeholder(&self) -> Option<&str> {
        self.placeholder.as_deref()
    }
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
    pub fn validation(&self) -> Option<&str> {
        self.validation.as_deref()
    }
    pub fn set_validation(&mut self, value: Option<String>) {
        self.validation = value;
    }
    pub fn set_secret(&mut self, secret: bool) {
        self.secret = secret;
    }
    pub fn handle_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let start = self.value[..self.cursor]
                        .char_indices()
                        .last()
                        .map(|(index, _)| index)
                        .unwrap_or(0);
                    self.value.drain(start..self.cursor);
                    self.cursor = start;
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.value.len() {
                    let end = self.value[self.cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(index, _)| self.cursor + index)
                        .unwrap_or(self.value.len());
                    self.value.drain(self.cursor..end);
                }
            }
            KeyCode::Left => {
                if self.cursor > 0 {
                    self.cursor = self.value[..self.cursor]
                        .char_indices()
                        .last()
                        .map(|(index, _)| index)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if self.cursor < self.value.len() {
                    self.cursor = self.value[self.cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(index, _)| self.cursor + index)
                        .unwrap_or(self.value.len());
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.value.len(),
            KeyCode::Char(character) => {
                self.value.insert(self.cursor, character);
                self.cursor += character.len_utf8();
            }
            _ => return false,
        }
        true
    }
}
