use std::env;

#[derive(Debug, Clone, Copy)]
pub struct ColorConfig {
    pub enabled: bool,
}

impl Default for ColorConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ColorConfig {
    pub fn new() -> Self {
        let enabled = env::var("NO_COLOR").is_err()
            && env::var("TERM")
                .map(|t| t != "dumb")
                .unwrap_or(true);
        Self { enabled }
    }

    pub fn colorize(&self, text: &str, style: Style) -> String {
        if !self.enabled {
            return text.to_string();
        }
        format!("{}{}\x1b[0m", style.prefix(), text)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub fg: Option<u8>,
    pub bg: Option<u8>,
    pub bold: bool,
}

impl Style {
    pub const fn new() -> Self {
        Self {
            fg: None,
            bg: None,
            bold: false,
        }
    }

    pub const fn fg(mut self, color: u8) -> Self {
        self.fg = Some(color);
        self
    }

    pub const fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    fn prefix(&self) -> String {
        let mut codes = Vec::new();
        if self.bold {
            codes.push("1".to_string());
        }
        if let Some(fg) = self.fg {
            codes.push(format!("3{}", fg));
        }
        if let Some(bg) = self.bg {
            codes.push(format!("4{}", bg));
        }
        if codes.is_empty() {
            String::new()
        } else {
            format!("\x1b[{}m", codes.join(";"))
        }
    }
}

pub const SUCCESS: Style = Style::new().fg(2);
pub const WARNING: Style = Style::new().fg(3);
pub const ERROR: Style = Style::new().fg(1);
pub const INFO: Style = Style::new().fg(4);
pub const MUTED: Style = Style::new().fg(8);
pub const HEADING: Style = Style::new().bold();

pub fn success(config: &ColorConfig, text: &str) -> String {
    config.colorize(text, SUCCESS)
}

pub fn warning(config: &ColorConfig, text: &str) -> String {
    config.colorize(text, WARNING)
}

pub fn error(config: &ColorConfig, text: &str) -> String {
    config.colorize(text, ERROR)
}

pub fn info(config: &ColorConfig, text: &str) -> String {
    config.colorize(text, INFO)
}

pub fn muted(config: &ColorConfig, text: &str) -> String {
    config.colorize(text, MUTED)
}

pub fn heading(config: &ColorConfig, text: &str) -> String {
    config.colorize(text, HEADING)
}
