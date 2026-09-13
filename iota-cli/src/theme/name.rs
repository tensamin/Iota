use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThemeName {
    Monospace,
    Binary,
    #[default]
    Ansi,
    Surface,
}

impl ThemeName {
    pub const ALL: [Self; 4] = [Self::Monospace, Self::Binary, Self::Ansi, Self::Surface];

    pub fn supported_names() -> &'static str {
        "monospace, binary, ansi, surface"
    }

    pub fn ratatool_id(self) -> ratatool::ThemeId {
        ratatool::ThemeId::new(self.to_string())
    }
}

impl fmt::Display for ThemeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Monospace => "monospace",
            Self::Binary => "binary",
            Self::Ansi => "ansi",
            Self::Surface => "surface",
        })
    }
}

impl FromStr for ThemeName {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "monospace" => Ok(Self::Monospace),
            "binary" => Ok(Self::Binary),
            "ansi" => Ok(Self::Ansi),
            "surface" => Ok(Self::Surface),
            _ => Err(format!(
                "unknown theme `{value}`; supported themes: {}",
                Self::supported_names()
            )),
        }
    }
}
