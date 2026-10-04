use super::ThemeName;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UiConfig {
    #[serde(default)]
    pub theme: ThemeName,
    /// Whether opening the interactive UI should launch a locally installed daemon.
    #[serde(default)]
    pub daemon_start_policy: DaemonStartPolicy,
    #[serde(default)]
    pub color: TerminalPolicy,
    #[serde(default)]
    pub unicode: TerminalPolicy,
    /// Default CLI output format for headless commands.
    #[serde(default)]
    pub cli_output: CliOutputFormat,
    /// Whether destructive CLI operations require --yes by default.
    #[serde(default = "default_false")]
    pub cli_require_confirmation: bool,
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CliOutputFormat {
    #[default]
    Text,
    Json,
    Yaml,
    Table,
}

impl CliOutputFormat {
    pub fn all() -> &'static [CliOutputFormat] {
        &[
            CliOutputFormat::Text,
            CliOutputFormat::Json,
            CliOutputFormat::Yaml,
            CliOutputFormat::Table,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            CliOutputFormat::Text => "text",
            CliOutputFormat::Json => "json",
            CliOutputFormat::Yaml => "yaml",
            CliOutputFormat::Table => "table",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            CliOutputFormat::Text => CliOutputFormat::Json,
            CliOutputFormat::Json => CliOutputFormat::Yaml,
            CliOutputFormat::Yaml => CliOutputFormat::Table,
            CliOutputFormat::Table => CliOutputFormat::Text,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TerminalPolicy {
    #[default]
    Auto,
    Always,
    Never,
}

impl TerminalPolicy {
    pub fn next(&self) -> Self {
        match self {
            TerminalPolicy::Auto => TerminalPolicy::Always,
            TerminalPolicy::Always => TerminalPolicy::Never,
            TerminalPolicy::Never => TerminalPolicy::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DaemonStartPolicy {
    #[default]
    Ask,
    WithUi,
}
impl Serialize for DaemonStartPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Ask => serializer.serialize_str("ask"),
            Self::WithUi => serializer.serialize_str("with_ui"),
        }
    }
}
impl<'de> Deserialize<'de> for DaemonStartPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Compat {
            Policy(String),
            Legacy(bool),
        }
        match Compat::deserialize(deserializer)? {
            Compat::Policy(v) if v == "with_ui" || v == "WithUi" => Ok(Self::WithUi),
            Compat::Policy(_) => Ok(Self::Ask),
            Compat::Legacy(true) => Ok(Self::WithUi),
            Compat::Legacy(false) => Ok(Self::Ask),
        }
    }
}
impl UiConfig {
    pub fn path() -> PathBuf {
        iota_paths::config_dir().join("ui.yaml")
    }

    fn fallback_path() -> Option<PathBuf> {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|d| d.join(".config").join("iota").join("ui.yaml"))
    }

    pub fn load() -> Result<Self, io::Error> {
        let path = match std::panic::catch_unwind(Self::path) {
            Ok(path) => path,
            Err(_) => Self::fallback_path().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "could not determine config path")
            })?,
        };
        Self::load_from(&path)
    }

    fn load_from(path: &Path) -> Result<Self, io::Error> {
        if !path.exists() {
            return Ok(Self::default());
        }
        serde_yaml::from_str(&fs::read_to_string(path)?).map_err(io::Error::other)
    }

    pub fn save(&self) -> Result<(), io::Error> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let yaml = serde_yaml::to_string(self).map_err(io::Error::other)?;
        fs::write(path, yaml)
    }

    /// Load from config path, or return defaults if the config path can't be resolved.
    /// This avoids panics when `IOTA_SOCKET` is not set (e.g. in unit tests).
    pub fn load_or_default() -> Self {
        Self::load().unwrap_or_default()
    }

    pub fn resolve_theme(override_theme: Option<ThemeName>) -> ThemeName {
        Self::resolve_theme_from(
            override_theme,
            std::env::var("IOTA_THEME").ok().as_deref(),
            &Self::path(),
        )
    }

    fn resolve_theme_from(
        override_theme: Option<ThemeName>,
        environment_theme: Option<&str>,
        config_path: &Path,
    ) -> ThemeName {
        if let Some(theme) = override_theme {
            return theme;
        }
        if let Some(value) = environment_theme {
            match ThemeName::from_str(value) {
                Ok(theme) => return theme,
                Err(error) => {
                    eprintln!("Invalid IOTA_THEME value: {error}; checking UI configuration.");
                }
            }
        }
        match Self::load_from(config_path) {
            Ok(config) => config.theme,
            Err(error) => {
                eprintln!(
                    "Could not read UI configuration {}: {error}; using ansi.",
                    config_path.display()
                );
                ThemeName::Ansi
            }
        }
    }

    /// Resolve the default CLI output format from config file and environment.
    /// Priority: IOTA_OUTPUT env var > config file > "text" default.
    pub fn resolve_cli_output(&self) -> CliOutputFormat {
        if let Ok(value) = std::env::var("IOTA_OUTPUT") {
            match value.to_ascii_lowercase().as_str() {
                "json" => return CliOutputFormat::Json,
                "yaml" | "yml" => return CliOutputFormat::Yaml,
                "table" => return CliOutputFormat::Table,
                _ => {}
            }
        }
        self.cli_output
    }

    /// Resolve the default --yes behavior from config file and environment.
    /// Priority: IOTA_YES env var > config file > false default.
    pub fn resolve_cli_require_confirmation(&self) -> bool {
        if let Ok(value) = std::env::var("IOTA_YES") {
            match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "y" => return false,
                "0" | "false" | "no" | "n" => return true,
                _ => {}
            }
        }
        self.cli_require_confirmation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("iota-ui-config-{}-{name}.yaml", std::process::id()))
    }

    #[test]
    fn command_line_override_has_highest_precedence() {
        let path = config_path("override");
        fs::write(&path, "theme: surface\n").unwrap();
        let resolved =
            UiConfig::resolve_theme_from(Some(ThemeName::Binary), Some("monospace"), &path);
        fs::remove_file(path).unwrap();
        assert_eq!(resolved, ThemeName::Binary);
    }

    #[test]
    fn environment_precedes_stored_configuration() {
        let path = config_path("environment");
        fs::write(&path, "theme: surface\n").unwrap();
        let resolved = UiConfig::resolve_theme_from(None, Some("monospace"), &path);
        fs::remove_file(path).unwrap();
        assert_eq!(resolved, ThemeName::Monospace);
    }

    #[test]
    fn stored_configuration_precedes_default() {
        let path = config_path("stored");
        fs::write(&path, "theme: surface\n").unwrap();
        let resolved = UiConfig::resolve_theme_from(None, None, &path);
        fs::remove_file(path).unwrap();
        assert_eq!(resolved, ThemeName::Surface);
    }

    #[test]
    fn invalid_stored_configuration_falls_back_to_ansi() {
        let path = config_path("invalid");
        fs::write(&path, "theme: ultraviolet\n").unwrap();
        let resolved = UiConfig::resolve_theme_from(None, None, &path);
        fs::remove_file(path).unwrap();
        assert_eq!(resolved, ThemeName::Ansi);
    }

    #[test]
    fn missing_configuration_falls_back_to_ansi() {
        let path = config_path("missing");
        let _ = fs::remove_file(&path);
        assert_eq!(
            UiConfig::resolve_theme_from(None, None, &path),
            ThemeName::Ansi
        );
    }

    #[test]
    fn cli_output_defaults_to_text() {
        let config = UiConfig::default();
        assert_eq!(config.resolve_cli_output(), CliOutputFormat::Text);
    }

    #[test]
    fn cli_output_cycles_through_variants() {
        assert_eq!(CliOutputFormat::Text.next(), CliOutputFormat::Json);
        assert_eq!(CliOutputFormat::Json.next(), CliOutputFormat::Yaml);
        assert_eq!(CliOutputFormat::Yaml.next(), CliOutputFormat::Table);
        assert_eq!(CliOutputFormat::Table.next(), CliOutputFormat::Text);
    }

    #[test]
    fn require_confirmation_defaults_to_false() {
        let config = UiConfig::default();
        assert!(!config.resolve_cli_require_confirmation());
    }

    #[test]
    fn cli_output_serializes_roundtrip() {
        let config = UiConfig {
            cli_output: CliOutputFormat::Table,
            cli_require_confirmation: true,
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let loaded: UiConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(loaded.cli_output, CliOutputFormat::Table);
        assert!(loaded.cli_require_confirmation);
    }
}
