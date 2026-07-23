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
    pub fn load() -> Result<Self, io::Error> {
        Self::load_from(&Self::path())
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
}
