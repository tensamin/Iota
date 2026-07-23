mod config;
mod model;
mod name;
mod presets;

pub use config::{DaemonStartPolicy, UiConfig};
pub use model::*;
pub use name::ThemeName;

pub fn resolve(name: ThemeName) -> ResolvedTheme {
    presets::resolve(name)
}
