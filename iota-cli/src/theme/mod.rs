mod config;
mod model;
mod name;
mod presets;

pub use config::{CliOutputFormat, DaemonStartPolicy, TerminalPolicy, UiConfig};
pub use model::*;
pub use name::ThemeName;

pub fn resolve(name: ThemeName) -> ResolvedTheme {
    presets::resolve(name)
}

pub fn resolve_with_capabilities(
    name: ThemeName,
    color_enabled: bool,
    unicode_enabled: bool,
) -> ResolvedTheme {
    let mut theme = if color_enabled {
        presets::resolve(name)
    } else {
        presets::resolve(ThemeName::Monospace)
    };
    theme.name = name;
    theme.unicode = unicode_enabled;
    if !unicode_enabled {
        if matches!(theme.console.cursor, CursorPresentation::Character { .. }) {
            theme.console.cursor = CursorPresentation::Character {
                glyph: "|",
                style: theme.console.text,
            };
        }
    }
    theme
}

/// Resolve a theme against the terminal's color depth. Surface uses RGB
/// colors, so a portable ANSI preset is selected when truecolor is absent.
pub fn resolve_with_terminal_profile(
    name: ThemeName,
    color_enabled: bool,
    unicode_enabled: bool,
    truecolor_enabled: bool,
) -> ResolvedTheme {
    let effective = if color_enabled && !truecolor_enabled && matches!(name, ThemeName::Surface) {
        ThemeName::Ansi
    } else {
        name
    };
    resolve_with_capabilities(effective, color_enabled, unicode_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    #[test]
    fn no_color_policy_removes_palette_dependencies() {
        let theme = resolve_with_capabilities(ThemeName::Surface, false, true);
        assert_eq!(theme.name, ThemeName::Surface);
        assert_eq!(theme.status.error.fg, None);
        assert_eq!(theme.surfaces.panel.bg, None);
    }

    #[test]
    fn ascii_policy_replaces_character_cursor() {
        let theme = resolve_with_capabilities(ThemeName::Monospace, false, false);
        assert!(!theme.unicode);
        match theme.console.cursor {
            CursorPresentation::Character { glyph, .. } => assert_eq!(glyph, "|"),
            CursorPresentation::StyledCell(_) => panic!("expected an ASCII character cursor"),
        }
        assert_ne!(theme.graphs.ram, Color::Blue);
    }

    #[test]
    fn surface_uses_ansi_fallback_without_truecolor() {
        let theme = resolve_with_terminal_profile(ThemeName::Surface, true, true, false);
        assert_eq!(theme.name, ThemeName::Ansi);
        assert_eq!(theme.surfaces.panel.bg, None);
    }
}
