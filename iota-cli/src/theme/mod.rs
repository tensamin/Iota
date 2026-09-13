mod config;
mod model;
mod name;
mod presets;

pub use config::{CliOutputFormat, DaemonStartPolicy, TerminalPolicy, UiConfig};
pub use model::*;
pub use name::ThemeName;

pub fn ratatool_policy(policy: TerminalPolicy) -> ratatool::CapabilityPolicy {
    match policy {
        TerminalPolicy::Auto => ratatool::CapabilityPolicy::Auto,
        TerminalPolicy::Always => ratatool::CapabilityPolicy::Force,
        TerminalPolicy::Never => ratatool::CapabilityPolicy::Disable,
    }
}

pub fn terminal_options(
    color: TerminalPolicy,
    unicode: TerminalPolicy,
) -> ratatool::TerminalOptions {
    ratatool::TerminalOptions {
        color: ratatool_policy(color),
        unicode: ratatool_policy(unicode),
        overrides: Default::default(),
    }
}

pub fn registry() -> ratatool::ThemeRegistry {
    let mut registry = ratatool::ThemeRegistry::new();
    let plain = presets::resolve(ThemeName::Monospace);
    let styled = presets::resolve(ThemeName::Binary);
    let ansi = presets::resolve(ThemeName::Ansi);
    for name in ThemeName::ALL {
        let selected = presets::resolve(name);
        let color = if matches!(name, ThemeName::Surface) {
            &ansi
        } else {
            &selected
        };
        registry.register(ratatool::ThemeFamily::new(
            name.ratatool_id(),
            generic_variant(&selected),
            generic_variant(color),
            generic_variant(&styled),
            generic_variant(&plain),
        ));
    }
    registry
}

fn generic_variant(theme: &ResolvedTheme) -> ratatool::ThemeVariant {
    ratatool::ThemeVariant {
        text: ratatool::TextTheme {
            normal: theme.text.normal,
            muted: theme.text.muted,
            emphasis: theme.text.heading,
            disabled: theme.borders.disabled,
            heading: theme.text.heading,
            link: theme.text.link,
            code: theme.text.code,
        },
        borders: ratatool::BorderTheme {
            normal: theme.borders.normal,
            focused: theme.borders.focused,
            disabled: theme.borders.disabled,
        },
        surfaces: ratatool::SurfaceTheme {
            background: theme.surfaces.canvas,
            panel: theme.surfaces.panel,
            panel_focused: theme.surfaces.panel_focused,
            panel_header: theme.surfaces.panel_alternate,
            raised: theme.surfaces.panel_alternate,
            toolbar: theme.surfaces.toolbar,
            footer: theme.surfaces.footer,
            overlay: theme.surfaces.overlay,
        },
        buttons: ratatool::ButtonTheme {
            primary: theme.buttons.primary,
            primary_focused: theme.buttons.primary_focused,
            secondary: theme.buttons.neutral,
            secondary_focused: theme.buttons.neutral_focused,
            cancel: theme.buttons.cancel,
            cancel_focused: theme.buttons.cancel_focused,
            destructive: theme.buttons.destructive,
            destructive_focused: theme.buttons.destructive,
            disabled: theme.buttons.disabled,
        },
        status: ratatool::StatusTheme {
            info: theme.status.info,
            success: theme.status.success,
            warning: theme.status.warning,
            error: theme.status.error,
        },
        input: ratatool::InputTheme {
            normal: theme.text.normal,
            focused: theme.borders.focused,
            placeholder: theme.text.muted,
            selection: theme.surfaces.panel_selected,
        },
        selection: ratatool::SelectionTheme {
            normal: theme.text.normal,
            selected: theme.surfaces.panel_selected,
            focused: theme.borders.focused,
            disabled: theme.borders.disabled,
        },
        metrics: ratatool::ThemeMetrics {
            panel_presentation: match theme.chrome {
                ChromeMode::Bordered => ratatool::PanelPresentation::Bordered,
                ChromeMode::Surfaces => ratatool::PanelPresentation::Surface,
            },
        },
    }
}

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
    fn terminal_profile_changes_preserve_surface_identity() {
        let registry = registry();
        let mut state = ratatool::ThemeState::new(
            ThemeName::Surface.ratatool_id(),
            ratatool::TerminalProfile::truecolor_unicode(),
            &registry,
        )
        .unwrap();
        state
            .set_profile(ratatool::TerminalProfile::ansi16_unicode(), &registry)
            .unwrap();
        assert_eq!(state.selected(), &ThemeName::Surface.ratatool_id());
        assert_eq!(state.profile().color_depth, ratatool::ColorDepth::Ansi16);
    }
}
