use crate::theme::ResolvedTheme;

/// Immutable state shared by every component during one render pass.
pub struct RenderContext<'a> {
    pub theme: &'a ResolvedTheme,
}
