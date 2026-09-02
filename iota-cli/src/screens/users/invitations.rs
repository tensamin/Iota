/* Invitation state remains capability-gated until the daemon implements its protocol. */
pub const UNSUPPORTED_MESSAGE: &str =
    "Invitation management is not supported by the connected daemon.";

pub fn empty_message(supported: bool) -> &'static str {
    if supported {
        "No invitations.\n\nInvitation protocol support is not implemented in this client build."
    } else {
        "No invitations.\n\nInvitation management is not supported by the connected daemon."
    }
}

pub fn render(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    context: &crate::render_context::RenderContext<'_>,
    supported: bool,
) {
    frame.render_widget(
        ratatui::widgets::Paragraph::new(empty_message(supported)).style(context.theme.text.muted),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::{UNSUPPORTED_MESSAGE, empty_message};

    #[test]
    fn absent_capability_is_explained_in_the_empty_state() {
        assert!(empty_message(false).contains(UNSUPPORTED_MESSAGE));
    }

    #[test]
    fn supported_daemon_does_not_show_the_capability_error() {
        assert!(!empty_message(true).contains(UNSUPPORTED_MESSAGE));
    }
}
