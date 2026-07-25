use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};

/// Reusable viewport policy for long, vertically stacked terminal content.
#[derive(Clone, Copy, Debug)]
pub struct ScrollOptions {
    pub show_scrollbar: bool,
    pub render_partial_components: bool,
}
impl Default for ScrollOptions {
    fn default() -> Self {
        Self {
            show_scrollbar: true,
            render_partial_components: true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScrollField {
    pub offset: u16,
    pub options: ScrollOptions,
}
impl ScrollField {
    pub fn up(&mut self, amount: u16) {
        self.offset = self.offset.saturating_sub(amount);
    }
    pub fn down(&mut self, amount: u16, content_height: u16, viewport_height: u16) {
        self.offset = (self.offset.saturating_add(amount))
            .min(content_height.saturating_sub(viewport_height));
    }
    pub fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        content: Paragraph<'_>,
        content_height: u16,
    ) {
        frame.render_widget(content.scroll((self.offset, 0)), area);
        if self.options.show_scrollbar && content_height > area.height {
            let mut state =
                ScrollbarState::new(content_height as usize).position(self.offset as usize);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight),
                area,
                &mut state,
            );
        }
    }
}
