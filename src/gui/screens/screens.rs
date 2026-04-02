use std::any::Any;

use crossterm::event::KeyEvent;
use ratatui::{Frame, layout::Rect};

use crate::gui::interaction_result::InteractionResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavDirection {
    Up,
    Down,
    Left,
    Right,

    Next,
    Prev,
}

pub trait Screen: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn render(&self, f: &mut Frame, rect: Rect);
    fn handle_input(&mut self, event: KeyEvent) -> InteractionResult;
}
