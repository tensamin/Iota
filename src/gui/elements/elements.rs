use std::any::Any;

use crossterm::event::KeyEvent;
use ratatui::{Frame, layout::Rect, widgets::Borders};

use crate::gui::{interaction_result::InteractionResult, screens::screens::Screen};

#[allow(unused)]
pub trait Element: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn render(&self, f: &mut Frame, r: Rect);
}

#[allow(unused)]
pub trait JoinableElement: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn as_element(&self) -> &dyn Element;
    fn as_element_mut(&mut self) -> &mut dyn Element;

    fn set_borders(&mut self, borders: Borders);
    fn set_joins(&mut self, joins: Borders);
}

#[allow(unused)]
pub trait InfoElement: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn as_element(&self) -> &dyn Element;
    fn as_element_mut(&mut self) -> &mut dyn Element;

    fn get_info_screen(&self) -> Box<dyn Screen>;
}

#[allow(unused)]
pub trait InteractableElement: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn as_element(&self) -> &dyn Element;
    fn as_element_mut(&mut self) -> &mut dyn Element;

    fn interact(&mut self, key: KeyEvent) -> InteractionResult;

    fn can_focus(&self) -> bool;
    fn is_focused(&self) -> bool;
    fn focus(&mut self, f: bool);
}
