use std::{any::Any, sync::Arc};

use crossterm::event::KeyEvent;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{
        Block, Borders,
        canvas::{Canvas, Line},
    },
};

use crate::{
    APP_STATE,
    gui::{
        elements::elements::{Element, InteractableElement, JoinableElement},
        interaction_result::InteractionResult,
        ui::UI,
        util::borders::draw_block_joins,
    },
};

pub enum GRAPHS {
    Ram,
    Cpu,
    Ping,
}

impl GRAPHS {
    pub fn get_color(&self) -> Color {
        match self {
            GRAPHS::Ram => Color::Blue,
            GRAPHS::Cpu => Color::Red,
            GRAPHS::Ping => Color::Green,
        }
    }

    pub fn get_graph(&self) -> Vec<(f64, f64)> {
        match self {
            GRAPHS::Ram => APP_STATE.lock().unwrap().with_width(28).ram.clone(),
            GRAPHS::Cpu => APP_STATE.lock().unwrap().with_width(28).cpu.clone(),
            GRAPHS::Ping => APP_STATE.lock().unwrap().with_width(28).ping.clone(),
        }
    }

    pub fn get_unit(&self) -> String {
        match self {
            GRAPHS::Ram => "MB".to_string(),
            GRAPHS::Cpu => "%".to_string(),
            GRAPHS::Ping => "ms".to_string(),
        }
    }
}

#[allow(unused)]
pub struct GraphCard {
    ui: Arc<UI>,
    graph_type: GRAPHS,

    focused: bool,
    pub title: String,

    borders: Borders,
    joins: Borders,

    open: bool,
}

impl GraphCard {
    pub fn new(ui: Arc<UI>, graph_type: GRAPHS, title: String) -> Self {
        Self {
            ui,
            graph_type,
            focused: false,
            title,
            borders: Borders::ALL,
            joins: Borders::NONE,
            open: true,
        }
    }

    pub fn set_open(&mut self, open: bool) {
        self.open = open;
    }
}
impl Element for GraphCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, r: Rect) {
        if self.open {
            let graph = self.graph_type.get_graph();
            let unit = self.graph_type.get_unit();
            let min_x = graph.first().map(|(x, _)| *x).unwrap_or(0.0);
            let max_x = graph.last().map(|(x, _)| *x).unwrap_or(100.0);
            let min_y = graph
                .iter()
                .map(|(_, y)| *y)
                .filter(|y| *y > 0.0)
                .min_by(|a, b| a.total_cmp(b))
                .unwrap_or(0.0);
            let max_y = graph.iter().map(|(_, y)| *y).fold(-1.0, f64::max);

            let block = Block::default()
                .title(format!(
                    "{}:─{}{}─{}min/{}max",
                    self.title,
                    graph.last().unwrap_or(&(0.0, 0.0)).1 as i64,
                    unit,
                    min_y as i64,
                    max_y as i64,
                ))
                .borders(self.borders)
                .border_style(if self.focused {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                });

            let canvas = Canvas::default()
                .block(block)
                .x_bounds([min_x, max_x])
                .y_bounds([0.0, 100.0])
                .paint(|ctx| {
                    for (x, y) in &graph {
                        ctx.draw(&Line {
                            x1: *x,
                            y1: 0.0,
                            x2: *x,
                            y2: *y,
                            color: self.graph_type.get_color(),
                        });
                    }
                });
            f.render_widget(canvas, r);
        } else {
            let block = Block::default()
                .title("")
                .borders(self.borders)
                .border_style(if self.focused {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                });
            f.render_widget(block, r);
        }
        draw_block_joins(f, r, self.borders, self.joins);
    }
}

impl JoinableElement for GraphCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_element(&self) -> &dyn Element {
        self
    }

    fn as_element_mut(&mut self) -> &mut dyn Element {
        self
    }

    fn set_borders(&mut self, borders: Borders) {
        self.borders = borders;
    }

    fn set_joins(&mut self, joins: Borders) {
        self.joins = joins;
    }
}

impl InteractableElement for GraphCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_element(&self) -> &dyn Element {
        self
    }

    fn as_element_mut(&mut self) -> &mut dyn Element {
        self
    }

    fn interact(&mut self, _key: KeyEvent) -> InteractionResult {
        InteractionResult::Handled
    }

    fn can_focus(&self) -> bool {
        true
    }

    fn is_focused(&self) -> bool {
        self.focused
    }

    fn focus(&mut self, f: bool) {
        self.focused = f;
    }
}
