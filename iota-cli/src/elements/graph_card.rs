use std::any::Any;

use crossterm::event::KeyEvent;
use iota_state::ClientState;
use ratatui::{
    Frame,
    layout::Rect,
    widgets::{
        Block, Borders,
        canvas::{Canvas, Line},
    },
};

use crate::theme::ResolvedTheme;
use crate::{
    elements::elements::{Element, InteractableElement, JoinableElement},
    screens::screens::IotaInteraction,
    util::borders::draw_block_joins,
};

pub enum GRAPHS {
    Ram,
    Cpu,
    Ping,
}

impl GRAPHS {
    pub fn get_color(&self, theme: &crate::theme::ResolvedTheme) -> ratatui::style::Color {
        match self {
            GRAPHS::Ram => theme.graphs.ram,
            GRAPHS::Cpu => theme.graphs.cpu,
            GRAPHS::Ping => theme.graphs.ping,
        }
    }

    pub fn get_graph(&self, state: &ClientState, sample_width: usize) -> Vec<(f64, f64)> {
        let state = match state.app.try_lock() {
            Ok(state) => state,
            Err(_) => return Vec::new(),
        };
        match self {
            GRAPHS::Ram => state
                .with_width(sample_width.min(u16::MAX as usize) as u16)
                .ram
                .clone(),
            GRAPHS::Cpu => state
                .with_width(sample_width.min(u16::MAX as usize) as u16)
                .cpu
                .clone(),
            GRAPHS::Ping => state
                .with_width(sample_width.min(u16::MAX as usize) as u16)
                .ping
                .clone(),
        }
    }

    pub fn get_unit(&self) -> String {
        match self {
            // Memory is collected as a percentage of total RAM, not MiB.
            GRAPHS::Ram => "%".to_string(),
            GRAPHS::Cpu => "%".to_string(),
            GRAPHS::Ping => "ms".to_string(),
        }
    }
}

#[allow(unused)]
pub struct GraphCard {
    state: ClientState,
    graph_type: GRAPHS,

    focused: bool,
    pub title: String,

    borders: Borders,
    joins: Borders,

    open: bool,
    sample_width: usize,
}

impl GraphCard {
    pub fn new(state: ClientState, graph_type: GRAPHS, title: String) -> Self {
        Self {
            state,
            graph_type,
            focused: false,
            title,
            borders: Borders::ALL,
            joins: Borders::NONE,
            open: true,
            sample_width: 28,
        }
    }

    pub fn set_open(&mut self, open: bool) {
        self.open = open;
    }

    pub fn set_sample_width(&mut self, sample_width: usize) {
        self.sample_width = sample_width.max(1);
    }
}
impl Element for GraphCard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, r: Rect, theme: &ResolvedTheme) {
        if self.open {
            let graph = self.graph_type.get_graph(&self.state, self.sample_width);
            if graph.is_empty() {
                let block = Block::default()
                    .title(format!(" {} ", self.title))
                    .borders(self.borders)
                    .border_style(if self.focused {
                        theme.graphs.focused_border
                    } else {
                        theme.graphs.border
                    });
                f.render_widget(
                    ratatui::widgets::Paragraph::new("No metric samples yet.")
                        .style(theme.text.muted)
                        .block(block),
                    r,
                );
                return;
            }
            let unit = self.graph_type.get_unit();
            let min_x = graph.first().map(|(x, _)| *x).unwrap_or(0.0);
            let max_x = graph.last().map(|(x, _)| *x).unwrap_or(100.0);
            let max_x = if max_x <= min_x { min_x + 1.0 } else { max_x };
            let min_y = graph
                .iter()
                .map(|(_, y)| *y)
                .filter(|y| *y > 0.0)
                .min_by(|a, b| a.total_cmp(b))
                .unwrap_or(0.0);
            let max_y = graph.iter().map(|(_, y)| *y).fold(0.0, f64::max);
            let y_upper = match self.graph_type {
                GRAPHS::Cpu | GRAPHS::Ram => 100.0,
                GRAPHS::Ping => (max_y * 1.2).max(10.0),
            };

            let surface = matches!(theme.chrome, crate::theme::ChromeMode::Surfaces);
            let title = format!(
                "{}: {}{}  {}min/{}max",
                self.title,
                graph.last().unwrap_or(&(0.0, 0.0)).1 as i64,
                unit,
                min_y as i64,
                max_y as i64
            );
            let plot_area = if surface {
                crate::controls::panel::render_panel(f, r, &title, self.focused, theme)
            } else {
                r
            };
            let block = Block::default()
                .title(if surface {
                    String::new()
                } else {
                    format!(
                        "{}:─{}{}─{}min/{}max",
                        self.title,
                        graph.last().unwrap_or(&(0.0, 0.0)).1 as i64,
                        unit,
                        min_y as i64,
                        max_y as i64,
                    )
                })
                .borders(if surface { Borders::NONE } else { self.borders })
                .border_style(if self.focused {
                    theme.graphs.focused_border
                } else {
                    theme.graphs.border
                });

            let canvas = Canvas::default()
                .block(block)
                .x_bounds([min_x, max_x])
                .y_bounds([0.0, y_upper])
                .paint(|ctx| {
                    for (x, y) in &graph {
                        ctx.draw(&Line {
                            x1: *x,
                            y1: 0.0,
                            x2: *x,
                            y2: *y,
                            color: self.graph_type.get_color(theme),
                        });
                    }
                });
            f.render_widget(canvas, plot_area);
        } else {
            let block = Block::default()
                .title("")
                .borders(self.borders)
                .border_style(if self.focused {
                    theme.graphs.focused_border
                } else {
                    theme.graphs.border
                });
            f.render_widget(block, r);
        }
        if !matches!(theme.chrome, crate::theme::ChromeMode::Surfaces) {
            draw_block_joins(
                f,
                r,
                self.borders,
                self.joins,
                if self.focused {
                    theme.borders.focused
                } else {
                    theme.borders.normal
                },
            );
        }
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

    fn interact(&mut self, _key: KeyEvent) -> IotaInteraction {
        IotaInteraction::Changed
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
