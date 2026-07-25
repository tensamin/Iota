use std::any::Any;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::{Block, Borders, Paragraph},
};

use crate::{
    elements::{
        elements::Element,
        graph_card::{GRAPHS, GraphCard},
    },
    interaction_result::InteractionResult,
    render_context::RenderContext,
    screens::screens::{AppAction, HitMap, KeyHint, Screen, UiEvent},
    ui::UI,
};

const RANGES: &[(usize, &str)] = &[(30, "Recent"), (120, "Medium"), (300, "Long")];

pub struct MetricsScreen {
    graphs: Vec<GraphCard>,
    range_index: usize,
}

impl MetricsScreen {
    pub async fn new(ui: std::sync::Arc<UI>) -> Option<Self> {
        let state = ui.client_state().await?;
        let mut screen = Self {
            graphs: vec![
                GraphCard::new(ui.clone(), state.clone(), GRAPHS::Ram, "RAM".into()),
                GraphCard::new(ui.clone(), state.clone(), GRAPHS::Cpu, "CPU".into()),
                GraphCard::new(ui, state, GRAPHS::Ping, "Ping".into()),
            ],
            range_index: 0,
        };
        screen.apply_range();
        Some(screen)
    }

    fn apply_range(&mut self) {
        let width = RANGES[self.range_index].0;
        for graph in &mut self.graphs {
            graph.set_sample_width(width);
        }
    }

    fn change_range(&mut self, delta: isize) {
        self.range_index =
            (self.range_index as isize + delta).clamp(0, RANGES.len() as isize - 1) as usize;
        self.apply_range();
    }
}

impl Screen for MetricsScreen {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        context: &RenderContext<'_>,
        hits: &mut HitMap,
    ) {
        let block = Block::default()
            .title(" Metrics ")
            .borders(Borders::ALL)
            .border_style(context.theme.borders.normal);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(inner);
        frame.render_widget(
            Paragraph::new(format!(
                "Range: {} ({} samples)   Left/Right to change",
                RANGES[self.range_index].1, RANGES[self.range_index].0
            ))
            .style(context.theme.text.heading),
            rows[0],
        );
        for (graph, graph_area) in self.graphs.iter().zip(rows[1..].iter()) {
            graph.render(frame, *graph_area, context);
        }
        hits.register(rows[0], AppAction::OpenMetrics);
    }

    fn handle_event(&mut self, event: UiEvent) -> InteractionResult {
        let UiEvent::Key(key) = event else {
            return InteractionResult::Unhandled;
        };
        match key.code {
            KeyCode::Left => {
                self.change_range(-1);
                InteractionResult::Handled
            }
            KeyCode::Right => {
                self.change_range(1);
                InteractionResult::Handled
            }
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => {
                InteractionResult::CloseScreen
            }
            _ => InteractionResult::Unhandled,
        }
    }

    fn key_hints(&self) -> Vec<KeyHint> {
        vec![
            KeyHint {
                keys: "Left/Right",
                action: "Range",
            },
            KeyHint {
                keys: "Esc/B",
                action: "Back",
            },
            KeyHint {
                keys: "F6",
                action: "Header",
            },
        ]
    }
}
