use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::{Block, Borders, Paragraph},
};

use crate::theme::ResolvedTheme;
use crate::{
    elements::{
        elements::Element,
        graph_card::{GRAPHS, GraphCard},
    },
    screens::screens::{
        AppAction, HitMap, IotaInteraction, IotaMessage, IotaScreen, KeyHint, UiEvent,
    },
};

const RANGES: &[(usize, &str)] = &[(30, "Recent"), (120, "Medium"), (300, "Long")];

pub struct MetricsScreen {
    graphs: Vec<GraphCard>,
    range_index: usize,
}

impl MetricsScreen {
    pub fn from_state(state: iota_state::ClientState) -> Self {
        let mut screen = Self {
            graphs: vec![
                GraphCard::new(state.clone(), GRAPHS::Ram, "RAM".into()),
                GraphCard::new(state.clone(), GRAPHS::Cpu, "CPU".into()),
                GraphCard::new(state, GRAPHS::Ping, "Ping".into()),
            ],
            range_index: 0,
        };
        screen.apply_range();
        screen
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

impl IotaScreen for MetricsScreen {
    fn render_legacy(
        &self,
        frame: &mut Frame,
        area: Rect,
        theme: &ResolvedTheme,
        hits: &mut HitMap,
    ) {
        let block = Block::default()
            .title(" Metrics ")
            .borders(Borders::ALL)
            .border_style(theme.borders.normal);
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
            .style(theme.text.heading),
            rows[0],
        );
        for (graph, graph_area) in self.graphs.iter().zip(rows[1..].iter()) {
            graph.render(frame, *graph_area, theme);
        }
        hits.register(rows[0], IotaMessage::Action(AppAction::OpenMetrics));
    }

    fn handle_event(&mut self, event: &UiEvent) -> IotaInteraction {
        let event = event.clone();
        let UiEvent::Key(key) = event else {
            return IotaInteraction::Unhandled;
        };
        match key.code {
            KeyCode::Left => {
                self.change_range(-1);
                IotaInteraction::Changed
            }
            KeyCode::Right => {
                self.change_range(1);
                IotaInteraction::Changed
            }
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => IotaInteraction::Pop,
            _ => IotaInteraction::Unhandled,
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
