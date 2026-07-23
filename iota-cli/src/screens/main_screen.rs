use crate::{
    elements::{
        console_card::ConsoleCard,
        elements::{InteractableElement, JoinableElement},
        graph_card::{GRAPHS, GraphCard},
        log_card::LogCard,
    },
    interaction_result::InteractionResult,
    ipc_client::{DaemonStatus, IpcConnectionState},
    render_context::RenderContext,
    screens::screens::{NavDirection, Screen},
    ui::UI,
};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Margin, Rect},
    widgets::{Block, Borders},
};
use tokio::sync::watch;

use std::{any::Any, sync::Arc};

pub struct MainScreen {
    elements: Vec<Box<dyn InteractableElement>>,
    nav_grid: Vec<Vec<Option<usize>>>,
    selected_coords: (usize, usize),
    graphs_open: bool,
    connection_status_rx: watch::Receiver<IpcConnectionState>,
    daemon_status_rx: watch::Receiver<DaemonStatus>,
}

impl MainScreen {
    pub async fn new(ui: Arc<UI>) -> Self {
        let mut elements: Vec<Box<dyn InteractableElement>> = Vec::new();

        let nav_grid = vec![
            vec![Some(0), Some(2)],
            vec![Some(0), Some(3)],
            vec![Some(1), Some(4)],
        ];

        let state = ui
            .client_state()
            .await
            .expect("MainScreen requires an attached daemon");
        let mut log_card = LogCard::new(state.clone());
        log_card.set_borders(Borders::TOP.union(Borders::RIGHT).union(Borders::LEFT));
        let ipc = ui
            .ipc()
            .await
            .expect("MainScreen requires an attached daemon");
        let mut console_card = ConsoleCard::new("Console", "", ipc.clone());
        console_card.set_joins(Borders::TOP);

        elements.push(Box::new(log_card));
        elements.push(Box::new(console_card));

        let mut ram_graph = GraphCard::new(ui.clone(), state.clone(), GRAPHS::Ram, "RAM".into());
        ram_graph.set_borders(Borders::TOP.union(Borders::LEFT).union(Borders::RIGHT));
        elements.push(Box::new(ram_graph));
        let mut cpu_graph = GraphCard::new(ui.clone(), state.clone(), GRAPHS::Cpu, "CPU".into());
        cpu_graph.set_borders(Borders::TOP.union(Borders::LEFT).union(Borders::RIGHT));
        cpu_graph.set_joins(Borders::TOP);
        elements.push(Box::new(cpu_graph));
        let mut ping_graph = GraphCard::new(ui.clone(), state, GRAPHS::Ping, "Ping".into());
        ping_graph.set_joins(Borders::TOP);
        elements.push(Box::new(ping_graph));

        let graphs_open = true;

        let connection_status_rx = ipc.connection_status();
        let daemon_status_rx = ipc.daemon_status();

        let mut screen = MainScreen {
            elements,
            nav_grid,
            selected_coords: (1, 0),
            graphs_open,
            connection_status_rx,
            daemon_status_rx,
        };
        screen.focus_current();
        screen
    }

    fn focus_current(&mut self) {
        let (y, x) = self.selected_coords;
        if let Some(Some(index)) = self.nav_grid.get(y).and_then(|row| row.get(x)) {
            if let Some(element) = self.elements.get_mut(*index) {
                if element.can_focus() {
                    element.focus(true);
                }
            }
        }
    }

    fn unfocus_current(&mut self, y: usize, x: usize) {
        if let Some(Some(index)) = self.nav_grid.get(y).and_then(|row| row.get(x)) {
            if let Some(element) = self.elements.get_mut(*index) {
                element.focus(false);
            }
        }
    }

    fn navigate(&mut self, direction: NavDirection) {
        let (current_row, current_col) = self.selected_coords;
        let current_element = self.nav_grid[current_row][current_col];

        self.unfocus_current(current_row, current_col);

        let (delta_row, delta_col) = match direction {
            NavDirection::Up => (-1isize, 0),
            NavDirection::Down => (1, 0),
            NavDirection::Left => (0, -1),
            NavDirection::Right => (0, 1),
            _ => (0, 0),
        };

        let mut next_row = current_row as isize;
        let mut next_col = current_col as isize;

        loop {
            next_row += delta_row;
            next_col += delta_col;

            if next_row < 0 || next_col < 0 {
                self.selected_coords = (
                    (next_row - delta_row) as usize,
                    (next_col - delta_col) as usize,
                );
                break;
            }
            let next_row_u = next_row as usize;
            let next_col_u = next_col as usize;

            if next_row_u >= self.nav_grid.len() {
                self.selected_coords = (
                    (next_row - delta_row) as usize,
                    (next_col - delta_col) as usize,
                );
                break;
            }

            if let Some(row) = self.nav_grid.get(next_row_u) {
                if next_col_u >= row.len() {
                    self.selected_coords = (
                        (next_row - delta_row) as usize,
                        (next_col - delta_col) as usize,
                    );
                    break;
                }

                if let Some(next_element) = row[next_col_u] {
                    if Some(next_element) != current_element {
                        self.selected_coords = (next_row_u, next_col_u);
                        self.focus_current();
                        return;
                    }
                }
            }
        }

        self.focus_current();
    }

    /// Cycle focus between unique elements in the navigation grid.
    fn navigate_focus(&mut self, forward: bool) {
        // Collect unique elements in grid order.
        let mut positions: Vec<(usize, usize)> = Vec::new(); // (row, col)
        let mut seen: Vec<Option<usize>> = Vec::new();
        for (y, row) in self.nav_grid.iter().enumerate() {
            for (x, elem_opt) in row.iter().enumerate() {
                if elem_opt.is_some() && !seen.contains(elem_opt) {
                    seen.push(*elem_opt);
                    positions.push((y, x));
                }
            }
        }

        let current = self.selected_coords;
        let current_pos = positions
            .iter()
            .position(|&(r, c)| r == current.0 && c == current.1);

        let next_pos = if let Some(idx) = current_pos {
            if forward {
                (idx + 1) % positions.len()
            } else {
                (idx + positions.len() - 1) % positions.len()
            }
        } else {
            0
        };

        self.unfocus_current(self.selected_coords.0, self.selected_coords.1);
        self.selected_coords = positions[next_pos];
        self.focus_current();
    }
}

impl Screen for MainScreen {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, rect: Rect, context: &RenderContext<'_>) {
        // A watch Ref blocks senders until it is dropped.  Rendering may do
        // terminal I/O, so retain only owned snapshots for the whole frame.
        let status = self.connection_status_rx.borrow().clone();
        let daemon = self.daemon_status_rx.borrow().clone();
        let status_text = match status {
            IpcConnectionState::Connected => "Connected".to_string(),
            IpcConnectionState::Connecting => "Connecting...".to_string(),
            IpcConnectionState::Reconnecting { attempt } => {
                format!("Reconnecting (attempt {})...", attempt)
            }
            IpcConnectionState::Incompatible { message } => {
                format!("Incompatible protocol: {}", message)
            }
            IpcConnectionState::Failed { message } => {
                format!("Connection failed: {}", message)
            }
            IpcConnectionState::Disconnected => "Disconnected".to_string(),
        };
        let readiness = daemon
            .startup_phase
            .map(|phase| format!("{:?}", phase))
            .unwrap_or_else(|| "Waiting for status".into());
        let health = daemon
            .degraded_reason
            .as_deref()
            .map(|reason| format!(" — {reason}"))
            .unwrap_or_default();
        let version = if daemon.version.is_empty() {
            String::new()
        } else {
            format!(" v{}", daemon.version)
        };
        let main_block = Block::default()
            .title(format!(
                "Iota{version} [{status_text}; {readiness}{health}]"
            ))
            .borders(Borders::ALL)
            .border_style(context.theme.borders.normal)
            .title_style(context.theme.borders.title);
        f.render_widget(main_block, rect);

        let inner = rect.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });

        let graphs_width = if self.graphs_open && inner.width >= 70 {
            30
        } else {
            2
        };
        let main_width = inner.width.saturating_sub(graphs_width);

        let horizontal_chunks = Layout::default()
            .direction(ratatui::layout::Direction::Horizontal)
            .constraints([
                Constraint::Length(main_width),
                Constraint::Length(graphs_width),
            ])
            .split(inner);

        let left_area = horizontal_chunks[0];
        let right_area = horizontal_chunks[1];

        let left_rows =
            Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(left_area);

        if let Some(log) = self.elements.get(0) {
            log.as_element().render(f, left_rows[0], context);
        }

        if let Some(console) = self.elements.get(1) {
            console.as_element().render(f, left_rows[1], context);
        }

        let graph_elements: Vec<_> = self
            .elements
            .iter()
            .filter(|el| el.as_any().is::<GraphCard>())
            .collect();

        if !graph_elements.is_empty() {
            let graph_chunks = Layout::vertical(
                graph_elements
                    .iter()
                    .map(|_| Constraint::Ratio(1, graph_elements.len() as u32))
                    .collect::<Vec<_>>(),
            )
            .split(right_area);

            for (el, area) in graph_elements.iter().zip(graph_chunks.iter()) {
                el.as_element().render(f, *area, context);
            }
        }
    }

    fn handle_input(&mut self, event: KeyEvent) -> InteractionResult {
        match event.code {
            KeyCode::Tab => {
                self.navigate_focus(true);
                return InteractionResult::Handled;
            }
            KeyCode::BackTab => {
                self.navigate_focus(false);
                return InteractionResult::Handled;
            }
            KeyCode::Enter | KeyCode::Char(' ') if self.selected_coords.1 == 1 => {
                self.graphs_open = !self.graphs_open;
                for element in self.elements.iter_mut() {
                    if let Some(graph) = element.as_any_mut().downcast_mut::<GraphCard>() {
                        graph.set_open(self.graphs_open);
                    }
                }
                return InteractionResult::Handled;
            }
            _ => {
                let (y, x) = self.selected_coords;
                if let Some(Some(index)) = self.nav_grid.get(y).and_then(|r| r.get(x)) {
                    if let Some(el) = self.elements.get_mut(*index) {
                        let result = el.interact(event);
                        if matches!(result, InteractionResult::Unhandled) {
                            match event.code {
                                KeyCode::Up => self.navigate(NavDirection::Up),
                                KeyCode::Down => self.navigate(NavDirection::Down),
                                KeyCode::Left => self.navigate(NavDirection::Left),
                                KeyCode::Right => self.navigate(NavDirection::Right),
                                _ => {}
                            }
                        }
                        return result;
                    }
                }
            }
        }

        InteractionResult::Handled
    }
}
