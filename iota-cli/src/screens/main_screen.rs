use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    elements::{
        console_card::ConsoleCard,
        elements::{InteractableElement, JoinableElement},
        graph_card::{GRAPHS, GraphCard},
        log_card::LogCard,
    },
    interaction_result::InteractionResult,
    ipc_client::{DaemonStatus, IpcConnectionState},
    render_context::RenderContext,
    screens::{
        overview::OverviewScreen,
        screens::{AppAction, HitMap, KeyHint, NavDirection, Screen, UiEvent},
    },
    ui::UI,
};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::Borders,
};
use tokio::sync::watch;

use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

pub struct MainScreen {
    elements: Vec<Box<dyn InteractableElement>>,
    nav_grid: Vec<Vec<Option<usize>>>,
    selected_coords: (usize, usize),
    graphs_open: bool,
    connection_status_rx: watch::Receiver<IpcConnectionState>,
    daemon_status_rx: watch::Receiver<DaemonStatus>,
    layout_width: AtomicU16,
}

impl MainScreen {
    pub fn connection_status(&self) -> watch::Receiver<IpcConnectionState> {
        self.connection_status_rx.clone()
    }
    pub fn daemon_status(&self) -> watch::Receiver<DaemonStatus> {
        self.daemon_status_rx.clone()
    }
    fn status_summary(&self) -> String {
        let connection = match self.connection_status_rx.borrow().clone() {
            IpcConnectionState::Connected => "[OK] Connected".to_owned(),
            IpcConnectionState::Connecting => "[..] Connecting".to_owned(),
            IpcConnectionState::Reconnecting { .. } => "[WARN] Reconnecting".to_owned(),
            IpcConnectionState::Failed { .. } | IpcConnectionState::Incompatible { .. } => {
                "[FAIL] Failed".to_owned()
            }
            IpcConnectionState::Disconnected => "[WARN] Disconnected".to_owned(),
        };
        let daemon = self.daemon_status_rx.borrow().clone();
        let version = if daemon.version.is_empty() {
            String::new()
        } else {
            format!(" v{}", daemon.version)
        };
        let ready = daemon
            .startup_phase
            .map(|phase| format!(" {:?}", phase))
            .unwrap_or_default();
        format!("IOTA{version}    {connection}{ready}")
    }
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
            layout_width: AtomicU16::new(0),
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
                if x == 1
                    && (!self.graphs_open || self.layout_width.load(Ordering::Relaxed) < 70)
                {
                    continue;
                }
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

    fn render(&self, f: &mut Frame, rect: Rect, context: &RenderContext<'_>, hits: &mut HitMap) {
        self.layout_width.store(rect.width, Ordering::Relaxed);
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
        let _ = (status_text, readiness, health, version);
        f.render_widget(
            ratatui::widgets::Block::default().style(context.theme.surfaces.canvas),
            rect,
        );
        let inner = rect;

        let metrics_visible = self.graphs_open && inner.width >= 70;
        let graphs_width = if metrics_visible { 30 } else { 0 };
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
        hits.register(left_area, AppAction::FocusLogs);
        if metrics_visible {
            hits.register(right_area, AppAction::FocusMetrics);
        }

        if inner.width >= 70 {
            let metrics_button = Rect {
                x: right_area.x,
                y: right_area.y,
                width: right_area.width,
                height: 1,
            };
            render_button(
                f,
                metrics_button,
                ActionButton {
                    label: if self.graphs_open {
                        "Hide metrics"
                    } else {
                        "Show metrics"
                    },
                    intent: ButtonIntent::Neutral,
                    focused: false,
                    enabled: true,
                },
                context.theme,
            );
            hits.register(metrics_button, AppAction::ToggleMetrics);
        }

        let left_rows =
            Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(left_area);
        hits.register(left_rows[1], AppAction::FocusConsole);

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

        if metrics_visible && !graph_elements.is_empty() {
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

    fn handle_event(&mut self, event: UiEvent) -> InteractionResult {
        if let UiEvent::Paste(text) = &event {
            if self.selected_coords == (2, 0) {
                if let Some(console) = self
                    .elements
                    .get_mut(1)
                    .and_then(|element| element.as_any_mut().downcast_mut::<ConsoleCard>())
                {
                    console.handle_paste(text);
                    return InteractionResult::Handled;
                }
            }
            return InteractionResult::Unhandled;
        }
        if let UiEvent::Resize(width, _) = &event {
            self.layout_width.store(*width, Ordering::Relaxed);
            if *width < 70 && self.selected_coords.1 == 1 {
                self.unfocus_current(self.selected_coords.0, self.selected_coords.1);
                self.selected_coords = (0, 0);
                self.focus_current();
            }
            return InteractionResult::Handled;
        }
        let UiEvent::Key(event) = event else {
            return InteractionResult::Unhandled;
        };
        // A focused console consumes text and cursor keys before dashboard
        // shortcuts; commands such as `users` must remain typeable.
        if self.selected_coords == (2, 0) && !matches!(event.code, KeyCode::Tab | KeyCode::BackTab)
        {
            if let Some(console) = self.elements.get_mut(1) {
                return console.interact(event);
            }
        }
        match event.code {
            KeyCode::Tab => {
                self.navigate_focus(true);
                return InteractionResult::Handled;
            }
            KeyCode::BackTab => {
                self.navigate_focus(false);
                return InteractionResult::Handled;
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                let conn_rx = self.connection_status_rx.clone();
                let daemon_rx = self.daemon_status_rx.clone();
                return InteractionResult::OpenScreen {
                    screen: Box::new(OverviewScreen::new(conn_rx, daemon_rx)),
                };
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                return InteractionResult::AppTask {
                    task: Box::pin(async {
                        UiEvent::App(crate::screens::screens::AppEvent::OpenUsers)
                    }),
                };
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                return InteractionResult::AppTask {
                    task: Box::pin(async {
                        UiEvent::App(crate::screens::screens::AppEvent::OpenMetrics)
                    }),
                };
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
    fn handle_action(&mut self, action: AppAction) -> InteractionResult {
        match action {
            AppAction::ToggleMetrics => {
                self.graphs_open = !self.graphs_open;
                for element in &mut self.elements {
                    if let Some(graph) = element.as_any_mut().downcast_mut::<GraphCard>() {
                        graph.set_open(self.graphs_open);
                    }
                }
                InteractionResult::Handled
            }
            AppAction::OpenOverview => {
                self.handle_event(UiEvent::Key(KeyEvent::from(KeyCode::Char('o'))))
            }
            AppAction::OpenUsers => {
                self.handle_event(UiEvent::Key(KeyEvent::from(KeyCode::Char('u'))))
            }
            AppAction::FocusLogs => {
                self.unfocus_current(self.selected_coords.0, self.selected_coords.1);
                self.selected_coords = (0, 0);
                self.focus_current();
                InteractionResult::Handled
            }
            AppAction::FocusConsole => {
                self.unfocus_current(self.selected_coords.0, self.selected_coords.1);
                self.selected_coords = (2, 0);
                self.focus_current();
                InteractionResult::Handled
            }
            AppAction::FocusMetrics => {
                self.unfocus_current(self.selected_coords.0, self.selected_coords.1);
                self.selected_coords = (0, 1);
                self.focus_current();
                InteractionResult::Handled
            }
            _ => InteractionResult::Unhandled,
        }
    }
    fn app_title(&self) -> String {
        self.status_summary()
    }
    fn key_hints(&self) -> Vec<KeyHint> {
        if self.selected_coords == (2, 0) {
            vec![
                KeyHint { keys: "Enter", action: "Send" },
                KeyHint { keys: "Up/Down", action: "History" },
                KeyHint { keys: "Tab", action: "Complete" },
                KeyHint { keys: "F6", action: "Header" },
            ]
        } else if self.selected_coords == (0, 0) {
            vec![
                KeyHint { keys: "J/K", action: "Scroll logs" },
                KeyHint { keys: "Enter", action: "Lock scroll" },
                KeyHint { keys: "/", action: "Filter" },
                KeyHint { keys: "M", action: "Metrics screen" },
                KeyHint { keys: "Tab", action: "Next panel" },
                KeyHint { keys: "F6", action: "Header" },
            ]
        } else {
            vec![
                KeyHint { keys: "Enter", action: "Toggle metrics" },
                KeyHint { keys: "Tab", action: "Next panel" },
                KeyHint { keys: "F6", action: "Header" },
            ]
        }
    }
}
