use crate::theme::ResolvedTheme;
use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    elements::{
        console_card::ConsoleCard,
        elements::{InteractableElement, JoinableElement},
        graph_card::{GRAPHS, GraphCard},
        log_card::LogCard,
    },
    screens::screens::{
        AppAction, HitMap, IotaEffect, IotaInteraction, IotaMessage, IotaScreen, KeyHint,
        NavDirection, UiEvent,
    },
};

use crossterm::event::{KeyCode, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::Borders,
};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};

pub struct MainScreen {
    elements: Vec<Box<dyn InteractableElement>>,
    focus_graph: ratatool::FocusGraph<MainFocus>,
    focus: MainFocus,
    graphs_open: bool,
    layout_width: AtomicU16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
enum MainFocus {
    #[default]
    Logs,
    Console,
    Ram,
    Cpu,
    Ping,
}

impl MainFocus {
    const ORDER: [Self; 5] = [Self::Logs, Self::Ram, Self::Cpu, Self::Console, Self::Ping];

    const fn element_index(self) -> usize {
        match self {
            Self::Logs => 0,
            Self::Console => 1,
            Self::Ram => 2,
            Self::Cpu => 3,
            Self::Ping => 4,
        }
    }

    const fn is_metric(self) -> bool {
        matches!(self, Self::Ram | Self::Cpu | Self::Ping)
    }
}

impl MainScreen {
    pub fn new(ipc: Arc<crate::ipc_client::IpcClient>) -> Self {
        let mut elements: Vec<Box<dyn InteractableElement>> = Vec::new();

        let mut focus_graph = ratatool::FocusGraph::default();
        focus_graph.connect_bidirectional(MainFocus::Logs, NavDirection::Down, MainFocus::Console);
        focus_graph.connect_bidirectional(MainFocus::Logs, NavDirection::Right, MainFocus::Ram);
        focus_graph.connect_bidirectional(MainFocus::Ram, NavDirection::Down, MainFocus::Cpu);
        focus_graph.connect_bidirectional(MainFocus::Cpu, NavDirection::Down, MainFocus::Ping);
        focus_graph.connect_bidirectional(MainFocus::Console, NavDirection::Right, MainFocus::Ping);

        let state = ipc.state();
        let mut log_card = LogCard::new(state.clone());
        log_card.set_borders(Borders::TOP.union(Borders::RIGHT).union(Borders::LEFT));
        let mut console_card = ConsoleCard::new("Console", "", ipc.clone());
        console_card.set_joins(Borders::TOP);

        elements.push(Box::new(log_card));
        elements.push(Box::new(console_card));

        let mut ram_graph = GraphCard::new(state.clone(), GRAPHS::Ram, "RAM".into());
        ram_graph.set_borders(Borders::TOP.union(Borders::LEFT).union(Borders::RIGHT));
        elements.push(Box::new(ram_graph));
        let mut cpu_graph = GraphCard::new(state.clone(), GRAPHS::Cpu, "CPU".into());
        cpu_graph.set_borders(Borders::TOP.union(Borders::LEFT).union(Borders::RIGHT));
        cpu_graph.set_joins(Borders::TOP);
        elements.push(Box::new(cpu_graph));
        let mut ping_graph = GraphCard::new(state, GRAPHS::Ping, "Ping".into());
        ping_graph.set_joins(Borders::TOP);
        elements.push(Box::new(ping_graph));

        let graphs_open = true;

        let mut screen = MainScreen {
            elements,
            focus_graph,
            focus: MainFocus::Logs,
            graphs_open,
            layout_width: AtomicU16::new(0),
        };
        screen.focus_current();
        screen
    }

    fn focus_current(&mut self) {
        if let Some(element) = self.elements.get_mut(self.focus.element_index())
            && element.can_focus()
        {
            element.focus(true);
        }
    }

    fn unfocus_current(&mut self) {
        if let Some(element) = self.elements.get_mut(self.focus.element_index()) {
            element.focus(false);
        }
    }

    fn navigate(&mut self, direction: NavDirection) {
        let Some(target) = self.focus_graph.target(&self.focus, direction).copied() else {
            return;
        };
        if target.is_metric()
            && (!self.graphs_open || self.layout_width.load(Ordering::Relaxed) < 70)
        {
            return;
        }
        self.unfocus_current();
        self.focus = target;
        self.focus_current();
    }

    /// Cycle focus between unique elements in the navigation grid.
    fn navigate_focus(&mut self, forward: bool) {
        let positions = MainFocus::ORDER
            .into_iter()
            .filter(|focus| {
                !focus.is_metric()
                    || (self.graphs_open && self.layout_width.load(Ordering::Relaxed) >= 70)
            })
            .collect::<Vec<_>>();
        let current_pos = positions.iter().position(|focus| *focus == self.focus);

        let next_pos = if let Some(idx) = current_pos {
            if forward {
                (idx + 1) % positions.len()
            } else {
                (idx + positions.len() - 1) % positions.len()
            }
        } else {
            0
        };

        self.unfocus_current();
        self.focus = positions[next_pos];
        self.focus_current();
    }
}

impl IotaScreen for MainScreen {
    fn render_legacy(&self, f: &mut Frame, rect: Rect, theme: &ResolvedTheme, hits: &mut HitMap) {
        self.layout_width.store(rect.width, Ordering::Relaxed);
        f.render_widget(
            ratatui::widgets::Block::default().style(theme.surfaces.canvas),
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
        hits.register(left_area, IotaMessage::Action(AppAction::FocusLogs));
        if metrics_visible {
            hits.register(right_area, IotaMessage::Action(AppAction::FocusMetrics));
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
                theme,
            );
            hits.register(
                metrics_button,
                IotaMessage::Action(AppAction::ToggleMetrics),
            );
        }

        let left_rows =
            Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(left_area);
        hits.register(left_rows[1], IotaMessage::Action(AppAction::FocusConsole));

        if let Some(log) = self.elements.first() {
            log.as_element().render(f, left_rows[0], theme);
        }

        if let Some(console) = self.elements.get(1) {
            console.as_element().render(f, left_rows[1], theme);
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
                el.as_element().render(f, *area, theme);
            }
        }
    }

    fn handle_event(&mut self, event: &UiEvent) -> IotaInteraction {
        let event = event.clone();
        if let UiEvent::Pointer {
            event,
            hit: Some(IotaMessage::Action(AppAction::FocusLogs)),
        } = &event
        {
            let Some(log) = self
                .elements
                .get_mut(0)
                .and_then(|element| element.as_any_mut().downcast_mut::<LogCard>())
            else {
                return IotaInteraction::Unhandled;
            };
            match event.kind {
                MouseEventKind::ScrollUp => log.scroll_older(),
                MouseEventKind::ScrollDown => log.scroll_newer(),
                _ => return IotaInteraction::Unhandled,
            }
            self.unfocus_current();
            self.focus = MainFocus::Logs;
            self.focus_current();
            return IotaInteraction::Changed;
        }
        if let UiEvent::Paste(text) = &event {
            if self.focus == MainFocus::Console
                && let Some(console) = self
                    .elements
                    .get_mut(1)
                    .and_then(|element| element.as_any_mut().downcast_mut::<ConsoleCard>())
            {
                console.handle_paste(text);
                return IotaInteraction::Changed;
            }
            return IotaInteraction::Unhandled;
        }
        if let UiEvent::Resize { width, .. } = &event {
            self.layout_width.store(*width, Ordering::Relaxed);
            if *width < 70 && self.focus.is_metric() {
                self.unfocus_current();
                self.focus = MainFocus::Logs;
                self.focus_current();
            }
            return IotaInteraction::Changed;
        }
        let UiEvent::Key(event) = event else {
            return IotaInteraction::Unhandled;
        };
        // A focused console consumes text and cursor keys before dashboard
        // shortcuts; commands such as `users` must remain typeable.
        if self.focus == MainFocus::Console
            && !matches!(event.code, KeyCode::Tab | KeyCode::BackTab)
            && let Some(console) = self.elements.get_mut(1)
        {
            return console.interact(event);
        }
        match event.code {
            KeyCode::Tab => {
                self.navigate_focus(true);
                return IotaInteraction::Changed;
            }
            KeyCode::BackTab => {
                self.navigate_focus(false);
                return IotaInteraction::Changed;
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                return IotaInteraction::Effect(IotaEffect::OpenOverview);
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                return IotaInteraction::Effect(IotaEffect::OpenUsers);
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                return IotaInteraction::Effect(IotaEffect::OpenMetrics);
            }
            KeyCode::Enter | KeyCode::Char(' ') if self.focus.is_metric() => {
                self.graphs_open = !self.graphs_open;
                for element in self.elements.iter_mut() {
                    if let Some(graph) = element.as_any_mut().downcast_mut::<GraphCard>() {
                        graph.set_open(self.graphs_open);
                    }
                }
                return IotaInteraction::Changed;
            }
            _ => {
                if let Some(el) = self.elements.get_mut(self.focus.element_index()) {
                    let result = el.interact(event);
                    if matches!(result, IotaInteraction::Unhandled) {
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

        IotaInteraction::Changed
    }
    fn handle_action(&mut self, action: AppAction) -> IotaInteraction {
        match action {
            AppAction::ToggleMetrics => {
                self.graphs_open = !self.graphs_open;
                for element in &mut self.elements {
                    if let Some(graph) = element.as_any_mut().downcast_mut::<GraphCard>() {
                        graph.set_open(self.graphs_open);
                    }
                }
                IotaInteraction::Changed
            }
            AppAction::OpenOverview => IotaInteraction::Effect(IotaEffect::OpenOverview),
            AppAction::OpenUsers => IotaInteraction::Effect(IotaEffect::OpenUsers),
            AppAction::FocusLogs => {
                self.unfocus_current();
                self.focus = MainFocus::Logs;
                self.focus_current();
                IotaInteraction::Changed
            }
            AppAction::FocusConsole => {
                self.unfocus_current();
                self.focus = MainFocus::Console;
                self.focus_current();
                IotaInteraction::Changed
            }
            AppAction::FocusMetrics => {
                self.unfocus_current();
                self.focus = MainFocus::Ram;
                self.focus_current();
                IotaInteraction::Changed
            }
            _ => IotaInteraction::Unhandled,
        }
    }
    fn key_hints(&self) -> Vec<KeyHint> {
        if self.focus == MainFocus::Console {
            vec![
                KeyHint {
                    keys: "Enter",
                    action: "Send",
                },
                KeyHint {
                    keys: "Up/Down",
                    action: "History",
                },
                KeyHint {
                    keys: "Tab",
                    action: "Complete",
                },
                KeyHint {
                    keys: "F6",
                    action: "Header",
                },
            ]
        } else if self.focus == MainFocus::Logs {
            vec![
                KeyHint {
                    keys: "J/K",
                    action: "Scroll logs",
                },
                KeyHint {
                    keys: "Enter",
                    action: "Lock scroll",
                },
                KeyHint {
                    keys: "/",
                    action: "Filter",
                },
                KeyHint {
                    keys: "M",
                    action: "Metrics screen",
                },
                KeyHint {
                    keys: "Tab",
                    action: "Next panel",
                },
                KeyHint {
                    keys: "F6",
                    action: "Header",
                },
            ]
        } else {
            vec![
                KeyHint {
                    keys: "Enter",
                    action: "Toggle metrics",
                },
                KeyHint {
                    keys: "Tab",
                    action: "Next panel",
                },
                KeyHint {
                    keys: "F6",
                    action: "Header",
                },
            ]
        }
    }
}
