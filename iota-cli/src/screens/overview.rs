use crate::theme::ResolvedTheme;
use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    ipc_client::{DaemonStatus, IpcConnectionState},
    screens::screens::{
        AppAction, HitMap, IotaInteraction, IotaMessage, IotaScreen, KeyHint, UiEvent,
    },
};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::watch;

pub struct OverviewScreen {
    connection_rx: watch::Receiver<IpcConnectionState>,
    daemon_rx: watch::Receiver<DaemonStatus>,
    _focus: Focus,
    scroll_offset: usize,
    content_height: AtomicUsize,
    viewport_height: AtomicUsize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Back,
}

impl OverviewScreen {
    pub fn new(
        connection_rx: watch::Receiver<IpcConnectionState>,
        daemon_rx: watch::Receiver<DaemonStatus>,
    ) -> Self {
        Self {
            connection_rx,
            daemon_rx,
            _focus: Focus::Back,
            scroll_offset: 0,
            content_height: AtomicUsize::new(0),
            viewport_height: AtomicUsize::new(1),
        }
    }

    fn build_lines(&self, theme: &crate::theme::ResolvedTheme) -> Vec<Line<'static>> {
        let conn = self.connection_rx.borrow().clone();
        let daemon = self.daemon_rx.borrow().clone();

        let mut lines = Vec::new();

        lines.push(Line::from(Span::styled("Connection", theme.text.heading)));
        lines.push(Line::from(format!("  State: {}", connection_label(&conn))));
        let omikron = daemon.components.get(&iota_ipc::ComponentId::Omikron);
        let omikron_label = match omikron.map(|health| health.status) {
            Some(iota_ipc::HealthStatus::Healthy) => "[OK] Connected",
            Some(iota_ipc::HealthStatus::Degraded) => "[WARN] Connecting or unavailable",
            Some(iota_ipc::HealthStatus::Failed) => "[FAIL] Authentication failed",
            None => "Unknown",
        };
        lines.push(Line::from(format!("  Omikron: {omikron_label}")));
        if let Some(message) = omikron.and_then(|health| health.message.as_deref()) {
            lines.push(Line::from(format!("  Omikron detail: {message}")));
        }
        lines.push(Line::from(""));

        lines.push(Line::from(Span::styled("Daemon", theme.text.heading)));
        lines.push(Line::from(format!(
            "  Version: {}",
            version_or_unknown(&daemon.version)
        )));
        lines.push(Line::from(format!(
            "  Instance: {}",
            truncate_id(&daemon.instance_id)
        )));

        let phase = daemon
            .startup_phase
            .map(|p| format!("{:?}", p))
            .unwrap_or_else(|| "Unknown".into());
        lines.push(Line::from(format!("  Phase: {}", phase)));

        let lifecycle = daemon
            .lifecycle
            .map(|l| format!("{:?}", l))
            .unwrap_or_else(|| "Unknown".into());
        lines.push(Line::from(format!("  Lifecycle: {}", lifecycle)));

        let health = match daemon.health {
            iota_ipc::HealthStatus::Healthy => "[OK] Healthy",
            iota_ipc::HealthStatus::Degraded => "[WARN] Degraded",
            iota_ipc::HealthStatus::Failed => "[FAIL] Failed",
        };
        lines.push(Line::from(format!("  Health: {health}")));

        if let Some(ref reason) = daemon.degraded_reason {
            lines.push(Line::from(Span::styled(
                format!("  Degraded: {reason}"),
                theme.status.warning,
            )));
        }

        let mode = daemon
            .deployment_mode
            .map(|m| format!("{:?}", m))
            .unwrap_or_else(|| "Unknown".into());
        lines.push(Line::from(format!("  Deployment: {mode}")));

        let supervisor = daemon
            .supervisor
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "Unknown".into());
        lines.push(Line::from(format!("  Supervisor: {supervisor}")));

        if !daemon.components.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Components", theme.text.heading)));
            for (id, health) in &daemon.components {
                let status_str = match health.status {
                    iota_ipc::HealthStatus::Healthy => "[OK] healthy",
                    iota_ipc::HealthStatus::Degraded => "[WARN] degraded",
                    iota_ipc::HealthStatus::Failed => "[FAIL] failed",
                };
                let suffix = health
                    .message
                    .as_deref()
                    .map(|m| format!(" ({m})"))
                    .unwrap_or_default();
                lines.push(Line::from(format!("  {:?}: {}{}", id, status_str, suffix)));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Press Esc or B to return to the dashboard",
            theme.text.muted,
        )));

        lines
    }
}

fn connection_label(conn: &IpcConnectionState) -> String {
    match conn {
        IpcConnectionState::Connected => "Connected".into(),
        IpcConnectionState::Connecting => "Connecting...".into(),
        IpcConnectionState::Reconnecting { attempt } => {
            format!("Reconnecting (attempt {attempt})...")
        }
        IpcConnectionState::Incompatible { message } => {
            format!("Incompatible: {message}")
        }
        IpcConnectionState::Failed { message } => format!("Failed: {message}"),
        IpcConnectionState::Disconnected => "Disconnected".into(),
    }
}

fn version_or_unknown(v: &str) -> String {
    if v.is_empty() {
        "Unknown".into()
    } else {
        v.into()
    }
}

fn truncate_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}…", &id[..8])
    } else {
        id.into()
    }
}

impl IotaScreen for OverviewScreen {
    fn render_legacy(&self, f: &mut Frame, rect: Rect, theme: &ResolvedTheme, _hits: &mut HitMap) {
        let block = Block::default()
            .title(" Overview ")
            .borders(Borders::ALL)
            .border_style(theme.borders.normal)
            .title_style(theme.borders.title);
        let inner = if matches!(theme.chrome, crate::theme::ChromeMode::Surfaces) {
            crate::controls::panel::render_panel(f, rect, "Overview", false, theme)
        } else {
            let inner = block.inner(rect);
            f.render_widget(block, rect);
            inner
        };
        let rows = ratatui::layout::Layout::vertical([
            ratatui::layout::Constraint::Min(1),
            ratatui::layout::Constraint::Length(1),
        ])
        .split(inner);

        let lines = self.build_lines(theme);
        self.content_height.store(lines.len(), Ordering::Relaxed);
        self.viewport_height
            .store(rows[0].height as usize, Ordering::Relaxed);
        let par = Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .scroll((self.scroll_offset as u16, 0));
        f.render_widget(par, rows[0]);
        render_button(
            f,
            rows[1],
            ActionButton {
                label: "Back",
                intent: ButtonIntent::Cancel,
                focused: self._focus == Focus::Back,
                enabled: true,
            },
            theme,
        );
        _hits.register(rows[1], IotaMessage::Action(AppAction::Back));
    }

    fn handle_event(&mut self, event: &UiEvent) -> IotaInteraction {
        let event = event.clone();
        let UiEvent::Key(event) = event else {
            return IotaInteraction::Unhandled;
        };
        match event.code {
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => IotaInteraction::Pop,
            KeyCode::Down | KeyCode::Char('j') => {
                let max = self
                    .content_height
                    .load(Ordering::Relaxed)
                    .saturating_sub(self.viewport_height.load(Ordering::Relaxed));
                self.scroll_offset = self.scroll_offset.saturating_add(1).min(max);
                IotaInteraction::Changed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
                IotaInteraction::Changed
            }
            KeyCode::PageDown => {
                let page = self.viewport_height.load(Ordering::Relaxed).max(1);
                let max = self
                    .content_height
                    .load(Ordering::Relaxed)
                    .saturating_sub(page);
                self.scroll_offset = self.scroll_offset.saturating_add(page).min(max);
                IotaInteraction::Changed
            }
            KeyCode::PageUp => {
                let page = self.viewport_height.load(Ordering::Relaxed).max(1);
                self.scroll_offset = self.scroll_offset.saturating_sub(page);
                IotaInteraction::Changed
            }
            KeyCode::Home => {
                self.scroll_offset = 0;
                IotaInteraction::Changed
            }
            KeyCode::End => {
                self.scroll_offset = self
                    .content_height
                    .load(Ordering::Relaxed)
                    .saturating_sub(self.viewport_height.load(Ordering::Relaxed));
                IotaInteraction::Changed
            }
            _ => IotaInteraction::Unhandled,
        }
    }
    fn handle_action(&mut self, action: AppAction) -> IotaInteraction {
        if action == AppAction::Back {
            IotaInteraction::Pop
        } else {
            IotaInteraction::Unhandled
        }
    }
    fn key_hints(&self) -> Vec<KeyHint> {
        vec![
            KeyHint {
                keys: "Up/Down",
                action: "Scroll",
            },
            KeyHint {
                keys: "PgUp/PgDn",
                action: "Page",
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
