use crate::ipc_client::{DaemonStatus, IpcConnectionState};
use crate::theme::ResolvedTheme;
use crate::{
    controls::button::ButtonIntent,
    screens::screens::{AppAction, HitMap},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

fn connection_badge(
    state: &IpcConnectionState,
    theme: &ResolvedTheme,
) -> (&'static str, ratatui::style::Style) {
    match state {
        IpcConnectionState::Connected => ("OK", theme.status.success),
        IpcConnectionState::Connecting => ("..", theme.status.warning),
        IpcConnectionState::Reconnecting { .. } => ("WARN", theme.status.warning),
        IpcConnectionState::Failed { .. } | IpcConnectionState::Incompatible { .. } => {
            ("FAIL", theme.status.error)
        }
        IpcConnectionState::Disconnected => ("WARN", theme.status.warning),
    }
}

fn omikron_badge(daemon: &DaemonStatus, theme: &ResolvedTheme) -> (String, ratatui::style::Style) {
    use iota_ipc::ComponentId;
    let health = daemon.components.get(&ComponentId::Omikron);
    let (label, style) = match health.map(|h| h.status) {
        Some(iota_ipc::HealthStatus::Healthy) => ("OK", theme.status.success),
        Some(iota_ipc::HealthStatus::Degraded) => ("WARN", theme.status.warning),
        Some(iota_ipc::HealthStatus::Failed) => ("FAIL", theme.status.error),
        None => ("--", theme.text.muted),
    };
    let detail = health
        .and_then(|h| h.message.as_deref())
        .map(|m| format!(" {m}"))
        .unwrap_or_default();
    (format!("{label}{detail}"), style)
}

pub fn render_header(
    frame: &mut Frame,
    area: Rect,
    connection: &IpcConnectionState,
    daemon: &DaemonStatus,
    theme: &ResolvedTheme,
    hits: &mut HitMap,
    focused_action: Option<usize>,
) {
    let version = if daemon.version.is_empty() {
        String::new()
    } else {
        format!(" v{}", daemon.version)
    };

    let rows =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    let cells = Layout::horizontal([
        Constraint::Min(28),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(8),
    ])
    .split(rows[0]);
    let cells2 = Layout::horizontal([
        Constraint::Min(28),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(8),
    ])
    .split(rows[1]);

    let (ipc_label, ipc_style) = connection_badge(connection, theme);
    let (omikron_text, omikron_style) = omikron_badge(daemon, theme);

    let brand_line1 = Line::from(vec![
        Span::styled(format!(" IOTA{version}"), theme.surfaces.toolbar),
        Span::styled(format!("  IPC:[{ipc_label}]"), ipc_style),
    ]);
    let brand_line2 = Line::from(vec![
        Span::styled(" Omikron: ", theme.surfaces.toolbar),
        Span::styled(format!("[{omikron_text}]"), omikron_style),
    ]);
    let brand_area = Rect {
        x: area.x,
        y: area.y,
        width: cells[0].width,
        height: area.height,
    };
    frame.render_widget(
        Paragraph::new(vec![brand_line1, brand_line2]).style(theme.surfaces.toolbar),
        brand_area,
    );
    hits.register(brand_area, AppAction::OpenMain);

    for (index, (top, _bottom, label, intent, action)) in [
        (
            cells[1],
            cells2[1],
            "Overview",
            ButtonIntent::Primary,
            AppAction::OpenOverview,
        ),
        (
            cells[2],
            cells2[2],
            "Users",
            ButtonIntent::Neutral,
            AppAction::OpenUsers,
        ),
        (
            cells[3],
            cells2[3],
            "Settings",
            ButtonIntent::Neutral,
            AppAction::OpenSettings,
        ),
        (
            cells[4],
            cells2[4],
            "Quit",
            ButtonIntent::Destructive,
            AppAction::Quit,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let button_area = Rect {
            x: top.x,
            y: top.y,
            width: top.width,
            height: area.height,
        };
        let style = match (intent, focused_action == Some(index)) {
            (ButtonIntent::Primary, true) => theme.buttons.primary_focused,
            (ButtonIntent::Primary, false) => theme.buttons.primary,
            (ButtonIntent::Neutral, true) => theme.buttons.neutral_focused,
            (ButtonIntent::Neutral, false) => theme.buttons.neutral,
            (ButtonIntent::Cancel, true) => theme.buttons.cancel_focused,
            (ButtonIntent::Cancel, false) => theme.buttons.cancel,
            (ButtonIntent::Destructive, _) => theme.buttons.destructive,
        };
        let display_label = if focused_action == Some(index) {
            format!("› {label}")
        } else {
            label.to_owned()
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(display_label, style)),
                Line::from(""),
            ]),
            button_area,
        );
        hits.register(button_area, action);
    }
}
