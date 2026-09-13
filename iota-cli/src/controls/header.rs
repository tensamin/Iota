use crate::ipc_client::{DaemonStatus, IpcConnectionState};
use crate::theme::ResolvedTheme;
use crate::{
    controls::button::ButtonIntent,
    screens::screens::{AppAction, HitMap, IotaMessage},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

#[derive(Debug, Clone, Copy)]
pub struct HeaderItem {
    pub label: &'static str,
    pub intent: ButtonIntent,
    pub action: AppAction,
}

pub const HEADER_ITEMS: &[HeaderItem] = &[
    HeaderItem {
        label: "Overview",
        intent: ButtonIntent::Primary,
        action: AppAction::OpenOverview,
    },
    HeaderItem {
        label: "Users",
        intent: ButtonIntent::Neutral,
        action: AppAction::OpenUsers,
    },
    HeaderItem {
        label: "Settings",
        intent: ButtonIntent::Neutral,
        action: AppAction::OpenSettings,
    },
    HeaderItem {
        label: "Quit",
        intent: ButtonIntent::Destructive,
        action: AppAction::Quit,
    },
];

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
    let constraints = std::iter::once(Constraint::Min(28))
        .chain(
            HEADER_ITEMS
                .iter()
                .map(|item| Constraint::Length(if item.label == "Quit" { 8 } else { 12 })),
        )
        .collect::<Vec<_>>();
    let cells = Layout::horizontal(constraints.clone()).split(rows[0]);

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
    hits.register(brand_area, IotaMessage::Action(AppAction::OpenMain));

    for (index, item) in HEADER_ITEMS.iter().enumerate() {
        let top = cells[index + 1];
        let button_area = Rect {
            x: top.x,
            y: top.y,
            width: top.width,
            height: area.height,
        };
        let style = match (item.intent, focused_action == Some(index)) {
            (ButtonIntent::Primary, true) => theme.buttons.primary_focused,
            (ButtonIntent::Primary, false) => theme.buttons.primary,
            (ButtonIntent::Neutral, true) => theme.buttons.neutral_focused,
            (ButtonIntent::Neutral, false) => theme.buttons.neutral,
            (ButtonIntent::Cancel, true) => theme.buttons.cancel_focused,
            (ButtonIntent::Cancel, false) => theme.buttons.cancel,
            (ButtonIntent::Destructive, _) => theme.buttons.destructive,
        };
        let display_label = if focused_action == Some(index) {
            format!("› {}", item.label)
        } else {
            item.label.to_owned()
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(display_label, style)),
                Line::from(""),
            ]),
            button_area,
        );
        hits.register(button_area, IotaMessage::Action(item.action));
    }
}
