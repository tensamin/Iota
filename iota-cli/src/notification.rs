use std::time::{Duration, Instant};

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::theme::ResolvedTheme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationKind {
    Success,
    Warning,
    Error,
    Info,
}

#[derive(Clone)]
pub struct Notification {
    pub message: String,
    pub kind: NotificationKind,
    pub created_at: Instant,
    pub duration: Duration,
}

impl Notification {
    pub fn success(message: impl Into<String>) -> Self {
        Self::new(message, NotificationKind::Success, Duration::from_secs(3))
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(message, NotificationKind::Warning, Duration::from_secs(4))
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::new(message, NotificationKind::Error, Duration::from_secs(5))
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self::new(message, NotificationKind::Info, Duration::from_secs(3))
    }

    fn new(message: impl Into<String>, kind: NotificationKind, duration: Duration) -> Self {
        Self {
            message: message.into(),
            kind,
            created_at: Instant::now(),
            duration,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.duration
    }

    pub fn remaining(&self) -> Duration {
        self.duration.saturating_sub(self.created_at.elapsed())
    }

    pub fn progress(&self) -> f64 {
        let elapsed = self.created_at.elapsed().as_secs_f64();
        let total = self.duration.as_secs_f64();
        (elapsed / total).min(1.0)
    }
}

pub fn render_notification(
    frame: &mut Frame,
    area: Rect,
    notification: &Notification,
    theme: &ResolvedTheme,
) {
    let (prefix, style) = match notification.kind {
        NotificationKind::Success => ("✓ ", theme.status.success),
        NotificationKind::Warning => ("⚠ ", theme.status.warning),
        NotificationKind::Error => ("✗ ", theme.status.error),
        NotificationKind::Info => ("ℹ ", theme.status.info),
    };

    let remaining = notification.remaining().as_secs();
    let progress = notification.progress();

    let mut spans = vec![
        Span::styled(prefix, style),
        Span::styled(&notification.message, theme.text.normal),
    ];

    if remaining > 0 {
        let bar_width = 10;
        let filled = ((1.0 - progress) * bar_width as f64) as usize;
        let empty = bar_width - filled;
        let bar: String = "█".repeat(filled) + &"░".repeat(empty);
        spans.push(Span::styled(
            format!("  [{bar}] {remaining}s"),
            theme.text.muted,
        ));
    }

    let paragraph = Paragraph::new(Line::from(spans));
    frame.render_widget(paragraph, area);
}

pub fn render_notification_area(
    frame: &mut Frame,
    area: Rect,
    notifications: &[Notification],
    theme: &ResolvedTheme,
) {
    if notifications.is_empty() {
        return;
    }

    let visible_height = area.height as usize;
    let start = notifications.len().saturating_sub(visible_height);
    let visible = &notifications[start..];

    for (i, notification) in visible.iter().enumerate() {
        let row = Rect {
            x: area.x,
            y: area.y + i as u16,
            width: area.width,
            height: 1,
        };
        render_notification(frame, row, notification, theme);
    }
}
