use iota_ipc::{DaemonMessage, LogEntry};
use iota_logger::subscribe;
use tokio::sync::broadcast;

/* The daemon adapts logger output to the wire protocol so the logger stays
 * independent from both the socket implementation and TUI state. */
pub fn spawn(message_tx: broadcast::Sender<DaemonMessage>) {
    let Some(mut logs) = subscribe() else {
        return;
    };
    tokio::spawn(async move {
        while let Ok(entry) = logs.recv().await {
            let _ = message_tx.send(DaemonMessage::LogEntry(LogEntry {
                timestamp_ms: entry.timestamp_ms,
                sender: entry.sender,
                message: entry.message,
                is_error: entry.is_error,
            }));
        }
    });
}
