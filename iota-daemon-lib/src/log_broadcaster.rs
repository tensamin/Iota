use crate::log_buffer::LogBuffer;
use iota_ipc::{DaemonMessage, LogEntry};
use iota_logger::subscribe;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/* The daemon adapts logger output to the wire protocol so the logger stays
 * independent from both the socket implementation and TUI state. */
pub fn spawn(
    message_tx: broadcast::Sender<DaemonMessage>,
    buffer: Arc<Mutex<LogBuffer>>,
) {
    let Some(mut logs) = subscribe() else {
        return;
    };
    tokio::spawn(async move {
        while let Ok(entry) = logs.recv().await {
            let entry = LogEntry {
                timestamp_ms: entry.timestamp_ms,
                sender: entry.sender,
                message: entry.message,
                is_error: entry.is_error,
            };
            if let Ok(mut buf) = buffer.lock() {
                buf.push(entry.clone());
            }
            let _ = message_tx.send(DaemonMessage::LogEntry(entry));
        }
    });
}
