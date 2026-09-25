use crate::log_buffer::LogBuffer;
use iota_ipc::{DaemonMessage, LogEntry};
use iota_logger::subscribe;
use iota_state::UiLogEntry;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

/* The daemon adapts logger output to the wire protocol so the logger stays
 * independent from both the socket implementation and TUI state. */
pub fn spawn(message_tx: broadcast::Sender<DaemonMessage>, buffer: Arc<Mutex<LogBuffer>>) {
    let Some(logs) = subscribe() else {
        return;
    };
    tokio::spawn(forward_logs(logs, message_tx, buffer));
}

pub(crate) async fn forward_logs(
    mut logs: broadcast::Receiver<UiLogEntry>,
    message_tx: broadcast::Sender<DaemonMessage>,
    buffer: Arc<Mutex<LogBuffer>>,
) {
    loop {
        match logs.recv().await {
            Ok(entry) => {
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
            Err(RecvError::Lagged(skipped)) => {
                let _ = message_tx.send(DaemonMessage::Gap { skipped });
            }
            Err(RecvError::Closed) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lag_reports_gap_and_continues_forwarding() {
        let (logs_tx, logs_rx) = broadcast::channel(2);
        let (message_tx, mut messages) = broadcast::channel(16);
        let buffer = Arc::new(Mutex::new(LogBuffer::new(8)));
        for index in 0..4 {
            let _ = logs_tx.send(UiLogEntry {
                timestamp_ms: index,
                sender: "Client".into(),
                message: index.to_string(),
                is_error: false,
            });
        }
        let task = tokio::spawn(forward_logs(logs_rx, message_tx, buffer.clone()));
        assert!(matches!(
            messages.recv().await.unwrap(),
            DaemonMessage::Gap { skipped: 2 }
        ));
        assert!(matches!(
            messages.recv().await.unwrap(),
            DaemonMessage::LogEntry(_)
        ));
        let _ = logs_tx.send(UiLogEntry {
            timestamp_ms: 4,
            sender: "Client".into(),
            message: "after lag".into(),
            is_error: false,
        });
        let mut found = false;
        for _ in 0..2 {
            if let DaemonMessage::LogEntry(entry) = messages.recv().await.unwrap() {
                found |= entry.message == "after lag";
            }
        }
        assert!(found);
        drop(logs_tx);
        task.await.unwrap();
        assert!(
            buffer
                .lock()
                .unwrap()
                .recent(4)
                .iter()
                .any(|entry| entry.message == "after lag")
        );
    }
}
