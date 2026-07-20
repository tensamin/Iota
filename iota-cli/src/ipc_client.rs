use iota_ipc::{ClientMessage, DaemonMessage, read_msg, write_msg};
use iota_state::{ClientState, UiLogEntry};
use std::io::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::Mutex;

/* The TUI owns this cache. IPC updates replace daemon snapshots and append
 * logs, so rendering never reaches into daemon-owned storage or connections. */
pub struct IpcClient {
    state: ClientState,
    writer: Mutex<OwnedWriteHalf>,
}

impl IpcClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let stream = UnixStream::connect(path).await?;
        let (mut reader, writer) = stream.into_split();
        let client = Arc::new(Self {
            state: ClientState::new(),
            writer: Mutex::new(writer),
        });
        let reader_client = client.clone();
        tokio::spawn(async move {
            while let Ok(message) = read_msg::<_, DaemonMessage>(&mut reader).await {
                reader_client.apply(message).await;
            }
        });
        client.send(ClientMessage::Subscribe).await?;
        Ok(client)
    }

    pub fn state(&self) -> ClientState {
        self.state.clone()
    }

    pub async fn send_command(&self, seq: u64, line: String) -> Result<()> {
        self.send(ClientMessage::Command { seq, line }).await
    }

    async fn send(&self, message: ClientMessage) -> Result<()> {
        let mut writer = self.writer.lock().await;
        write_msg(&mut *writer, &message).await
    }

    async fn apply(&self, message: DaemonMessage) {
        let mut state = self
            .state
            .app
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match message {
            DaemonMessage::LogEntry(entry) => state.push_log(UiLogEntry {
                timestamp_ms: entry.timestamp_ms,
                sender: entry.sender,
                message: entry.message,
                is_error: entry.is_error,
            }),
            DaemonMessage::StateUpdate(snapshot) => {
                state.cpu = snapshot.cpu;
                state.ram = snapshot.ram;
                state.ping = snapshot.ping;
                state.net_up = snapshot.net_up;
                state.net_down = snapshot.net_down;
                state.sys_info = snapshot.sys_info;
            }
            DaemonMessage::CommandResult {
                success, message, ..
            } => state.push_log(UiLogEntry {
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                sender: "Command".into(),
                message,
                is_error: !success,
            }),
            DaemonMessage::Pong { .. } => {}
        }
    }
}
