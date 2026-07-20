use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ClientMessage {
    Command { seq: u64, line: String },
    Subscribe,
    Ping { seq: u64 },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum DaemonMessage {
    LogEntry(LogEntry),
    StateUpdate(StateSnapshot),
    CommandResult {
        seq: u64,
        success: bool,
        message: String,
    },
    Pong {
        seq: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogEntry {
    pub timestamp_ms: u128,
    pub sender: String,
    pub message: String,
    pub is_error: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateSnapshot {
    pub cpu: Vec<(f64, f64)>,
    pub ram: Vec<(f64, f64)>,
    pub ping: Vec<(f64, f64)>,
    pub net_up: Vec<(f64, f64)>,
    pub net_down: Vec<(f64, f64)>,
    pub sys_info: String,
}
