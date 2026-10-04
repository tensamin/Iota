use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, TrySendError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use mtp::codec::{CommunicationType, CommunicationValue, DataTypeId, DataValue, TypeMap};
use ratatui::style::Color;

use iota_state::{UNIQUE, UiLogEntry};
use tokio::sync::broadcast;
pub mod language_creator;
pub mod language_manager;

static LOGGER: OnceLock<mpsc::SyncSender<LogMessage>> = OnceLock::new();
static LOG_BROADCASTER: OnceLock<broadcast::Sender<UiLogEntry>> = OnceLock::new();
static DROPPED_LOGS: AtomicU64 = AtomicU64::new(0);
const DEFAULT_LOGGER_QUEUE_CAPACITY: usize = 1024;
const DROPPED_LOG_REPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_LOG_FILE_BYTES: u64 = 16 * 1024 * 1024;
const RETAINED_LOG_FILES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}
impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(unused)]
pub enum PrintType {
    Call,
    Client,
    Iota,
    Omikron,
    Omega,
    General,
    Command,
}
impl PrintType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Client => "client",
            Self::Iota => "iota",
            Self::Omikron => "omikron",
            Self::Omega => "omega",
            Self::General => "general",
            Self::Command => "command",
        }
    }
    pub fn prefix_color(self) -> Color {
        match self {
            PrintType::Call => Color::Magenta,
            PrintType::Client => Color::Green,
            PrintType::Iota => Color::Yellow,
            PrintType::Omikron => Color::Blue,
            PrintType::Omega => Color::Cyan,
            PrintType::General => Color::LightCyan,
            PrintType::Command => Color::LightGreen,
        }
    }
}

struct LogMessage {
    timestamp_ms: u128,
    prefix: String,
    kind: PrintType,
    is_error: bool,
    level: LogLevel,
    event: &'static str,
    translation_key: Option<String>,
    format_args: Vec<String>,
    message: Option<String>,
}

/* The logger owns file persistence while consumers receive rendered entries
 * through a process-local broadcast subscription. */
pub fn startup() {
    startup_with_log_dir_and_capacity(
        Some(
            iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
                .expect("resolve Iota user paths")
                .log_dir,
        ),
        DEFAULT_LOGGER_QUEUE_CAPACITY,
    );
}

/// `None` keeps logging on stderr only (the systemd default).
pub fn startup_with_log_dir(log_dir: Option<std::path::PathBuf>) {
    startup_with_log_dir_and_capacity(log_dir, DEFAULT_LOGGER_QUEUE_CAPACITY);
}

pub fn startup_with_log_dir_and_capacity(log_dir: Option<PathBuf>, queue_capacity: usize) {
    let (tx, rx) = mpsc::sync_channel::<LogMessage>(queue_capacity.max(1));
    if LOGGER.set(tx).is_err() {
        return;
    }
    let (broadcast_tx, _) = broadcast::channel(512);
    let _ = LOG_BROADCASTER.set(broadcast_tx.clone());

    thread::spawn(move || {
        let start_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut sequence = 0;
        let mut file = log_dir.as_ref().and_then(|log_dir| {
            if let Err(error) = fs::create_dir_all(log_dir) {
                eprintln!(
                    "Unable to create Iota log directory {}: {error}",
                    log_dir.display()
                );
                return None;
            }
            prune_logs(log_dir);
            match open_log(log_dir, start_ts, sequence) {
                Ok(file) => Some(file),
                Err(error) => {
                    eprintln!(
                        "Unable to open Iota log file in {}: {error}",
                        log_dir.display()
                    );
                    None
                }
            }
        });
        let mut last_drop_report = Instant::now();
        loop {
            let msg = match rx.recv_timeout(DROPPED_LOG_REPORT_INTERVAL) {
                Ok(msg) => msg,
                Err(RecvTimeoutError::Timeout) => {
                    report_dropped_logs(&mut file, &broadcast_tx);
                    last_drop_report = Instant::now();
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    report_dropped_logs(&mut file, &broadcast_tx);
                    break;
                }
            };
            let resolved_message = if let Some(key) = msg.translation_key {
                let args: Vec<&str> = msg.format_args.iter().map(|s| s.as_str()).collect();
                language_manager::format(&key, &args)
            } else {
                msg.message.unwrap_or_default()
            };

            let timestamp = format_timestamp_inline(msg.timestamp_ms);

            let prefix = if msg.prefix.is_empty() {
                String::new()
            } else {
                format!("{} ", msg.prefix)
            };

            let line = format!(
                "{} level={} component={} direction={} sender=- event={} message={:?}",
                msg.timestamp_ms,
                msg.level.as_str(),
                msg.kind.as_str(),
                match msg.prefix.trim() {
                    ">" => "in",
                    "<" => "out",
                    ">>" => "internal",
                    _ => "local",
                },
                msg.event,
                format!("{prefix}{resolved_message}")
            );

            if let Some(file) = file.as_mut()
                && let Err(error) = writeln!(file, "{line}")
            {
                eprintln!("Unable to write Iota log file: {error}");
            }

            let _ = writeln!(std::io::stderr(), "{timestamp} {line}");

            let ui_message = if msg.event == "message" {
                resolved_message.clone()
            } else {
                format!("event={} {}", msg.event, resolved_message)
            };

            let entry = UiLogEntry {
                timestamp_ms: msg.timestamp_ms,
                sender: format!("{:?}", msg.kind),
                message: ui_message,
                is_error: msg.is_error,
            };

            let _ = broadcast_tx.send(entry);
            if last_drop_report.elapsed() >= DROPPED_LOG_REPORT_INTERVAL {
                report_dropped_logs(&mut file, &broadcast_tx);
                last_drop_report = Instant::now();
            }
            if let (Some(file), Some(log_dir)) = (file.as_mut(), log_dir.as_ref()) {
                rotate_log_if_needed(file, log_dir, start_ts, &mut sequence);
            }
        }
    });
}

pub fn subscribe() -> Option<broadcast::Receiver<UiLogEntry>> {
    LOG_BROADCASTER.get().map(broadcast::Sender::subscribe)
}

fn format_timestamp_inline(timestamp_ms: u128) -> String {
    let secs = (timestamp_ms / 1000) as i64;
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    format!("[{:02}:{:02}:{:02}]", hours, minutes, seconds)
}

fn open_log(dir: &Path, start_ts: u64, sequence: u32) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(dir.join(format!("log_{start_ts}_{sequence}.txt")))
}

fn rotate_log_if_needed(file: &mut std::fs::File, dir: &Path, start_ts: u64, sequence: &mut u32) {
    if !file
        .metadata()
        .is_ok_and(|meta| meta.len() >= MAX_LOG_FILE_BYTES)
    {
        return;
    }
    let next = sequence.saturating_add(1);
    match open_log(dir, start_ts, next) {
        Ok(new_file) => {
            *file = new_file;
            *sequence = next;
            prune_logs(dir);
        }
        Err(error) => eprintln!("Unable to rotate Iota log file: {error}"),
    }
}

fn prune_logs(dir: &Path) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!(
                "Unable to enumerate Iota log directory {}: {error}",
                dir.display()
            );
            return;
        }
    };
    let mut logs = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("log_") && name.ends_with(".txt"))
        })
        .collect::<Vec<_>>();
    logs.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(UNIX_EPOCH)
    });
    let remove_count = logs.len().saturating_sub(RETAINED_LOG_FILES);
    for entry in logs.into_iter().take(remove_count) {
        if let Err(error) = fs::remove_file(entry.path()) {
            eprintln!("Unable to remove old Iota log file: {error}");
        }
    }
}

fn report_dropped_logs(
    file: &mut Option<std::fs::File>,
    broadcaster: &broadcast::Sender<UiLogEntry>,
) {
    let dropped = DROPPED_LOGS.swap(0, Ordering::Relaxed);
    if dropped == 0 {
        return;
    }
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let message = format!("count={dropped}");
    let line = format!(
        "{timestamp_ms} level=ERROR component=general direction=internal sender=- event=logger.dropped message={message:?}"
    );
    if let Some(file) = file
        && let Err(error) = writeln!(file, "{line}")
    {
        eprintln!("Unable to write Iota log file: {error}");
    }
    eprintln!("{line}");
    let _ = broadcaster.send(UiLogEntry {
        timestamp_ms,
        sender: "General".into(),
        message: format!("event=logger.dropped {message}"),
        is_error: true,
    });
}

fn enqueue(message: LogMessage) {
    let Some(tx) = LOGGER.get() else {
        return;
    };
    UNIQUE.store(true, Ordering::Relaxed);
    match tx.try_send(message) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            DROPPED_LOGS.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => eprintln!("Iota logger thread has stopped"),
    }
}

pub fn log_internal_translated(
    kind: PrintType,
    prefix: String,
    is_error: bool,
    key: &str,
    args: Vec<String>,
) {
    enqueue(LogMessage {
        timestamp_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        prefix,
        kind,
        is_error,
        level: if is_error {
            LogLevel::Error
        } else {
            LogLevel::Info
        },
        event: "message",
        translation_key: Some(key.to_string()),
        format_args: args,
        message: None,
    });
}

pub fn log_internal(kind: PrintType, prefix: String, is_error: bool, message: String) {
    log_event_internal(
        kind,
        if is_error {
            LogLevel::Error
        } else {
            LogLevel::Info
        },
        "message",
        prefix,
        message,
    );
}

pub fn log_event_internal(
    kind: PrintType,
    level: LogLevel,
    event: &'static str,
    prefix: String,
    message: String,
) {
    enqueue(LogMessage {
        timestamp_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        prefix,
        kind,
        is_error: level == LogLevel::Error,
        level,
        event,
        translation_key: None,
        format_args: Vec::new(),
        message: Some(message),
    });
}

#[macro_export]
macro_rules! log_event {
    ($kind:expr, $level:expr, $event:expr, $($arg:tt)*) => {
        $crate::log_event_internal($kind, $level, $event, String::new(), format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_t {
    ($key:expr) => {
        $crate::log_internal_translated(
            $crate::PrintType::General,
            "".to_string(),
            false,
            $key,
            vec![]
        )
    };

    ($key:expr, $($arg:expr),+) => {
        $crate::log_internal_translated(
            $crate::PrintType::General,
            "".to_string(),
            false,
            $key,
            vec![$($arg),+]
        )
    };
}

#[macro_export]
macro_rules! log_t_err {
    ($key:expr) => {
        $crate::log_internal_translated(
            $crate::PrintType::General,
            "".to_string(),
            true,
            $key,
            vec![]
        )
    };

    ($key:expr, $($arg:expr),+) => {
        $crate::log_internal_translated(
            $crate::PrintType::General,
            "".to_string(),
            true,
            $key,
            vec![$($arg.to_string()),+]
        )
    };
}

/// Log a command message.
#[macro_export]
macro_rules! log_command {
    ($($arg:tt)*) => {
        $crate::log_internal(
            $crate::PrintType::Command,
            "".to_string(),
            false,
            format!($($arg)*)
        )
    };
}

/// Log a general informational message.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::log_internal(
            $crate::PrintType::General,
            "".to_string(),
            false,
            format!($($arg)*)
        )
    };
}

/// Log an inbound message (`>`).
#[macro_export]
macro_rules! log_in {
    ($($arg:tt)*) => {
        $crate::log_internal(
            $crate::PrintType::General,
            ">".to_string(),
            false,
            format!($($arg)*)
        )
    };
}

/// Log an outbound message (`<`).
#[macro_export]
macro_rules! log_out {
    ($($arg:tt)*) => {
        $crate::log_internal(
            $crate::PrintType::General,
            "<".to_string(),
            false,
            format!($($arg)*)
        )
    };
}

/// Log an error message (`>>`).
#[macro_export]
macro_rules! log_err {
    ($($arg:tt)*) => {
        $crate::log_internal(
            $crate::PrintType::General,
            ">>".to_string(),
            true,
            format!($($arg)*)
        )
    };
}

// ******** COMMUNICATION VALUES ********
pub fn log_cv_internal(
    prefix: &'static str,
    cv: &CommunicationValue,
    print_type: Option<PrintType>,
) {
    let formatted = format_cv(cv);

    log_event_internal(
        print_type.unwrap_or(PrintType::General),
        LogLevel::Debug,
        if prefix.trim() == "<" {
            "protocol.sent"
        } else {
            "protocol.received"
        },
        prefix.to_string(),
        formatted,
    );
}

pub fn format_cv(cv: &CommunicationValue) -> String {
    let mut parts = Vec::new();

    match (cv.sender(), cv.receiver()) {
        (Some(sender), Some(receiver)) => parts.push(format!("{} > {}", sender, receiver)),
        (Some(sender), None) => parts.push(sender.to_string()),
        (None, Some(receiver)) => parts.push(format!("> {}", receiver)),
        (None, None) => {}
    }

    let comm_type = cv
        .get_comm_type_enum()
        .map(|kind| kind.to_string())
        .unwrap_or_else(|| cv.get_type().to_string());
    let id = cv
        .id()
        .map_or_else(|| "none".to_string(), |value| value.to_string());
    parts.push(format!("{} (id={})", comm_type, id));

    if cv.is_type(CommunicationType::Relay) {
        parts.push("<opaque relay payload>".into());
        return parts.join(": ");
    }
    if let Some(data) = cv.data() {
        let type_map = cv.type_map().cloned().unwrap_or_else(TypeMap::latest);
        parts.push(format_data_container(data, &type_map));
    }

    parts.join(": ")
}

fn format_data_container(data: &[(DataTypeId, DataValue)], type_map: &TypeMap) -> String {
    data.iter()
        .map(|(key, value)| {
            let name = type_map
                .data_type_name(key.0)
                .map(str::to_owned)
                .unwrap_or_else(|| key.to_string());
            match value {
                DataValue::SignedNumber(value)
                    if matches!(
                        name.as_str(),
                        "UserId"
                            | "IotaId"
                            | "OmikronId"
                            | "InvitationId"
                            | "RelayMessageId"
                            | "VersionNumber"
                            | "Offset"
                            | "Amount"
                    ) =>
                {
                    format!("{name}={value}")
                }
                DataValue::UnsignedNumber(value)
                    if matches!(
                        name.as_str(),
                        "UserId"
                            | "IotaId"
                            | "OmikronId"
                            | "InvitationId"
                            | "RelayMessageId"
                            | "VersionNumber"
                            | "Offset"
                            | "Amount"
                    ) =>
                {
                    format!("{name}={value}")
                }
                DataValue::Container(inner) => {
                    format!("{name}={{ {} }}", format_data_container(inner, type_map))
                }
                DataValue::Array(values) => format!("{name}=<array:{}>", values.len()),
                DataValue::Str(_) => format!("{name}=<string>"),
                DataValue::Bytes(_) => format!("{name}=<bytes>"),
                DataValue::Bool(_) | DataValue::BoolTrue | DataValue::BoolFalse => {
                    format!("{name}=<bool>")
                }
                DataValue::SignedNumber(_) | DataValue::UnsignedNumber(_) => {
                    format!("{name}=<number>")
                }
                _ => format!("{name}=<value>"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[macro_export]
macro_rules! log_cv {
    ($kind:expr, $cv:expr) => {
        $crate::log_cv_internal("", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::log_cv_internal("", &$cv, None)
    };
}

#[macro_export]
macro_rules! log_cv_in {
    ($kind:expr, $cv:expr) => {
        $crate::log_cv_internal("> ", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::log_cv_internal("> ", $cv, None)
    };
}

#[macro_export]
macro_rules! log_cv_out {
    ($kind:expr, $cv:expr) => {
        $crate::log_cv_internal("< ", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::log_cv_internal("< ", $cv, None)
    };
}

#[cfg(test)]
mod tests {
    use super::format_cv;
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    #[test]
    fn protocol_values_are_metadata_only() {
        let value = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(
                DataType::SessionToken,
                DataValue::Str("session-secret-value".into()),
            )
            .add_typed_default(
                DataType::CallToken,
                DataValue::Str("livekit-secret-token".into()),
            )
            .add_typed_default(DataType::Username, DataValue::Str("alice".into()))
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(172));
        let formatted = format_cv(&value);
        for secret in ["session-secret-value", "livekit-secret-token", "alice"] {
            assert!(!formatted.contains(secret));
        }
        assert!(formatted.contains("SessionToken=<string>"));
        assert!(formatted.contains("UserId=172"));
        assert!(
            format_cv(&CommunicationValue::new(CommunicationType::Relay))
                .contains("<opaque relay payload>")
        );
    }
}
