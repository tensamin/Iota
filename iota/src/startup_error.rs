use std::{fmt, io, path::PathBuf, process::ExitCode};

#[allow(dead_code)]
#[derive(Debug)]
pub enum StartupError {
    Cancelled,
    DaemonExecutableMissing(PathBuf),
    LocalSocketNotWritable(PathBuf, io::Error),
    SystemManagerUnavailable,
    SystemPermissionDenied(String),
    SystemCommandTimedOut(String),
    SocketPermissionDenied(PathBuf),
    IpcTimedOut(PathBuf),
    ProtocolMismatch { daemon: u16, minimum: u16 },
    DaemonExited { message: String },
    IpcBindUnavailable(String),
    Terminal(String),
    Consent(String),
    InvalidCommand(String),
    Other(String),
}

impl StartupError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Cancelled => 130,
            Self::InvalidCommand(_) => 2,
            _ => 1,
        }
    }

    pub fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::DaemonExecutableMissing(_) => {
                Some("Install the daemon with `iota daemon install` or ensure it is in your PATH.")
            }
            Self::LocalSocketNotWritable(_, _) => {
                Some("Check permissions on the parent directory or run as your user (not root).")
            }
            Self::SystemManagerUnavailable => {
                Some("Install systemd or another supported process manager.")
            }
            Self::SystemPermissionDenied(_) => {
                Some("Run with appropriate privileges or use a user-level daemon instead.")
            }
            Self::SocketPermissionDenied(_) => {
                Some(
                    "Check file permissions on the socket or ensure the daemon is running as your user.",
                )
            }
            Self::IpcTimedOut(_) => {
                Some(
                    "The daemon may be starting up. Wait a moment and try again, or check daemon logs.",
                )
            }
            Self::ProtocolMismatch { .. } => {
                Some("Update your CLI or daemon to match versions.")
            }
            Self::DaemonExited { .. } => {
                Some("Restart the daemon with `iota daemon restart`.")
            }
            Self::IpcBindUnavailable(_) => {
                Some("Another instance may be running. Stop it first or use a different socket path.")
            }
            Self::Terminal(_) => {
                Some("Use a terminal that supports interactive mode, or run commands headlessly.")
            }
            Self::Consent(_) => {
                Some("Run `iota terms accept` in an interactive terminal to review and accept terms.")
            }
            Self::InvalidCommand(_) => {
                Some("Run `iota --help` to see available commands.")
            }
            _ => None,
        }
    }
}
impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Cancelled."),
            Self::DaemonExecutableMissing(path) => write!(
                f,
                "Daemon executable is missing or not executable: {}",
                path.display()
            ),
            Self::LocalSocketNotWritable(path, error) => write!(
                f,
                "Local socket path is not writable ({}): {error}",
                path.display()
            ),
            Self::SystemManagerUnavailable => {
                f.write_str("No supported system process manager is available.")
            }
            Self::SystemPermissionDenied(message) => {
                write!(f, "System-level authorization is required: {message}")
            }
            Self::SystemCommandTimedOut(command) => {
                write!(f, "System command timed out: {command}")
            }
            Self::SocketPermissionDenied(path) => {
                write!(f, "Permission denied for IPC socket {}", path.display())
            }
            Self::IpcTimedOut(path) => write!(f, "IPC operation timed out for {}", path.display()),
            Self::ProtocolMismatch { daemon, minimum } => write!(
                f,
                "Daemon protocol {daemon} is incompatible; minimum supported version is {minimum}"
            ),
            Self::DaemonExited { message } => f.write_str(message),
            Self::IpcBindUnavailable(message) => {
                write!(f, "Daemon IPC listener is unavailable: {message}")
            }
            Self::Terminal(message) => write!(f, "Interactive terminal is unavailable: {message}"),
            Self::Consent(message) | Self::InvalidCommand(message) | Self::Other(message) => {
                f.write_str(message)
            }
        }
    }
}
pub fn exit_code(error: &StartupError) -> ExitCode {
    ExitCode::from(error.exit_code())
}

pub fn print_error(error: &StartupError) {
    let color = crate::cli_color::ColorConfig::new();
    eprintln!("{} {}", crate::cli_color::error(&color, "error:"), error);
    if let Some(suggestion) = error.suggestion() {
        eprintln!(
            "  {} {}",
            crate::cli_color::info(&color, "hint:"),
            suggestion
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_and_invalid_commands_have_stable_codes() {
        assert_eq!(StartupError::Cancelled.exit_code(), 130);
        assert_eq!(StartupError::InvalidCommand("bad".into()).exit_code(), 2);
    }
    #[test]
    fn administrative_errors_are_actionable() {
        let error = StartupError::SystemPermissionDenied("run as an administrator".into());
        assert!(error.to_string().contains("authorization"));
        assert!(error.to_string().contains("administrator"));
    }
    #[test]
    fn most_errors_have_suggestions() {
        assert!(StartupError::DaemonExecutableMissing(PathBuf::from("iota-daemon")).suggestion().is_some());
        assert!(StartupError::IpcTimedOut(PathBuf::from("/tmp/iota.sock")).suggestion().is_some());
        assert!(StartupError::Cancelled.suggestion().is_none());
    }
}
