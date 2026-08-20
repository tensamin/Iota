use async_trait::async_trait;
use std::{
    fmt::{Display, Formatter},
    sync::Arc,
};

pub const PROCESS_MANAGER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitStatus {
    pub active: bool,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupMode {
    AlwaysOn,
    SocketActivated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAction {
    Start,
    Stop,
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetectedStartupMode {
    AlwaysOn,
    SocketActivated,
    Disabled,
    Conflicting,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonStartupStatus {
    pub service: UnitStatus,
    pub socket: UnitStatus,
    pub detected: DetectedStartupMode,
}

impl DaemonStartupStatus {
    pub fn classify(service: UnitStatus, socket: UnitStatus) -> Self {
        let detected = match (service.enabled, socket.enabled) {
            (true, false) => DetectedStartupMode::AlwaysOn,
            (false, true) => DetectedStartupMode::SocketActivated,
            (false, false) => DetectedStartupMode::Disabled,
            (true, true) => DetectedStartupMode::Conflicting,
        };
        Self {
            service,
            socket,
            detected,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessManagerErrorKind {
    CommandUnavailable,
    PermissionDenied,
    UnitMissing,
    CommandFailed,
    ParseFailed,
    VerificationFailed,
    TimedOut,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessManagerError {
    pub kind: ProcessManagerErrorKind,
    message: String,
}
impl ProcessManagerError {
    pub fn new(kind: ProcessManagerErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn kind(&self) -> ProcessManagerErrorKind {
        self.kind
    }
}
impl Display for ProcessManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ProcessManagerError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn output(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<CommandOutput, ProcessManagerError>;
}

#[async_trait]
pub trait ProcessManager: Send + Sync {
    fn name(&self) -> &'static str;
    async fn unit_status(&self, unit: &str) -> Result<UnitStatus, ProcessManagerError>;
    async fn set_iota_startup_mode(
        &self,
        mode: StartupMode,
    ) -> Result<DaemonStartupStatus, ProcessManagerError>;
    async fn iota_startup_status(&self) -> Result<DaemonStartupStatus, ProcessManagerError> {
        Ok(DaemonStartupStatus::classify(
            self.unit_status("iota-daemon.service").await?,
            self.unit_status("iota-daemon.socket").await?,
        ))
    }
    async fn enable_startup(
        &self,
        mode: StartupMode,
    ) -> Result<DaemonStartupStatus, ProcessManagerError> {
        self.set_iota_startup_mode(mode).await
    }
    async fn disable_startup(&self) -> Result<DaemonStartupStatus, ProcessManagerError> {
        self.set_iota_startup_mode(StartupMode::SocketActivated)
            .await
    }
    async fn process_action(
        &self,
        action: ProcessAction,
    ) -> Result<DaemonStartupStatus, ProcessManagerError> {
        let unit = "iota-daemon.service";
        match action {
            ProcessAction::Start => self.unit_action(&["start", unit]).await?,
            ProcessAction::Stop => self.unit_action(&["stop", unit]).await?,
            ProcessAction::Restart => self.unit_action(&["restart", unit]).await?,
        }
        self.iota_startup_status().await
    }
    async fn unit_action(&self, _action: &[&str]) -> Result<(), ProcessManagerError> {
        Err(ProcessManagerError::new(
            ProcessManagerErrorKind::CommandFailed,
            "process actions are unsupported",
        ))
    }
}

pub async fn detect() -> Option<Arc<dyn ProcessManager>> {
    #[cfg(target_os = "linux")]
    {
        systemd::SystemdManager::detect()
            .await
            .map(|m| Arc::new(m) as Arc<dyn ProcessManager>)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
mod systemd {
    use super::*;
    use std::{path::Path, process::Stdio};
    use tokio::{io::AsyncRead, process::Command, time::timeout};

    const SERVICE: &str = "iota-daemon.service";
    const SOCKET: &str = "iota-daemon.socket";
    const COMMON: [&str; 2] = ["--no-pager", "--no-ask-password"];
    const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;

    pub struct RealExecutor;

    async fn read_bounded<R>(reader: R) -> std::io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;

        let mut output = Vec::new();
        reader
            .take((MAX_COMMAND_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut output)
            .await?;
        if output.len() > MAX_COMMAND_OUTPUT_BYTES {
            output.truncate(MAX_COMMAND_OUTPUT_BYTES);
        }
        Ok(output)
    }

    async fn collect_output(
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
    ) -> Result<(Vec<u8>, Vec<u8>), ProcessManagerError> {
        let (stdout_result, stderr_result) =
            tokio::join!(read_bounded(stdout), read_bounded(stderr));
        let stdout = stdout_result.map_err(|error| {
            ProcessManagerError::new(
                ProcessManagerErrorKind::CommandFailed,
                format!("stdout read failed: {error}"),
            )
        })?;
        let stderr = stderr_result.map_err(|error| {
            ProcessManagerError::new(
                ProcessManagerErrorKind::CommandFailed,
                format!("stderr read failed: {error}"),
            )
        })?;
        Ok((stdout, stderr))
    }

    impl RealExecutor {
        async fn output_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            process_timeout: std::time::Duration,
        ) -> Result<CommandOutput, ProcessManagerError> {
            let mut child = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| {
                    ProcessManagerError::new(
                        ProcessManagerErrorKind::CommandUnavailable,
                        format!("Could not run {program}: {e}"),
                    )
                })?;

            let stdout = child.stdout.take().ok_or_else(|| {
                ProcessManagerError::new(
                    ProcessManagerErrorKind::CommandFailed,
                    "command stdout pipe was not created",
                )
            })?;
            let stderr = child.stderr.take().ok_or_else(|| {
                ProcessManagerError::new(
                    ProcessManagerErrorKind::CommandFailed,
                    "command stderr pipe was not created",
                )
            })?;
            let output_task = tokio::spawn(collect_output(stdout, stderr));

            let status = match timeout(process_timeout, child.wait()).await {
                Ok(result) => result.map_err(|e| {
                    ProcessManagerError::new(ProcessManagerErrorKind::CommandFailed, e.to_string())
                })?,
                Err(_) => {
                    // Keep the Child alive across the timeout. Explicitly
                    // terminate it and await wait() so the OS child is
                    // reaped before reporting the timeout.
                    let kill_error = child.start_kill().err();
                    let wait_error = child.wait().await.err();
                    output_task.abort();
                    let _ = output_task.await;

                    if let Some(error) = wait_error {
                        return Err(ProcessManagerError::new(
                            ProcessManagerErrorKind::CommandFailed,
                            format!("{program} timed out and could not be reaped: {error}"),
                        ));
                    }
                    let termination_detail = kill_error
                        .map(|error| format!("; termination request reported: {error}"))
                        .unwrap_or_default();
                    return Err(ProcessManagerError::new(
                        ProcessManagerErrorKind::TimedOut,
                        format!(
                            "{program} timed out after {} seconds{termination_detail}",
                            process_timeout.as_secs(),
                        ),
                    ));
                }
            };

            let (stdout, stderr) = output_task.await.map_err(|error| {
                ProcessManagerError::new(
                    ProcessManagerErrorKind::CommandFailed,
                    format!("command output task failed: {error}"),
                )
            })??;
            Ok(CommandOutput {
                success: status.success(),
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            })
        }
    }

    #[async_trait]
    impl CommandExecutor for RealExecutor {
        async fn output(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, ProcessManagerError> {
            self.output_with_timeout(program, args, PROCESS_MANAGER_TIMEOUT)
                .await
        }
    }

    pub struct SystemdManager {
        executor: Arc<dyn CommandExecutor>,
        service: &'static str,
        socket: &'static str,
    }
    impl SystemdManager {
        pub async fn detect() -> Option<Self> {
            if !Path::new("/run/systemd/system").is_dir() {
                return None;
            }
            let executor: Arc<dyn CommandExecutor> = Arc::new(RealExecutor);
            let mut manager = executor
                .output("systemctl", &["--version", &COMMON[0], &COMMON[1]])
                .await
                .ok()
                .filter(|r| r.success)
                .map(|_| Self {
                    executor,
                    service: SERVICE,
                    socket: SOCKET,
                })?;
            if manager.status("iota.service").await.is_ok() {
                manager.service = "iota.service";
                manager.socket = "iota.socket";
            }
            Some(manager)
        }
        #[cfg(test)]
        pub fn with_executor(executor: Arc<dyn CommandExecutor>) -> Self {
            Self {
                executor,
                service: SERVICE,
                socket: SOCKET,
            }
        }
        async fn run(&self, action: &[&str]) -> Result<(), ProcessManagerError> {
            let mut args = COMMON.to_vec();
            args.extend_from_slice(action);
            let output = self.executor.output("systemctl", &args).await?;
            if output.success {
                return Ok(());
            }
            let detail = if output.stderr.trim().is_empty() {
                output.stdout.trim()
            } else {
                output.stderr.trim()
            };
            let kind = if detail.to_ascii_lowercase().contains("access denied")
                || detail.to_ascii_lowercase().contains("permission denied")
            {
                ProcessManagerErrorKind::PermissionDenied
            } else {
                ProcessManagerErrorKind::CommandFailed
            };
            Err(ProcessManagerError::new(
                kind,
                if detail.is_empty() {
                    format!("systemctl {} failed", action.join(" "))
                } else {
                    detail.to_owned()
                },
            ))
        }
        async fn status(&self, unit: &str) -> Result<UnitStatus, ProcessManagerError> {
            let mut args = COMMON.to_vec();
            args.extend_from_slice(&[
                "show",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=UnitFileState",
                "--value",
                unit,
            ]);
            let output = self.executor.output("systemctl", &args).await?;
            if !output.success {
                let detail = if output.stderr.trim().is_empty() {
                    output.stdout.trim()
                } else {
                    output.stderr.trim()
                };
                let kind = if detail.to_ascii_lowercase().contains("denied") {
                    ProcessManagerErrorKind::PermissionDenied
                } else {
                    ProcessManagerErrorKind::CommandFailed
                };
                return Err(ProcessManagerError::new(
                    kind,
                    format!("systemctl could not inspect {unit}: {detail}"),
                ));
            }
            let values: Vec<_> = output.stdout.lines().map(str::trim).collect();
            if values.len() < 3 {
                return Err(ProcessManagerError::new(
                    ProcessManagerErrorKind::ParseFailed,
                    format!("systemctl returned incomplete state for {unit}"),
                ));
            }
            if values[0] == "not-found" {
                return Err(ProcessManagerError::new(
                    ProcessManagerErrorKind::UnitMissing,
                    format!("systemd unit {unit} was not found"),
                ));
            }
            if values[0] != "loaded" {
                return Err(ProcessManagerError::new(
                    ProcessManagerErrorKind::ParseFailed,
                    format!("unsupported LoadState `{}` for {unit}", values[0]),
                ));
            }
            let active = match values[1] {
                "active" => true,
                "inactive" | "failed" | "activating" | "deactivating" | "reloading" => false,
                v => {
                    return Err(ProcessManagerError::new(
                        ProcessManagerErrorKind::ParseFailed,
                        format!("unsupported ActiveState `{v}` for {unit}"),
                    ));
                }
            };
            let enabled = match values[2] {
                "enabled" | "enabled-runtime" => true,
                "disabled" | "static" | "indirect" | "masked" | "generated" | "transient" => false,
                v => {
                    return Err(ProcessManagerError::new(
                        ProcessManagerErrorKind::ParseFailed,
                        format!("unsupported UnitFileState `{v}` for {unit}"),
                    ));
                }
            };
            Ok(UnitStatus { active, enabled })
        }
        async fn verify(
            &self,
            expected: DetectedStartupMode,
        ) -> Result<DaemonStartupStatus, ProcessManagerError> {
            let status = self.iota_startup_status().await?;
            if status.detected == expected {
                Ok(status)
            } else {
                Err(ProcessManagerError::new(
                    ProcessManagerErrorKind::VerificationFailed,
                    format!(
                        "systemd reported {:?} after applying {:?}",
                        status.detected, expected
                    ),
                ))
            }
        }
    }
    #[async_trait]
    impl ProcessManager for SystemdManager {
        fn name(&self) -> &'static str {
            "systemd"
        }
        async fn unit_status(&self, unit: &str) -> Result<UnitStatus, ProcessManagerError> {
            self.status(unit).await
        }
        async fn iota_startup_status(&self) -> Result<DaemonStartupStatus, ProcessManagerError> {
            Ok(DaemonStartupStatus::classify(
                self.status(self.service).await?,
                self.status(self.socket).await?,
            ))
        }
        async fn set_iota_startup_mode(
            &self,
            mode: StartupMode,
        ) -> Result<DaemonStartupStatus, ProcessManagerError> {
            match mode {
                StartupMode::AlwaysOn => {
                    self.run(&["disable", self.socket]).await?;
                    self.run(&["enable", "--now", self.service]).await?;
                    self.verify(DetectedStartupMode::AlwaysOn).await
                }
                StartupMode::SocketActivated => {
                    self.run(&["disable", "--now", self.service]).await?;
                    self.run(&["enable", "--now", self.socket]).await?;
                    self.verify(DetectedStartupMode::SocketActivated).await
                }
            }
        }
        async fn unit_action(&self, action: &[&str]) -> Result<(), ProcessManagerError> {
            self.run(action).await
        }
        async fn process_action(
            &self,
            action: ProcessAction,
        ) -> Result<DaemonStartupStatus, ProcessManagerError> {
            let verb = match action {
                ProcessAction::Start => "start",
                ProcessAction::Stop => "stop",
                ProcessAction::Restart => "restart",
            };
            self.run(&[verb, self.service]).await?;
            self.iota_startup_status().await
        }
        async fn disable_startup(&self) -> Result<DaemonStartupStatus, ProcessManagerError> {
            self.run(&["disable", "--now", self.service]).await?;
            self.run(&["disable", "--now", self.socket]).await?;
            self.verify(DetectedStartupMode::Disabled).await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        struct Fake {
            calls: Mutex<Vec<Vec<String>>>,
            results: Mutex<Vec<CommandOutput>>,
        }
        #[async_trait]
        impl CommandExecutor for Fake {
            async fn output(
                &self,
                _: &str,
                args: &[&str],
            ) -> Result<CommandOutput, ProcessManagerError> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(args.iter().map(|arg| (*arg).to_owned()).collect());
                Ok(self.results.lock().unwrap().remove(0))
            }
        }
        fn ok(stdout: &str) -> CommandOutput {
            CommandOutput {
                success: true,
                stdout: stdout.into(),
                stderr: String::new(),
            }
        }

        #[tokio::test]
        async fn every_systemctl_operation_disables_interactive_features() {
            let fake = Arc::new(Fake {
                calls: Mutex::new(Vec::new()),
                results: Mutex::new(vec![ok("loaded\nactive\nenabled\n")]),
            });
            let manager = SystemdManager::with_executor(fake.clone());
            manager.unit_status(SERVICE).await.unwrap();
            let call = &fake.calls.lock().unwrap()[0];
            assert!(call.contains(&"--no-pager".into()));
            assert!(call.contains(&"--no-ask-password".into()));
        }

        #[tokio::test]
        async fn timed_out_real_child_is_terminated_and_reaped() {
            use std::fs;
            use std::time::Duration;

            let directory = tempfile::tempdir().unwrap();
            let pid_file = directory.path().join("child.pid");
            let script = format!(
                "printf '%s' \"$$\" > '{}'; exec sleep 60",
                pid_file.display()
            );
            let executor = RealExecutor;
            let task = tokio::spawn(async move {
                executor
                    .output_with_timeout("sh", &["-c", &script], Duration::from_millis(50))
                    .await
            });

            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            let pid = loop {
                if let Ok(contents) = fs::read_to_string(&pid_file) {
                    if let Ok(pid) = contents.parse::<libc::pid_t>() {
                        break pid;
                    }
                }
                assert!(tokio::time::Instant::now() < deadline);
                tokio::task::yield_now().await;
            };

            let result = task.await.unwrap();
            assert_eq!(
                result.unwrap_err().kind(),
                ProcessManagerErrorKind::TimedOut
            );
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

            let mut status = 0;
            let wait_result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            assert_eq!(wait_result, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modes_distinct() {
        assert_ne!(StartupMode::AlwaysOn, StartupMode::SocketActivated);
    }

    struct BlockingExecutor;
    #[async_trait::async_trait]
    impl CommandExecutor for BlockingExecutor {
        async fn output(&self, _: &str, _: &[&str]) -> Result<CommandOutput, ProcessManagerError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn executor_future_can_be_cancelled_without_blocking_runtime() {
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            BlockingExecutor.output("systemctl", &["show"]),
        )
        .await;
        assert!(result.is_err());
    }
}
