use iota_ipc::StateSnapshot;
use iota_state::DaemonState;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{RefreshKind, System};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Reason the daemon is shutting down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    Stop,
    Restart,
    Fatal(String),
}

impl ShutdownReason {
    pub fn exit_code(&self) -> i32 {
        match self {
            ShutdownReason::Stop => 0,
            ShutdownReason::Restart => 75,
            ShutdownReason::Fatal(_) => 1,
        }
    }
}

/// Tracks the lifecycle phase of the daemon for IPC visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupPhase {
    Starting,
    MigratingStorage,
    LoadingUsers,
    StartingServices,
    Ready,
    Degraded,
    Stopping,
}

impl From<StartupPhase> for iota_ipc::StartupPhase {
    fn from(phase: StartupPhase) -> Self {
        match phase {
            StartupPhase::Starting => iota_ipc::StartupPhase::Starting,
            StartupPhase::MigratingStorage => iota_ipc::StartupPhase::MigratingStorage,
            StartupPhase::LoadingUsers => iota_ipc::StartupPhase::LoadingUsers,
            StartupPhase::StartingServices => iota_ipc::StartupPhase::StartingServices,
            StartupPhase::Ready => iota_ipc::StartupPhase::Ready,
            StartupPhase::Degraded => iota_ipc::StartupPhase::Degraded,
            StartupPhase::Stopping => iota_ipc::StartupPhase::Stopping,
        }
    }
}

/* This wrapper exposes daemon state as IPC-safe snapshots while preserving a
 * single owned state instance for all daemon subsystems. The cancellation token
 * is the single lifecycle signal — all subsystems check it instead of a
 * separate boolean. */
pub struct DaemonRuntime {
    pub state: Arc<DaemonState>,
    pub cancellation: CancellationToken,
    pub shutdown_tx: watch::Sender<Option<ShutdownReason>>,
    pub startup_phase: watch::Sender<StartupPhase>,
    pub degraded_reason: watch::Sender<Option<String>>,
}

impl Clone for DaemonRuntime {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            cancellation: self.cancellation.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            startup_phase: self.startup_phase.clone(),
            degraded_reason: self.degraded_reason.clone(),
        }
    }
}

impl Default for DaemonRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonRuntime {
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(None);
        let (startup_phase, _) = watch::channel(StartupPhase::Starting);
        let (degraded_reason, _) = watch::channel(None);
        Self {
            state: Arc::new(DaemonState::new()),
            cancellation: CancellationToken::new(),
            shutdown_tx,
            startup_phase,
            degraded_reason,
        }
    }

    pub fn shutdown(&self, reason: ShutdownReason) {
        self.cancellation.cancel();
        let _ = self.shutdown_tx.send(Some(reason));
    }

    pub fn shutdown_reason(&self) -> Option<ShutdownReason> {
        self.shutdown_tx.borrow().clone()
    }

    pub fn is_shutting_down(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn set_startup_phase(&self, phase: StartupPhase) {
        let _ = self.startup_phase.send(phase);
    }

    pub fn current_startup_phase(&self) -> StartupPhase {
        *self.startup_phase.borrow()
    }

    pub fn mark_degraded(&self, reason: String) {
        let _ = self.degraded_reason.send(Some(reason.clone()));
        let _ = self.startup_phase.send(StartupPhase::Degraded);
    }

    pub fn snapshot(&self) -> StateSnapshot {
        let state = self
            .state
            .app
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        StateSnapshot {
            cpu: state.cpu.clone(),
            ram: state.ram.clone(),
            ping: state.ping.clone(),
            net_up: state.net_up.clone(),
            net_down: state.net_down.clone(),
            sys_info: state.sys_info.clone(),
        }
    }

    pub fn spawn_system_monitor(&self) {
        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.state.active_tasks.insert("System monitor".into());
            let mut system = System::new_with_specifics(RefreshKind::everything());
            let mut counter = 0.0;
            loop {
                if runtime.is_shutting_down() {
                    break;
                }
                system.refresh_cpu_all();
                system.refresh_memory();
                let cpu = system.global_cpu_usage() as f64;
                let total_memory = system.total_memory();
                let ram = if total_memory == 0 {
                    0.0
                } else {
                    system.used_memory() as f64 / total_memory as f64 * 100.0
                };
                {
                    let mut state = runtime
                        .state
                        .app
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    state.push_cpu((counter, cpu));
                    state.push_ram((counter, ram));
                    state.sys_info = format!("CPU: {cpu:.1}%  RAM: {ram:.1}%");
                }
                counter += 1.0;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            runtime.state.active_tasks.remove("System monitor");
        });
    }
}
