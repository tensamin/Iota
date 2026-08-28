use crate::TaskRegistry;
use iota_ipc::StateSnapshot;
use iota_state::DaemonState;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
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
 * is the single lifecycle signal, and all subsystems check it instead of a
 * separate boolean. */
pub struct DaemonRuntime {
    pub state: Arc<DaemonState>,
    pub cancellation: CancellationToken,
    pub shutdown_tx: watch::Sender<Option<ShutdownReason>>,
    shutdown_rx: watch::Receiver<Option<ShutdownReason>>,
    pub startup_phase: watch::Sender<StartupPhase>,
    pub degraded_reason: watch::Sender<Option<String>>,
    startup_phase_rx: watch::Receiver<StartupPhase>,
    degraded_reason_rx: watch::Receiver<Option<String>>,
    pub lifecycle: watch::Sender<iota_ipc::LifecyclePhase>,
    pub startup_step: watch::Sender<Option<String>>,
    pub components: watch::Sender<BTreeMap<iota_ipc::ComponentId, iota_ipc::ComponentHealth>>,
    lifecycle_rx: watch::Receiver<iota_ipc::LifecyclePhase>,
    startup_step_rx: watch::Receiver<Option<String>>,
    components_rx: watch::Receiver<BTreeMap<iota_ipc::ComponentId, iota_ipc::ComponentHealth>>,
    pub tasks: TaskRegistry,
}

impl Clone for DaemonRuntime {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            cancellation: self.cancellation.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_rx: self.shutdown_rx.clone(),
            startup_phase: self.startup_phase.clone(),
            degraded_reason: self.degraded_reason.clone(),
            startup_phase_rx: self.startup_phase_rx.clone(),
            degraded_reason_rx: self.degraded_reason_rx.clone(),
            lifecycle: self.lifecycle.clone(),
            startup_step: self.startup_step.clone(),
            components: self.components.clone(),
            lifecycle_rx: self.lifecycle_rx.clone(),
            startup_step_rx: self.startup_step_rx.clone(),
            components_rx: self.components_rx.clone(),
            tasks: self.tasks.clone(),
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
        let (shutdown_tx, shutdown_rx) = watch::channel(None);
        let (startup_phase, startup_phase_rx) = watch::channel(StartupPhase::Starting);
        let (degraded_reason, degraded_reason_rx) = watch::channel(None);
        let (lifecycle, lifecycle_rx) = watch::channel(iota_ipc::LifecyclePhase::Starting);
        let (startup_step, startup_step_rx) = watch::channel(Some("starting".to_string()));
        let (components, components_rx) = watch::channel(BTreeMap::new());
        Self {
            state: Arc::new(DaemonState::new()),
            cancellation: CancellationToken::new(),
            shutdown_tx,
            shutdown_rx,
            startup_phase,
            degraded_reason,
            startup_phase_rx,
            degraded_reason_rx,
            lifecycle,
            startup_step,
            components,
            lifecycle_rx,
            startup_step_rx,
            components_rx,
            tasks: TaskRegistry::default(),
        }
    }

    pub fn shutdown(&self, reason: ShutdownReason) {
        self.request_shutdown(reason);
        self.begin_shutdown();
    }

    pub fn request_shutdown(&self, reason: ShutdownReason) {
        if self.shutdown_tx.borrow().is_none() {
            let _ = self.shutdown_tx.send(Some(reason));
        }
    }

    pub fn begin_shutdown(&self) {
        self.cancellation.cancel();
    }

    pub fn shutdown_reason(&self) -> Option<ShutdownReason> {
        self.shutdown_tx.borrow().clone()
    }

    pub fn is_shutting_down(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn set_startup_phase(&self, phase: StartupPhase) {
        let _ = self.startup_phase.send(phase);
        let (lifecycle, step) = match phase {
            StartupPhase::Ready => (iota_ipc::LifecyclePhase::Ready, None),
            StartupPhase::Stopping => (iota_ipc::LifecyclePhase::Stopping, Some("stopping".into())),
            StartupPhase::MigratingStorage => (
                iota_ipc::LifecyclePhase::Starting,
                Some("migrating_storage".into()),
            ),
            StartupPhase::LoadingUsers => (
                iota_ipc::LifecyclePhase::Starting,
                Some("loading_users".into()),
            ),
            StartupPhase::StartingServices => (
                iota_ipc::LifecyclePhase::Starting,
                Some("starting_services".into()),
            ),
            StartupPhase::Starting | StartupPhase::Degraded => {
                (iota_ipc::LifecyclePhase::Starting, Some("starting".into()))
            }
        };
        let _ = self.lifecycle.send(lifecycle);
        let _ = self.startup_step.send(step);
    }

    pub fn current_startup_phase(&self) -> StartupPhase {
        *self.startup_phase.borrow()
    }

    pub fn mark_degraded(&self, reason: String) {
        let _ = self.degraded_reason.send(Some(reason.clone()));
        self.set_component_degraded(iota_ipc::ComponentId::Omikron, reason);
    }

    pub fn set_component_healthy(&self, component: iota_ipc::ComponentId, message: Option<String>) {
        self.update_component(component, iota_ipc::HealthStatus::Healthy, message);
    }

    pub fn set_component_degraded(&self, component: iota_ipc::ComponentId, message: String) {
        self.update_component(component, iota_ipc::HealthStatus::Degraded, Some(message));
    }

    pub fn set_component_failed(&self, component: iota_ipc::ComponentId, message: String) {
        self.update_component(component, iota_ipc::HealthStatus::Failed, Some(message));
    }

    fn update_component(
        &self,
        component: iota_ipc::ComponentId,
        status: iota_ipc::HealthStatus,
        message: Option<String>,
    ) {
        let mut components = self.components.borrow().clone();
        components.insert(
            component,
            iota_ipc::ComponentHealth {
                status,
                message,
                changed_at_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            },
        );
        let _ = self.components.send(components);
    }

    pub fn overall_health(&self) -> iota_ipc::HealthStatus {
        let components = self.components.borrow();
        if [iota_ipc::ComponentId::Ipc, iota_ipc::ComponentId::Storage]
            .iter()
            .any(|id| {
                components
                    .get(id)
                    .is_some_and(|v| v.status == iota_ipc::HealthStatus::Failed)
            })
        {
            return iota_ipc::HealthStatus::Failed;
        }
        if components.values().any(|v| {
            v.status == iota_ipc::HealthStatus::Degraded
                || v.status == iota_ipc::HealthStatus::Failed
        }) {
            iota_ipc::HealthStatus::Degraded
        } else {
            iota_ipc::HealthStatus::Healthy
        }
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
            startup_phase: self.current_startup_phase().into(),
            degraded_reason: self.degraded_reason.borrow().clone(),
            lifecycle: *self.lifecycle.borrow(),
            startup_step: self.startup_step.borrow().clone(),
            overall_health: self.overall_health(),
            components: self.components.borrow().clone(),
        }
    }

    pub async fn spawn_system_monitor(&self) {
        let runtime = self.clone();
        self.tasks
            .spawn_tracked("system-monitor", async move {
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
                Ok(())
            })
            .await;
    }
}
