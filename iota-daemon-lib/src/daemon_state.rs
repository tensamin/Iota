use iota_ipc::StateSnapshot;
use iota_state::DaemonState;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{RefreshKind, System};

/* This wrapper exposes daemon state as IPC-safe snapshots while preserving a
 * single owned state instance for all daemon subsystems. */
#[derive(Clone, Default)]
pub struct DaemonRuntime {
    pub state: Arc<DaemonState>,
}

impl DaemonRuntime {
    pub fn new() -> Self {
        Self {
            state: Arc::new(DaemonState::new()),
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
        }
    }

    pub fn spawn_system_monitor(&self) {
        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.state.active_tasks.insert("System monitor".into());
            let mut system = System::new_with_specifics(RefreshKind::everything());
            let mut counter = 0.0;
            loop {
                if *runtime.state.shutdown.read().await {
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
