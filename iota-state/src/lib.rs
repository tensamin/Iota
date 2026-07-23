use dashmap::DashSet;
use json::{JsonValue, object};
#[cfg(feature = "legacy-globals")]
use once_cell::sync::Lazy;
use std::collections::VecDeque;
#[cfg(feature = "legacy-globals")]
use std::sync::LazyLock;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
#[cfg(feature = "legacy-globals")]
use std::thread;
#[cfg(feature = "legacy-globals")]
use std::time::Duration;
#[cfg(feature = "legacy-globals")]
use sysinfo::{RefreshKind, System};
use tokio::sync::{Mutex as TokioMutex, RwLock};

/* Process-owned daemon state and TUI-local state must be separate because IPC,
 * rather than shared memory, is the boundary between the two binaries. */
#[derive(Clone)]
pub struct DaemonState {
    pub app: Arc<Mutex<AppState>>,
    pub shutdown: Arc<RwLock<bool>>,
    pub reload: Arc<RwLock<bool>>,
    pub active_tasks: Arc<DashSet<String>>,
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            app: Arc::new(Mutex::new(AppState::new())),
            shutdown: Arc::new(RwLock::new(false)),
            reload: Arc::new(RwLock::new(false)),
            active_tasks: Arc::new(DashSet::new()),
        }
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

/* The TUI keeps only the daemon data it renders. This state is never shared
 * with the daemon and is populated from daemon IPC messages. */
#[derive(Clone)]
pub struct ClientState {
    pub app: Arc<TokioMutex<AppState>>,
}

impl ClientState {
    pub fn new() -> Self {
        Self {
            app: Arc::new(TokioMutex::new(AppState::new())),
        }
    }
}

impl Default for ClientState {
    fn default() -> Self {
        Self::new()
    }
}

pub const MAX_POINTS: usize = 1000;
pub const MAX_LOGS: usize = 100;

pub static UNIQUE: AtomicBool = AtomicBool::new(true);

#[derive(Clone, Debug)]
pub struct UiLogEntry {
    pub timestamp_ms: u128,
    pub sender: String,
    pub message: String,
    pub is_error: bool,
}

impl UiLogEntry {
    pub fn format_timestamp(&self) -> String {
        let secs = (self.timestamp_ms / 1000) as i64;
        let hours = (secs / 3600) % 24;
        let minutes = (secs / 60) % 60;
        let seconds = secs % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub logs: VecDeque<UiLogEntry>,
    pub cpu: Vec<(f64, f64)>,
    pub ram: Vec<(f64, f64)>,
    pub ping: Vec<(f64, f64)>,
    pub net_up: Vec<(f64, f64)>,
    pub net_down: Vec<(f64, f64)>,
    pub sys_info: String,
    next_sample_id: u64,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            logs: VecDeque::new(),
            cpu: Vec::new(),
            ram: Vec::new(),
            ping: Vec::new(),
            net_up: Vec::new(),
            net_down: Vec::new(),
            sys_info: String::from("Loading..."),
            next_sample_id: 0,
        }
    }

    pub fn push_log(&mut self, msg: UiLogEntry) {
        if self.logs.len() >= MAX_LOGS {
            self.logs.pop_front();
        }
        self.logs.push_back(msg);
    }

    pub fn get_logs(&self) -> &VecDeque<UiLogEntry> {
        &self.logs
    }

    pub fn push_cpu(&mut self, pt: (f64, f64)) {
        let x = self.next_sample();
        self.cpu.push((x, pt.1));
        if self.cpu.len() > MAX_POINTS {
            self.cpu.remove(0);
        }
    }

    pub fn push_ram(&mut self, pt: (f64, f64)) {
        let x = self.next_sample();
        self.ram.push((x, pt.1));
        if self.ram.len() > MAX_POINTS {
            self.ram.remove(0);
        }
    }

    pub fn push_ping_val(&mut self, pt: f64) {
        let x = self.next_sample();
        self.ping.push((x, pt));
        if self.ping.len() > MAX_POINTS {
            self.ping.remove(0);
        }
    }

    pub fn push_net_up(&mut self, pt: (f64, f64)) {
        let x = self.next_sample();
        self.net_up.push((x, pt.1));
        if self.net_up.len() > MAX_POINTS {
            self.net_up.remove(0);
        }
    }

    pub fn push_net_down(&mut self, pt: (f64, f64)) {
        let x = self.next_sample();
        self.net_down.push((x, pt.1));
        if self.net_down.len() > MAX_POINTS {
            self.net_down.remove(0);
        }
    }

    fn next_sample(&mut self) -> f64 {
        let value = self.next_sample_id as f64;
        self.next_sample_id = self.next_sample_id.saturating_add(1);
        value
    }

    pub fn to_json(&self) -> JsonValue {
        object! {
            "cpu" => self.cpu.iter().map(|(_, y)| *y).collect::<Vec<f64>>(),
            "ram" => self.ram.iter().map(|(_, y)| *y).collect::<Vec<f64>>(),
            "ping" => self.ping.iter().map(|(_, y)| *y).collect::<Vec<f64>>(),
            "net_up" => self.net_up.iter().map(|(_, y)| *y).collect::<Vec<f64>>(),
            "net_down" => self.net_down.iter().map(|(_, y)| *y).collect::<Vec<f64>>(),
        }
    }

    pub fn with_width(&self, width: u16) -> Self {
        let mut new = self.clone();
        new.cpu = Self::downsample_to_fit_width(&new.cpu, width);
        new.ram = Self::downsample_to_fit_width(&new.ram, width);
        new.ping = Self::downsample_to_fit_width(&new.ping, width);
        new.net_up = Self::downsample_to_fit_width(&new.net_up, width);
        new.net_down = Self::downsample_to_fit_width(&new.net_down, width);
        new
    }

    fn downsample_to_fit_width(data: &[(f64, f64)], width: u16) -> Vec<(f64, f64)> {
        let width_usize = (width as usize) * 2;
        let len = data.len();

        if len >= width_usize {
            data[len - width_usize..].to_vec()
        } else {
            let mut result = Vec::with_capacity(width_usize);

            let dx = 1.0;
            let pad_len = width_usize - len;

            let start_x = data
                .first()
                .map(|(x, _)| x - (dx * pad_len as f64))
                .unwrap_or(0.0);

            for i in 0..pad_len {
                result.push((start_x + i as f64 * dx, -1.0));
            }

            result.extend_from_slice(data);
            result
        }
    }
}

#[cfg(feature = "legacy-globals")]
#[deprecated(note = "use DaemonState or ClientState")]
pub static APP_STATE: LazyLock<Arc<Mutex<AppState>>> =
    LazyLock::new(|| Arc::new(Mutex::new(AppState::new())));

#[cfg(feature = "legacy-globals")]
#[deprecated(note = "use DaemonState")]
pub static SHUTDOWN: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));
#[cfg(feature = "legacy-globals")]
#[deprecated(note = "use DaemonState")]
pub static RELOAD: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(true));
#[cfg(feature = "legacy-globals")]
#[deprecated(note = "use DaemonState")]
pub static ACTIVE_TASKS: Lazy<DashSet<String>> = Lazy::new(|| DashSet::new());

#[cfg(feature = "legacy-globals")]
pub fn setup(state: &DaemonState) {
    state.active_tasks.insert("System info loader".to_string());
    let state = state.clone();
    tokio::spawn(async move {
        let mut sys = System::new_with_specifics(RefreshKind::everything());
        let mut last_total_received = 0u64;
        let mut last_total_transmitted = 0u64;
        let mut counter = 0.0;
        loop {
            if *state.shutdown.read().await {
                break;
            }
            sys.refresh_all();

            let mut tcpu = 0;
            for cpu in sys.cpus() {
                tcpu += cpu.cpu_usage() as i64;
                tcpu /= 2;
            }
            let ram = (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0;

            let total_received = 0u64;
            let total_transmitted = 0u64;

            let delta_received = if last_total_received == 0 {
                0
            } else {
                total_received.saturating_sub(last_total_received)
            };
            let delta_transmitted = if last_total_transmitted == 0 {
                0
            } else {
                total_transmitted.saturating_sub(last_total_transmitted)
            };
            last_total_received = total_received;
            last_total_transmitted = total_transmitted;

            let net_down = delta_received as f64;
            let net_up = delta_transmitted as f64;

            {
                let mut st = state.app.lock().unwrap();
                st.push_cpu((counter, tcpu as f64));
                st.push_ram((counter, ram));
                st.push_net_down((counter, net_down));
                st.push_net_up((counter, net_up));

                st.sys_info = format!("NetDown: {}  NetUp: {}", delta_received, delta_transmitted);
            }

            counter += 1.0;
            if counter > 30.0 {
                thread::sleep(Duration::from_millis(500));
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
        state.active_tasks.remove("System info loader");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_coordinates_remain_monotonic_after_history_rollover() {
        let mut state = AppState::new();
        for value in 0..(MAX_POINTS + 25) {
            state.push_ping_val(value as f64);
        }
        assert_eq!(state.ping.len(), MAX_POINTS);
        assert!(state.ping.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }
}
