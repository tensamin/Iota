use crate::{ACTIVE_TASKS, APP_STATE, SHUTDOWN, gui::elements::log_card::UiLogEntry};
use json::{JsonValue, object};
use std::{collections::VecDeque, thread, time::Duration};
use sysinfo::{RefreshKind, System};

#[derive(Clone)]
pub struct AppState {
    pub logs: VecDeque<UiLogEntry>,
    pub cpu: Vec<(f64, f64)>,
    pub ram: Vec<(f64, f64)>,
    pub ping: Vec<(f64, f64)>,
    pub net_up: Vec<(f64, f64)>,
    pub net_down: Vec<(f64, f64)>,
    pub sys_info: String,
}
const MAX_POINTS: usize = 1000;
const MAX_LOGS: usize = 100;

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
        self.cpu.push(pt);
        if self.cpu.len() > MAX_POINTS {
            self.cpu.remove(0);
        }
    }

    pub fn push_ram(&mut self, pt: (f64, f64)) {
        self.ram.push(pt);
        if self.ram.len() > MAX_POINTS {
            self.ram.remove(0);
        }
    }

    pub fn push_ping_val(&mut self, pt: f64) {
        self.ping.push((self.ping.len() as f64, pt));
        if self.ping.len() > MAX_POINTS {
            self.ping.remove(0);
        }
    }

    pub fn push_net_up(&mut self, pt: (f64, f64)) {
        self.net_up.push(pt);
        if self.net_up.len() > MAX_POINTS {
            self.net_up.remove(0);
        }
    }

    pub fn push_net_down(&mut self, pt: (f64, f64)) {
        self.net_down.push(pt);
        if self.net_down.len() > MAX_POINTS {
            self.net_down.remove(0);
        }
    }
    pub fn to_json(&self) -> JsonValue {
        let json = object! {
            "cpu" => self.cpu
            .iter()
            .map(|(_, y)| *y)
            .collect::<Vec<f64>>(),
            "ram" => self.ram
            .iter()
            .map(|(_, y)| *y)
            .collect::<Vec<f64>>(),
            "ping" => self
            .ping
            .iter()
            .map(|(_, y)| *y)
            .collect::<Vec<f64>>(),
            "net_up" => self
            .net_up
            .iter()
            .map(|(_, y)| *y)
            .collect::<Vec<f64>>(),
            "net_down" => self
            .net_down
            .iter()
            .map(|(_, y)| *y)
            .collect::<Vec<f64>>(),
        };
        json
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
            let _ = data.first().map(|(_, y)| *y).unwrap_or(0.0);

            for i in 0..pad_len {
                result.push((start_x + i as f64 * dx, -1 as f64));
            }

            result.extend_from_slice(data);
            result
        }
    }
}

pub fn setup() {
    ACTIVE_TASKS.insert("System info loader".to_string());
    tokio::spawn(async move {
        let mut sys = System::new_with_specifics(RefreshKind::everything());
        let mut last_total_received = 0u64;
        let mut last_total_transmitted = 0u64;
        let mut counter = 0.0;
        loop {
            if *SHUTDOWN.read().await {
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
                let mut st = APP_STATE.lock().unwrap();
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
        ACTIVE_TASKS.remove("System info loader");
    });
}
