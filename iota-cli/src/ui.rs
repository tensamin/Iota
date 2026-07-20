use crate::{
    input_handler::setup_input_handler, interaction_result::InteractionResult,
    ipc_client::IpcClient, screens::screens::Screen,
};
use crossterm::event::KeyEvent;
use once_cell::sync::Lazy;
use ratatui::{Terminal, backend::CrosstermBackend, init};
use std::{
    collections::VecDeque,
    io::Stdout,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::RwLock, time::Instant};

/// UI state and rendering

pub static FPS: Lazy<RwLock<(f64, f64)>> = Lazy::new(|| RwLock::new((0.0, 0.0)));

pub struct UI {
    ipc: Arc<IpcClient>,
    shutdown: AtomicBool,
    pub terminal: Arc<Mutex<Terminal<CrosstermBackend<Stdout>>>>,
    screen_stack: Arc<RwLock<Vec<Box<dyn Screen>>>>,
}

pub fn start_tui(ipc: Arc<IpcClient>) -> Arc<UI> {
    let ui = Arc::new(UI::new(ipc));
    let uic = ui.clone();
    tokio::spawn(async move {
        let mut last_render = Instant::now();

        let mut fps_samples: VecDeque<f64> = VecDeque::with_capacity(20);
        let mut skip_samples: VecDeque<u16> = VecDeque::with_capacity(20);

        let mut fps_sum = 0.0;
        let mut skip_sum: u32 = 0;

        let mut skipped = 0;

        loop {
            if uic.is_shutdown() {
                break;
            }

            if skipped > 5 {
                uic.render().await;

                skip_samples.push_back(skipped);
                skip_sum += skipped as u32;

                if skip_samples.len() > 20 {
                    if let Some(old) = skip_samples.pop_front() {
                        skip_sum -= old as u32;
                    }
                }

                skipped = 0;

                let elapsed = last_render.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let fps = 1.0 / elapsed;

                    fps_samples.push_back(fps);
                    fps_sum += fps;

                    if fps_samples.len() > 20 {
                        if let Some(old) = fps_samples.pop_front() {
                            fps_sum -= old;
                        }
                    }
                }

                let avg_fps = if !fps_samples.is_empty() {
                    fps_sum / fps_samples.len() as f64
                } else {
                    0.0
                };

                let avg_skips_percentage = if !skip_samples.is_empty() {
                    let avg_skipped = skip_sum as f64 / skip_samples.len() as f64;
                    let total_iterations = avg_skipped + 1.0;
                    (avg_skipped / total_iterations) * 100.0
                } else {
                    0.0
                };

                *FPS.write().await = (avg_fps, avg_skips_percentage);

                last_render = Instant::now();
            } else {
                skipped += 1;
            }
            tokio::time::sleep(Duration::from_millis(16)).await;
        }
        ratatui::restore();
    });
    setup_input_handler(ui.clone());
    ui
}
impl UI {
    pub fn new(ipc: Arc<IpcClient>) -> Self {
        let terminal = init();
        Self {
            ipc,
            shutdown: AtomicBool::new(false),
            terminal: Arc::new(Mutex::new(terminal)),
            screen_stack: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn ipc(&self) -> Arc<IpcClient> {
        self.ipc.clone()
    }

    pub fn client_state(&self) -> iota_state::ClientState {
        self.ipc.state()
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub async fn send_restart(&self) -> std::io::Result<()> {
        self.ipc.send_command(0, "restart".into()).await
    }

    pub async fn set_screen(&self, screen: Box<dyn Screen>) {
        self.screen_stack.write().await.push(screen);
    }
    pub async fn replace_screen(&self, screen: Box<dyn Screen>) {
        let mut stack = self.screen_stack.write().await;
        stack.pop();
        stack.push(screen);
    }
    pub async fn handle_input(self: Arc<Self>, key_event: KeyEvent) {
        let result = {
            let mut stack = self.screen_stack.write().await;
            if let Some(screen) = stack.last_mut() {
                screen.handle_input(key_event)
            } else {
                return;
            }
        };
        match result {
            InteractionResult::OpenScreen { screen } => {
                self.set_screen(screen).await;
            }
            InteractionResult::OpenFutureScreen { screen: fut } => {
                let ui = self.clone();
                let screen = fut.await;
                ui.set_screen(screen).await;
            }
            InteractionResult::CloseScreen => {
                let mut stack = self.screen_stack.write().await;
                stack.pop();

                if stack.is_empty() {
                    self.request_shutdown();
                }
            }
            InteractionResult::Handled => {}
            InteractionResult::Unhandled => {}
        }
    }

    pub async fn render(&self) {
        if let Some(screen) = self.screen_stack.read().await.last() {
            let mut terminal = self.terminal.lock().unwrap();
            terminal
                .draw(|f| {
                    screen.render(f, f.area());
                })
                .unwrap();
        }
    }
}
