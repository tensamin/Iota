use crate::{
    ACTIVE_TASKS, SHUTDOWN,
    gui::{
        input_handler::setup_input_handler, interaction_result::InteractionResult,
        screens::screens::Screen,
    },
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
pub static UNIQUE: AtomicBool = AtomicBool::new(true);

pub static FPS: Lazy<RwLock<(f64, f64)>> = Lazy::new(|| RwLock::new((0.0, 0.0)));

pub struct UI {
    pub terminal: Arc<Mutex<Terminal<CrosstermBackend<Stdout>>>>,
    screen_stack: Arc<RwLock<Vec<Box<dyn Screen>>>>,
}

pub fn start_tui() -> Arc<UI> {
    let ui = Arc::new(UI::new());
    let uic = ui.clone();
    ACTIVE_TASKS.insert("UI Renderer".to_string());
    tokio::spawn(async move {
        let mut last_render = Instant::now();

        let mut fps_samples: VecDeque<f64> = VecDeque::with_capacity(20);
        let mut skip_samples: VecDeque<u16> = VecDeque::with_capacity(20);

        let mut fps_sum = 0.0;
        let mut skip_sum: u32 = 0;

        let mut skipped = 0;

        loop {
            if *SHUTDOWN.read().await {
                break;
            }

            if skipped > 5 || UNIQUE.load(Ordering::Relaxed) {
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
                UNIQUE.store(false, Ordering::Relaxed);
            } else {
                skipped += 1;
            }
            tokio::time::sleep(Duration::from_millis(16)).await;
        }
        ACTIVE_TASKS.remove("UI Renderer");
        ratatui::restore();
    });
    setup_input_handler(ui.clone());
    ui
}
impl UI {
    pub fn new() -> Self {
        let terminal = init();
        Self {
            terminal: Arc::new(Mutex::new(terminal)),
            screen_stack: Arc::new(RwLock::new(Vec::new())),
        }
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
                    *SHUTDOWN.write().await = true;
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
