use crate::{
    input_handler::setup_input_handler,
    interaction_result::InteractionResult,
    ipc_client::IpcClient,
    render_context::RenderContext,
    screens::screens::Screen,
    theme::{self, ResolvedTheme, ThemeName},
};
use crossterm::event::KeyEvent;
use once_cell::sync::Lazy;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    io,
    io::Stdout,
    panic::PanicHookInfo,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// UI state and rendering

pub static FPS: Lazy<RwLock<(f64, f64)>> = Lazy::new(|| RwLock::new((0.0, 0.0)));

pub struct UI {
    ipc: RwLock<Option<Arc<IpcClient>>>,
    shutdown_on_empty: bool,
    cancellation: CancellationToken,
    pub terminal: Arc<Mutex<Terminal<CrosstermBackend<Stdout>>>>,
    screen_stack: Arc<RwLock<Vec<Box<dyn Screen>>>>,
    theme: RwLock<Arc<ResolvedTheme>>,
    pub(crate) invalidation: Notify,
    failure: Arc<Mutex<Option<String>>>,
}

pub fn start_tui(ipc: Arc<IpcClient>) -> io::Result<TuiSession> {
    start_tui_with_theme(ipc, theme::resolve(ThemeName::Ansi))
}

pub fn start_tui_with_theme(ipc: Arc<IpcClient>, theme: ResolvedTheme) -> io::Result<TuiSession> {
    start_session(UI::new(Some(ipc), true, theme)?)
}

pub fn start_bootstrap_tui() -> io::Result<TuiSession> {
    start_bootstrap_tui_with_theme(theme::resolve(ThemeName::Ansi))
}

pub fn start_bootstrap_tui_with_theme(theme: ResolvedTheme) -> io::Result<TuiSession> {
    start_session(UI::new(None, false, theme)?)
}

fn start_session(ui: UI) -> io::Result<TuiSession> {
    let ui = Arc::new(ui);
    let uic = ui.clone();
    let renderer_task = tokio::spawn(async move {
        let cancellation = uic.cancellation_token();
        let result: io::Result<()> = loop {
            tokio::select! {
                _ = cancellation.cancelled() => break Ok(()),
                _ = uic.invalidation.notified() => { if !uic.is_shutdown() { uic.render().await?; } },
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => { if !uic.is_shutdown() { uic.render().await?; } },
            }
        };
        if let Err(error) = &result {
            *uic.failure.lock().unwrap() = Some(error.to_string());
            uic.request_shutdown();
        }
        result
    });
    let input_task = setup_input_handler(ui.clone());
    // Some terminals deliver Ctrl+C as SIGINT even while crossterm is in raw
    // mode. Keep this independent of key-event handling for bootstrap work.
    let signal_task = {
        #[cfg(unix)]
        {
            let signal_ui = ui.clone();
            Some(tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    signal_ui.request_shutdown();
                }
            }))
        }
        #[cfg(not(unix))]
        {
            None
        }
    };
    let previous_hook = Arc::new(Mutex::new(Some(std::panic::take_hook())));
    let hook_for_panic = previous_hook.clone();
    std::panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
        ratatui::restore();
        if let Some(hook) = hook_for_panic.lock().unwrap().as_ref() {
            hook(info);
        }
    }));
    Ok(TuiSession {
        ui,
        renderer_task,
        input_task,
        signal_task,
        restored: AtomicBool::new(false),
        previous_hook,
    })
}

pub struct TuiSession {
    ui: Arc<UI>,
    renderer_task: JoinHandle<io::Result<()>>,
    input_task: JoinHandle<Result<(), String>>,
    signal_task: Option<JoinHandle<()>>,
    restored: AtomicBool,
    previous_hook: Arc<Mutex<Option<Box<dyn Fn(&PanicHookInfo<'_>) + Send + Sync + 'static>>>>,
}

impl TuiSession {
    pub fn ui(&self) -> Arc<UI> {
        self.ui.clone()
    }
    pub async fn shutdown(mut self) -> Option<String> {
        self.ui.request_shutdown();
        // Restore raw-mode state before waiting on cooperative tasks.  A
        // misbehaving task must never leave the invoking shell unusable.
        self.restore_terminal_once();
        let renderer =
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut self.renderer_task).await;
        let input =
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut self.input_task).await;
        if renderer.is_err() {
            self.renderer_task.abort();
        }
        if input.is_err() {
            self.input_task.abort();
        }
        if let Some(task) = self.signal_task.as_mut() {
            task.abort();
            let _ = task.await;
        }
        self.restore_panic_hook();
        match renderer {
            Err(_) => Some("renderer did not stop within 2 seconds".into()),
            Ok(Err(error)) => Some(format!("renderer task failed: {error}")),
            Ok(Ok(Err(error))) => Some(error.to_string()),
            Ok(Ok(Ok(()))) => match input {
                Err(_) => Some("input handler did not stop within 2 seconds".into()),
                Ok(Err(error)) => Some(format!("input handler failed: {error}")),
                Ok(Ok(Err(error))) => Some(error),
                Ok(Ok(Ok(()))) => None,
            },
        }
    }
    fn restore_terminal_once(&self) {
        if !self.restored.swap(true, Ordering::AcqRel) {
            ratatui::restore();
        }
    }
    fn restore_panic_hook(&self) {
        if let Some(hook) = self.previous_hook.lock().unwrap().take() {
            std::panic::set_hook(hook);
        }
    }
}
impl Drop for TuiSession {
    fn drop(&mut self) {
        self.ui.request_shutdown();
        self.renderer_task.abort();
        self.input_task.abort();
        if let Some(task) = self.signal_task.as_ref() {
            task.abort();
        }
        self.restore_panic_hook();
        self.restore_terminal_once();
    }
}
impl UI {
    pub(crate) fn new(
        ipc: Option<Arc<IpcClient>>,
        shutdown_on_empty: bool,
        theme: ResolvedTheme,
    ) -> io::Result<Self> {
        let terminal = ratatui::try_init()?;
        Ok(Self {
            ipc: RwLock::new(ipc),
            shutdown_on_empty,
            cancellation: CancellationToken::new(),
            terminal: Arc::new(Mutex::new(terminal)),
            screen_stack: Arc::new(RwLock::new(Vec::new())),
            theme: RwLock::new(Arc::new(theme)),
            invalidation: Notify::new(),
            failure: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn ipc(&self) -> Option<Arc<IpcClient>> {
        self.ipc.read().await.clone()
    }

    pub async fn client_state(&self) -> Option<iota_state::ClientState> {
        self.ipc.read().await.as_ref().map(|ipc| ipc.state())
    }

    pub async fn attach_daemon(&self, ipc: Arc<IpcClient>) {
        *self.ipc.write().await = Some(ipc);
    }

    pub async fn set_theme(&self, theme: ResolvedTheme) {
        *self.theme.write().await = Arc::new(theme);
        self.invalidate();
    }
    pub async fn theme_name(&self) -> ThemeName {
        self.theme.read().await.name
    }

    pub fn is_shutdown(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn request_shutdown(&self) {
        self.cancellation.cancel();
        self.invalidate();
    }
    pub fn invalidate(&self) {
        self.invalidation.notify_one();
    }
    pub fn failure(&self) -> Option<String> {
        self.failure.lock().ok().and_then(|f| f.clone())
    }
    pub async fn handle_paste(&self, _text: String) {
        self.invalidate();
    }

    /// Lets bootstrap operations race their work against Ctrl+C without
    /// blocking the input task or leaving the terminal in raw mode.
    pub async fn wait_for_shutdown(&self) {
        self.cancellation.cancelled().await;
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub async fn set_screen(&self, screen: Box<dyn Screen>) {
        self.screen_stack.write().await.push(screen);
        self.invalidate();
    }
    pub async fn replace_screen(&self, screen: Box<dyn Screen>) {
        let mut stack = self.screen_stack.write().await;
        stack.clear();
        stack.push(screen);
        self.invalidate();
    }
    pub async fn set_root_screen(&self, screen: Box<dyn Screen>) {
        let mut stack = self.screen_stack.write().await;
        stack.clear();
        stack.push(screen);
        self.invalidate();
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
                tokio::select! {
                    screen = fut => ui.set_screen(screen).await,
                    _ = ui.cancellation.cancelled() => return,
                }
            }
            InteractionResult::CloseScreen => {
                let mut stack = self.screen_stack.write().await;
                stack.pop();

                if stack.is_empty() && self.shutdown_on_empty {
                    self.request_shutdown();
                }
            }
            InteractionResult::Handled => {}
            InteractionResult::Unhandled => {}
        }
        self.invalidate();
    }

    pub async fn render(&self) -> io::Result<()> {
        let theme = self.theme.read().await.clone();
        let context = RenderContext {
            theme: theme.as_ref(),
        };
        // The renderer is the only task that takes the terminal lock.  Screen
        // mutations use the stack lock briefly before invalidating a frame.
        if let Some(screen) = self.screen_stack.read().await.last() {
            let mut terminal = self
                .terminal
                .lock()
                .map_err(|_| io::Error::other("terminal mutex poisoned"))?;
            terminal.draw(|f| {
                screen.render(f, f.area(), &context);
            })?;
        }
        Ok(())
    }
}
