use crate::{
    controls::header::render_header,
    help_overlay::HelpOverlay,
    input_handler::setup_input_handler,
    interaction_result::InteractionResult,
    ipc_client::{DaemonStatus, IpcClient, IpcConnectionState},
    notification::{Notification, render_notification_area},
    render_context::RenderContext,
    screens::{
        main_screen::MainScreen,
        metrics::MetricsScreen,
        overview::OverviewScreen,
        screens::{AppAction, AppEvent, HitMap, Screen, UiEvent},
        settings::SettingsScreen,
        users::{UserEntry, UsersScreen},
    },
    theme::{self, ResolvedTheme, ThemeName},
};
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, KeyCode, KeyEvent, MouseEventKind,
};
use once_cell::sync::Lazy;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
};
use std::{
    io,
    io::Stdout,
    panic::PanicHookInfo,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Notify, RwLock, mpsc};
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
    hits: Mutex<HitMap>,
    app_event_tx: mpsc::UnboundedSender<UiEvent>,
    app_event_rx: Mutex<Option<mpsc::UnboundedReceiver<UiEvent>>>,
    header_focus: Mutex<Option<usize>>,
    notifications: Arc<Mutex<Vec<Notification>>>,
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
    let mut app_event_rx = ui
        .app_event_rx
        .lock()
        .map_err(|_| io::Error::other("application event queue poisoned"))?
        .take()
        .ok_or_else(|| io::Error::other("application event queue already started"))?;
    let app_ui = ui.clone();
    let app_event_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = app_ui.cancellation.cancelled() => break,
                event = app_event_rx.recv() => match event {
                    Some(event) => app_ui.clone().handle_event(event).await,
                    None => break,
                },
            }
        }
    });
    let uic = ui.clone();
    let renderer_task = tokio::spawn(async move {
        let cancellation = uic.cancellation_token();
        let result: io::Result<()> = loop {
            tokio::select! {
                _ = cancellation.cancelled() => break Ok(()),
                _ = uic.invalidation.notified() => { if !uic.is_shutdown() { uic.render().await?; } },
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
        app_event_task,
        signal_task,
        restored: AtomicBool::new(false),
        previous_hook,
    })
}

pub struct TuiSession {
    ui: Arc<UI>,
    renderer_task: JoinHandle<io::Result<()>>,
    input_task: JoinHandle<Result<(), String>>,
    app_event_task: JoinHandle<()>,
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
        self.app_event_task.abort();
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
            let _ = crossterm::execute!(io::stdout(), DisableMouseCapture);
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
        self.app_event_task.abort();
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
        crossterm::execute!(io::stdout(), EnableMouseCapture)?;
        let (app_event_tx, app_event_rx) = mpsc::unbounded_channel();
        Ok(Self {
            ipc: RwLock::new(ipc),
            shutdown_on_empty,
            cancellation: CancellationToken::new(),
            terminal: Arc::new(Mutex::new(terminal)),
            screen_stack: Arc::new(RwLock::new(Vec::new())),
            theme: RwLock::new(Arc::new(theme)),
            invalidation: Notify::new(),
            failure: Arc::new(Mutex::new(None)),
            hits: Mutex::new(HitMap::default()),
            app_event_tx,
            app_event_rx: Mutex::new(Some(app_event_rx)),
            header_focus: Mutex::new(None),
            notifications: Arc::new(Mutex::new(Vec::new())),
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
    /// Lets bootstrap operations race their work against Ctrl+C without
    /// blocking the input task or leaving the terminal in raw mode.
    pub async fn wait_for_shutdown(&self) {
        self.cancellation.cancelled().await;
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub async fn push_notification(&self, notification: Notification) {
        if let Ok(mut notifications) = self.notifications.lock() {
            notifications.push(notification);
            self.invalidate();
        }
    }

    pub async fn clear_expired_notifications(&self) {
        if let Ok(mut notifications) = self.notifications.lock() {
            let before = notifications.len();
            notifications.retain(|n| !n.is_expired());
            if notifications.len() != before {
                self.invalidate();
            }
        }
    }

    pub async fn notifications(&self) -> Vec<Notification> {
        self.notifications.lock().map(|n| n.clone()).unwrap_or_default()
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
        self.handle_event(UiEvent::Key(key_event)).await;
    }
    pub async fn handle_event(self: Arc<Self>, event: UiEvent) {
        if matches!(&event, UiEvent::App(AppEvent::OpenUsers)) {
            self.open_users().await;
            return;
        }
        if matches!(&event, UiEvent::App(AppEvent::OpenMetrics)) {
            if let Some(screen) = MetricsScreen::new(self.clone()).await {
                self.set_screen(Box::new(screen)).await;
            }
            return;
        }
        if let UiEvent::App(AppEvent::ApplyTheme { theme, persist }) = &event {
            self.set_theme(theme::resolve(*theme)).await;
            if *persist {
                let mut config = theme::UiConfig::load().unwrap_or_default();
                config.theme = *theme;
                let result = config
                    .save()
                    .map_err(|error| format!("Could not save UI settings: {error}"));
                let _ = self
                    .app_event_tx
                    .send(UiEvent::App(AppEvent::ThemeSaved(result)));
            }
            return;
        }
        if let UiEvent::App(AppEvent::SaveSettings {
            theme,
            color,
            unicode,
            cli_output,
            cli_require_confirmation,
        }) = &event
        {
            self.set_theme(theme::resolve(*theme)).await;
            let mut config = theme::UiConfig::load().unwrap_or_default();
            config.theme = *theme;
            config.color = *color;
            config.unicode = *unicode;
            config.cli_output = *cli_output;
            config.cli_require_confirmation = *cli_require_confirmation;
            let result = config
                .save()
                .map_err(|error| format!("Could not save UI settings: {error}"));
            let _ = self
                .app_event_tx
                .send(UiEvent::App(AppEvent::ThemeSaved(result)));
            return;
        }
        if matches!(&event, UiEvent::App(AppEvent::RegenerateKeysRequested)) {
            let Some(ipc) = self.ipc().await else {
                let _ = self
                    .app_event_tx
                    .send(UiEvent::App(AppEvent::KeysRegenerated(Err(
                        "Not connected to daemon.".into(),
                    ))));
                return;
            };
            let sender = self.app_event_tx.clone();
            tokio::spawn(async move {
                let result = match ipc
                    .send_request(iota_ipc::LocalRequest::RotateIotaIdentity)
                    .await
                {
                    Ok(iota_ipc::ResponseResult::Ok(_)) => Ok(()),
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Cannot regenerate keys: {error}"))
                    }
                    Err(error) => Err(format!("Cannot regenerate keys: {error}")),
                };
                let _ = sender.send(UiEvent::App(AppEvent::KeysRegenerated(result)));
            });
            return;
        }
        if let UiEvent::Key(key) = &event {
            let header_is_focused = self
                .header_focus
                .lock()
                .map(|focus| focus.is_some())
                .unwrap_or(false);
            if key.code == KeyCode::F(6) {
                if let Ok(mut focus) = self.header_focus.lock() {
                    *focus = if focus.is_some() { None } else { Some(0) };
                }
                self.invalidate();
                return;
            }
            if key.code == KeyCode::Char('?') {
                let has_help_overlay = self
                    .screen_stack
                    .read()
                    .await
                    .iter()
                    .any(|s| s.as_any().downcast_ref::<HelpOverlay>().is_some());
                if !has_help_overlay {
                    self.set_screen(Box::new(HelpOverlay::new())).await;
                }
                return;
            }
            if header_is_focused {
                let mut action = None;
                if let Ok(mut focus) = self.header_focus.lock() {
                    let index = focus.unwrap_or(0);
                    match key.code {
                        KeyCode::Left | KeyCode::BackTab => *focus = Some((index + 3) % 4),
                        KeyCode::Right | KeyCode::Tab => *focus = Some((index + 1) % 4),
                        KeyCode::Enter | KeyCode::Char(' ') => {
                            action = Some(
                                [
                                    AppAction::OpenOverview,
                                    AppAction::OpenUsers,
                                    AppAction::OpenSettings,
                                    AppAction::Quit,
                                ][index],
                            );
                            *focus = None;
                        }
                        KeyCode::Esc => *focus = None,
                        _ => {}
                    }
                }
                if let Some(action) = action {
                    self.dispatch_action(action).await;
                } else {
                    self.invalidate();
                }
                return;
            }
        }
        if let UiEvent::Mouse(mouse) = &event {
            if matches!(
                mouse.kind,
                MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            ) {
                let action = self
                    .hits
                    .lock()
                    .ok()
                    .and_then(|hits| hits.action_at(mouse.column, mouse.row));
                if action == Some(AppAction::FocusLogs) {
                    self.dispatch_action(AppAction::FocusLogs).await;
                    let key = if matches!(mouse.kind, MouseEventKind::ScrollUp) {
                        KeyCode::Up
                    } else {
                        KeyCode::Down
                    };
                    // Log scrolling is a local, handled interaction; route it
                    // directly rather than recursively constructing another
                    // async UI event future.
                    if let Some(screen) = self.screen_stack.write().await.last_mut() {
                        let _ = screen.handle_event(UiEvent::Key(KeyEvent::from(key)));
                    }
                    self.invalidate();
                    return;
                }
            }
            if matches!(
                mouse.kind,
                MouseEventKind::Down(crossterm::event::MouseButton::Left)
            ) {
                if let Some(action) = self
                    .hits
                    .lock()
                    .ok()
                    .and_then(|hits| hits.action_at(mouse.column, mouse.row))
                {
                    self.dispatch_action(action).await;
                    return;
                }
            }
        }
        let result = {
            let mut stack = self.screen_stack.write().await;
            if let Some(screen) = stack.last_mut() {
                screen.handle_event(event)
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
            InteractionResult::AppTask { task } => {
                let sender = self.app_event_tx.clone();
                tokio::spawn(async move {
                    let event = task.await;
                    let _ = sender.send(event);
                });
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

    async fn dispatch_action(self: &Arc<Self>, action: AppAction) {
        match action {
            AppAction::Quit => self.request_shutdown(),
            AppAction::OpenMain => {
                let mut stack = self.screen_stack.write().await;
                if stack.len() > 1 {
                    stack.truncate(1);
                }
                drop(stack);
                self.invalidate();
            }
            AppAction::OpenOverview => {
                let status = {
                    let stack = self.screen_stack.read().await;
                    stack
                        .iter()
                        .rev()
                        .find_map(|s| s.as_any().downcast_ref::<MainScreen>())
                        .map(|main| (main.connection_status(), main.daemon_status()))
                };
                if let Some((connection, daemon)) = status {
                    self.set_screen(Box::new(OverviewScreen::new(connection, daemon)))
                        .await;
                }
            }
            AppAction::OpenUsers => self.open_users().await,
            AppAction::OpenSettings => {
                let current = self.theme_name().await;
                self.set_screen(Box::new(SettingsScreen::new(current)))
                    .await;
            }
            AppAction::OpenMetrics => {
                if let Some(screen) = MetricsScreen::new(self.clone()).await {
                    self.set_screen(Box::new(screen)).await;
                }
            }
            action => {
                let result = {
                    let mut stack = self.screen_stack.write().await;
                    stack.last_mut().map(|screen| screen.handle_action(action))
                };
                if matches!(result, Some(InteractionResult::CloseScreen)) {
                    let mut stack = self.screen_stack.write().await;
                    stack.pop();
                }
                self.invalidate();
            }
        }
    }
    async fn open_users(self: &Arc<Self>) {
        let Some(ipc) = self.ipc().await else { return };
        self.set_screen(Box::new(UsersScreen::loading(ipc.clone())))
            .await;
        let sender = self.app_event_tx.clone();
        let ui = self.clone();
        tokio::spawn(async move {
            let load = async {
                match ipc.send_request(iota_ipc::LocalRequest::ListUsers).await {
                    Ok(iota_ipc::ResponseResult::Ok(iota_ipc::ResponsePayload::Users(users))) => {
                        Ok(users
                            .into_iter()
                            .map(|u| UserEntry {
                                user_id: u.user_id,
                                username: u.username,
                                state: u.state,
                                data_present: u.data_present,
                                credential_present: u.credential_present,
                            })
                            .collect())
                    }
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Cannot load users: {error}"))
                    }
                    Ok(_) => Err("Daemon returned an unexpected response while loading users.".into()),
                    Err(error) => Err(format!("Cannot load users: {error}")),
                }
            };
            tokio::pin!(load);
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(200));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let result = loop {
                tokio::select! {
                    result = &mut load => break result,
                    _ = ticker.tick() => {
                        ui.invalidate();
                    }
                }
            };
            let _ = sender.send(UiEvent::App(AppEvent::UsersLoaded(result)));
        });
    }

    pub async fn render(&self) -> io::Result<()> {
        self.clear_expired_notifications().await;
        let theme = self.theme.read().await.clone();
        let context = RenderContext {
            theme: theme.as_ref(),
        };
        // The renderer is the only task that takes the terminal lock.  Screen
        // mutations use the stack lock briefly before invalidating a frame.
        let stack_guard = self.screen_stack.read().await;
        let (connection, daemon) = stack_guard
            .iter()
            .find_map(|item| item.as_any().downcast_ref::<MainScreen>())
            .map(|main| {
                (
                    main.connection_status().borrow().clone(),
                    main.daemon_status().borrow().clone(),
                )
            })
            .unwrap_or_else(|| (IpcConnectionState::Disconnected, DaemonStatus::default()));
        if let Some(screen) = stack_guard.last() {
            let mut terminal = self
                .terminal
                .lock()
                .map_err(|_| io::Error::other("terminal mutex poisoned"))?;
            let mut hits = HitMap::default();
            terminal.draw(|f| {
                let rows = Layout::vertical([
                    Constraint::Length(2),
                    Constraint::Min(1),
                    Constraint::Length(1),
                ])
                .split(f.area());
                let header_focus = self.header_focus.lock().ok().and_then(|focus| *focus);
                render_header(
                    f,
                    rows[0],
                    &connection,
                    &daemon,
                    context.theme,
                    &mut hits,
                    header_focus,
                );
                let hints = if header_focus.is_some() {
                    " Left/Right: choose   Enter: activate   Esc/F6: screen".to_owned()
                } else {
                    let mut screen_hints: Vec<String> = screen
                        .key_hints()
                        .into_iter()
                        .map(|hint| format!("{}: {}", hint.keys, hint.action))
                        .collect();
                    if !screen_hints.iter().any(|h| h.contains("?")) {
                        screen_hints.push("?: Help".to_owned());
                    }
                    screen_hints.join("   ")
                };
                f.render_widget(
                    ratatui::widgets::Paragraph::new(format!(" {hints}")).style(
                        context
                            .theme
                            .surfaces
                            .footer
                            .patch(context.theme.text.muted),
                    ),
                    rows[2],
                );
                screen.render(f, rows[1], &context, &mut hits);

                if let Ok(notifications) = self.notifications.try_lock() {
                    if !notifications.is_empty() {
                        let notification_area = Rect {
                            x: rows[1].x + rows[1].width.saturating_sub(40),
                            y: rows[1].y,
                            width: 40.min(rows[1].width),
                            height: 3.min(rows[1].height),
                        };
                        render_notification_area(f, notification_area, &notifications, context.theme);
                    }
                }
            })?;
            if let Ok(mut current) = self.hits.lock() {
                *current = hits;
            }
        }
        Ok(())
    }
}
