use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use crossterm::event::{KeyCode, KeyModifiers};
use once_cell::sync::Lazy;
use ratatool::{
    AsyncEventSource, Interaction, NotificationOverlay, Runtime, ScreenPresentation,
    SessionOptions, TerminalSession, ThemeState,
};
use ratatui::layout::{Constraint, Layout, Rect};
use tokio::{
    sync::{RwLock, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    controls::header::{HEADER_ITEMS, render_header},
    help_overlay::HelpOverlay,
    ipc_client::{DaemonStatus, IpcClient, IpcConnectionState},
    screens::{
        metrics::MetricsScreen,
        overview::OverviewScreen,
        screens::{
            AppAction, AppEvent, HitMap, IotaEffect, IotaInteraction, IotaMessage, IotaScreen,
            UiEvent,
        },
        settings::SettingsScreen,
        users::{
            UserEntry, UsersScreen, context::credential_status_label,
            credential_export::write_private_export, model::UserAction,
        },
    },
    theme::{self, ResolvedTheme, ThemeName},
};

pub static FPS: Lazy<RwLock<(f64, f64)>> = Lazy::new(|| RwLock::new((0.0, 0.0)));

const UI_EVENT_CAPACITY: usize = 128;
const UI_COMMAND_CAPACITY: usize = 32;
static NEXT_NOTIFICATION_ID: AtomicU64 = AtomicU64::new(1);

struct DriverThemeConfig {
    selected: ThemeName,
    color: theme::TerminalPolicy,
    unicode: theme::TerminalPolicy,
}

pub struct DaemonViewState {
    pub connection: tokio::sync::watch::Receiver<IpcConnectionState>,
    pub status: tokio::sync::watch::Receiver<DaemonStatus>,
}

struct IotaScreenEntry {
    screen: Box<dyn IotaScreen>,
    presentation: ScreenPresentation,
}

pub struct IotaShellState {
    screens: Vec<IotaScreenEntry>,
    header_focus: Option<usize>,
    notifications: NotificationOverlay,
    daemon_view: Option<DaemonViewState>,
    ipc: Option<Arc<IpcClient>>,
    theme: ResolvedTheme,
    shutdown_on_empty: bool,
}

pub type SharedShellState = Arc<Mutex<IotaShellState>>;

pub enum UiCommand {
    Push(Box<dyn IotaScreen>, ScreenPresentation),
    ReplaceRoot(Box<dyn IotaScreen>),
    AttachDaemon(Arc<IpcClient>),
    Notify(ratatool::Notification),
    SetTheme(Box<ResolvedTheme>),
    Shutdown,
    Redraw,
}

#[derive(Clone)]
pub struct UiHandle {
    commands: mpsc::Sender<UiCommand>,
    event_tx: mpsc::Sender<IotaMessage>,
    cancellation: CancellationToken,
    ipc: Arc<RwLock<Option<Arc<IpcClient>>>>,
    failure: Arc<Mutex<Option<String>>>,
}

pub struct TuiSession {
    ui: Arc<UiHandle>,
    driver: JoinHandle<io::Result<()>>,
}

pub fn start_tui(ipc: Arc<IpcClient>) -> io::Result<TuiSession> {
    start_tui_with_theme(ipc, theme::resolve(ThemeName::Ansi))
}

pub fn start_tui_with_theme(
    ipc: Arc<IpcClient>,
    initial_theme: ResolvedTheme,
) -> io::Result<TuiSession> {
    let config = theme::UiConfig::load_or_default();
    start_session(Some(ipc), true, initial_theme, config.color, config.unicode)
}

pub fn start_bootstrap_tui() -> io::Result<TuiSession> {
    start_bootstrap_tui_with_theme(theme::resolve(ThemeName::Ansi))
}

pub fn start_bootstrap_tui_with_theme(initial_theme: ResolvedTheme) -> io::Result<TuiSession> {
    let config = theme::UiConfig::load_or_default();
    start_session(None, false, initial_theme, config.color, config.unicode)
}

pub fn start_bootstrap_tui_with_config(
    selected: ThemeName,
    color: theme::TerminalPolicy,
    unicode: theme::TerminalPolicy,
) -> io::Result<TuiSession> {
    start_session(None, false, theme::resolve(selected), color, unicode)
}

fn start_session(
    ipc: Option<Arc<IpcClient>>,
    shutdown_on_empty: bool,
    initial_theme: ResolvedTheme,
    color_policy: theme::TerminalPolicy,
    unicode_policy: theme::TerminalPolicy,
) -> io::Result<TuiSession> {
    let session = TerminalSession::enter(SessionOptions {
        mouse_capture: true,
        ..SessionOptions::default()
    })?;
    let (commands, command_rx) = mpsc::channel(UI_COMMAND_CAPACITY);
    let (event_tx, event_source) = AsyncEventSource::channel(UI_EVENT_CAPACITY);
    let cancellation = CancellationToken::new();
    let selected_theme = initial_theme.name;
    let shared_ipc = Arc::new(RwLock::new(ipc.clone()));
    let failure = Arc::new(Mutex::new(None));
    let shell = Arc::new(Mutex::new(IotaShellState {
        screens: Vec::new(),
        header_focus: None,
        notifications: NotificationOverlay::default(),
        daemon_view: ipc.as_ref().map(daemon_view),
        ipc,
        theme: initial_theme,
        shutdown_on_empty,
    }));
    let ui = Arc::new(UiHandle {
        commands: commands.clone(),
        event_tx: event_tx.clone(),
        cancellation: cancellation.clone(),
        ipc: shared_ipc,
        failure: failure.clone(),
    });
    let driver = tokio::spawn(async move {
        let result = run_driver(
            session,
            shell,
            command_rx,
            event_source,
            event_tx,
            cancellation.clone(),
            DriverThemeConfig {
                selected: selected_theme,
                color: color_policy,
                unicode: unicode_policy,
            },
        )
        .await;
        if let Err(error) = &result {
            if let Ok(mut slot) = failure.lock() {
                *slot = Some(error.to_string());
            }
            cancellation.cancel();
        }
        result
    });
    Ok(TuiSession { ui, driver })
}

fn daemon_view(ipc: &Arc<IpcClient>) -> DaemonViewState {
    DaemonViewState {
        connection: ipc.connection_status(),
        status: ipc.daemon_status(),
    }
}

impl TuiSession {
    pub fn ui(&self) -> Arc<UiHandle> {
        self.ui.clone()
    }

    pub async fn shutdown(mut self) -> Option<String> {
        self.ui.request_shutdown();
        match tokio::time::timeout(std::time::Duration::from_secs(2), &mut self.driver).await {
            Err(_) => {
                self.driver.abort();
                Some("UiHandle driver did not stop within 2 seconds".into())
            }
            Ok(Err(error)) => Some(format!("UiHandle driver task failed: {error}")),
            Ok(Ok(Err(error))) => Some(error.to_string()),
            Ok(Ok(Ok(()))) => self.ui.failure(),
        }
    }
}

impl Drop for TuiSession {
    fn drop(&mut self) {
        self.ui.request_shutdown();
        self.driver.abort();
    }
}

impl UiHandle {
    pub async fn ipc(&self) -> Option<Arc<IpcClient>> {
        self.ipc.read().await.clone()
    }

    pub async fn attach_daemon(&self, ipc: Arc<IpcClient>) {
        *self.ipc.write().await = Some(ipc.clone());
        let _ = self.commands.send(UiCommand::AttachDaemon(ipc)).await;
    }

    pub async fn set_theme(&self, theme: ResolvedTheme) {
        let _ = self
            .commands
            .send(UiCommand::SetTheme(Box::new(theme)))
            .await;
    }

    pub fn is_shutdown(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn request_shutdown(&self) {
        self.cancellation.cancel();
        let _ = self.commands.try_send(UiCommand::Shutdown);
    }

    pub fn invalidate(&self) {
        let _ = self.event_tx.try_send(IotaMessage::Invalidate);
    }

    pub fn failure(&self) -> Option<String> {
        self.failure.lock().ok().and_then(|failure| failure.clone())
    }

    pub async fn wait_for_shutdown(&self) {
        self.cancellation.cancelled().await;
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub async fn push_notification(&self, mut notification: ratatool::Notification) {
        if notification.id == 0 {
            notification.id = NEXT_NOTIFICATION_ID.fetch_add(1, Ordering::Relaxed);
        }
        let _ = self.commands.send(UiCommand::Notify(notification)).await;
    }

    pub async fn set_screen(&self, screen: Box<dyn IotaScreen>) {
        let _ = self
            .commands
            .send(UiCommand::Push(screen, ScreenPresentation::Replace))
            .await;
    }

    pub async fn replace_screen(&self, screen: Box<dyn IotaScreen>) {
        self.set_root_screen(screen).await;
    }

    pub async fn set_root_screen(&self, screen: Box<dyn IotaScreen>) {
        let _ = self.commands.send(UiCommand::ReplaceRoot(screen)).await;
    }

    pub async fn render(&self) -> io::Result<()> {
        self.commands
            .send(UiCommand::Redraw)
            .await
            .map_err(|_| io::Error::other("UiHandle driver is closed"))
    }
}

struct IotaShell {
    state: SharedShellState,
}

impl IotaShell {
    fn new(state: SharedShellState) -> Self {
        Self { state }
    }

    fn route_interaction(
        &self,
        state: &mut IotaShellState,
        interaction: IotaInteraction,
    ) -> Interaction<IotaMessage> {
        match interaction {
            IotaInteraction::Unhandled => Interaction::Unhandled,
            IotaInteraction::Changed => Interaction::changed(),
            IotaInteraction::Push {
                screen,
                presentation,
            } => {
                state.screens.push(IotaScreenEntry {
                    screen,
                    presentation,
                });
                Interaction::changed()
            }
            IotaInteraction::Pop => {
                state.screens.pop();
                if state.screens.is_empty() && state.shutdown_on_empty {
                    Interaction::Exit
                } else {
                    Interaction::changed()
                }
            }
            IotaInteraction::Effect(effect) => Interaction::message(IotaMessage::Effect(effect)),
            IotaInteraction::Exit => Interaction::Exit,
        }
    }

    fn dispatch_action(
        &self,
        state: &mut IotaShellState,
        action: AppAction,
    ) -> Interaction<IotaMessage> {
        let interaction = match action {
            AppAction::Quit => IotaInteraction::Exit,
            AppAction::OpenMain => {
                state.screens.truncate(1);
                IotaInteraction::Changed
            }
            AppAction::OpenOverview => match &state.daemon_view {
                Some(view) => IotaInteraction::Push {
                    screen: Box::new(OverviewScreen::new(
                        view.connection.clone(),
                        view.status.clone(),
                    )),
                    presentation: ScreenPresentation::Replace,
                },
                None => IotaInteraction::Unhandled,
            },
            AppAction::OpenUsers => IotaInteraction::Effect(IotaEffect::OpenUsers),
            AppAction::OpenSettings => IotaInteraction::Push {
                screen: Box::new(SettingsScreen::new(state.theme.name)),
                presentation: ScreenPresentation::Replace,
            },
            AppAction::OpenMetrics => match &state.ipc {
                Some(ipc) => IotaInteraction::Push {
                    screen: Box::new(MetricsScreen::from_state(ipc.state())),
                    presentation: ScreenPresentation::Replace,
                },
                None => IotaInteraction::Unhandled,
            },
            action => state
                .screens
                .last_mut()
                .map_or(IotaInteraction::Unhandled, |entry| {
                    entry.screen.handle_action(action)
                }),
        };
        self.route_interaction(state, interaction)
    }
}

impl ratatool::Screen<IotaMessage> for IotaShell {
    fn render(&mut self, ui: &mut ratatool::UiFrame<'_, '_, IotaMessage>, area: Rect) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let rows = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);
        let theme = state.theme.clone();
        let (connection, daemon) = state
            .daemon_view
            .as_ref()
            .map(|view| {
                (
                    view.connection.borrow().clone(),
                    view.status.borrow().clone(),
                )
            })
            .unwrap_or_else(|| (IpcConnectionState::Disconnected, DaemonStatus::default()));

        let mut header_hits = HitMap::new();
        render_header(
            ui.frame(),
            rows[0],
            &connection,
            &daemon,
            &theme,
            &mut header_hits,
            state.header_focus,
        );
        for region in header_hits.regions() {
            ui.hit_map().register(region.area, region.action.clone());
        }

        let first_visible = state
            .screens
            .iter()
            .rposition(|entry| entry.presentation == ScreenPresentation::Replace)
            .unwrap_or(0);
        for entry in &mut state.screens[first_visible..] {
            if entry.presentation == ScreenPresentation::ModalOverlay {
                ui.hit_map().clear();
            }
            entry.screen.render(ui, rows[1], &theme);
        }

        let hints = if state.header_focus.is_some() {
            " Left/Right: choose   Enter: activate   Esc/F6: screen".to_owned()
        } else {
            let mut hints = state
                .screens
                .last()
                .map(|entry| entry.screen.key_hints())
                .unwrap_or_default()
                .into_iter()
                .map(|hint| format!("{}: {}", hint.keys, hint.action))
                .collect::<Vec<_>>();
            if !hints.iter().any(|hint| hint.contains('?')) {
                hints.push("?: Help".into());
            }
            format!(" {}", hints.join("   "))
        };
        let footer_style = ui.theme().surfaces.footer.patch(ui.theme().text.muted);
        ui.frame().render_widget(
            ratatui::widgets::Paragraph::new(hints).style(footer_style),
            rows[2],
        );
        ui.notifications(rows[1], &state.notifications);
    }

    fn handle_event(&mut self, event: &ratatool::UiEvent<IotaMessage>) -> Interaction<IotaMessage> {
        let Ok(mut state) = self.state.lock() else {
            return Interaction::Unhandled;
        };
        match event {
            ratatool::UiEvent::Message(IotaMessage::Action(action)) => {
                self.dispatch_action(&mut state, *action)
            }
            ratatool::UiEvent::Message(IotaMessage::Effect(effect)) => {
                Interaction::message(IotaMessage::Effect(effect.clone()))
            }
            ratatool::UiEvent::Message(IotaMessage::Event(event)) => {
                let interaction =
                    state
                        .screens
                        .last_mut()
                        .map_or(IotaInteraction::Unhandled, |entry| {
                            entry
                                .screen
                                .handle_event(&UiEvent::Message(IotaMessage::Event(event.clone())))
                        });
                self.route_interaction(&mut state, interaction)
            }
            ratatool::UiEvent::Message(IotaMessage::Invalidate) => Interaction::changed(),
            ratatool::UiEvent::Tick => {
                if state.notifications.expire(Instant::now()) {
                    Interaction::changed()
                } else {
                    Interaction::unchanged()
                }
            }
            ratatool::UiEvent::Key(key) => {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('q') | KeyCode::Char('c'))
                {
                    return Interaction::Exit;
                }
                if key.code == KeyCode::F(6) {
                    state.header_focus = if state.header_focus.is_some() {
                        None
                    } else {
                        Some(0)
                    };
                    return Interaction::changed();
                }
                if key.code == KeyCode::Char('?') {
                    state.screens.push(IotaScreenEntry {
                        screen: Box::new(HelpOverlay::new()),
                        presentation: ScreenPresentation::ModalOverlay,
                    });
                    return Interaction::changed();
                }
                if let Some(index) = state.header_focus {
                    match key.code {
                        KeyCode::Left | KeyCode::BackTab => {
                            state.header_focus =
                                Some((index + HEADER_ITEMS.len() - 1) % HEADER_ITEMS.len())
                        }
                        KeyCode::Right | KeyCode::Tab => {
                            state.header_focus = Some((index + 1) % HEADER_ITEMS.len())
                        }
                        KeyCode::Enter | KeyCode::Char(' ') => {
                            let action = HEADER_ITEMS.get(index).map(|item| item.action);
                            state.header_focus = None;
                            if let Some(action) = action {
                                return self.dispatch_action(&mut state, action);
                            }
                        }
                        KeyCode::Esc => state.header_focus = None,
                        _ => {}
                    }
                    return Interaction::changed();
                }
                let interaction = state
                    .screens
                    .last_mut()
                    .map_or(IotaInteraction::Unhandled, |entry| {
                        entry.screen.handle_event(&UiEvent::Key(*key))
                    });
                self.route_interaction(&mut state, interaction)
            }
            ratatool::UiEvent::Paste(text) => {
                let interaction = state
                    .screens
                    .last_mut()
                    .map_or(IotaInteraction::Unhandled, |entry| {
                        entry.screen.handle_event(&UiEvent::Paste(text.clone()))
                    });
                self.route_interaction(&mut state, interaction)
            }
            ratatool::UiEvent::Resize { width, height } => {
                let interaction =
                    state
                        .screens
                        .last_mut()
                        .map_or(IotaInteraction::Unhandled, |entry| {
                            entry.screen.handle_event(&UiEvent::Resize {
                                width: *width,
                                height: *height,
                            })
                        });
                self.route_interaction(&mut state, interaction)
            }
            ratatool::UiEvent::Pointer { event, hit } => {
                let interaction =
                    state
                        .screens
                        .last_mut()
                        .map_or(IotaInteraction::Unhandled, |entry| {
                            entry.screen.handle_event(&UiEvent::Pointer {
                                event: *event,
                                hit: hit.clone(),
                            })
                        });
                self.route_interaction(&mut state, interaction)
            }
            ratatool::UiEvent::Mouse(_) => Interaction::Unhandled,
        }
    }
}

async fn run_driver(
    mut session: TerminalSession,
    shell: SharedShellState,
    mut command_rx: mpsc::Receiver<UiCommand>,
    mut event_source: AsyncEventSource<IotaMessage>,
    event_tx: mpsc::Sender<IotaMessage>,
    cancellation: CancellationToken,
    theme_config: DriverThemeConfig,
) -> io::Result<()> {
    let registry = theme::registry();
    let profile = ratatool::detect_current(&theme::terminal_options(
        theme_config.color,
        theme_config.unicode,
    ));
    let mut theme_state = ThemeState::new(theme_config.selected.ratatool_id(), profile, &registry)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut runtime = Runtime::new(IotaShell::new(shell.clone()));

    while runtime.is_running() {
        runtime.draw_if_due(session.terminal_mut(), &theme_state)?;
        let deadline = runtime.next_redraw();
        tokio::select! {
            result = event_source.next(deadline) => {
                let Some(event) = result? else { break };
                if let Some(message) = runtime.dispatch(event) {
                    handle_runtime_message(message, &mut runtime, &shell, &event_tx, &mut theme_state, &registry).await?;
                }
            }
            command = command_rx.recv() => {
                let Some(command) = command else { break };
                apply_ui_command(command, &shell, &mut runtime, &event_tx, &mut theme_state, &registry).await?;
            }
            _ = cancellation.cancelled() => runtime.request_exit(),
            _ = ctrl_c() => runtime.request_exit(),
        }
    }
    cancellation.cancel();
    Ok(())
}

#[cfg(unix)]
async fn ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(not(unix))]
async fn ctrl_c() {
    std::future::pending::<()>().await;
}

async fn apply_ui_command(
    command: UiCommand,
    shell: &SharedShellState,
    runtime: &mut Runtime<IotaMessage>,
    event_tx: &mpsc::Sender<IotaMessage>,
    theme_state: &mut ThemeState,
    registry: &ratatool::ThemeRegistry,
) -> io::Result<()> {
    match command {
        UiCommand::Push(screen, presentation) => {
            shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?
                .screens
                .push(IotaScreenEntry {
                    screen,
                    presentation,
                });
            runtime.request_redraw();
        }
        UiCommand::ReplaceRoot(screen) => {
            let mut state = shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?;
            state.screens.clear();
            state.screens.push(IotaScreenEntry {
                screen,
                presentation: ScreenPresentation::Replace,
            });
            runtime.request_redraw();
        }
        UiCommand::AttachDaemon(ipc) => {
            let mut state = shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?;
            state.daemon_view = Some(daemon_view(&ipc));
            state.ipc = Some(ipc.clone());
            drop(state);
            bridge_daemon_updates(ipc, event_tx.clone());
            runtime.request_redraw();
        }
        UiCommand::Notify(notification) => {
            let deadline = {
                let mut state = shell
                    .lock()
                    .map_err(|_| io::Error::other("shell state poisoned"))?;
                state.notifications.push(notification);
                state.notifications.next_expiration()
            };
            if let Some(deadline) = deadline {
                runtime.request_redraw_at(deadline);
            }
            runtime.request_redraw();
        }
        UiCommand::SetTheme(theme) => {
            theme_state
                .select_theme(theme.name.ratatool_id(), registry)
                .map_err(|error| io::Error::other(error.to_string()))?;
            shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?
                .theme = *theme;
            runtime.request_redraw();
        }
        UiCommand::Shutdown => runtime.request_exit(),
        UiCommand::Redraw => runtime.request_redraw(),
    }
    Ok(())
}

async fn handle_runtime_message(
    message: IotaMessage,
    runtime: &mut Runtime<IotaMessage>,
    shell: &SharedShellState,
    event_tx: &mpsc::Sender<IotaMessage>,
    theme_state: &mut ThemeState,
    registry: &ratatool::ThemeRegistry,
) -> io::Result<()> {
    match message {
        IotaMessage::Action(action) => {
            let interaction = {
                let mut state = shell
                    .lock()
                    .map_err(|_| io::Error::other("shell state poisoned"))?;
                let shell_screen = IotaShell::new(shell.clone());
                shell_screen.dispatch_action(&mut state, action)
            };
            match interaction {
                Interaction::Exit => runtime.request_exit(),
                Interaction::Handled {
                    changed: true,
                    message,
                } => {
                    runtime.request_redraw();
                    if let Some(message) = message {
                        Box::pin(handle_runtime_message(
                            message,
                            runtime,
                            shell,
                            event_tx,
                            theme_state,
                            registry,
                        ))
                        .await?;
                    }
                }
                Interaction::Handled {
                    message: Some(message),
                    ..
                } => {
                    Box::pin(handle_runtime_message(
                        message,
                        runtime,
                        shell,
                        event_tx,
                        theme_state,
                        registry,
                    ))
                    .await?
                }
                _ => {}
            }
        }
        IotaMessage::Effect(effect) => {
            run_effect(effect, runtime, shell, event_tx, theme_state, registry).await?
        }
        IotaMessage::Event(_) => {
            let _ = event_tx.send(message).await;
        }
        IotaMessage::Invalidate => runtime.request_redraw(),
    }
    Ok(())
}

async fn run_effect(
    effect: IotaEffect,
    runtime: &mut Runtime<IotaMessage>,
    shell: &SharedShellState,
    event_tx: &mpsc::Sender<IotaMessage>,
    theme_state: &mut ThemeState,
    registry: &ratatool::ThemeRegistry,
) -> io::Result<()> {
    match effect {
        IotaEffect::OpenUsers => {
            let ipc = shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?
                .ipc
                .clone();
            if let Some(ipc) = ipc {
                shell
                    .lock()
                    .map_err(|_| io::Error::other("shell state poisoned"))?
                    .screens
                    .push(IotaScreenEntry {
                        screen: Box::new(UsersScreen::loading(ipc.clone())),
                        presentation: ScreenPresentation::Replace,
                    });
                runtime.request_redraw();
                spawn_users_load(ipc, event_tx.clone());
            }
        }
        IotaEffect::OpenMetrics => {
            let ipc = shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?
                .ipc
                .clone();
            if let Some(ipc) = ipc {
                shell
                    .lock()
                    .map_err(|_| io::Error::other("shell state poisoned"))?
                    .screens
                    .push(IotaScreenEntry {
                        screen: Box::new(MetricsScreen::from_state(ipc.state())),
                        presentation: ScreenPresentation::Replace,
                    });
                runtime.request_redraw();
            }
        }
        IotaEffect::OpenOverview => {
            let view = {
                let state = shell
                    .lock()
                    .map_err(|_| io::Error::other("shell state poisoned"))?;
                state
                    .daemon_view
                    .as_ref()
                    .map(|view| (view.connection.clone(), view.status.clone()))
            };
            if let Some((connection, status)) = view {
                shell
                    .lock()
                    .map_err(|_| io::Error::other("shell state poisoned"))?
                    .screens
                    .push(IotaScreenEntry {
                        screen: Box::new(OverviewScreen::new(connection, status)),
                        presentation: ScreenPresentation::Replace,
                    });
                runtime.request_redraw();
            }
        }
        IotaEffect::ApplyTheme {
            theme: name,
            persist,
        } => {
            theme_state
                .select_theme(name.ratatool_id(), registry)
                .map_err(|error| io::Error::other(error.to_string()))?;
            shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?
                .theme = theme::resolve(name);
            runtime.request_redraw();
            if persist {
                let tx = event_tx.clone();
                tokio::spawn(async move {
                    let mut config = theme::UiConfig::load_or_default();
                    config.theme = name;
                    let result = config
                        .save()
                        .map_err(|error| format!("Could not save UiHandle settings: {error}"));
                    let _ = tx
                        .send(IotaMessage::Event(AppEvent::ThemeSaved(result)))
                        .await;
                });
            }
        }
        IotaEffect::SaveSettings {
            theme: name,
            color,
            unicode,
            cli_output,
            cli_require_confirmation,
        } => {
            let options = theme::terminal_options(color, unicode);
            let profile = ratatool::detect_current(&options);
            theme_state
                .select_theme(name.ratatool_id(), registry)
                .map_err(|error| io::Error::other(error.to_string()))?;
            theme_state
                .set_profile(profile, registry)
                .map_err(|error| io::Error::other(error.to_string()))?;
            shell
                .lock()
                .map_err(|_| io::Error::other("shell state poisoned"))?
                .theme = theme::resolve_with_capabilities(
                name,
                !matches!(profile.color_depth, ratatool::ColorDepth::None),
                matches!(profile.charset, ratatool::Charset::Unicode),
            );
            runtime.request_redraw();
            let tx = event_tx.clone();
            tokio::spawn(async move {
                let mut config = theme::UiConfig::load_or_default();
                config.theme = name;
                config.color = color;
                config.unicode = unicode;
                config.cli_output = cli_output;
                config.cli_require_confirmation = cli_require_confirmation;
                let result = config
                    .save()
                    .map_err(|error| format!("Could not save UiHandle settings: {error}"));
                let _ = tx
                    .send(IotaMessage::Event(AppEvent::ThemeSaved(result)))
                    .await;
            });
        }
        other => spawn_ipc_effect(other, shell, event_tx.clone())?,
    }
    Ok(())
}

fn spawn_users_load(ipc: Arc<IpcClient>, tx: mpsc::Sender<IotaMessage>) {
    tokio::spawn(async move {
        let result = list_users(&ipc).await;
        let _ = tx
            .send(IotaMessage::Event(AppEvent::UsersLoaded(result)))
            .await;
    });
}

async fn list_users(ipc: &IpcClient) -> Result<Vec<UserEntry>, String> {
    match ipc.send_request(iota_ipc::LocalRequest::ListUsers).await {
        Ok(iota_ipc::ResponseResult::Ok(iota_ipc::ResponsePayload::Users(users))) => Ok(users
            .into_iter()
            .map(|user| UserEntry {
                user_id: user.user_id,
                username: user.username,
                state: user.state,
                data_present: user.data_present,
                credential_status: user.credential_status,
                pending_operation: user.pending_operation,
            })
            .collect()),
        Ok(iota_ipc::ResponseResult::Error(error)) => Err(format!("Cannot load users: {error}")),
        Ok(_) => Err("Daemon returned an unexpected response while loading users.".into()),
        Err(error) => Err(format!("Cannot load users: {error}")),
    }
}

fn spawn_ipc_effect(
    effect: IotaEffect,
    shell: &SharedShellState,
    tx: mpsc::Sender<IotaMessage>,
) -> io::Result<()> {
    let ipc = shell
        .lock()
        .map_err(|_| io::Error::other("shell state poisoned"))?
        .ipc
        .clone();
    let Some(ipc) = ipc else { return Ok(()) };
    tokio::spawn(async move {
        let event = match effect {
            IotaEffect::RegenerateKeys => {
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
                AppEvent::KeysRegenerated(result)
            }
            IotaEffect::RefreshUsers => AppEvent::UsersLoaded(list_users(&ipc).await),
            IotaEffect::LoadNewestTerms { kind } => {
                let result = iota_terms::get_terms(kind)
                    .await
                    .ok_or_else(|| "Could not fetch the legal document.".to_owned());
                AppEvent::TermsLoaded { kind, result }
            }
            IotaEffect::InspectTu { credential } => {
                let result = match ipc
                    .send_request(iota_ipc::LocalRequest::InspectTuCredential { credential })
                    .await
                {
                    Ok(iota_ipc::ResponseResult::Ok(
                        iota_ipc::ResponsePayload::TuCredentialPreview(preview),
                    )) => Ok(preview),
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Credential inspection failed: {error}"))
                    }
                    Ok(_) => Err(
                        "Credential inspection failed: daemon returned an unexpected response."
                            .into(),
                    ),
                    Err(error) => Err(format!("Credential inspection failed: {error}")),
                };
                AppEvent::TuInspected(result)
            }
            IotaEffect::AttachUserFromTu { credential } => {
                let result = match ipc
                    .send_request(iota_ipc::LocalRequest::AttachUserFromTu { credential })
                    .await
                {
                    Ok(iota_ipc::ResponseResult::Ok(_)) => Ok("Attached existing user.".into()),
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Attach existing user failed: {error}"))
                    }
                    Err(error) => Err(format!("Attach existing user failed: {error}")),
                };
                AppEvent::UserOperationFinished(result)
            }
            IotaEffect::RunUserOperation { action, user_id } => {
                let response = match action {
                    UserAction::Release => {
                        ipc.send_request(iota_ipc::LocalRequest::ReleaseUser { user_id })
                            .await
                    }
                    UserAction::PurgeData => {
                        ipc.send_request(iota_ipc::LocalRequest::PurgeUserData { user_id })
                            .await
                    }
                    UserAction::ExportTu => {
                        let event = AppEvent::UserOperationFinished(Err(
                            "Credential export requires a destination path.".into(),
                        ));
                        let _ = tx.send(IotaMessage::Event(event)).await;
                        return;
                    }
                    UserAction::DeleteAccount => {
                        ipc.send_request(iota_ipc::LocalRequest::CompleteDeleteUser {
                            user_id,
                            credential: None,
                        })
                        .await
                    }
                    UserAction::Reconcile => {
                        ipc.send_request(iota_ipc::LocalRequest::ReconcileUser { user_id })
                            .await
                    }
                    UserAction::Diagnostics => {
                        ipc.send_request(iota_ipc::LocalRequest::GetUserDiagnostics { user_id })
                            .await
                    }
                    UserAction::ForceDetach => {
                        ipc.send_request(iota_ipc::LocalRequest::ForceDetachUser { user_id })
                            .await
                    }
                    UserAction::ForgetResidency => {
                        ipc.send_request(iota_ipc::LocalRequest::ForgetReleasedUser { user_id })
                            .await
                    }
                };
                let result = match response {
                    Ok(iota_ipc::ResponseResult::Ok(
                        iota_ipc::ResponsePayload::UserDiagnostics(diagnostics),
                    )) => Ok(format!(
                        "Diagnostics: state={:?}, data={}, credential={}, TAuth grants={}, pending={}",
                        diagnostics.local_state,
                        if diagnostics.data_present {
                            "present"
                        } else {
                            "empty"
                        },
                        credential_status_label(diagnostics.credential_status),
                        diagnostics.tauth_grant_count,
                        diagnostics
                            .pending_operation
                            .unwrap_or_else(|| "none".into()),
                    )),
                    Ok(iota_ipc::ResponseResult::Ok(
                        iota_ipc::ResponsePayload::UserReconciled(result),
                    )) => Ok(format!("Reconciliation result: {:?}.", result.action)),
                    Ok(iota_ipc::ResponseResult::Ok(_)) => {
                        Ok(format!("{} completed.", action.label()))
                    }
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("{} failed: {error}", action.label()))
                    }
                    Err(error) => Err(format!("{} failed: {error}", action.label())),
                };
                AppEvent::UserOperationFinished(result)
            }
            IotaEffect::ExportCredential {
                user_id,
                destination,
            } => {
                let result = match ipc
                    .send_request(iota_ipc::LocalRequest::ExportUserCredential { user_id })
                    .await
                {
                    Ok(iota_ipc::ResponseResult::Ok(
                        iota_ipc::ResponsePayload::UserCredentialExport {
                            user_id: response_user_id,
                            username,
                            credential,
                        },
                    )) if response_user_id == user_id => {
                        write_private_export(&destination, credential.0.as_bytes())
                            .map(|()| {
                                format!(
                                    "Exported credential for {username} to {}.",
                                    destination.display()
                                )
                            })
                            .map_err(|error| {
                                format!(
                                    "Credential export failed for {}: {error}",
                                    destination.display()
                                )
                            })
                    }
                    Ok(iota_ipc::ResponseResult::Ok(_)) => Err(
                        "Credential export failed: daemon returned an unexpected response.".into(),
                    ),
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Credential export failed: {error}"))
                    }
                    Err(error) => Err(format!("Credential export failed: {error}")),
                };
                AppEvent::CredentialExportFinished(result)
            }
            IotaEffect::CreateUser { username } => {
                let result = match ipc
                    .send_request(iota_ipc::LocalRequest::CreateUser { username })
                    .await
                {
                    Ok(iota_ipc::ResponseResult::Ok(iota_ipc::ResponsePayload::UserCreated {
                        username,
                        user_id,
                    })) => Ok(format!("Created user {username} ({user_id}).")),
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Create user failed: {error}"))
                    }
                    Ok(_) => {
                        Err("Create user failed: daemon returned an unexpected response.".into())
                    }
                    Err(error) => Err(format!("Create user failed: {error}")),
                };
                AppEvent::UserOperationFinished(result)
            }
            IotaEffect::CreateInvitation { authority } => {
                let result = match ipc
                    .send_request(iota_ipc::LocalRequest::CreateInvitation {
                        authority,
                        lifetime_seconds: 7 * 24 * 60 * 60,
                        password: None,
                        label: None,
                    })
                    .await
                {
                    Ok(iota_ipc::ResponseResult::Ok(
                        iota_ipc::ResponsePayload::InvitationCreated(invitation),
                    )) => Ok(format!(
                        "Invitation {} created. Token: {}  Link: {}{}",
                        invitation.invitation_id,
                        invitation.raw_token.0,
                        invitation.short_url.as_deref().unwrap_or("unavailable"),
                        if invitation.mirror_synced {
                            ""
                        } else {
                            "  Local metadata is still synchronizing."
                        },
                    )),
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Create invitation failed: {error}"))
                    }
                    Ok(_) => Err(
                        "Create invitation failed: daemon returned an unexpected response.".into(),
                    ),
                    Err(error) => Err(format!("Create invitation failed: {error}")),
                };
                AppEvent::UserOperationFinished(result)
            }
            IotaEffect::OpenUsers
            | IotaEffect::OpenMetrics
            | IotaEffect::OpenOverview
            | IotaEffect::ApplyTheme { .. }
            | IotaEffect::SaveSettings { .. } => return,
        };
        let _ = tx.send(IotaMessage::Event(event)).await;
    });
    Ok(())
}

fn bridge_daemon_updates(ipc: Arc<IpcClient>, tx: mpsc::Sender<IotaMessage>) {
    let mut connection = ipc.connection_status();
    let mut status = ipc.daemon_status();
    let mut updates = ipc.ui_updates();
    tokio::spawn(async move {
        loop {
            let changed = tokio::select! {
                result = connection.changed() => result,
                result = status.changed() => result,
                result = updates.changed() => result,
            };
            if changed.is_err() || tx.send(IotaMessage::Invalidate).await.is_err() {
                break;
            }
        }
    });
}
