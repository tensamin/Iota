use crate::{
    controls::{
        button::{ActionButton, ButtonIntent, render_button},
        choice::{ChoiceKind, render_choice_line},
    },
    interaction_result::InteractionResult,
    ipc_client::IpcClient,
    render_context::RenderContext,
    screens::screens::{AppAction, AppEvent, HitMap, KeyHint, Screen, UiEvent},
};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};

#[derive(Clone, Debug)]
pub struct UserEntry {
    pub user_id: i64,
    pub username: String,
    pub state: iota_ipc::LocalUserState,
    pub data_present: bool,
    pub credential_present: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    List,
    AddButton,
    RemoveButton,
    Back,
}
#[derive(Clone, Debug)]
enum Dialog {
    Add { username: String },
    Remove { user: UserEntry },
}

pub struct UsersScreen {
    users: Vec<UserEntry>,
    focused_index: usize,
    focus: Focus,
    ipc: Arc<IpcClient>,
    message: Option<String>,
    dialog: Option<Dialog>,
    pending_dialog: Option<Dialog>,
    loading: bool,
    pending: bool,
    scroll_offset: usize,
    viewport_height: AtomicUsize,
    filter: String,
    filtering: bool,
    tick: AtomicU8,
}

impl UsersScreen {
    pub fn new(ipc: Arc<IpcClient>, users: Vec<UserEntry>) -> Self {
        Self {
            users,
            focused_index: 0,
            focus: Focus::List,
            ipc,
            message: None,
            dialog: None,
            pending_dialog: None,
            loading: false,
            pending: false,
            scroll_offset: 0,
            viewport_height: AtomicUsize::new(1),
            filter: String::new(),
            filtering: false,
            tick: AtomicU8::new(0),
        }
    }

    pub fn loading(ipc: Arc<IpcClient>) -> Self {
        let mut screen = Self::new(ipc, Vec::new());
        screen.loading = true;
        screen.message = Some("Loading users…".into());
        screen
    }

    fn render_user_list(&self, f: &mut Frame, area: Rect, context: &RenderContext<'_>) {
        let visible_indices = self.filtered_indices();
        let title = if self.filter.is_empty() {
            format!("Users ({})", self.users.len())
        } else {
            format!(
                "Users ({}/{}) filter: {}",
                visible_indices.len(),
                self.users.len(),
                self.filter
            )
        };
        let inner = if matches!(context.theme.chrome, crate::theme::ChromeMode::Surfaces) {
            crate::controls::panel::render_panel(
                f,
                area,
                &title,
                self.focus == Focus::List,
                context.theme,
            )
        } else {
            let block = Block::default()
                .title(format!(" {title} "))
                .borders(Borders::ALL)
                .border_style(context.theme.borders.normal);
            let inner = block.inner(area);
            f.render_widget(block, area);
            inner
        };

        if self.loading {
            const SPINNERS: &[u8] = b"|/-\\";
            let ch = SPINNERS[self.tick.fetch_add(1, Ordering::Relaxed) as usize % SPINNERS.len()];
            f.render_widget(Paragraph::new(format!("{ch} Loading users…")), inner);
            return;
        }
        if visible_indices.is_empty() {
            let par = Paragraph::new(if self.users.is_empty() {
                "No users found."
            } else {
                "No users match the filter."
            });
            f.render_widget(par, inner);
            return;
        }

        let mut lines = Vec::new();
        self.viewport_height
            .store(inner.height as usize, Ordering::Relaxed);
        let labels: Vec<(usize, String)> = visible_indices
            .iter()
            .skip(self.scroll_offset)
            .take(inner.height as usize)
            .map(|user_index| {
                let user = &self.users[*user_index];
                (
                    *user_index,
                    format!(
                        "{:>6}  {}  {}{}",
                        user.user_id,
                        user.username,
                        match user.state {
                            iota_ipc::LocalUserState::Managed => "managed",
                            iota_ipc::LocalUserState::Released => "released",
                        },
                        if user.data_present {
                            ""
                        } else {
                            ", data purged"
                        }
                    ),
                )
            })
            .collect();
        for (user_index, label) in &labels {
            let visual = crate::controls::choice::ChoiceVisualState {
                selected: false,
                focused: self.focus == Focus::List && *user_index == self.focused_index,
                enabled: !self.loading && !self.pending,
            };
            lines.push(render_choice_line(
                &label,
                ChoiceKind::Radio,
                visual,
                context.theme,
            ));
        }
        let par = Paragraph::new(lines);
        f.render_widget(par, inner);
    }

    fn render_actions(&self, f: &mut Frame, area: Rect, context: &RenderContext<'_>) {
        let rows = Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(area);

        if let Some(msg) = &self.message {
            let par = Paragraph::new(Line::from(Span::styled(
                msg.as_str(),
                context.theme.text.muted,
            )));
            f.render_widget(par, rows[0]);
        }

        let buttons_area = Layout::horizontal([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(rows[1]);

        render_button(
            f,
            buttons_area[0],
            ActionButton {
                label: "Back",
                intent: ButtonIntent::Cancel,
                focused: self.focus == Focus::Back,
                enabled: true,
            },
            context.theme,
        );
        render_button(
            f,
            buttons_area[1],
            ActionButton {
                label: "Add",
                intent: ButtonIntent::Primary,
                focused: self.focus == Focus::AddButton,
                enabled: true,
            },
            context.theme,
        );
        render_button(
            f,
            buttons_area[2],
            ActionButton {
                label: "Release",
                intent: ButtonIntent::Destructive,
                focused: self.focus == Focus::RemoveButton,
                enabled: !self.loading && !self.pending && !self.users.is_empty(),
            },
            context.theme,
        );
    }

    fn activate(&mut self) -> InteractionResult {
        if self.loading || self.pending {
            return InteractionResult::Handled;
        }
        if let Some(dialog) = self.dialog.take() {
            match dialog {
                Dialog::Add { username } if !username.trim().is_empty() => {
                    let name = username.trim().to_owned();
                    self.pending_dialog = Some(Dialog::Add { username });
                    self.pending = true;
                    self.message = Some("Creating user…".into());
                    let ipc = self.ipc.clone();
                    return InteractionResult::AppTask {
                        task: Box::pin(async move {
                            let result = match ipc.send_request(iota_ipc::LocalRequest::CreateUser { username: name }).await {
                            Ok(iota_ipc::ResponseResult::Ok(iota_ipc::ResponsePayload::UserCreated { user_id, username })) => Ok(UserEntry { user_id, username, state: iota_ipc::LocalUserState::Managed, data_present: true, credential_present: true }),
                            Ok(iota_ipc::ResponseResult::Error(error)) => Err(format!("Cannot create user: {error}")),
                            Ok(_) => Err("Daemon returned an unexpected response while creating the user.".into()),
                            Err(error) => Err(format!("Cannot create user: {error}")),
                        };
                            UiEvent::App(AppEvent::UserCreated(result))
                        }),
                    };
                }
                Dialog::Remove { user } => {
                    self.pending_dialog = Some(Dialog::Remove { user: user.clone() });
                    let ipc = self.ipc.clone();
                    let id = user.user_id;
                    self.pending = true;
                    self.message = Some(format!("Releasing {}…", user.username));
                    return InteractionResult::AppTask {
                        task: Box::pin(async move {
                            let result = match ipc.send_request(iota_ipc::LocalRequest::ReleaseUser { user_id: id }).await {
                            Ok(iota_ipc::ResponseResult::Ok(iota_ipc::ResponsePayload::Acknowledged { .. })) => Ok(()),
                            Ok(iota_ipc::ResponseResult::Error(error)) => Err(format!("Cannot release user: {error}")),
                            Ok(_) => Err("Daemon returned an unexpected response while releasing the user.".into()),
                            Err(error) => Err(format!("Cannot release user: {error}")),
                        };
                            UiEvent::App(AppEvent::UserRemoved {
                                user_id: id,
                                result,
                            })
                        }),
                    };
                }
                Dialog::Add { .. } => self.message = Some("A username is required.".into()),
            }
            return InteractionResult::Handled;
        }
        match self.focus {
            Focus::Back => InteractionResult::CloseScreen,
            Focus::AddButton => {
                self.dialog = Some(Dialog::Add {
                    username: String::new(),
                });
                InteractionResult::Handled
            }
            Focus::RemoveButton => {
                if let Some(user) = self.users.get(self.focused_index) {
                    self.dialog = Some(Dialog::Remove { user: user.clone() });
                }
                InteractionResult::Handled
            }
            Focus::List => InteractionResult::Handled,
        }
    }

    fn next_focus(&mut self) {
        self.focus = match self.focus {
            Focus::List => Focus::AddButton,
            Focus::AddButton => Focus::RemoveButton,
            Focus::RemoveButton => Focus::Back,
            Focus::Back => Focus::List,
        };
    }

    fn prev_focus(&mut self) {
        self.focus = match self.focus {
            Focus::List => Focus::Back,
            Focus::Back => Focus::RemoveButton,
            Focus::RemoveButton => Focus::AddButton,
            Focus::AddButton => Focus::List,
        };
    }

    fn keep_focused_user_visible(&mut self) {
        let indices = self.filtered_indices();
        let Some(position) = indices
            .iter()
            .position(|index| *index == self.focused_index)
        else {
            self.scroll_offset = 0;
            return;
        };
        let height = self.viewport_height.load(Ordering::Relaxed).max(1);
        if position < self.scroll_offset {
            self.scroll_offset = position;
        } else if position >= self.scroll_offset + height {
            self.scroll_offset = position + 1 - height;
        }
    }

    fn move_user_focus(&mut self, index: usize) {
        if !self.users.is_empty() {
            self.focused_index = index.min(self.users.len() - 1);
            self.keep_focused_user_visible();
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let needle = self.filter.to_ascii_lowercase();
        self.users
            .iter()
            .enumerate()
            .filter(|(_, user)| {
                needle.is_empty()
                    || user.username.to_ascii_lowercase().contains(&needle)
                    || user.user_id.to_string().contains(&needle)
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn move_visible(&mut self, delta: isize) {
        let indices = self.filtered_indices();
        if indices.is_empty() {
            return;
        }
        let current = indices
            .iter()
            .position(|index| *index == self.focused_index)
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, indices.len() as isize - 1) as usize;
        self.move_user_focus(indices[next]);
    }

    fn reset_focus_to_filter(&mut self) {
        self.scroll_offset = 0;
        if let Some(index) = self.filtered_indices().first().copied() {
            self.focused_index = index;
        }
    }
}

impl Screen for UsersScreen {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, rect: Rect, context: &RenderContext<'_>, hits: &mut HitMap) {
        let outer_block = Block::default()
            .title(" Users ")
            .borders(Borders::ALL)
            .border_style(context.theme.borders.normal)
            .title_style(context.theme.borders.title);
        let inner = if matches!(context.theme.chrome, crate::theme::ChromeMode::Surfaces) {
            crate::controls::panel::render_panel(f, rect, "Users", false, context.theme)
        } else {
            let inner = outer_block.inner(rect);
            f.render_widget(outer_block, rect);
            inner
        };

        let chunks = Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(inner);

        self.render_user_list(f, chunks[0], context);
        self.render_actions(f, chunks[1], context);
        if let Some(dialog) = &self.dialog {
            f.render_widget(Block::default().style(context.theme.surfaces.overlay), rect);
            let popup = crate::layout::fit::centered_rect(
                rect,
                crate::layout::fit::RequiredSize {
                    width: 42,
                    height: 7,
                },
            );
            let text = match dialog {
                Dialog::Add { username } => {
                    format!("Add user\nUsername: {username}")
                }
                Dialog::Remove { user } => format!(
                    "Remove user {} (ID {})?\nThis removes the local user record.",
                    user.username, user.user_id
                ),
            };
            let block = Block::default()
                .title(" Confirm ")
                .borders(Borders::ALL)
                .border_style(context.theme.borders.focused)
                .style(context.theme.surfaces.overlay);
            let popup_inner = block.inner(popup);
            f.render_widget(block, popup);
            let dialog_rows =
                Layout::vertical([Constraint::Min(2), Constraint::Length(1)]).split(popup_inner);
            f.render_widget(
                Paragraph::new(text).style(context.theme.text.normal),
                dialog_rows[0],
            );
            let dialog_buttons =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(dialog_rows[1]);
            render_button(
                f,
                dialog_buttons[0],
                ActionButton {
                    label: "Cancel",
                    intent: ButtonIntent::Cancel,
                    focused: false,
                    enabled: true,
                },
                context.theme,
            );
            render_button(
                f,
                dialog_buttons[1],
                ActionButton {
                    label: match dialog {
                        Dialog::Add { .. } => "Create",
                        Dialog::Remove { .. } => "Remove",
                    },
                    intent: match dialog {
                        Dialog::Add { .. } => ButtonIntent::Primary,
                        Dialog::Remove { .. } => ButtonIntent::Destructive,
                    },
                    focused: true,
                    enabled: true,
                },
                context.theme,
            );
            hits.register(dialog_buttons[0], AppAction::CancelDialog);
            hits.register(dialog_buttons[1], AppAction::ConfirmDialog);
        }
        let buttons = Layout::horizontal([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(chunks[1]);
        if self.dialog.is_none() {
            hits.register(buttons[0], AppAction::Back);
        }
        if self.dialog.is_none() && !self.loading && !self.pending {
            hits.register(buttons[1], AppAction::AddUser);
        }
        if self.dialog.is_none() && !self.loading && !self.pending && !self.users.is_empty() {
            hits.register(buttons[2], AppAction::RemoveUser);
        }
        if self.dialog.is_none() {
            let list_height = chunks[0].height.saturating_sub(2) as usize;
            let filtered_indices = self.filtered_indices();
            for visible in 0..list_height {
                let position = self.scroll_offset + visible;
                let Some(index) = filtered_indices.get(position).copied() else {
                    break;
                };
                hits.register(
                    Rect {
                        x: chunks[0].x.saturating_add(1),
                        y: chunks[0].y.saturating_add(1 + visible as u16),
                        width: chunks[0].width.saturating_sub(2),
                        height: 1,
                    },
                    AppAction::SelectUser(index),
                );
            }
        }
    }

    fn handle_event(&mut self, event: UiEvent) -> InteractionResult {
        let event = match event {
            UiEvent::App(AppEvent::UsersLoaded(result)) => {
                self.loading = false;
                match result {
                    Ok(users) => {
                        self.users = users;
                        self.message = None;
                    }
                    Err(error) => self.message = Some(error),
                }
                return InteractionResult::Handled;
            }
            UiEvent::App(AppEvent::UserCreated(result)) => {
                self.pending = false;
                match result {
                    Ok(user) => {
                        self.pending_dialog = None;
                        self.focused_index = self.users.len();
                        self.users.push(user.clone());
                        self.message = Some(format!(
                            "Created user {} ({}).",
                            user.username, user.user_id
                        ));
                    }
                    Err(error) => {
                        self.dialog = self.pending_dialog.take();
                        self.message = Some(error);
                    }
                }
                return InteractionResult::Handled;
            }
            UiEvent::App(AppEvent::UserRemoved { user_id, result }) => {
                self.pending = false;
                match result {
                    Ok(()) => {
                        self.pending_dialog = None;
                        if let Some(user) =
                            self.users.iter_mut().find(|user| user.user_id == user_id)
                        {
                            user.state = iota_ipc::LocalUserState::Released;
                            user.credential_present = false;
                        }
                        self.message =
                            Some(format!("Released user {user_id}; hosted data retained."));
                    }
                    Err(error) => {
                        self.dialog = self.pending_dialog.take();
                        self.message = Some(error);
                    }
                }
                return InteractionResult::Handled;
            }
            UiEvent::Paste(text) if matches!(self.dialog, Some(Dialog::Add { .. })) => {
                if let Some(Dialog::Add { username }) = self.dialog.as_mut() {
                    username.push_str(&text.replace(['\r', '\n'], " "));
                }
                return InteractionResult::Handled;
            }
            UiEvent::Key(event) => event,
            _ => return InteractionResult::Unhandled,
        };
        if self.filtering && self.dialog.is_none() {
            match event.code {
                KeyCode::Esc => {
                    self.filtering = false;
                    self.filter.clear();
                    self.reset_focus_to_filter();
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.reset_focus_to_filter();
                }
                KeyCode::Char(c)
                    if !event
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.filter.push(c);
                    self.reset_focus_to_filter();
                }
                _ => {}
            }
            return InteractionResult::Handled;
        }
        if let Some(Dialog::Add { username }) = self.dialog.as_mut() {
            match event.code {
                KeyCode::Esc => {
                    self.dialog = None;
                    return InteractionResult::Handled;
                }
                KeyCode::Enter => return self.activate(),
                KeyCode::Backspace => {
                    username.pop();
                    return InteractionResult::Handled;
                }
                KeyCode::Char(c)
                    if !c.is_control()
                        && !event
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    username.push(c);
                    return InteractionResult::Handled;
                }
                _ => return InteractionResult::Handled,
            }
        }
        if self.dialog.is_some() {
            return match event.code {
                KeyCode::Esc => {
                    self.dialog = None;
                    InteractionResult::Handled
                }
                KeyCode::Enter => self.activate(),
                _ => InteractionResult::Handled,
            };
        }
        match event.code {
            KeyCode::Esc => InteractionResult::CloseScreen,
            KeyCode::Char('/') if self.focus == Focus::List => {
                self.filtering = true;
                self.filter.clear();
                self.reset_focus_to_filter();
                InteractionResult::Handled
            }
            KeyCode::Tab => {
                self.next_focus();
                InteractionResult::Handled
            }
            KeyCode::BackTab => {
                self.prev_focus();
                InteractionResult::Handled
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.focus == Focus::List {
                    self.move_visible(1);
                }
                InteractionResult::Handled
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.focus == Focus::List {
                    self.move_visible(-1);
                }
                InteractionResult::Handled
            }
            KeyCode::PageDown if self.focus == Focus::List && !self.users.is_empty() => {
                let page = self.viewport_height.load(Ordering::Relaxed).max(1);
                self.move_visible(page as isize);
                InteractionResult::Handled
            }
            KeyCode::PageUp if self.focus == Focus::List && !self.users.is_empty() => {
                let page = self.viewport_height.load(Ordering::Relaxed).max(1);
                self.move_visible(-(page as isize));
                InteractionResult::Handled
            }
            KeyCode::Home if self.focus == Focus::List => {
                if let Some(index) = self.filtered_indices().first().copied() {
                    self.move_user_focus(index);
                }
                InteractionResult::Handled
            }
            KeyCode::End if self.focus == Focus::List && !self.users.is_empty() => {
                if let Some(index) = self.filtered_indices().last().copied() {
                    self.move_user_focus(index);
                }
                InteractionResult::Handled
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate(),
            _ => InteractionResult::Unhandled,
        }
    }
    fn handle_action(&mut self, action: AppAction) -> InteractionResult {
        match action {
            AppAction::Back => InteractionResult::CloseScreen,
            AppAction::AddUser => {
                self.focus = Focus::AddButton;
                self.activate()
            }
            AppAction::RemoveUser => {
                self.focus = Focus::RemoveButton;
                self.activate()
            }
            AppAction::SelectUser(index) if self.dialog.is_none() => {
                self.focus = Focus::List;
                self.move_user_focus(index);
                InteractionResult::Handled
            }
            AppAction::ConfirmDialog if self.dialog.is_some() => self.activate(),
            AppAction::CancelDialog if self.dialog.is_some() => {
                self.dialog = None;
                InteractionResult::Handled
            }
            _ => InteractionResult::Unhandled,
        }
    }
    fn key_hints(&self) -> Vec<KeyHint> {
        if self.dialog.is_some() {
            vec![
                KeyHint {
                    keys: "Enter",
                    action: "Confirm",
                },
                KeyHint {
                    keys: "Esc",
                    action: "Cancel",
                },
            ]
        } else {
            vec![
                KeyHint {
                    keys: "Up/Down",
                    action: "Select user",
                },
                KeyHint {
                    keys: "PgUp/PgDn",
                    action: "Page",
                },
                KeyHint {
                    keys: "/",
                    action: "Filter",
                },
                KeyHint {
                    keys: "Tab",
                    action: "Move focus",
                },
                KeyHint {
                    keys: "F6",
                    action: "Header",
                },
            ]
        }
    }
}
