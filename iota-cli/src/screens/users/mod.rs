pub mod action_menu;
pub mod add_flow;
pub mod confirmations;
pub mod context;
pub mod credential_export;
pub mod invitations;
pub mod list;
pub mod model;

use crate::theme::ResolvedTheme;
use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    ipc_client::IpcClient,
    screens::screens::{
        AppAction, AppEvent, HitMap, IotaEffect, IotaInteraction, IotaMessage, IotaScreen, KeyHint,
        UiEvent,
    },
};
use action_menu::UserActionMenu;
use add_flow::{AddUserFlow, AddUserPhase};
use confirmations::UserConfirmation;
use credential_export::CredentialExportState;
use crossterm::event::{KeyCode, KeyModifiers};
use model::{FocusZone, UserAction, UserAdminTab, available_action_groups};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

#[derive(Clone, Debug)]
pub struct UserEntry {
    pub user_id: i64,
    pub username: String,
    pub state: iota_ipc::LocalUserState,
    pub data_present: bool,
    pub credential_status: iota_ipc::CredentialStatus,
    pub pending_operation: Option<iota_ipc::UserOperationSummary>,
}

#[derive(Clone, Debug)]
enum UsersOverlay {
    Add(AddUserFlow),
    UserMenu(UserActionMenu),
    Confirm(UserConfirmation),
    CredentialExport(CredentialExportState),
}

pub struct UsersScreen {
    ipc: Arc<IpcClient>,
    users: Vec<UserEntry>,
    selected_user_id: Option<i64>,
    active_tab: UserAdminTab,
    focus_zone: FocusZone,
    toolbar_index: usize,
    action_group_index: usize,
    filter: String,
    filtering: bool,
    scroll_offset: usize,
    viewport_height: AtomicUsize,
    overlay: Option<UsersOverlay>,
    loading: bool,
    pending: bool,
    message: Option<String>,
    tick: AtomicU8,
}

impl UsersScreen {
    pub fn new(ipc: Arc<IpcClient>, users: Vec<UserEntry>) -> Self {
        let selected_user_id = users.first().map(|user| user.user_id);
        Self {
            ipc,
            users,
            selected_user_id,
            active_tab: UserAdminTab::Users,
            focus_zone: FocusZone::UserList,
            toolbar_index: 0,
            action_group_index: 0,
            filter: String::new(),
            filtering: false,
            scroll_offset: 0,
            viewport_height: AtomicUsize::new(1),
            overlay: None,
            loading: false,
            pending: false,
            message: None,
            tick: AtomicU8::new(0),
        }
    }
    pub fn loading(ipc: Arc<IpcClient>) -> Self {
        let mut screen = Self::new(ipc, Vec::new());
        screen.loading = true;
        screen.message = Some("Loading users…".into());
        screen
    }
    fn selected_user(&self) -> Option<&UserEntry> {
        let id = self.selected_user_id?;
        self.users.iter().find(|user| user.user_id == id)
    }
    fn visible_users(&self) -> Vec<&UserEntry> {
        self.users
            .iter()
            .filter(|user| list::matches_filter(user, &self.filter))
            .collect()
    }
    fn restore_selection(&mut self) {
        if self.selected_user().is_none() {
            self.selected_user_id = self.visible_users().first().map(|user| user.user_id);
        }
        self.keep_selected_visible();
    }
    fn keep_selected_visible(&mut self) {
        let Some(id) = self.selected_user_id else {
            self.scroll_offset = 0;
            return;
        };
        let visible = self.visible_users();
        let Some(position) = visible.iter().position(|user| user.user_id == id) else {
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
    fn move_selection(&mut self, delta: isize) {
        let visible = self.visible_users();
        if visible.is_empty() {
            return;
        }
        let current = self
            .selected_user_id
            .and_then(|id| visible.iter().position(|user| user.user_id == id))
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, visible.len() as isize - 1) as usize;
        self.selected_user_id = Some(visible[next].user_id);
        self.keep_selected_visible();
    }
    fn groups(&self) -> Vec<model::ActionGroupEntry> {
        self.selected_user()
            .map(available_action_groups)
            .unwrap_or_default()
    }
    fn begin_action(&mut self, action: UserAction) -> IotaInteraction {
        if action == UserAction::ExportTu && !self.credential_export_supported() {
            self.message =
                Some("Credential export is not supported by the connected daemon.".into());
            return IotaInteraction::Changed;
        }
        if let Some(user) = self.selected_user().cloned() {
            if action == UserAction::ExportTu {
                self.overlay = Some(UsersOverlay::CredentialExport(CredentialExportState::new(
                    user,
                )));
                return IotaInteraction::Changed;
            }
            if action.requires_confirmation() {
                self.overlay = Some(UsersOverlay::Confirm(UserConfirmation { user, action }));
            } else {
                return self.start_operation(action, user.user_id);
            }
        }
        IotaInteraction::Changed
    }
    fn credential_export_supported(&self) -> bool {
        self.ipc
            .daemon_status()
            .borrow()
            .capabilities
            .iter()
            .any(|capability| capability == "credential_export_v1")
    }
    fn invitation_supported(&self) -> bool {
        self.ipc
            .daemon_status()
            .borrow()
            .capabilities
            .iter()
            .any(|capability| capability == "user_invitations_v1")
    }
    fn new_add_flow(&self) -> AddUserFlow {
        let status = self.ipc.daemon_status();
        let capabilities = status.borrow().capabilities.clone();
        AddUserFlow::new(
            capabilities
                .iter()
                .any(|value| value == "user_invitations_v1"),
            capabilities.iter().any(|value| value == "tu_inspection_v1"),
        )
    }
    fn start_tu_inspection(&mut self, credential: iota_ipc::SecretString) -> IotaInteraction {
        if let Some(UsersOverlay::Add(flow)) = self.overlay.as_mut() {
            flow.phase = AddUserPhase::InspectingTu;
            flow.credential = Some(credential.clone());
            flow.error = None;
        }
        IotaInteraction::Effect(IotaEffect::InspectTu { credential })
    }
    fn start_tu_attachment(&mut self, credential: iota_ipc::SecretString) -> IotaInteraction {
        self.pending = true;
        self.overlay = None;
        self.message = Some("Attaching existing user…".into());
        IotaInteraction::Effect(IotaEffect::AttachUserFromTu { credential })
    }
    fn start_operation(&mut self, action: UserAction, user_id: i64) -> IotaInteraction {
        self.pending = true;
        self.overlay = None;
        self.message = Some(format!("{}…", action.label()));
        IotaInteraction::Effect(IotaEffect::RunUserOperation { action, user_id })
    }
    fn start_credential_export(
        &mut self,
        user_id: i64,
        destination: std::path::PathBuf,
    ) -> IotaInteraction {
        self.pending = true;
        self.overlay = None;
        self.message = Some("Exporting credential…".into());
        IotaInteraction::Effect(IotaEffect::ExportCredential {
            user_id,
            destination,
        })
    }
    fn start_create(&mut self, username: String) -> IotaInteraction {
        self.pending = true;
        self.message = Some("Creating user…".into());
        self.overlay = None;
        IotaInteraction::Effect(IotaEffect::CreateUser { username })
    }
    fn start_invitation(&mut self, authority: iota_ipc::InvitationAuthority) -> IotaInteraction {
        self.pending = true;
        self.message = Some("Creating invitation…".into());
        self.overlay = None;
        IotaInteraction::Effect(IotaEffect::CreateInvitation { authority })
    }
    fn refresh(&self) -> IotaInteraction {
        IotaInteraction::Effect(IotaEffect::RefreshUsers)
    }
    fn render_list(&self, frame: &mut Frame, area: Rect, theme: &ResolvedTheme, hits: &mut HitMap) {
        let block = Block::default()
            .title(" Users ")
            .borders(Borders::ALL)
            .border_style(theme.borders.normal);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        self.viewport_height
            .store(inner.height as usize, Ordering::Relaxed);
        if self.loading {
            let spinner = b"|/-\\"[self.tick.fetch_add(1, Ordering::Relaxed) as usize % 4] as char;
            frame.render_widget(Paragraph::new(format!("{spinner} Loading users…")), inner);
            return;
        }
        let visible = self.visible_users();
        if visible.is_empty() {
            let text = if self.users.is_empty() {
                "No users are managed or retained on this Iota."
            } else {
                "No users match the current filter."
            };
            frame.render_widget(Paragraph::new(text), inner);
            return;
        }
        let mut lines = Vec::new();
        for (row, user) in visible
            .iter()
            .skip(self.scroll_offset)
            .take(inner.height as usize)
            .enumerate()
        {
            let label = format!(
                "{:<18} {:<9} {:<8} {}",
                user.username,
                context::state_label(user),
                if user.data_present {
                    "Present"
                } else {
                    "Empty"
                },
                context::credential_status_label(user.credential_status)
            );
            let prefix = if self.focus_zone == FocusZone::UserList
                && self.selected_user_id == Some(user.user_id)
            {
                "> "
            } else {
                "  "
            };
            lines.push(Line::from(format!("{prefix}{label}")));
            hits.register(
                Rect {
                    x: inner.x,
                    y: inner.y + row as u16,
                    width: inner.width,
                    height: 1,
                },
                IotaMessage::Action(AppAction::SelectUser(user.user_id)),
            );
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
    fn render_context(
        &self,
        frame: &mut Frame,
        area: Rect,
        theme: &ResolvedTheme,
        hits: &mut HitMap,
    ) {
        let block = Block::default()
            .title(" Selected user ")
            .borders(Borders::ALL)
            .border_style(theme.borders.normal);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let Some(user) = self.selected_user() else {
            frame.render_widget(
                Paragraph::new("Select a user to inspect local lifecycle state."),
                inner,
            );
            return;
        };
        let groups = self.groups();
        let details = vec![
            Line::from(Span::styled(user.username.as_str(), theme.text.normal)),
            Line::from(format!("State        {}", context::state_label(user))),
            Line::from(format!(
                "Hosted data  {}",
                if user.data_present {
                    "Present"
                } else {
                    "Empty"
                }
            )),
            Line::from(format!(
                "Credential   {}",
                context::credential_status_label(user.credential_status)
            )),
            Line::from(format!(
                "Pending      {}",
                user.pending_operation
                    .as_ref()
                    .map(context::pending_operation_label)
                    .unwrap_or_else(|| "None".into())
            )),
        ];
        let rows = Layout::vertical([Constraint::Min(5), Constraint::Length(3)]).split(inner);
        frame.render_widget(Paragraph::new(details), rows[0]);
        let widths = vec![Constraint::Ratio(1, groups.len().max(1) as u32); groups.len().max(1)];
        let buttons = Layout::horizontal(widths).split(rows[1]);
        for (index, entry) in groups.iter().enumerate() {
            let focused =
                self.focus_zone == FocusZone::UserActions && self.action_group_index == index;
            render_button(
                frame,
                buttons[index],
                ActionButton {
                    label: entry.group.label(),
                    intent: ButtonIntent::Neutral,
                    focused,
                    enabled: !self.pending,
                },
                theme,
            );
            if !self.pending {
                hits.register(
                    buttons[index],
                    IotaMessage::Action(AppAction::OpenUserGroup(entry.group)),
                );
            }
        }
    }
    fn render_overlay(
        &self,
        frame: &mut Frame,
        rect: Rect,
        theme: &ResolvedTheme,
        hits: &mut HitMap,
    ) {
        let Some(overlay) = &self.overlay else {
            return;
        };
        let area = ratatool::layout::centered_rect(
            rect,
            ratatool::layout::RequiredSize {
                width: 56,
                height: 12,
            },
        );
        frame.render_widget(Clear, area);
        let block = Block::default()
            .title(match overlay {
                UsersOverlay::Add(flow) => match flow.phase {
                    AddUserPhase::ChooseMethod => " Add User ",
                    AddUserPhase::ConfigureCreate => " Create User ",
                    _ => " Add User ",
                },
                UsersOverlay::UserMenu(menu) => menu.group.label(),
                UsersOverlay::Confirm(confirm) => confirm.title(),
                UsersOverlay::CredentialExport(_) => " Export TU ",
            })
            .borders(Borders::ALL)
            .border_style(theme.borders.focused)
            .style(theme.surfaces.overlay);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        match overlay {
            UsersOverlay::Add(flow) => match flow.phase {
                AddUserPhase::ChooseMethod => {
                    let lines = flow
                        .methods
                        .items()
                        .iter()
                        .enumerate()
                        .map(|(index, item)| {
                            Line::from(format!(
                                "{} {}{}",
                                if flow.methods.selected_index() == Some(index) {
                                    ">"
                                } else {
                                    " "
                                },
                                item.label,
                                item.disabled_reason
                                    .as_ref()
                                    .map(|reason| format!(" ({reason})"))
                                    .unwrap_or_default()
                            ))
                        })
                        .collect::<Vec<_>>();
                    frame.render_widget(Paragraph::new(lines), inner);
                }
                AddUserPhase::ConfigureCreate => {
                    let value = flow.username.value();
                    let message = flow
                        .error
                        .as_deref()
                        .unwrap_or("Enter selects Create. Esc returns to methods.");
                    frame.render_widget(
                        Paragraph::new(format!("Username  [{value}]\n\n{message}")),
                        inner,
                    );
                }
                AddUserPhase::ConfigureImport => {
                    let value = flow.import_path.value();
                    let message = flow
                        .error
                        .as_deref()
                        .unwrap_or("Enter inspects the credential. Esc returns to methods.");
                    frame.render_widget(
                        Paragraph::new(format!("TU path  [{value}]\n\n{message}")),
                        inner,
                    );
                }
                AddUserPhase::ConfigureInvitation => {
                    let lines = flow
                        .invitation_authorities
                        .items()
                        .iter()
                        .enumerate()
                        .map(|(index, item)| {
                            Line::from(format!(
                                "{} {}{}",
                                if flow.invitation_authorities.selected_index() == Some(index) {
                                    ">"
                                } else {
                                    " "
                                },
                                item.label,
                                item.disabled_reason
                                    .as_ref()
                                    .map(|reason| format!(" ({reason})"))
                                    .unwrap_or_default()
                            ))
                        })
                        .chain(std::iter::once(Line::from(
                            "\nEnter creates a single-use invitation valid for one week.",
                        )))
                        .collect::<Vec<_>>();
                    frame.render_widget(Paragraph::new(lines), inner);
                }
                AddUserPhase::InspectingTu => {
                    frame.render_widget(Paragraph::new("Inspecting credential…"), inner);
                }
                AddUserPhase::ReviewImport => {
                    if let Some(preview) = &flow.preview {
                        let assignment = preview
                            .assigned_iota_id
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "Unassigned".into());
                        frame.render_widget(
                            Paragraph::new(format!(
                                "Username      {}\nUser ID       {}\nCurrent Iota  {}\nDestination   This Iota\n\nEnter attaches. Esc returns to the path.",
                                preview.username, preview.user_id, assignment
                            )),
                            inner,
                        );
                    }
                }
                _ => frame.render_widget(Paragraph::new(invitations::UNSUPPORTED_MESSAGE), inner),
            },
            UsersOverlay::UserMenu(menu) => {
                let lines = menu
                    .menu
                    .items()
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        Line::from(format!(
                            "{} {}{}",
                            if menu.menu.selected_index() == Some(index) {
                                ">"
                            } else {
                                " "
                            },
                            item.label,
                            item.disabled_reason
                                .as_ref()
                                .map(|reason| format!(" ({reason})"))
                                .unwrap_or_default()
                        ))
                    })
                    .collect::<Vec<_>>();
                frame.render_widget(Paragraph::new(lines), inner);
            }
            UsersOverlay::Confirm(confirm) => {
                let rows =
                    Layout::vertical([Constraint::Min(5), Constraint::Length(3)]).split(inner);
                frame.render_widget(Paragraph::new(confirm.message()), rows[0]);
                let buttons =
                    Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                        .split(rows[1]);
                render_button(
                    frame,
                    buttons[0],
                    ActionButton {
                        label: "Cancel",
                        intent: ButtonIntent::Cancel,
                        focused: false,
                        enabled: true,
                    },
                    theme,
                );
                render_button(
                    frame,
                    buttons[1],
                    ActionButton {
                        label: confirm.confirm_label(),
                        intent: ButtonIntent::Destructive,
                        focused: true,
                        enabled: !self.pending,
                    },
                    theme,
                );
                hits.register(buttons[0], IotaMessage::Action(AppAction::CancelDialog));
                hits.register(buttons[1], IotaMessage::Action(AppAction::ConfirmDialog));
            }
            UsersOverlay::CredentialExport(export) => {
                let value = export.destination.value();
                let message = export
                    .error
                    .as_deref()
                    .unwrap_or("Enter exports the TU. Esc cancels.");
                frame.render_widget(
                    Paragraph::new(format!(
                        "User         {}\nDestination  [{value}]\n\n{message}",
                        export.user.username
                    )),
                    inner,
                );
            }
        }
    }
}

impl IotaScreen for UsersScreen {
    fn render_legacy(
        &self,
        frame: &mut Frame,
        rect: Rect,
        theme: &ResolvedTheme,
        hits: &mut HitMap,
    ) {
        let outer = Block::default()
            .title(" User management ")
            .borders(Borders::ALL)
            .border_style(theme.borders.normal);
        let inner = outer.inner(rect);
        frame.render_widget(outer, rect);
        let rows = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(2),
        ])
        .split(inner);
        let header = Layout::horizontal([
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(20),
            Constraint::Length(18),
        ])
        .split(rows[0]);
        for (index, (label, tab)) in [
            ("Users", UserAdminTab::Users),
            ("Invitations", UserAdminTab::Invitations),
        ]
        .into_iter()
        .enumerate()
        {
            render_button(
                frame,
                header[index],
                ActionButton {
                    label,
                    intent: ButtonIntent::Neutral,
                    focused: self.active_tab == tab,
                    enabled: !self.pending,
                },
                theme,
            );
            if !self.pending {
                hits.register(
                    header[index],
                    IotaMessage::Action(AppAction::SetUserAdminTab(tab)),
                );
            }
        }
        frame.render_widget(
            Paragraph::new(if self.active_tab == UserAdminTab::Users {
                format!("Search [{}]", self.filter)
            } else {
                "Pending, redeemed, revoked, and expired invitations".into()
            })
            .style(if self.filtering {
                theme.text.normal
            } else {
                theme.text.muted
            }),
            header[2],
        );
        let add_enabled = !self.pending
            && (self.active_tab == UserAdminTab::Users || self.invitation_supported());
        render_button(
            frame,
            header[3],
            ActionButton {
                label: if self.active_tab == UserAdminTab::Users {
                    "+ Add User"
                } else {
                    "+ New Invitation"
                },
                intent: ButtonIntent::Primary,
                focused: self.focus_zone == FocusZone::Toolbar && self.toolbar_index == 0,
                enabled: add_enabled,
            },
            theme,
        );
        if add_enabled {
            hits.register(header[3], IotaMessage::Action(AppAction::AddUser));
        }
        let panes = if rows[1].width >= 70 {
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(rows[1])
        } else {
            Layout::horizontal([Constraint::Percentage(100), Constraint::Length(0)]).split(rows[1])
        };
        if self.active_tab == UserAdminTab::Users {
            self.render_list(frame, panes[0], theme, hits);
            if panes[1].width > 0 {
                self.render_context(frame, panes[1], theme, hits);
            }
        } else {
            invitations::render(frame, rows[1], theme, self.invitation_supported());
        }
        if let Some(message) = &self.message {
            frame.render_widget(
                Paragraph::new(message.as_str()).style(theme.text.muted),
                rows[2],
            );
        }
        self.render_overlay(frame, rect, theme, hits);
    }
    fn handle_event(&mut self, event: &UiEvent) -> IotaInteraction {
        let event = event.clone();
        match event {
            UiEvent::Message(IotaMessage::Event(AppEvent::UsersLoaded(result))) => {
                self.loading = false;
                match result {
                    Ok(users) => {
                        self.users = users;
                        self.restore_selection();
                    }
                    Err(error) => self.message = Some(error),
                }
                IotaInteraction::Changed
            }
            UiEvent::Message(IotaMessage::Event(AppEvent::UserOperationFinished(result))) => {
                self.pending = false;
                self.message = Some(match result {
                    Ok(message) => message,
                    Err(error) => error,
                });
                self.refresh()
            }
            UiEvent::Message(IotaMessage::Event(AppEvent::CredentialExportFinished(result))) => {
                self.pending = false;
                self.message = Some(match result {
                    Ok(message) => message,
                    Err(error) => error,
                });
                IotaInteraction::Changed
            }
            UiEvent::Message(IotaMessage::Event(AppEvent::TuInspected(result))) => {
                if let Some(UsersOverlay::Add(flow)) = self.overlay.as_mut() {
                    match result {
                        Ok(preview) => {
                            flow.inspection_succeeded(preview);
                        }
                        Err(error) => {
                            flow.inspection_failed(error);
                        }
                    }
                }
                IotaInteraction::Changed
            }
            UiEvent::Paste(text) => {
                if let Some(UsersOverlay::Add(flow)) = self.overlay.as_mut() {
                    let sanitized = text.replace(['\r', '\n'], " ");
                    let input = match flow.phase {
                        AddUserPhase::ConfigureCreate => Some(&mut flow.username),
                        AddUserPhase::ConfigureImport => Some(&mut flow.import_path),
                        _ => None,
                    };
                    if let Some(input) = input {
                        input.insert_text(&sanitized);
                        return IotaInteraction::Changed;
                    }
                }
                if let Some(UsersOverlay::CredentialExport(export)) = self.overlay.as_mut() {
                    export
                        .destination
                        .insert_text(&text.replace(['\r', '\n'], " "));
                    return IotaInteraction::Changed;
                }
                if self.filtering {
                    self.filter.push_str(&text.replace(['\r', '\n'], " "));
                    self.restore_selection();
                    return IotaInteraction::Changed;
                }
                IotaInteraction::Unhandled
            }
            UiEvent::Key(key) => {
                if let Some(overlay) = &mut self.overlay {
                    match overlay {
                        UsersOverlay::Add(flow) => match flow.phase {
                            AddUserPhase::ChooseMethod => {
                                if matches!(
                                    flow.methods.handle_key(key.code),
                                    ratatool::MenuResult::Moved
                                        | ratatool::MenuResult::Unchanged
                                        | ratatool::MenuResult::NoSelection
                                ) {
                                    return IotaInteraction::Changed;
                                }
                                match key.code {
                                    KeyCode::Enter => {
                                        flow.choose();
                                        IotaInteraction::Changed
                                    }
                                    KeyCode::Esc => {
                                        self.overlay = None;
                                        IotaInteraction::Changed
                                    }
                                    _ => IotaInteraction::Changed,
                                }
                            }
                            AddUserPhase::ConfigureCreate => match key.code {
                                KeyCode::Esc => {
                                    flow.phase = AddUserPhase::ChooseMethod;
                                    IotaInteraction::Changed
                                }
                                KeyCode::Enter => {
                                    let username = flow.username.value().trim().to_owned();
                                    if username.is_empty() {
                                        flow.error = Some("A username is required.".into());
                                        IotaInteraction::Changed
                                    } else {
                                        self.start_create(username)
                                    }
                                }
                                _ => {
                                    flow.username.handle_key(key);
                                    IotaInteraction::Changed
                                }
                            },
                            AddUserPhase::ConfigureImport => match key.code {
                                KeyCode::Esc => {
                                    flow.phase = AddUserPhase::ChooseMethod;
                                    IotaInteraction::Changed
                                }
                                KeyCode::Enter => {
                                    let path = flow.import_path.value().trim();
                                    if path.is_empty() {
                                        flow.error = Some("A TU path is required.".into());
                                        IotaInteraction::Changed
                                    } else {
                                        match std::fs::read_to_string(path) {
                                            Ok(contents) => self.start_tu_inspection(
                                                iota_ipc::SecretString(contents),
                                            ),
                                            Err(error) => {
                                                flow.error = Some(format!(
                                                    "Cannot read credential {path}: {error}"
                                                ));
                                                IotaInteraction::Changed
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    flow.import_path.handle_key(key);
                                    IotaInteraction::Changed
                                }
                            },
                            AddUserPhase::ConfigureInvitation => {
                                if matches!(
                                    flow.invitation_authorities.handle_key(key.code),
                                    ratatool::MenuResult::Moved
                                        | ratatool::MenuResult::Unchanged
                                        | ratatool::MenuResult::NoSelection
                                ) {
                                    return IotaInteraction::Changed;
                                }
                                match key.code {
                                    KeyCode::Esc => {
                                        flow.phase = AddUserPhase::ChooseMethod;
                                        IotaInteraction::Changed
                                    }
                                    KeyCode::Enter => {
                                        let authority = flow
                                            .invitation_authorities
                                            .selected_item()
                                            .map(|item| item.value);
                                        if let Some(authority) = authority {
                                            self.start_invitation(authority)
                                        } else {
                                            IotaInteraction::Changed
                                        }
                                    }
                                    _ => IotaInteraction::Changed,
                                }
                            }
                            AddUserPhase::ReviewImport => match key.code {
                                KeyCode::Esc => {
                                    flow.phase = AddUserPhase::ConfigureImport;
                                    IotaInteraction::Changed
                                }
                                KeyCode::Enter => {
                                    if let Some(credential) = flow.credential.clone() {
                                        flow.attachment_started();
                                        self.start_tu_attachment(credential)
                                    } else {
                                        flow.error =
                                            Some("Credential must be inspected again.".into());
                                        flow.phase = AddUserPhase::ConfigureImport;
                                        IotaInteraction::Changed
                                    }
                                }
                                _ => IotaInteraction::Changed,
                            },
                            _ => {
                                self.overlay = None;
                                IotaInteraction::Changed
                            }
                        },
                        UsersOverlay::UserMenu(menu) => {
                            match menu.menu.handle_key(key.code) {
                                ratatool::MenuResult::Moved
                                | ratatool::MenuResult::Unchanged
                                | ratatool::MenuResult::NoSelection => {
                                    return IotaInteraction::Changed;
                                }
                                ratatool::MenuResult::Activated(action) => {
                                    return self.begin_action(action);
                                }
                                ratatool::MenuResult::Unhandled => {}
                            }
                            match key.code {
                                KeyCode::Esc => {
                                    self.overlay = None;
                                    IotaInteraction::Changed
                                }
                                KeyCode::Enter => {
                                    let action = menu.menu.selected_item().map(|item| item.value);
                                    action.map_or(IotaInteraction::Changed, |action| {
                                        self.begin_action(action)
                                    })
                                }
                                _ => IotaInteraction::Changed,
                            }
                        }
                        UsersOverlay::Confirm(confirm) => match key.code {
                            KeyCode::Esc => {
                                self.overlay = None;
                                IotaInteraction::Changed
                            }
                            KeyCode::Enter => {
                                let action = confirm.action;
                                let user_id = confirm.user.user_id;
                                self.start_operation(action, user_id)
                            }
                            _ => IotaInteraction::Changed,
                        },
                        UsersOverlay::CredentialExport(export) => match key.code {
                            KeyCode::Esc => {
                                self.overlay = None;
                                IotaInteraction::Changed
                            }
                            KeyCode::Enter => {
                                let destination = export.destination.value().trim();
                                if destination.is_empty() {
                                    export.error = Some("A destination path is required.".into());
                                    IotaInteraction::Changed
                                } else {
                                    let user_id = export.user.user_id;
                                    let destination = std::path::PathBuf::from(destination);
                                    self.start_credential_export(user_id, destination)
                                }
                            }
                            _ => {
                                export.destination.handle_key(key);
                                IotaInteraction::Changed
                            }
                        },
                    }
                } else if self.active_tab == UserAdminTab::Invitations {
                    match key.code {
                        KeyCode::Esc => IotaInteraction::Pop,
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            if self.invitation_supported() {
                                self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                            } else {
                                self.message = Some(invitations::UNSUPPORTED_MESSAGE.into());
                            }
                            IotaInteraction::Changed
                        }
                        KeyCode::Char('u') | KeyCode::Char('U') => {
                            self.active_tab = UserAdminTab::Users;
                            self.focus_zone = FocusZone::UserList;
                            IotaInteraction::Changed
                        }
                        KeyCode::Char('i') | KeyCode::Char('I') => IotaInteraction::Changed,
                        _ => IotaInteraction::Unhandled,
                    }
                } else if self.filtering {
                    match key.code {
                        KeyCode::Esc => {
                            self.filtering = false;
                            self.filter.clear();
                            self.restore_selection();
                        }
                        KeyCode::Enter => self.filtering = false,
                        KeyCode::Backspace => {
                            self.filter.pop();
                            self.restore_selection();
                        }
                        KeyCode::Char(character)
                            if !key
                                .modifiers
                                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                        {
                            self.filter.push(character);
                            self.restore_selection();
                        }
                        _ => {}
                    };
                    IotaInteraction::Changed
                } else {
                    match key.code {
                        KeyCode::Esc => IotaInteraction::Pop,
                        KeyCode::Char('/') => {
                            self.filtering = true;
                            IotaInteraction::Changed
                        }
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                            IotaInteraction::Changed
                        }
                        KeyCode::Char('i') | KeyCode::Char('I') => {
                            self.active_tab = UserAdminTab::Invitations;
                            self.filtering = false;
                            IotaInteraction::Changed
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            self.move_selection(1);
                            IotaInteraction::Changed
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            self.move_selection(-1);
                            IotaInteraction::Changed
                        }
                        KeyCode::PageDown => {
                            self.move_selection(
                                self.viewport_height.load(Ordering::Relaxed) as isize
                            );
                            IotaInteraction::Changed
                        }
                        KeyCode::PageUp => {
                            self.move_selection(
                                -(self.viewport_height.load(Ordering::Relaxed) as isize),
                            );
                            IotaInteraction::Changed
                        }
                        KeyCode::Home => {
                            self.selected_user_id =
                                self.visible_users().first().map(|user| user.user_id);
                            self.keep_selected_visible();
                            IotaInteraction::Changed
                        }
                        KeyCode::End => {
                            self.selected_user_id =
                                self.visible_users().last().map(|user| user.user_id);
                            self.keep_selected_visible();
                            IotaInteraction::Changed
                        }
                        KeyCode::Tab => {
                            self.focus_zone = match self.focus_zone {
                                FocusZone::Toolbar => FocusZone::Search,
                                FocusZone::Search => FocusZone::UserList,
                                FocusZone::UserList => FocusZone::UserActions,
                                FocusZone::UserActions => FocusZone::Toolbar,
                            };
                            IotaInteraction::Changed
                        }
                        KeyCode::Left if self.focus_zone == FocusZone::UserActions => {
                            self.action_group_index = self.action_group_index.saturating_sub(1);
                            IotaInteraction::Changed
                        }
                        KeyCode::Right if self.focus_zone == FocusZone::UserActions => {
                            let last = self.groups().len().saturating_sub(1);
                            self.action_group_index = (self.action_group_index + 1).min(last);
                            IotaInteraction::Changed
                        }
                        KeyCode::Enter if self.focus_zone == FocusZone::Toolbar => {
                            self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                            IotaInteraction::Changed
                        }
                        KeyCode::Enter if self.focus_zone == FocusZone::UserActions => {
                            if let Some(entry) = self.groups().get(self.action_group_index) {
                                self.overlay = Some(UsersOverlay::UserMenu(UserActionMenu::new(
                                    entry.group,
                                    entry.actions.clone(),
                                    self.credential_export_supported(),
                                )));
                            }
                            IotaInteraction::Changed
                        }
                        _ => IotaInteraction::Unhandled,
                    }
                }
            }
            _ => IotaInteraction::Unhandled,
        }
    }
    fn handle_action(&mut self, action: AppAction) -> IotaInteraction {
        match action {
            AppAction::AddUser => {
                if self.active_tab == UserAdminTab::Invitations && !self.invitation_supported() {
                    self.message = Some(invitations::UNSUPPORTED_MESSAGE.into());
                } else {
                    self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                }
                IotaInteraction::Changed
            }
            AppAction::SetUserAdminTab(tab) if self.overlay.is_none() => {
                self.active_tab = tab;
                self.filtering = false;
                self.focus_zone = if tab == UserAdminTab::Users {
                    FocusZone::UserList
                } else {
                    FocusZone::Toolbar
                };
                IotaInteraction::Changed
            }
            AppAction::SelectUser(id) if self.overlay.is_none() => {
                self.selected_user_id = Some(id);
                self.focus_zone = FocusZone::UserList;
                self.keep_selected_visible();
                IotaInteraction::Changed
            }
            AppAction::OpenUserGroup(group) if self.overlay.is_none() => {
                if let Some(entry) = self.groups().into_iter().find(|entry| entry.group == group) {
                    self.overlay = Some(UsersOverlay::UserMenu(UserActionMenu::new(
                        group,
                        entry.actions,
                        self.credential_export_supported(),
                    )));
                }
                IotaInteraction::Changed
            }
            AppAction::ActivateUserAction(action) => self.begin_action(action),
            AppAction::ConfirmDialog => match &self.overlay {
                Some(UsersOverlay::Confirm(confirm)) => {
                    self.start_operation(confirm.action, confirm.user.user_id)
                }
                _ => IotaInteraction::Unhandled,
            },
            AppAction::CancelDialog => {
                self.overlay = None;
                IotaInteraction::Changed
            }
            _ => IotaInteraction::Unhandled,
        }
    }
    fn key_hints(&self) -> Vec<KeyHint> {
        if self.overlay.is_some() {
            vec![
                KeyHint {
                    keys: "Enter",
                    action: "Select",
                },
                KeyHint {
                    keys: "Esc",
                    action: "Cancel",
                },
            ]
        } else {
            vec![
                KeyHint {
                    keys: "↑/↓",
                    action: "Select user",
                },
                KeyHint {
                    keys: "A",
                    action: "Add user",
                },
                KeyHint {
                    keys: "/",
                    action: "Search",
                },
                KeyHint {
                    keys: "F6",
                    action: "Header",
                },
            ]
        }
    }
}
