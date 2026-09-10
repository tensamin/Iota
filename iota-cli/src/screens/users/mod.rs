pub mod action_menu;
pub mod add_flow;
pub mod confirmations;
pub mod context;
pub mod credential_export;
pub mod invitations;
pub mod list;
pub mod model;

use crate::{
    controls::button::{ActionButton, ButtonIntent, render_button},
    interaction_result::InteractionResult,
    ipc_client::IpcClient,
    render_context::RenderContext,
    screens::screens::{AppAction, AppEvent, HitMap, KeyHint, Screen, UiEvent},
};
use action_menu::UserActionMenu;
use add_flow::{AddUserFlow, AddUserPhase};
use confirmations::UserConfirmation;
use credential_export::{CredentialExportState, write_private_export};
use crossterm::event::{KeyCode, KeyModifiers};
use model::{FocusZone, UserAction, UserAdminTab, available_action_groups};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
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
    fn begin_action(&mut self, action: UserAction) -> InteractionResult {
        if action == UserAction::ExportTu && !self.credential_export_supported() {
            self.message =
                Some("Credential export is not supported by the connected daemon.".into());
            return InteractionResult::Handled;
        }
        if let Some(user) = self.selected_user().cloned() {
            if action == UserAction::ExportTu {
                self.overlay = Some(UsersOverlay::CredentialExport(CredentialExportState::new(
                    user,
                )));
                return InteractionResult::Handled;
            }
            if action.requires_confirmation() {
                self.overlay = Some(UsersOverlay::Confirm(UserConfirmation { user, action }));
            } else {
                return self.start_operation(action, user.user_id);
            }
        }
        InteractionResult::Handled
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
    fn start_tu_inspection(&mut self, credential: iota_ipc::SecretString) -> InteractionResult {
        let ipc = self.ipc.clone();
        if let Some(UsersOverlay::Add(flow)) = self.overlay.as_mut() {
            flow.phase = AddUserPhase::InspectingTu;
            flow.credential = Some(credential.clone());
            flow.error = None;
        }
        InteractionResult::AppTask {
            task: Box::pin(async move {
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
                UiEvent::App(AppEvent::TuInspected(result))
            }),
        }
    }
    fn start_tu_attachment(&mut self, credential: iota_ipc::SecretString) -> InteractionResult {
        self.pending = true;
        self.overlay = None;
        self.message = Some("Attaching existing user…".into());
        let ipc = self.ipc.clone();
        InteractionResult::AppTask {
            task: Box::pin(async move {
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
                UiEvent::App(AppEvent::UserOperationFinished(result))
            }),
        }
    }
    fn start_operation(&mut self, action: UserAction, user_id: i64) -> InteractionResult {
        self.pending = true;
        self.overlay = None;
        self.message = Some(format!("{}…", action.label()));
        let ipc = self.ipc.clone();
        InteractionResult::AppTask {
            task: Box::pin(async move {
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
                        return UiEvent::App(AppEvent::UserOperationFinished(Err(
                            "Credential export requires a destination path.".into(),
                        )));
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
                        "Diagnostics: state={:?}, data={}, credential={}, trusted apps={}, pending={}",
                        diagnostics.local_state,
                        if diagnostics.data_present {
                            "present"
                        } else {
                            "empty"
                        },
                        context::credential_status_label(diagnostics.credential_status),
                        diagnostics.trusted_app_count,
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
                UiEvent::App(AppEvent::UserOperationFinished(result))
            }),
        }
    }
    fn start_credential_export(
        &mut self,
        user_id: i64,
        destination: std::path::PathBuf,
    ) -> InteractionResult {
        self.pending = true;
        self.overlay = None;
        self.message = Some("Exporting credential…".into());
        let ipc = self.ipc.clone();
        InteractionResult::AppTask {
            task: Box::pin(async move {
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
                UiEvent::App(AppEvent::CredentialExportFinished(result))
            }),
        }
    }
    fn start_create(&mut self, username: String) -> InteractionResult {
        self.pending = true;
        self.message = Some("Creating user…".into());
        self.overlay = None;
        let ipc = self.ipc.clone();
        InteractionResult::AppTask {
            task: Box::pin(async move {
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
                UiEvent::App(AppEvent::UserOperationFinished(result))
            }),
        }
    }
    fn start_invitation(&mut self, authority: iota_ipc::InvitationAuthority) -> InteractionResult {
        self.pending = true;
        self.message = Some("Creating invitation…".into());
        self.overlay = None;
        let ipc = self.ipc.clone();
        InteractionResult::AppTask {
            task: Box::pin(async move {
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
                        "Invitation {} created. Token: {}  Link: {}",
                        invitation.invitation_id,
                        invitation.raw_token.0,
                        invitation.short_url.as_deref().unwrap_or("unavailable")
                    )),
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Create invitation failed: {error}"))
                    }
                    Ok(_) => Err(
                        "Create invitation failed: daemon returned an unexpected response.".into(),
                    ),
                    Err(error) => Err(format!("Create invitation failed: {error}")),
                };
                UiEvent::App(AppEvent::UserOperationFinished(result))
            }),
        }
    }
    fn refresh(&self) -> InteractionResult {
        let ipc = self.ipc.clone();
        InteractionResult::AppTask {
            task: Box::pin(async move {
                let result = match ipc.send_request(iota_ipc::LocalRequest::ListUsers).await {
                    Ok(iota_ipc::ResponseResult::Ok(iota_ipc::ResponsePayload::Users(users))) => {
                        Ok(users
                            .into_iter()
                            .map(|user| UserEntry {
                                user_id: user.user_id,
                                username: user.username,
                                state: user.state,
                                data_present: user.data_present,
                                credential_status: user.credential_status,
                                pending_operation: user.pending_operation,
                            })
                            .collect())
                    }
                    Ok(iota_ipc::ResponseResult::Error(error)) => {
                        Err(format!("Cannot reload users: {error}"))
                    }
                    Ok(_) => {
                        Err("Cannot reload users: daemon returned an unexpected response.".into())
                    }
                    Err(error) => Err(format!("Cannot reload users: {error}")),
                };
                UiEvent::App(AppEvent::UsersLoaded(result))
            }),
        }
    }
    fn render_list(
        &self,
        frame: &mut Frame,
        area: Rect,
        context: &RenderContext<'_>,
        hits: &mut HitMap,
    ) {
        let block = Block::default()
            .title(" Users ")
            .borders(Borders::ALL)
            .border_style(context.theme.borders.normal);
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
                AppAction::SelectUser(user.user_id),
            );
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
    fn render_context(
        &self,
        frame: &mut Frame,
        area: Rect,
        context: &RenderContext<'_>,
        hits: &mut HitMap,
    ) {
        let block = Block::default()
            .title(" Selected user ")
            .borders(Borders::ALL)
            .border_style(context.theme.borders.normal);
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
            Line::from(Span::styled(
                user.username.as_str(),
                context.theme.text.normal,
            )),
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
                context.theme,
            );
            if !self.pending {
                hits.register(buttons[index], AppAction::OpenUserGroup(entry.group));
            }
        }
    }
    fn render_overlay(
        &self,
        frame: &mut Frame,
        rect: Rect,
        context: &RenderContext<'_>,
        hits: &mut HitMap,
    ) {
        let Some(overlay) = &self.overlay else {
            return;
        };
        let area = crate::layout::fit::centered_rect(
            rect,
            crate::layout::fit::RequiredSize {
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
            .border_style(context.theme.borders.focused)
            .style(context.theme.surfaces.overlay);
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
                    let value = flow.username.display_value();
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
                    let value = flow.import_path.display_value();
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
                    context.theme,
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
                    context.theme,
                );
                hits.register(buttons[0], AppAction::CancelDialog);
                hits.register(buttons[1], AppAction::ConfirmDialog);
            }
            UsersOverlay::CredentialExport(export) => {
                let value = export.destination.display_value();
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

impl Screen for UsersScreen {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn render(
        &self,
        frame: &mut Frame,
        rect: Rect,
        context: &RenderContext<'_>,
        hits: &mut HitMap,
    ) {
        let outer = Block::default()
            .title(" User management ")
            .borders(Borders::ALL)
            .border_style(context.theme.borders.normal);
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
                context.theme,
            );
            if !self.pending {
                hits.register(header[index], AppAction::SetUserAdminTab(tab));
            }
        }
        frame.render_widget(
            Paragraph::new(if self.active_tab == UserAdminTab::Users {
                format!("Search [{}]", self.filter)
            } else {
                "Pending, redeemed, revoked, and expired invitations".into()
            })
            .style(if self.filtering {
                context.theme.text.normal
            } else {
                context.theme.text.muted
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
            context.theme,
        );
        if add_enabled {
            hits.register(header[3], AppAction::AddUser);
        }
        let panes = if rows[1].width >= 70 {
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(rows[1])
        } else {
            Layout::horizontal([Constraint::Percentage(100), Constraint::Length(0)]).split(rows[1])
        };
        if self.active_tab == UserAdminTab::Users {
            self.render_list(frame, panes[0], context, hits);
            if panes[1].width > 0 {
                self.render_context(frame, panes[1], context, hits);
            }
        } else {
            invitations::render(frame, rows[1], context, self.invitation_supported());
        }
        if let Some(message) = &self.message {
            frame.render_widget(
                Paragraph::new(message.as_str()).style(context.theme.text.muted),
                rows[2],
            );
        }
        self.render_overlay(frame, rect, context, hits);
    }
    fn handle_event(&mut self, event: UiEvent) -> InteractionResult {
        match event {
            UiEvent::App(AppEvent::UsersLoaded(result)) => {
                self.loading = false;
                match result {
                    Ok(users) => {
                        self.users = users;
                        self.restore_selection();
                    }
                    Err(error) => self.message = Some(error),
                }
                return InteractionResult::Handled;
            }
            UiEvent::App(AppEvent::UserOperationFinished(result)) => {
                self.pending = false;
                self.message = Some(match result {
                    Ok(message) => message,
                    Err(error) => error,
                });
                return self.refresh();
            }
            UiEvent::App(AppEvent::CredentialExportFinished(result)) => {
                self.pending = false;
                self.message = Some(match result {
                    Ok(message) => message,
                    Err(error) => error,
                });
                return InteractionResult::Handled;
            }
            UiEvent::App(AppEvent::TuInspected(result)) => {
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
                return InteractionResult::Handled;
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
                        for character in sanitized.chars() {
                            input.handle_key(KeyCode::Char(character));
                        }
                        return InteractionResult::Handled;
                    }
                }
                if let Some(UsersOverlay::CredentialExport(export)) = self.overlay.as_mut() {
                    for character in text.replace(['\r', '\n'], " ").chars() {
                        export.destination.handle_key(KeyCode::Char(character));
                    }
                    return InteractionResult::Handled;
                }
                if self.filtering {
                    self.filter.push_str(&text.replace(['\r', '\n'], " "));
                    self.restore_selection();
                    return InteractionResult::Handled;
                }
                return InteractionResult::Unhandled;
            }
            UiEvent::Key(key) => {
                if let Some(overlay) = &mut self.overlay {
                    match overlay {
                        UsersOverlay::Add(flow) => match flow.phase {
                            AddUserPhase::ChooseMethod => {
                                if flow.methods.handle_key(key.code) {
                                    return InteractionResult::Handled;
                                }
                                match key.code {
                                    KeyCode::Enter => {
                                        flow.choose();
                                        InteractionResult::Handled
                                    }
                                    KeyCode::Esc => {
                                        self.overlay = None;
                                        InteractionResult::Handled
                                    }
                                    _ => InteractionResult::Handled,
                                }
                            }
                            AddUserPhase::ConfigureCreate => match key.code {
                                KeyCode::Esc => {
                                    flow.phase = AddUserPhase::ChooseMethod;
                                    InteractionResult::Handled
                                }
                                KeyCode::Enter => {
                                    let username = flow.username.value().trim().to_owned();
                                    if username.is_empty() {
                                        flow.error = Some("A username is required.".into());
                                        InteractionResult::Handled
                                    } else {
                                        self.start_create(username)
                                    }
                                }
                                _ => {
                                    flow.username.handle_key(key.code);
                                    InteractionResult::Handled
                                }
                            },
                            AddUserPhase::ConfigureImport => match key.code {
                                KeyCode::Esc => {
                                    flow.phase = AddUserPhase::ChooseMethod;
                                    InteractionResult::Handled
                                }
                                KeyCode::Enter => {
                                    let path = flow.import_path.value().trim();
                                    if path.is_empty() {
                                        flow.error = Some("A TU path is required.".into());
                                        InteractionResult::Handled
                                    } else {
                                        match std::fs::read_to_string(path) {
                                            Ok(contents) => self.start_tu_inspection(
                                                iota_ipc::SecretString(contents),
                                            ),
                                            Err(error) => {
                                                flow.error = Some(format!(
                                                    "Cannot read credential {path}: {error}"
                                                ));
                                                InteractionResult::Handled
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    flow.import_path.handle_key(key.code);
                                    InteractionResult::Handled
                                }
                            },
                            AddUserPhase::ConfigureInvitation => {
                                if flow.invitation_authorities.handle_key(key.code) {
                                    return InteractionResult::Handled;
                                }
                                match key.code {
                                    KeyCode::Esc => {
                                        flow.phase = AddUserPhase::ChooseMethod;
                                        InteractionResult::Handled
                                    }
                                    KeyCode::Enter => {
                                        let authority = flow
                                            .invitation_authorities
                                            .selected_item()
                                            .map(|item| item.value);
                                        if let Some(authority) = authority {
                                            self.start_invitation(authority)
                                        } else {
                                            InteractionResult::Handled
                                        }
                                    }
                                    _ => InteractionResult::Handled,
                                }
                            }
                            AddUserPhase::ReviewImport => match key.code {
                                KeyCode::Esc => {
                                    flow.phase = AddUserPhase::ConfigureImport;
                                    InteractionResult::Handled
                                }
                                KeyCode::Enter => {
                                    if let Some(credential) = flow.credential.clone() {
                                        flow.attachment_started();
                                        self.start_tu_attachment(credential)
                                    } else {
                                        flow.error =
                                            Some("Credential must be inspected again.".into());
                                        flow.phase = AddUserPhase::ConfigureImport;
                                        InteractionResult::Handled
                                    }
                                }
                                _ => InteractionResult::Handled,
                            },
                            _ => {
                                self.overlay = None;
                                InteractionResult::Handled
                            }
                        },
                        UsersOverlay::UserMenu(menu) => {
                            if menu.menu.handle_key(key.code) {
                                return InteractionResult::Handled;
                            }
                            match key.code {
                                KeyCode::Esc => {
                                    self.overlay = None;
                                    InteractionResult::Handled
                                }
                                KeyCode::Enter => {
                                    let action = menu.menu.selected_item().map(|item| item.value);
                                    action.map_or(InteractionResult::Handled, |action| {
                                        self.begin_action(action)
                                    })
                                }
                                _ => InteractionResult::Handled,
                            }
                        }
                        UsersOverlay::Confirm(confirm) => match key.code {
                            KeyCode::Esc => {
                                self.overlay = None;
                                InteractionResult::Handled
                            }
                            KeyCode::Enter => {
                                let action = confirm.action;
                                let user_id = confirm.user.user_id;
                                self.start_operation(action, user_id)
                            }
                            _ => InteractionResult::Handled,
                        },
                        UsersOverlay::CredentialExport(export) => match key.code {
                            KeyCode::Esc => {
                                self.overlay = None;
                                InteractionResult::Handled
                            }
                            KeyCode::Enter => {
                                let destination = export.destination.value().trim();
                                if destination.is_empty() {
                                    export.error = Some("A destination path is required.".into());
                                    InteractionResult::Handled
                                } else {
                                    let user_id = export.user.user_id;
                                    let destination = std::path::PathBuf::from(destination);
                                    self.start_credential_export(user_id, destination)
                                }
                            }
                            _ => {
                                export.destination.handle_key(key.code);
                                InteractionResult::Handled
                            }
                        },
                    }
                } else if self.active_tab == UserAdminTab::Invitations {
                    match key.code {
                        KeyCode::Esc => InteractionResult::CloseScreen,
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            if self.invitation_supported() {
                                self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                            } else {
                                self.message = Some(invitations::UNSUPPORTED_MESSAGE.into());
                            }
                            InteractionResult::Handled
                        }
                        KeyCode::Char('u') | KeyCode::Char('U') => {
                            self.active_tab = UserAdminTab::Users;
                            self.focus_zone = FocusZone::UserList;
                            InteractionResult::Handled
                        }
                        KeyCode::Char('i') | KeyCode::Char('I') => InteractionResult::Handled,
                        _ => InteractionResult::Unhandled,
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
                    InteractionResult::Handled
                } else {
                    match key.code {
                        KeyCode::Esc => InteractionResult::CloseScreen,
                        KeyCode::Char('/') => {
                            self.filtering = true;
                            InteractionResult::Handled
                        }
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                            InteractionResult::Handled
                        }
                        KeyCode::Char('i') | KeyCode::Char('I') => {
                            self.active_tab = UserAdminTab::Invitations;
                            self.filtering = false;
                            InteractionResult::Handled
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            self.move_selection(1);
                            InteractionResult::Handled
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            self.move_selection(-1);
                            InteractionResult::Handled
                        }
                        KeyCode::PageDown => {
                            self.move_selection(
                                self.viewport_height.load(Ordering::Relaxed) as isize
                            );
                            InteractionResult::Handled
                        }
                        KeyCode::PageUp => {
                            self.move_selection(
                                -(self.viewport_height.load(Ordering::Relaxed) as isize),
                            );
                            InteractionResult::Handled
                        }
                        KeyCode::Home => {
                            self.selected_user_id =
                                self.visible_users().first().map(|user| user.user_id);
                            self.keep_selected_visible();
                            InteractionResult::Handled
                        }
                        KeyCode::End => {
                            self.selected_user_id =
                                self.visible_users().last().map(|user| user.user_id);
                            self.keep_selected_visible();
                            InteractionResult::Handled
                        }
                        KeyCode::Tab => {
                            self.focus_zone = match self.focus_zone {
                                FocusZone::Toolbar => FocusZone::Search,
                                FocusZone::Search => FocusZone::UserList,
                                FocusZone::UserList => FocusZone::UserActions,
                                FocusZone::UserActions => FocusZone::Toolbar,
                            };
                            InteractionResult::Handled
                        }
                        KeyCode::Left if self.focus_zone == FocusZone::UserActions => {
                            self.action_group_index = self.action_group_index.saturating_sub(1);
                            InteractionResult::Handled
                        }
                        KeyCode::Right if self.focus_zone == FocusZone::UserActions => {
                            let last = self.groups().len().saturating_sub(1);
                            self.action_group_index = (self.action_group_index + 1).min(last);
                            InteractionResult::Handled
                        }
                        KeyCode::Enter if self.focus_zone == FocusZone::Toolbar => {
                            self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                            InteractionResult::Handled
                        }
                        KeyCode::Enter if self.focus_zone == FocusZone::UserActions => {
                            if let Some(entry) = self.groups().get(self.action_group_index) {
                                self.overlay = Some(UsersOverlay::UserMenu(UserActionMenu::new(
                                    entry.group,
                                    entry.actions.clone(),
                                    self.credential_export_supported(),
                                )));
                            }
                            InteractionResult::Handled
                        }
                        _ => InteractionResult::Unhandled,
                    }
                }
            }
            _ => InteractionResult::Unhandled,
        }
    }
    fn handle_action(&mut self, action: AppAction) -> InteractionResult {
        match action {
            AppAction::AddUser => {
                if self.active_tab == UserAdminTab::Invitations && !self.invitation_supported() {
                    self.message = Some(invitations::UNSUPPORTED_MESSAGE.into());
                } else {
                    self.overlay = Some(UsersOverlay::Add(self.new_add_flow()));
                }
                InteractionResult::Handled
            }
            AppAction::SetUserAdminTab(tab) if self.overlay.is_none() => {
                self.active_tab = tab;
                self.filtering = false;
                self.focus_zone = if tab == UserAdminTab::Users {
                    FocusZone::UserList
                } else {
                    FocusZone::Toolbar
                };
                InteractionResult::Handled
            }
            AppAction::SelectUser(id) if self.overlay.is_none() => {
                self.selected_user_id = Some(id);
                self.focus_zone = FocusZone::UserList;
                self.keep_selected_visible();
                InteractionResult::Handled
            }
            AppAction::OpenUserGroup(group) if self.overlay.is_none() => {
                if let Some(entry) = self.groups().into_iter().find(|entry| entry.group == group) {
                    self.overlay = Some(UsersOverlay::UserMenu(UserActionMenu::new(
                        group,
                        entry.actions,
                        self.credential_export_supported(),
                    )));
                }
                InteractionResult::Handled
            }
            AppAction::ActivateUserAction(action) => self.begin_action(action),
            AppAction::ConfirmDialog => match &self.overlay {
                Some(UsersOverlay::Confirm(confirm)) => {
                    self.start_operation(confirm.action, confirm.user.user_id)
                }
                _ => InteractionResult::Unhandled,
            },
            AppAction::CancelDialog => {
                self.overlay = None;
                InteractionResult::Handled
            }
            _ => InteractionResult::Unhandled,
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
