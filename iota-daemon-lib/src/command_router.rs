use crate::log_buffer::LogBuffer;
use crate::{DaemonRuntime, DaemonServices};
use iota_ipc::{
    CommunitySummary, ComponentStatusResponse, ConfigResponse, DaemonMessage, ExitIntent,
    InvitationAuthority, InvitationCreated, InvitationState, InvitationSummary, IpcErrorCode,
    LocalRequest, LogEntriesResponse, LogEntry, MAX_MESSAGE_SIZE, OmikronStatusResponse,
    ReconcileAction, ResponseEnvelope, ResponsePayload, ResponseResult, StatusResponse,
    TaskSummary, UpdateStatusResponse, UserDetailResponse, UserDiagnostics, UserOperationKind,
    UserOperationSummary, UserReconcileResult, UserSummary,
};
use iota_logger::{log, log_command};
use iota_storage::users::pending_operations::{
    self, PendingUserOperation, PendingUserOperationKind, PendingUserOperationPhase,
};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::{self};
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::daemon_state::{ShutdownReason, StartupPhase};

pub use iota_ipc::IpcRole;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerContext {
    pub pid: i32,
    pub uid: u32,
    pub role: IpcRole,
}

const MAX_LOG_ENTRIES_PER_RESPONSE: usize = 512;

fn credential_status(
    residency: &user_manager::UserResidency,
    profile: Option<&iota_storage::users::user_profile::UserProfile>,
) -> iota_ipc::CredentialStatus {
    match (residency.state, residency.credential_origin) {
        (user_manager::LocalUserState::Released, _) => iota_ipc::CredentialStatus::None,
        (_, user_manager::CredentialOrigin::External) => iota_ipc::CredentialStatus::External,
        (_, user_manager::CredentialOrigin::Local)
            if profile.is_some_and(|profile| {
                iota_util::file_util::read_user_credential_with_legacy(
                    residency.user_id,
                    &profile.username,
                )
                .ok()
                .flatten()
                .is_some()
            }) =>
        {
            iota_ipc::CredentialStatus::LocalPresent
        }
        _ => iota_ipc::CredentialStatus::Missing,
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn invitation_created_after_mirror(
    authority: InvitationAuthority,
    invitation_id: i64,
    raw_token: String,
    expires_at: i64,
    short_url: Option<String>,
    mirror_result: Result<(), iota_storage::storage_error::StorageError>,
) -> InvitationCreated {
    let mirror_synced = match mirror_result {
        Ok(()) => true,
        Err(error) => {
            log!(
                "Invitation {} was created by Omega, but its local mirror could not be stored: {}",
                invitation_id,
                error
            );
            false
        }
    };
    InvitationCreated {
        authority,
        invitation_id,
        raw_token: iota_ipc::SecretString(raw_token),
        expires_at,
        short_url,
        mirror_synced,
    }
}

fn bounded_log_entries(mut entries: Vec<LogEntry>) -> Vec<LogEntry> {
    entries.truncate(MAX_LOG_ENTRIES_PER_RESPONSE);
    while !entries.is_empty() {
        let response = DaemonMessage::Response(ResponseEnvelope {
            request_id: u64::MAX,
            result: ResponseResult::Ok(ResponsePayload::LogEntries(LogEntriesResponse {
                entries: entries.clone(),
            })),
        });
        let fits = serde_json::to_vec(&response)
            .map(|encoded| encoded.len() <= MAX_MESSAGE_SIZE)
            .unwrap_or(false);
        if fits {
            return entries;
        }
        entries.remove(0);
    }
    entries
}

#[derive(Clone)]
pub struct CommandRouter {
    runtime: Arc<DaemonRuntime>,
    services: Arc<DaemonServices>,
    log_buffer: Arc<Mutex<LogBuffer>>,
}

impl CommandRouter {
    pub fn new(
        runtime: Arc<DaemonRuntime>,
        services: Arc<DaemonServices>,
        log_buffer: Arc<Mutex<LogBuffer>>,
    ) -> Self {
        Self {
            runtime,
            services,
            log_buffer,
        }
    }

    pub async fn route(
        &self,
        peer: &PeerContext,
        request_id: u64,
        request: LocalRequest,
    ) -> ResponseEnvelope {
        if !peer.role.allows(request.required_role()) {
            log!(
                "IPC authorization denied: pid={}, uid={}, role={:?}, request={:?}",
                peer.pid,
                peer.uid,
                peer.role,
                request
            );
            return ResponseEnvelope {
                request_id,
                result: ResponseResult::Error(IpcErrorCode::Unauthorized),
            };
        }

        log_command!(
            "pid={} uid={} role={:?} request={:?}",
            peer.pid,
            peer.uid,
            peer.role,
            request
        );
        let result = self.execute(request).await;
        ResponseEnvelope { request_id, result }
    }

    async fn execute(&self, request: LocalRequest) -> ResponseResult {
        if !self.services.active
            && !matches!(
                request,
                LocalRequest::GetStatus | LocalRequest::GetDaemonStatus
            )
        {
            return ResponseResult::Error(IpcErrorCode::Unauthorized);
        }
        let needs_omikron = matches!(
            request,
            LocalRequest::CreateUser { .. }
                | LocalRequest::InspectTuCredential { .. }
                | LocalRequest::AttachUserFromTu { .. }
                | LocalRequest::ReconcileUser { .. }
                | LocalRequest::ReleaseUser { .. }
                | LocalRequest::CompleteDeleteUser { .. }
                | LocalRequest::CreateInvitation {
                    authority: InvitationAuthority::Omega,
                    ..
                }
        );
        if needs_omikron && !self.services.omikron.is_connected().await {
            return ResponseResult::Error(
                if self.runtime.current_startup_phase() != StartupPhase::Ready {
                    IpcErrorCode::NotReady
                } else {
                    IpcErrorCode::OmikronUnavailable
                },
            );
        }
        match request {
            LocalRequest::GetStatus => {
                let phase = self.runtime.current_startup_phase();
                let degraded = self.runtime.degraded_reason.borrow().clone();
                let tasks: Vec<String> = self
                    .runtime
                    .state
                    .active_tasks
                    .iter()
                    .map(|task| task.to_string())
                    .collect();
                ResponseResult::Ok(ResponsePayload::Status(StatusResponse {
                    phase: format!("{:?}", phase),
                    tasks: tasks.clone(),
                    degraded_reason: degraded,
                }))
            }
            LocalRequest::ListTasks => {
                let tasks: Vec<TaskSummary> = self
                    .runtime
                    .state
                    .active_tasks
                    .iter()
                    .map(|task| TaskSummary {
                        name: task.to_string(),
                    })
                    .collect();
                ResponseResult::Ok(ResponsePayload::Tasks(tasks))
            }
            LocalRequest::ListUsers => {
                let pending = match pending_operations::get_all() {
                    Ok(operations) => operations
                        .into_iter()
                        .map(|operation| {
                            let kind = match operation.operation {
                                PendingUserOperationKind::Create => UserOperationKind::Create,
                                PendingUserOperationKind::Attach => UserOperationKind::Attach,
                                PendingUserOperationKind::Release => UserOperationKind::Release,
                                PendingUserOperationKind::Purge => UserOperationKind::Purge,
                            };
                            (
                                operation.user_id,
                                UserOperationSummary {
                                    operation: kind,
                                    phase: operation.phase.as_str().into(),
                                },
                            )
                        })
                        .collect::<std::collections::HashMap<_, _>>(),
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let users = match user_manager::get_residency() {
                    Ok(users) => users,
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                }
                .into_iter()
                .map(|user| {
                    let user_id = user.user_id;
                    let profile = user_manager::get_user(user.user_id)?;
                    Ok(UserSummary {
                        credential_status: credential_status(&user, profile.as_ref()),
                        user_id,
                        username: user.username,
                        state: match user.state {
                            user_manager::LocalUserState::Managed => {
                                iota_ipc::LocalUserState::Managed
                            }
                            user_manager::LocalUserState::Released => {
                                iota_ipc::LocalUserState::Released
                            }
                        },
                        data_present: user.data_present,
                        pending_operation: pending.get(&user_id).cloned(),
                    })
                })
                .collect::<Result<Vec<_>, iota_storage::storage_error::StorageError>>();
                let Ok(users) = users else {
                    return ResponseResult::Error(IpcErrorCode::StorageFailure);
                };
                ResponseResult::Ok(ResponsePayload::Users(users))
            }
            LocalRequest::CreateInvitation {
                authority,
                lifetime_seconds,
                password,
                label,
            } => {
                if authority == InvitationAuthority::Iota {
                    return ResponseResult::Error(IpcErrorCode::Unsupported);
                }
                if lifetime_seconds == 0 || lifetime_seconds > 7 * 24 * 60 * 60 {
                    return ResponseResult::Error(IpcErrorCode::InvalidRequest);
                }
                let password_protected = password.is_some();
                let mut request = CommunicationValue::new(CommunicationType::CreateUserInvitation)
                    .add_typed_default(
                        DataType::InvitationAuthority,
                        DataValue::Str("omega".into()),
                    )
                    .add_typed_default(
                        DataType::InvitationLifetimeSeconds,
                        DataValue::SignedNumber(lifetime_seconds.into()),
                    );
                if let Some(password) = password {
                    request = request.add_typed_default(
                        DataType::InvitationPassword,
                        DataValue::Str(password.0),
                    );
                }
                if let Some(label) = label.as_ref() {
                    request = request.add_typed_default(
                        DataType::InvitationLabel,
                        DataValue::Str(label.clone()),
                    );
                }
                let response = match self
                    .services
                    .omikron
                    .await_response(&request, Duration::from_secs(20))
                    .await
                {
                    Ok(response) => response,
                    Err(omikron_connector::OmikronError::Timeout(_)) => {
                        return ResponseResult::Error(IpcErrorCode::Timeout);
                    }
                    Err(_) => return ResponseResult::Error(IpcErrorCode::OmikronUnavailable),
                };
                let invitation_id = response
                    .get_data(DataType::InvitationId)
                    .as_signed_number()
                    .and_then(|value| i64::try_from(value).ok());
                let raw_token = response
                    .get_data(DataType::InvitationToken)
                    .as_str()
                    .map(str::to_owned);
                let expires_at = response
                    .get_data(DataType::InvitationExpiresAt)
                    .as_signed_number()
                    .and_then(|value| i64::try_from(value).ok());
                let created_at = response
                    .get_data(DataType::InvitationCreatedAt)
                    .as_signed_number()
                    .and_then(|value| i64::try_from(value).ok());
                let remote_revision = response
                    .get_data(DataType::InvitationRevision)
                    .as_signed_number()
                    .and_then(|value| i64::try_from(value).ok())
                    .unwrap_or(1);
                let short_url = response
                    .get_data(DataType::Link)
                    .as_str()
                    .map(str::to_owned);
                let Some((invitation_id, raw_token, created_at, expires_at)) = invitation_id
                    .zip(raw_token)
                    .zip(created_at)
                    .zip(expires_at)
                    .map(|(((id, token), created), expires)| (id, token, created, expires))
                else {
                    return ResponseResult::Error(IpcErrorCode::InternalFailure);
                };
                let summary = iota_storage::users::invitations::InvitationSummary {
                    invitation_id,
                    authority: iota_storage::users::invitations::InvitationAuthority::Omega,
                    label,
                    password_protected,
                    created_at,
                    expires_at: Some(expires_at),
                    state: iota_storage::users::invitations::InvitationState::Pending,
                    remote_revision,
                    redeemed_user_id: None,
                    redeemed_at: None,
                    revoked_at: None,
                    pending_action: None,
                    pending_action_at: None,
                    last_synced_at: Some(now_millis()),
                    local_provisioned_user_id: None,
                    local_provisioned_at: None,
                };
                let mirror_result =
                    iota_storage::users::invitations::insert(&summary, None, now_millis());
                ResponseResult::Ok(ResponsePayload::InvitationCreated(
                    invitation_created_after_mirror(
                        authority,
                        invitation_id,
                        raw_token,
                        expires_at,
                        short_url,
                        mirror_result,
                    ),
                ))
            }
            LocalRequest::ListInvitations { authority } => {
                if authority != Some(InvitationAuthority::Iota)
                    && self.services.omikron.is_connected().await
                {
                    match self.services.omikron.sync_omega_invitations().await {
                        Ok(()) => {}
                        Err(omikron_connector::OmikronError::Storage(_)) => {
                            return ResponseResult::Error(IpcErrorCode::StorageFailure);
                        }
                        Err(omikron_connector::OmikronError::Timeout(_)) => {
                            return ResponseResult::Error(IpcErrorCode::Timeout);
                        }
                        Err(omikron_connector::OmikronError::Disconnected(_)) => {
                            return ResponseResult::Error(IpcErrorCode::OmikronUnavailable);
                        }
                        Err(_) => return ResponseResult::Error(IpcErrorCode::InternalFailure),
                    }
                }
                if iota_storage::users::invitations::expire_pending(now_millis()).is_err() {
                    return ResponseResult::Error(IpcErrorCode::StorageFailure);
                }
                let invitations = match iota_storage::users::invitations::list() {
                    Ok(invitations) => invitations,
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let mut summaries = Vec::new();
                for invitation in invitations {
                    let invitation_authority = match invitation.authority {
                        iota_storage::users::invitations::InvitationAuthority::Omega => {
                            InvitationAuthority::Omega
                        }
                        iota_storage::users::invitations::InvitationAuthority::Iota => {
                            InvitationAuthority::Iota
                        }
                    };
                    if authority.is_some_and(|filter| filter != invitation_authority) {
                        continue;
                    }
                    let display_state = if invitation.pending_action
                        == Some(iota_storage::users::invitations::PendingAction::Revoke)
                    {
                        InvitationState::RevocationPending
                    } else if invitation.authority
                        == iota_storage::users::invitations::InvitationAuthority::Omega
                        && invitation.state
                            == iota_storage::users::invitations::InvitationState::Pending
                        && invitation
                            .expires_at
                            .is_some_and(|expires_at| expires_at <= now_millis())
                    {
                        InvitationState::Expired
                    } else {
                        match invitation.state {
                            iota_storage::users::invitations::InvitationState::Pending => {
                                InvitationState::Pending
                            }
                            iota_storage::users::invitations::InvitationState::Provisioning => {
                                InvitationState::Provisioning
                            }
                            iota_storage::users::invitations::InvitationState::Redeemed => {
                                InvitationState::Redeemed
                            }
                            iota_storage::users::invitations::InvitationState::Revoked => {
                                InvitationState::Revoked
                            }
                            iota_storage::users::invitations::InvitationState::Expired => {
                                InvitationState::Expired
                            }
                        }
                    };
                    summaries.push(InvitationSummary {
                        authority: invitation_authority,
                        invitation_id: invitation.invitation_id,
                        label: invitation.label,
                        password_protected: invitation.password_protected,
                        created_at: invitation.created_at,
                        expires_at: invitation.expires_at,
                        state: display_state,
                        redeemed_user_id: invitation.redeemed_user_id,
                        local_provisioned_user_id: invitation.local_provisioned_user_id,
                        local_provisioned_at: invitation.local_provisioned_at,
                    });
                }
                ResponseResult::Ok(ResponsePayload::Invitations(summaries))
            }
            LocalRequest::RevokeInvitation {
                authority,
                invitation_id,
            } => {
                if authority == InvitationAuthority::Iota {
                    return ResponseResult::Error(IpcErrorCode::Unsupported);
                }
                let changed = match iota_storage::users::invitations::mark_revoke_pending(
                    invitation_id,
                    now_millis(),
                ) {
                    Ok(changed) => changed,
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                if !changed {
                    return ResponseResult::Error(IpcErrorCode::Conflict);
                }
                if self.services.omikron.is_connected().await {
                    self.services
                        .omikron
                        .flush_pending_invitation_actions()
                        .await;
                }
                let invitation =
                    match iota_storage::users::invitations::list()
                        .ok()
                        .and_then(|items| {
                            items
                                .into_iter()
                                .find(|item| item.invitation_id == invitation_id)
                        }) {
                        Some(invitation) => invitation,
                        None => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                    };
                let state = if invitation.pending_action
                    == Some(iota_storage::users::invitations::PendingAction::Revoke)
                {
                    InvitationState::RevocationPending
                } else {
                    match invitation.state {
                        iota_storage::users::invitations::InvitationState::Pending => {
                            InvitationState::Pending
                        }
                        iota_storage::users::invitations::InvitationState::Provisioning => {
                            InvitationState::Provisioning
                        }
                        iota_storage::users::invitations::InvitationState::Redeemed => {
                            InvitationState::Redeemed
                        }
                        iota_storage::users::invitations::InvitationState::Revoked => {
                            InvitationState::Revoked
                        }
                        iota_storage::users::invitations::InvitationState::Expired => {
                            InvitationState::Expired
                        }
                    }
                };
                ResponseResult::Ok(ResponsePayload::InvitationUpdated(InvitationSummary {
                    authority: InvitationAuthority::Omega,
                    invitation_id,
                    label: invitation.label,
                    password_protected: invitation.password_protected,
                    created_at: invitation.created_at,
                    expires_at: invitation.expires_at,
                    state,
                    redeemed_user_id: invitation.redeemed_user_id,
                    local_provisioned_user_id: invitation.local_provisioned_user_id,
                    local_provisioned_at: invitation.local_provisioned_at,
                }))
            }
            LocalRequest::CreateUser { username } => {
                match omikron_connector::user_ops::create_user(
                    self.services.omikron.as_ref(),
                    &username,
                )
                .await
                {
                    Ok(user) => ResponseResult::Ok(ResponsePayload::UserCreated {
                        user_id: user.user_id,
                        username: user.username,
                    }),
                    Err(error) => {
                        log!("User creation failed: {error:?}");
                        match error {
                            omikron_connector::user_ops::CreateUserError::InvalidUsername => {
                                ResponseResult::Error(IpcErrorCode::InvalidRequest)
                            }
                            omikron_connector::user_ops::CreateUserError::Transport(
                                omikron_connector::OmikronError::Timeout(_),
                            ) => ResponseResult::Error(IpcErrorCode::Timeout),
                            omikron_connector::user_ops::CreateUserError::Transport(_) => {
                                ResponseResult::Error(IpcErrorCode::OmikronUnavailable)
                            }
                            omikron_connector::user_ops::CreateUserError::RemoteRejected => {
                                ResponseResult::Error(IpcErrorCode::Conflict)
                            }
                            omikron_connector::user_ops::CreateUserError::LocalFinalizationPending { .. } => {
                                ResponseResult::Error(IpcErrorCode::StorageFailure)
                            }
                            omikron_connector::user_ops::CreateUserError::LocalPersistence(_) => {
                                ResponseResult::Error(IpcErrorCode::StorageFailure)
                            }
                            omikron_connector::user_ops::CreateUserError::InvalidResponse => {
                                ResponseResult::Error(IpcErrorCode::InternalFailure)
                            }
                        }
                    }
                }
            }
            LocalRequest::PurgeUserData { user_id } => match user_manager::purge_user_data(user_id)
            {
                Ok(()) => ResponseResult::Ok(ResponsePayload::UserDataPurged { user_id }),
                Err(iota_storage::storage_error::StorageError::PendingRelayOwnershipUnknown) => {
                    log!(
                        "User data purge is waiting for pending relay ownership classification for {user_id}"
                    );
                    ResponseResult::Error(IpcErrorCode::StorageFailure)
                }
                Err(error) => {
                    log!("User data purge failed for {user_id}: {error}");
                    ResponseResult::Error(IpcErrorCode::StorageFailure)
                }
            },
            LocalRequest::AttachUserFromTu { credential } => {
                match omikron_connector::user_ops::attach_user_from_tu(
                    self.services.omikron.as_ref(),
                    &credential.0,
                )
                .await
                {
                    Ok(user) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!("Added {} ({}) to this Iota", user.username, user.user_id),
                    }),
                    Err(error) => {
                        log!("Credential attach failed: {error:?}");
                        ResponseResult::Error(IpcErrorCode::Unauthorized)
                    }
                }
            }
            LocalRequest::InspectTuCredential { credential } => {
                match omikron_connector::user_ops::inspect_tu_credential(
                    self.services.omikron.as_ref(),
                    &credential.0,
                )
                .await
                {
                    Ok(preview) => ResponseResult::Ok(ResponsePayload::TuCredentialPreview(
                        iota_ipc::TuCredentialPreview {
                            user_id: preview.user_id,
                            username: preview.username,
                            assigned_iota_id: preview.assigned_iota_id,
                        },
                    )),
                    Err(error) => {
                        log!("Credential inspection failed: {error:?}");
                        ResponseResult::Error(IpcErrorCode::Unauthorized)
                    }
                }
            }
            LocalRequest::ReconcileUser { user_id } => {
                let residency = match user_manager::get_residency_by_id(user_id) {
                    Ok(Some(residency)) => residency,
                    Ok(None) => return ResponseResult::Error(IpcErrorCode::NotFound),
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let omega_iota_id = match omikron_connector::user_ops::get_remote_user_assignment(
                    self.services.omikron.as_ref(),
                    user_id,
                )
                .await
                {
                    Ok(assignment) => assignment,
                    Err(error) => {
                        log!("User reconciliation failed for {user_id}: {error:?}");
                        return ResponseResult::Error(IpcErrorCode::OmikronUnavailable);
                    }
                };
                let local_iota_id = config_util::CONFIG
                    .load()
                    .iota_id
                    .and_then(|id| i64::try_from(id).ok());
                let action = if residency.state == user_manager::LocalUserState::Managed
                    && omega_iota_id != local_iota_id
                {
                    match user_manager::finalize_local_release(user_id, Some(&residency.username)) {
                        Ok(()) => ReconcileAction::ReleasedLocally,
                        Err(error) => {
                            log!("User reconciliation cleanup failed for {user_id}: {error}");
                            return ResponseResult::Error(IpcErrorCode::StorageFailure);
                        }
                    }
                } else {
                    ReconcileAction::None
                };
                ResponseResult::Ok(ResponsePayload::UserReconciled(UserReconcileResult {
                    user_id,
                    local_state: match residency.state {
                        user_manager::LocalUserState::Managed => iota_ipc::LocalUserState::Managed,
                        user_manager::LocalUserState::Released => {
                            iota_ipc::LocalUserState::Released
                        }
                    },
                    omega_iota_id,
                    action,
                }))
            }
            LocalRequest::ForceDetachUser { user_id } => {
                match user_manager::force_local_detach(user_id) {
                    Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!(
                            "Force-detached user {user_id} locally; Omega was not changed"
                        ),
                    }),
                    Err(error) => {
                        log!("Force local detach failed for {user_id}: {error}");
                        ResponseResult::Error(IpcErrorCode::StorageFailure)
                    }
                }
            }
            LocalRequest::ForgetReleasedUser { user_id } => {
                match user_manager::forget_released_user(user_id) {
                    Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!("Forgot released user residency {user_id}"),
                    }),
                    Err(error) => {
                        log!("Forget residency failed for {user_id}: {error}");
                        ResponseResult::Error(IpcErrorCode::Conflict)
                    }
                }
            }
            LocalRequest::GetUserDiagnostics { user_id } => {
                let residency = match user_manager::get_residency_by_id(user_id) {
                    Ok(Some(residency)) => residency,
                    Ok(None) => return ResponseResult::Error(IpcErrorCode::NotFound),
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let profile = match user_manager::get_user(user_id) {
                    Ok(profile) => profile,
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let pending_operation = match pending_operations::get_all() {
                    Ok(operations) => operations
                        .into_iter()
                        .find(|operation| operation.user_id == user_id)
                        .map(|operation| {
                            format!(
                                "{}/{}",
                                operation.operation.as_str(),
                                operation.phase.as_str()
                            )
                        }),
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let credential_status = credential_status(&residency, profile.as_ref());
                ResponseResult::Ok(ResponsePayload::UserDiagnostics(UserDiagnostics {
                    user_id,
                    username: residency.username,
                    local_state: match residency.state {
                        user_manager::LocalUserState::Managed => iota_ipc::LocalUserState::Managed,
                        user_manager::LocalUserState::Released => {
                            iota_ipc::LocalUserState::Released
                        }
                    },
                    data_present: residency.data_present,
                    credential_status,
                    trusted_app_count: profile
                        .as_ref()
                        .map_or(0, |profile| profile.trusted_apps.len()),
                    pending_operation,
                }))
            }
            LocalRequest::RevokeTrustedApp { user_id, app_id } => {
                match user_manager::revoke_trusted_app(user_id, &app_id) {
                    Ok(true) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!("Revoked trusted application {app_id} for user {user_id}"),
                    }),
                    Ok(false) => ResponseResult::Error(IpcErrorCode::NotFound),
                    Err(error) => {
                        log!("Trusted application revocation failed for {user_id}: {error}");
                        ResponseResult::Error(IpcErrorCode::StorageFailure)
                    }
                }
            }
            LocalRequest::RevokeAllTrustedApps { user_id } => {
                match user_manager::revoke_all_trusted_apps(user_id) {
                    Ok(removed) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!(
                            "Revoked {removed} trusted applications for user {user_id}"
                        ),
                    }),
                    Err(error) => {
                        log!("Trusted application revocation failed for {user_id}: {error}");
                        ResponseResult::Error(IpcErrorCode::StorageFailure)
                    }
                }
            }
            LocalRequest::CompleteDeleteUser {
                user_id,
                credential,
            } => {
                let contents = match credential {
                    Some(value) => Ok(value.0),
                    None => user_manager::get_user(user_id)
                        .map_err(|_| ())
                        .and_then(|user| user.ok_or(()))
                        .and_then(|user| {
                            iota_util::file_util::read_user_credential_with_legacy(
                                user_id,
                                &user.username,
                            )
                            .map_err(|_| ())
                        })
                        .and_then(|value| value.ok_or(())),
                };
                let Ok(contents) = contents else {
                    return ResponseResult::Error(IpcErrorCode::Unauthorized);
                };
                match omikron_connector::user_ops::complete_delete_user_with_tu(
                    self.services.omikron.as_ref(),
                    &contents,
                    user_id,
                )
                .await
                {
                    Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!("Deleted Tensamin account {user_id}"),
                    }),
                    Err(error) => {
                        log!("Credential deletion failed for {user_id}: {error:?}");
                        ResponseResult::Error(IpcErrorCode::Unauthorized)
                    }
                }
            }
            LocalRequest::RemoveUser { .. } => ResponseResult::Error(IpcErrorCode::InvalidRequest),
            LocalRequest::ReleaseUser { user_id } => {
                let user = match user_manager::get_user(user_id) {
                    Ok(user) => user,
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let Some(user) = user else {
                    return ResponseResult::Error(IpcErrorCode::NotFound);
                };
                if pending_operations::upsert(&PendingUserOperation {
                    user_id,
                    operation: PendingUserOperationKind::Release,
                    username: user.username,
                    public_key: None,
                    private_key_hash: None,
                    reset_token: None,
                    registration_token: None,
                    phase: PendingUserOperationPhase::Prepared,
                    created_at: now_millis(),
                })
                .is_err()
                {
                    return ResponseResult::Error(IpcErrorCode::StorageFailure);
                }
                let request = CommunicationValue::new(CommunicationType::ReleaseUserFromIota)
                    .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
                match self
                    .services
                    .omikron
                    .await_response(&request, Duration::from_secs(20))
                    .await
                {
                    Ok(response) if response.is_type(CommunicationType::Success) => {
                        match user_manager::release_user(user_id) {
                            Ok(()) if pending_operations::remove(user_id).is_ok() => {
                                ResponseResult::Ok(ResponsePayload::Acknowledged {
                                    message: format!(
                                        "Released user {user_id}; hosted data was retained"
                                    ),
                                })
                            }
                            Ok(()) => ResponseResult::Error(IpcErrorCode::StorageFailure),
                            Err(error) => {
                                log!(
                                    "Remote release succeeded but local cleanup failed for {user_id}: {error}"
                                );
                                ResponseResult::Error(IpcErrorCode::StorageFailure)
                            }
                        }
                    }
                    Ok(response) if response.is_type(CommunicationType::ErrorNotAuthenticated) => {
                        let _ = pending_operations::remove(user_id);
                        ResponseResult::Error(IpcErrorCode::Unauthorized)
                    }
                    Ok(_) => {
                        let _ = pending_operations::remove(user_id);
                        ResponseResult::Error(IpcErrorCode::Conflict)
                    }
                    Err(omikron_connector::OmikronError::Timeout(_)) => {
                        ResponseResult::Error(IpcErrorCode::Timeout)
                    }
                    Err(_) => ResponseResult::Error(IpcErrorCode::OmikronUnavailable),
                }
            }
            LocalRequest::ReconnectOmikron => match self.services.omikron.reconnect().await {
                Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                    message: "Reconnected to Omikron server".into(),
                }),
                Err(_) => ResponseResult::Error(IpcErrorCode::OmikronUnavailable),
            },
            LocalRequest::RotateIotaIdentity => {
                match self.services.omikron.rotate_identity().await {
                    Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: "New identity registered with Omikron".into(),
                    }),
                    Err(error) => {
                        log!("Iota identity rotation failed: {}", error);
                        ResponseResult::Error(IpcErrorCode::OmikronUnavailable)
                    }
                }
            }
            LocalRequest::RequestProcessExit { intent } => {
                if matches!(intent, ExitIntent::Restart)
                    && !matches!(
                        crate::deployment::from_environment().supervisor,
                        iota_ipc::SupervisorKind::Systemd | iota_ipc::SupervisorKind::IotaUi
                    )
                {
                    return ResponseResult::Error(IpcErrorCode::Conflict);
                }
                self.runtime.request_shutdown(match intent {
                    ExitIntent::Stop => ShutdownReason::Stop,
                    ExitIntent::Restart => ShutdownReason::Restart,
                });
                ResponseResult::Ok(ResponsePayload::Acknowledged {
                    message: "process exit accepted".into(),
                })
            }
            LocalRequest::GetDaemonStatus => ResponseResult::Ok(ResponsePayload::DaemonStatus(
                iota_ipc::DaemonStatusResponse {
                    formatted: format!("{:?}", self.runtime.snapshot()),
                },
            )),
            LocalRequest::RestartDaemon => {
                self.runtime.request_shutdown(ShutdownReason::Restart);
                ResponseResult::Ok(ResponsePayload::Acknowledged {
                    message: "Daemon restart requested".into(),
                })
            }
            LocalRequest::StopDaemon => {
                self.runtime.request_shutdown(ShutdownReason::Stop);
                ResponseResult::Ok(ResponsePayload::Acknowledged {
                    message: "Daemon shutdown requested".into(),
                })
            }
            LocalRequest::GetConfig => {
                let cfg = config_util::CONFIG.load();
                let yaml = serde_yaml::to_string(&**cfg).unwrap_or_default();
                ResponseResult::Ok(ResponsePayload::Config(ConfigResponse { yaml }))
            }
            LocalRequest::SetConfig { key, value } => {
                match config_util::modify_config_value(&key, &value) {
                    Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!("Set {key} = {value}"),
                    }),
                    Err(_e) => ResponseResult::Error(IpcErrorCode::InvalidRequest),
                }
            }
            LocalRequest::ReloadConfig => match config_util::load_config() {
                Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                    message: "Configuration reloaded".into(),
                }),
                Err(_) => ResponseResult::Error(IpcErrorCode::InvalidRequest),
            },
            LocalRequest::GetOmikronStatus => {
                let connected = self.services.omikron.is_connected().await;
                let iota_id = config_util::CONFIG.load().iota_id;
                ResponseResult::Ok(ResponsePayload::OmikronStatus(OmikronStatusResponse {
                    connected,
                    iota_id,
                }))
            }
            LocalRequest::ListComponents => {
                let snapshot = self.runtime.snapshot();
                let components: Vec<ComponentStatusResponse> = snapshot
                    .components
                    .into_iter()
                    .map(|(id, health)| ComponentStatusResponse {
                        id,
                        status: health.status,
                        message: health.message,
                    })
                    .collect();
                ResponseResult::Ok(ResponsePayload::Components(components))
            }
            LocalRequest::GetUser { user_id } => {
                let residency = match user_manager::get_residency_by_id(user_id) {
                    Ok(Some(residency)) => residency,
                    Ok(None) => return ResponseResult::Error(IpcErrorCode::NotFound),
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                match user_manager::get_user(user_id) {
                    Ok(Some(user)) => {
                        let credential_status = credential_status(&residency, Some(&user));
                        ResponseResult::Ok(ResponsePayload::UserDetail(UserDetailResponse {
                            user_id: user.user_id,
                            username: user.username,
                            display_name: user.display_name,
                            created_at: user.created_at,
                            trusted_apps: user.trusted_apps.keys().cloned().collect(),
                            state: iota_ipc::LocalUserState::Managed,
                            data_present: residency.data_present,
                            credential_status,
                        }))
                    }
                    Ok(None) if residency.state == user_manager::LocalUserState::Released => {
                        ResponseResult::Ok(ResponsePayload::UserDetail(UserDetailResponse {
                            user_id: residency.user_id,
                            username: residency.username,
                            display_name: None,
                            created_at: 0,
                            trusted_apps: Vec::new(),
                            state: iota_ipc::LocalUserState::Released,
                            data_present: residency.data_present,
                            credential_status: iota_ipc::CredentialStatus::None,
                        }))
                    }
                    Ok(None) => ResponseResult::Error(IpcErrorCode::StorageFailure),
                    Err(_) => ResponseResult::Error(IpcErrorCode::StorageFailure),
                }
            }
            LocalRequest::ExportUserCredential { user_id } => {
                let residency = match user_manager::get_residency_by_id(user_id) {
                    Ok(Some(residency)) => residency,
                    Ok(None) => return ResponseResult::Error(IpcErrorCode::NotFound),
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                if residency.state != user_manager::LocalUserState::Managed
                    || residency.credential_origin != user_manager::CredentialOrigin::Local
                {
                    return ResponseResult::Error(IpcErrorCode::Conflict);
                }
                let credential = match iota_util::file_util::read_user_credential_with_legacy(
                    user_id,
                    &residency.username,
                ) {
                    Ok(Some(credential)) => credential,
                    Ok(None) => return ResponseResult::Error(IpcErrorCode::NotFound),
                    Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                let parsed = match iota_util::tu::TuCredential::parse(&credential) {
                    Ok(parsed) if parsed.user_id == user_id => parsed,
                    Ok(_) | Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                };
                ResponseResult::Ok(ResponsePayload::UserCredentialExport {
                    user_id,
                    username: residency.username,
                    credential: iota_ipc::SecretString(parsed.to_canonical_string()),
                })
            }
            LocalRequest::ImportUser { .. } => ResponseResult::Error(IpcErrorCode::InvalidRequest),
            LocalRequest::GetLogs { limit } => {
                let entries = if let Ok(buf) = self.log_buffer.lock() {
                    bounded_log_entries(buf.recent(limit.min(MAX_LOG_ENTRIES_PER_RESPONSE)))
                } else {
                    Vec::new()
                };
                ResponseResult::Ok(ResponsePayload::LogEntries(LogEntriesResponse { entries }))
            }
            LocalRequest::CheckUpdate => match iota_updater::check_update().await {
                Ok(available) => {
                    ResponseResult::Ok(ResponsePayload::UpdateStatus(UpdateStatusResponse {
                        available,
                    }))
                }
                Err(_e) => ResponseResult::Error(IpcErrorCode::InternalFailure),
            },
            LocalRequest::ListCommunities => {
                let iota_id = config_util::CONFIG.load().iota_id;
                let Ok(iota_id) = iota_id.map(i64::try_from).unwrap_or(Ok(0)) else {
                    return ResponseResult::Ok(ResponsePayload::Communities(Vec::new()));
                };
                let stored =
                    match iota_storage::util::communities_util::CommunitiesUtil::get_communities(
                        iota_id,
                    ) {
                        Ok(stored) => stored,
                        Err(_) => return ResponseResult::Error(IpcErrorCode::StorageFailure),
                    };
                let summaries: Vec<CommunitySummary> = stored
                    .into_iter()
                    .map(|c| CommunitySummary {
                        name: c.address,
                        title: c.title,
                    })
                    .collect();
                ResponseResult::Ok(ResponsePayload::Communities(summaries))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InvitationAuthority, IpcRole, LocalRequest, bounded_log_entries,
        invitation_created_after_mirror,
    };
    use iota_ipc::{ExitIntent, LogEntry, SecretString};

    #[test]
    fn every_request_has_an_explicit_role_policy() {
        let requests = [
            LocalRequest::GetStatus,
            LocalRequest::ListTasks,
            LocalRequest::ListUsers,
            LocalRequest::CreateUser {
                username: "alice".into(),
            },
            LocalRequest::AttachUserFromTu {
                credential: SecretString("credential".into()),
            },
            LocalRequest::InspectTuCredential {
                credential: SecretString("credential".into()),
            },
            LocalRequest::ReconcileUser { user_id: 1 },
            LocalRequest::ForceDetachUser { user_id: 1 },
            LocalRequest::ForgetReleasedUser { user_id: 1 },
            LocalRequest::GetUserDiagnostics { user_id: 1 },
            LocalRequest::RevokeTrustedApp {
                user_id: 1,
                app_id: "desktop".into(),
            },
            LocalRequest::RevokeAllTrustedApps { user_id: 1 },
            LocalRequest::ExportUserCredential { user_id: 1 },
            LocalRequest::PurgeUserData { user_id: 1 },
            LocalRequest::ReleaseUser { user_id: 1 },
            LocalRequest::CompleteDeleteUser {
                user_id: 1,
                credential: None,
            },
            LocalRequest::RemoveUser { user_id: 1 },
            LocalRequest::ReconnectOmikron,
            LocalRequest::RotateIotaIdentity,
            LocalRequest::RequestProcessExit {
                intent: ExitIntent::Stop,
            },
            LocalRequest::GetDaemonStatus,
            LocalRequest::RestartDaemon,
            LocalRequest::StopDaemon,
            LocalRequest::GetConfig,
            LocalRequest::SetConfig {
                key: "port".into(),
                value: "1984".into(),
            },
            LocalRequest::ReloadConfig,
            LocalRequest::GetOmikronStatus,
            LocalRequest::ListComponents,
            LocalRequest::GetUser { user_id: 1 },
            LocalRequest::ImportUser {
                username: "alice".into(),
            },
            LocalRequest::GetLogs { limit: 10 },
            LocalRequest::CheckUpdate,
            LocalRequest::ListCommunities,
        ];

        assert_eq!(requests.len(), 33);
        for request in requests {
            let required = request.required_role();
            assert!(IpcRole::Admin.allows(required));
            assert_eq!(
                IpcRole::Operate.allows(required),
                required != IpcRole::Admin
            );
            assert_eq!(IpcRole::Read.allows(required), required == IpcRole::Read);
        }
    }

    #[test]
    fn log_responses_drop_entries_that_cannot_fit_one_ipc_frame() {
        let entries = vec![LogEntry {
            timestamp_ms: 0,
            sender: "test".into(),
            message: "x".repeat(2 * 1024 * 1024),
            is_error: false,
        }];

        assert!(bounded_log_entries(entries).is_empty());
    }

    #[test]
    fn omega_creation_credentials_survive_a_local_mirror_failure() {
        let created = invitation_created_after_mirror(
            InvitationAuthority::Omega,
            7,
            "raw-token".into(),
            99,
            Some("https://omega/direct/short".into()),
            Err(iota_storage::storage_error::StorageError::Other(
                "injected mirror failure".into(),
            )),
        );

        assert_eq!(created.raw_token.0, "raw-token");
        assert_eq!(
            created.short_url.as_deref(),
            Some("https://omega/direct/short")
        );
        assert!(!created.mirror_synced);
    }
}
