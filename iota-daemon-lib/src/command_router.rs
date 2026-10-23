mod commands;
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
use iota_logger::{LogLevel, PrintType, log, log_command, log_event};
use iota_storage::users::pending_operations::{self, PendingUserOperationKind};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::{self};
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::accounts::{AccountError, CreateUserRequest};
use crate::daemon_state::{ShutdownReason, StartupPhase};
use iota_identity::LocalUserId;

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
    request_id: u64,
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
            log_event!(
                PrintType::Command,
                LogLevel::Error,
                "invitation.mirror_store_failed",
                "request_id={} invitation_id={} error={}",
                request_id,
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
            log_event!(
                PrintType::Command,
                LogLevel::Warn,
                "ipc.authorization_denied",
                "request_id={} pid={} uid={} role={:?} request={}",
                request_id,
                peer.pid,
                peer.uid,
                peer.role,
                request.log_name()
            );
            return ResponseEnvelope {
                request_id,
                result: ResponseResult::Error(IpcErrorCode::Unauthorized),
            };
        }

        log_command!(
            "request_id={} pid={} uid={} role={:?} request={}",
            request_id,
            peer.pid,
            peer.uid,
            peer.role,
            request.log_name()
        );
        let result = self.execute(request_id, request).await;
        ResponseEnvelope { request_id, result }
    }
}

#[cfg(test)]
mod tests;
