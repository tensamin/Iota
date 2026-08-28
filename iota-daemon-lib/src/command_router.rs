use crate::log_buffer::LogBuffer;
use crate::{DaemonRuntime, DaemonServices};
use iota_ipc::{
    CommunitySummary, ComponentStatusResponse, ConfigResponse, DaemonMessage, ExitIntent,
    IpcErrorCode, LocalRequest, LogEntriesResponse, LogEntry, MAX_MESSAGE_SIZE,
    OmikronStatusResponse, ResponseEnvelope, ResponsePayload, ResponseResult, StatusResponse,
    TaskSummary, UpdateStatusResponse, UserDetailResponse, UserSummary,
};
use iota_logger::{log, log_command};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::{self};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::daemon_state::{ShutdownReason, StartupPhase};

pub use iota_ipc::IpcRole;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerContext {
    pub pid: i32,
    pub uid: u32,
    pub role: IpcRole,
}

const MAX_LOG_ENTRIES_PER_RESPONSE: usize = 512;

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
                | LocalRequest::AttachUserFromTu { .. }
                | LocalRequest::ReleaseUser { .. }
                | LocalRequest::CompleteDeleteUser { .. }
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
                let users: Vec<UserSummary> = user_manager::get_residency()
                    .into_iter()
                    .map(|user| UserSummary {
                        credential_present: user.state == user_manager::LocalUserState::Managed
                            && user_manager::get_user(user.user_id).is_some_and(|profile| {
                                iota_util::file_util::read_user_credential_with_legacy(
                                    user.user_id,
                                    &profile.username,
                                )
                                .ok()
                                .flatten()
                                .is_some()
                            }),
                        user_id: user.user_id,
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
                    })
                    .collect();
                ResponseResult::Ok(ResponsePayload::Users(users))
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
            LocalRequest::CompleteDeleteUser {
                user_id,
                credential,
            } => {
                let contents = match credential {
                    Some(value) => Ok(value.0),
                    None => user_manager::get_user(user_id)
                        .ok_or(())
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
                if user_manager::get_user(user_id).is_none() {
                    return ResponseResult::Error(IpcErrorCode::NotFound);
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
                            Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                                message: format!(
                                    "Released user {user_id}; hosted data was retained"
                                ),
                            }),
                            Err(error) => {
                                log!(
                                    "Remote release succeeded but local cleanup failed for {user_id}: {error}"
                                );
                                ResponseResult::Error(IpcErrorCode::StorageFailure)
                            }
                        }
                    }
                    Ok(response) if response.is_type(CommunicationType::ErrorNotAuthenticated) => {
                        ResponseResult::Error(IpcErrorCode::Unauthorized)
                    }
                    Ok(_) => ResponseResult::Error(IpcErrorCode::Conflict),
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
            LocalRequest::ReloadConfig => {
                config_util::load_config();
                ResponseResult::Ok(ResponsePayload::Acknowledged {
                    message: "Configuration reloaded".into(),
                })
            }
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
            LocalRequest::GetUser { user_id } => match user_manager::get_user(user_id) {
                Some(user) => {
                    let credential_present =
                        iota_util::file_util::read_user_credential_with_legacy(
                            user_id,
                            &user.username,
                        )
                        .ok()
                        .flatten()
                        .is_some();
                    ResponseResult::Ok(ResponsePayload::UserDetail(UserDetailResponse {
                        user_id: user.user_id,
                        username: user.username,
                        display_name: user.display_name,
                        created_at: user.created_at,
                        trusted_apps: user.trusted_apps.keys().cloned().collect(),
                        state: iota_ipc::LocalUserState::Managed,
                        data_present: user_manager::get_residency()
                            .iter()
                            .find(|entry| entry.user_id == user_id)
                            .is_none_or(|entry| entry.data_present),
                        credential_present,
                    }))
                }
                None => ResponseResult::Error(IpcErrorCode::NotFound),
            },
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
                    iota_storage::util::communities_util::CommunitiesUtil::get_communities(iota_id);
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
    use super::{IpcRole, LocalRequest, bounded_log_entries};
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

        assert_eq!(requests.len(), 25);
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
}
