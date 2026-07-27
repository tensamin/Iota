use crate::log_buffer::LogBuffer;
use crate::{DaemonRuntime, DaemonServices};
use iota_ipc::{
    CommunitySummary, ComponentStatusResponse, ConfigResponse, ExitIntent, IpcErrorCode,
    LocalRequest, LogEntriesResponse, OmikronStatusResponse, ResponseEnvelope, ResponsePayload,
    ResponseResult, StatusResponse, TaskSummary, UpdateStatusResponse, UserDetailResponse,
    UserSummary,
};
use iota_logger::{log, log_command};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::{self};
use mtp::codec::{CommunicationType, CommunicationValue};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::daemon_state::{ShutdownReason, StartupPhase};

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

    pub async fn route(&self, request_id: u64, request: LocalRequest) -> ResponseEnvelope {
        log_command!("{:?}", request);
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
            LocalRequest::CreateUser { .. } | LocalRequest::RemoveUser { .. }
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
                let users: Vec<UserSummary> = user_manager::get_users()
                    .into_iter()
                    .map(|user| UserSummary {
                        user_id: user.user_id,
                        username: user.username,
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
            LocalRequest::RemoveUser { user_id } => {
                let user = match user_manager::get_user(user_id) {
                    Some(user) => user,
                    None => return ResponseResult::Error(IpcErrorCode::NotFound),
                };
                let message = CommunicationValue::new(CommunicationType::DeleteUser)
                    .with_sender(user.user_id as u64);
                if let Err(_e) = self.services.omikron.send_message(&message).await {
                    return ResponseResult::Error(IpcErrorCode::OmikronUnavailable);
                }
                user_manager::remove_user(user.user_id);
                ResponseResult::Ok(ResponsePayload::UserRemoved { user_id })
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
                self.runtime.shutdown(match intent {
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
                self.runtime.shutdown(ShutdownReason::Restart);
                ResponseResult::Ok(ResponsePayload::Acknowledged {
                    message: "Daemon restart requested".into(),
                })
            }
            LocalRequest::StopDaemon => {
                self.runtime.shutdown(ShutdownReason::Stop);
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
                Some(user) => ResponseResult::Ok(ResponsePayload::UserDetail(UserDetailResponse {
                    user_id: user.user_id,
                    username: user.username,
                    display_name: user.display_name,
                    created_at: user.created_at,
                    trusted_apps: user.trusted_apps.keys().cloned().collect(),
                })),
                None => ResponseResult::Error(IpcErrorCode::NotFound),
            },
            LocalRequest::ImportUser { username } => {
                match user_manager::load_from_tu(&username).await {
                    Ok(()) => ResponseResult::Ok(ResponsePayload::Acknowledged {
                        message: format!("Imported user {username}"),
                    }),
                    Err(()) => ResponseResult::Error(IpcErrorCode::StorageFailure),
                }
            }
            LocalRequest::GetLogs { limit } => {
                let entries = if let Ok(buf) = self.log_buffer.lock() {
                    buf.recent(limit)
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
                let iota_id = config_util::CONFIG
                    .load()
                    .iota_id
                    .map(|id| id as i64)
                    .unwrap_or(0);
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

    pub async fn ping(&self, seconds: u64) -> Result<String, String> {
        let response = self
            .services
            .omikron
            .await_response(
                &CommunicationValue::new(CommunicationType::Ping),
                Duration::from_secs(seconds),
            )
            .await;
        match response {
            Ok(value) => {
                log!("{}", iota_logger::format_cv(&value));
                Ok("Ping response received".into())
            }
            Err(error) => Err(format!("Ping error: {error:?}")),
        }
    }
}
