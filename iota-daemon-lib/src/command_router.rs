use crate::DaemonRuntime;
use iota_ipc::{
    IpcErrorCode, LocalRequest, ResponseEnvelope, ResponseResult,
};
use iota_logger::{log, log_command};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::modify_config;
use mtp::codec::{CommunicationType, CommunicationValue};
use omikron_connector::omikron_connection::OMIKRON_CONNECTION;
use std::sync::Arc;
use std::time::Duration;

use crate::daemon_state::ShutdownReason;

#[derive(Clone)]
pub struct CommandRouter {
    runtime: Arc<DaemonRuntime>,
}

impl CommandRouter {
    pub fn new(runtime: Arc<DaemonRuntime>) -> Self {
        Self { runtime }
    }

    pub async fn route(&self, request_id: u64, request: LocalRequest) -> ResponseEnvelope {
        log_command!("{:?}", request);
        let result = self.execute(request).await;
        ResponseEnvelope {
            request_id,
            result,
        }
    }

    /// Parse a legacy console command string into a typed request.
    pub fn parse_console_command(line: &str) -> Option<LocalRequest> {
        let parts: Vec<&str> = line
            .trim_start_matches('/')
            .split_whitespace()
            .collect();
        match parts.as_slice() {
            ["help"] => None,
            ["tasks"] => Some(LocalRequest::ListTasks),
            ["ping", _] | ["ping"] => None,
            ["user", "add", username] => Some(LocalRequest::CreateUser {
                username: username.to_string(),
            }),
            ["user", "remove", username] => {
                let user = user_manager::get_user_by_username(username)?;
                Some(LocalRequest::RemoveUser {
                    user_id: user.user_id,
                })
            }
            ["user", "list"] => Some(LocalRequest::ListUsers),
            ["reconnect"] => Some(LocalRequest::ReconnectOmikron),
            ["regenerate", "keys"] => Some(LocalRequest::RotateIotaIdentity),
            ["reload"] | ["restart"] => Some(LocalRequest::RestartDaemon),
            ["shutdown"] | ["stop"] => Some(LocalRequest::StopDaemon),
            _ => None,
        }
    }

    async fn execute(&self, request: LocalRequest) -> ResponseResult {
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
                let mut info = format!("Phase: {:?}, Tasks: {}", phase, tasks.join(", "));
                if let Some(reason) = degraded {
                    info.push_str(&format!(", Degraded: {}", reason));
                }
                ResponseResult::Ok(info)
            }
            LocalRequest::ListTasks => {
                let tasks: Vec<String> = self
                    .runtime
                    .state
                    .active_tasks
                    .iter()
                    .map(|task| task.to_string())
                    .collect();
                ResponseResult::Ok(tasks.join(", "))
            }
            LocalRequest::ListUsers => {
                let users: Vec<String> = user_manager::get_users()
                    .into_iter()
                    .map(|user| format!("{} ({})", user.username, user.user_id))
                    .collect();
                ResponseResult::Ok(users.join("\n"))
            }
            LocalRequest::CreateUser { username } => {
                match omikron_connector::user_ops::create_user(&username).await {
                    (Some(user), _) => {
                        ResponseResult::Ok(format!("Created user {}", user.user_id))
                    }
                    _ => ResponseResult::Error(IpcErrorCode::StorageFailure),
                }
            }
            LocalRequest::RemoveUser { user_id } => {
                let user = match user_manager::get_user(user_id) {
                    Some(user) => user,
                    None => return ResponseResult::Error(IpcErrorCode::NotFound),
                };
                let message = CommunicationValue::new(CommunicationType::DeleteUser)
                    .with_sender(user.user_id as u64);
                if let Err(_e) = OMIKRON_CONNECTION.send_message(&message).await {
                    return ResponseResult::Error(IpcErrorCode::OmikronUnavailable);
                }
                user_manager::remove_user(user.user_id);
                ResponseResult::Ok(format!("Removed user {}", user.user_id))
            }
            LocalRequest::ReconnectOmikron => {
                OMIKRON_CONNECTION.reconnect().await;
                ResponseResult::Ok("Reconnected to Omikron server".into())
            }
            LocalRequest::RotateIotaIdentity => {
                modify_config(|config| {
                    config.public_key = None;
                    config.private_key = None;
                    config.iota_id = None;
                });
                OMIKRON_CONNECTION.reconnect().await;
                ResponseResult::Ok("Key pair regenerated and Omikron reconnection requested".into())
            }
            LocalRequest::RestartDaemon => {
                self.runtime.shutdown(ShutdownReason::Restart);
                ResponseResult::Ok("Daemon restart requested".into())
            }
            LocalRequest::StopDaemon => {
                self.runtime.shutdown(ShutdownReason::Stop);
                ResponseResult::Ok("Daemon shutdown requested".into())
            }
        }
    }

    pub async fn ping(&self, seconds: u64) -> Result<String, String> {
        let response = OMIKRON_CONNECTION
            .await_response(
                &CommunicationValue::new(CommunicationType::Ping),
                Some(Duration::from_secs(seconds)),
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
