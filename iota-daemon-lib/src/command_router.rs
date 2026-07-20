use crate::DaemonRuntime;
use iota_ipc::DaemonMessage;
use iota_logger::{log, log_command};
use iota_storage::users::user_manager;
use iota_storage::util::config_util::modify_config;
use mtp::codec::{CommunicationType, CommunicationValue};
use omikron_connector::omikron_connection::OMIKRON_CONNECTION;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct CommandRouter {
    runtime: Arc<DaemonRuntime>,
}

impl CommandRouter {
    pub fn new(runtime: Arc<DaemonRuntime>) -> Self {
        Self { runtime }
    }

    pub async fn route(&self, seq: u64, line: String) -> DaemonMessage {
        log_command!("{}", line);
        let result = self.execute(&line).await;
        DaemonMessage::CommandResult {
            seq,
            success: result.is_ok(),
            message: result.unwrap_or_else(|error| error),
        }
    }

    async fn execute(&self, line: &str) -> Result<String, String> {
        let parts = line
            .trim_start_matches('/')
            .split_whitespace()
            .collect::<Vec<_>>();
        match parts.as_slice() {
            ["tasks"] => Ok(self
                .runtime
                .state
                .active_tasks
                .iter()
                .map(|task| task.to_string())
                .collect::<Vec<_>>()
                .join(", ")),
            ["help"] => Ok(
                "Available commands: tasks, ping, user, reconnect, regenerate, reload, shutdown"
                    .into(),
            ),
            ["ping"] => self.ping(20).await,
            ["ping", seconds] => self.ping(seconds.parse::<u64>().unwrap_or(20)).await,
            ["user", "add", username] => {
                let (user, _) = omikron_connector::user_ops::create_user(username).await;
                user.map(|user| format!("Created user {}", user.user_id))
                    .ok_or_else(|| "User creation failed".into())
            }
            ["user", "remove", username] => {
                let user = user_manager::get_user_by_username(username)
                    .ok_or_else(|| "Username does not exist".to_string())?;
                let message = CommunicationValue::new(CommunicationType::DeleteUser)
                    .with_sender(user.user_id as u64);
                OMIKRON_CONNECTION
                    .send_message(&message)
                    .await
                    .map_err(|error| error.to_string())?;
                user_manager::remove_user(user.user_id);
                Ok(format!("Removed user {}", user.user_id))
            }
            ["user", "list"] => Ok(user_manager::get_users()
                .into_iter()
                .map(|user| format!("{} ({})", user.username, user.user_id))
                .collect::<Vec<_>>()
                .join("\n")),
            ["reconnect"] => {
                OMIKRON_CONNECTION.reconnect().await;
                Ok("Reconnected to Omikron server".into())
            }
            ["regenerate", "keys"] => {
                modify_config(|config| {
                    config.public_key = None;
                    config.private_key = None;
                    config.iota_id = None;
                });
                OMIKRON_CONNECTION.reconnect().await;
                Ok("Key pair regenerated and Omikron reconnection requested".into())
            }
            ["reload"] | ["restart"] => {
                *self.runtime.state.reload.write().await = true;
                *self.runtime.state.shutdown.write().await = true;
                Ok("Daemon restart requested".into())
            }
            ["shutdown"] | ["stop"] => {
                *self.runtime.state.shutdown.write().await = true;
                Ok("Daemon shutdown requested".into())
            }
            _ => Err("Unknown command".into()),
        }
    }

    async fn ping(&self, seconds: u64) -> Result<String, String> {
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
