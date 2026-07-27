use async_trait::async_trait;
use mtp::codec::CommunicationValue;
use omikron_connector::{OmikronClient, OmikronConnection, OmikronError};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
pub struct UserService;
#[derive(Default)]
pub struct ConfigService;

pub struct DaemonServices {
    pub omikron: Arc<dyn OmikronClient>,
    pub users: Arc<UserService>,
    pub config: Arc<ConfigService>,
    pub active: bool,
}

impl DaemonServices {
    pub fn new(omikron: Arc<OmikronConnection>) -> Arc<Self> {
        Arc::new(Self {
            omikron,
            users: Arc::new(UserService),
            config: Arc::new(ConfigService),
            active: true,
        })
    }

    /// Services used while the daemon is awaiting terms acceptance. They can
    /// never initiate a connection; the command router exposes status only.
    pub fn inactive() -> Arc<Self> {
        Arc::new(Self {
            omikron: Arc::new(InactiveOmikron),
            users: Arc::new(UserService),
            config: Arc::new(ConfigService),
            active: false,
        })
    }
}

struct InactiveOmikron;

#[async_trait]
impl OmikronClient for InactiveOmikron {
    async fn send_message(&self, _: &CommunicationValue) -> Result<(), OmikronError> {
        Err(OmikronError::Disconnected(
            "terms have not been accepted".into(),
        ))
    }
    async fn await_response(
        &self,
        _: &CommunicationValue,
        _: Duration,
    ) -> Result<CommunicationValue, OmikronError> {
        Err(OmikronError::Disconnected(
            "terms have not been accepted".into(),
        ))
    }
    async fn reconnect(&self) -> Result<(), OmikronError> {
        Err(OmikronError::Disconnected(
            "terms have not been accepted".into(),
        ))
    }
    async fn rotate_identity(&self) -> Result<(), OmikronError> {
        Err(OmikronError::Disconnected(
            "terms have not been accepted".into(),
        ))
    }
    async fn is_connected(&self) -> bool {
        false
    }
}
