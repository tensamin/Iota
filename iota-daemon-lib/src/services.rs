use omikron_connector::{OmikronClient, OmikronConnection};
use std::sync::Arc;

#[derive(Default)]
pub struct UserService;
#[derive(Default)]
pub struct ConfigService;

pub struct DaemonServices {
    pub omikron: Arc<dyn OmikronClient>,
    pub users: Arc<UserService>,
    pub config: Arc<ConfigService>,
}

impl DaemonServices {
    pub fn new(omikron: Arc<OmikronConnection>) -> Arc<Self> {
        Arc::new(Self {
            omikron,
            users: Arc::new(UserService),
            config: Arc::new(ConfigService),
        })
    }
}
