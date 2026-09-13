#[derive(Debug, Clone)]
pub struct Contact {
    pub user_id: i64,
    pub principal: Option<iota_identity::PrincipalHandle>,
    pub user_name: Option<String>,
    pub created_at: i64,
    pub last_message_at: Option<i64>,
    pub notifications: i64,
    pub notifications_read_at: i64,
}

impl Default for Contact {
    fn default() -> Self {
        Contact {
            user_id: 0,
            principal: None,
            user_name: None,
            created_at: 0,
            last_message_at: None,
            notifications: 0,
            notifications_read_at: 0,
        }
    }
}

impl Contact {
    pub fn new(user_id: i64) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        Contact {
            user_id,
            principal: None,
            user_name: None,
            created_at,
            last_message_at: None,
            notifications: 0,
            notifications_read_at: 0,
        }
    }

    pub fn for_principal(user_id: i64, principal: iota_identity::PrincipalHandle) -> Self {
        Self {
            principal: Some(principal),
            ..Self::new(user_id)
        }
    }
    pub fn set_last_message_at(&mut self, p0: i64) {
        self.last_message_at = Option::from(p0);
    }
}
