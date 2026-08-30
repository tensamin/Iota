#[derive(Debug, Clone)]
pub struct Contact {
    pub user_id: i64,
    pub user_name: Option<String>,
    pub created_at: i64,
    pub last_message_at: Option<i64>,
}

impl Default for Contact {
    fn default() -> Self {
        Contact {
            user_id: 0,
            user_name: None,
            created_at: 0,
            last_message_at: None,
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
            user_id: user_id,
            user_name: None,
            created_at,
            last_message_at: None,
        }
    }
    pub fn set_last_message_at(&mut self, p0: i64) {
        self.last_message_at = Option::from(p0);
    }
}
