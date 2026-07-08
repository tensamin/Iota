use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Contact {
    pub user_id: i64,
    pub user_name: Option<String>,
    pub last_message_at: Option<i64>,
}

impl Default for Contact {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        Contact {
            user_id: 0,
            user_name: None,
            last_message_at: Some(now),
        }
    }
}

impl Contact {
    pub fn new(user_id: i64) -> Self {
        Contact {
            user_id: user_id,
            user_name: None,
            last_message_at: None,
        }
    }
    pub fn set_last_message_at(&mut self, p0: i64) {
        self.last_message_at = Option::from(p0);
    }
}
