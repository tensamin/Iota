use crate::omikron::omikron_connection::OmikronConnection;
use crate::{APP_STATE, log};
use dashmap::DashMap;
use std::sync::LazyLock;
use std::time::Instant;
use tokio::time::Duration;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue, rand_u32};

static PING_TIMES: LazyLock<DashMap<u32, Instant>> = LazyLock::new(|| DashMap::new());

impl OmikronConnection {
    pub async fn send_ping(&self) {
        let id = rand_u32();

        PING_TIMES.insert(id, Instant::now());

        PING_TIMES.retain(|_, v| v.elapsed() < Duration::from_secs(30));

        let ping_message = CommunicationValue::new(CommunicationType::ping)
            .with_id(id)
            .add_data(
                DataTypes::last_ping,
                DataValue::Array(vec![DataValue::Number(*self.last_ping.lock().await)]),
            );

        self.send_message(&ping_message).await;
    }

    pub async fn handle_pong(&self, cv: &CommunicationValue) {
        let id = cv.get_id();

        if let Some((_, send_time)) = PING_TIMES.remove(&id) {
            let ping_ms = Instant::now().duration_since(send_time).as_millis() as i64;
            *self.last_ping.lock().await = ping_ms;
            APP_STATE.lock().unwrap().push_ping_val(ping_ms as f64);
        }
    }
}
