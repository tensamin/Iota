use crate::omikron_connection::OmikronConnection;
use dashmap::DashMap;
use iota_state::APP_STATE;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::LazyLock;
use std::time::Instant;
use tokio::time::Duration;

static PING_TIMES: LazyLock<DashMap<u32, Instant>> = LazyLock::new(|| DashMap::new());

impl OmikronConnection {
    pub async fn send_ping(&self) {
        let id = rand::random();

        PING_TIMES.insert(id, Instant::now());

        PING_TIMES.retain(|_, v| v.elapsed() < Duration::from_secs(30));

        let ping_message = CommunicationValue::new(CommunicationType::Ping)
            .with_id(id)
            .add_typed_default(
                DataType::LastPing,
                DataValue::Array(vec![DataValue::SignedNumber(*self.last_ping.lock().await as i128)]),
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
