use crate::omikron_connection::OmikronConnection;
use dashmap::DashMap;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::LazyLock;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::time::Duration;

static PING_TIMES: LazyLock<DashMap<u32, Instant>> = LazyLock::new(|| DashMap::new());

impl OmikronConnection {
    pub async fn send_ping(&self) {
        let id = rand::random();

        PING_TIMES.insert(id, Instant::now());

        PING_TIMES.retain(|_, v| v.elapsed() < Duration::from_secs(30));

        self.missed_pongs.fetch_add(1, Ordering::Relaxed);

        let ping_message = CommunicationValue::new(CommunicationType::Ping)
            .with_id(id)
            .add_typed_default(
                DataType::LastPing,
                DataValue::Array(vec![DataValue::SignedNumber(
                    *self.last_ping.lock().await as i128,
                )]),
            );

        let _ = self.send_message(&ping_message).await;
    }

    pub async fn handle_pong(&self, cv: &CommunicationValue) {
        self.missed_pongs.store(0, Ordering::Relaxed);

        let id = cv.get_id();

        if let Some((_, send_time)) = PING_TIMES.remove(&id) {
            let ping_ms = Instant::now().duration_since(send_time).as_millis() as i64;
            *self.last_ping.lock().await = ping_ms;
            self.app.lock().unwrap().push_ping_val(ping_ms as f64);
        }
    }
}
