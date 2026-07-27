use async_trait::async_trait;
use iota_daemon_lib::log_buffer::LogBuffer;
use iota_daemon_lib::{CommandRouter, DaemonRuntime, DaemonServices};
use iota_ipc::{LocalRequest, ResponseResult};
use mtp::codec::CommunicationValue;
use omikron_connector::{OmikronClient, OmikronError};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

struct FakeOmikron {
    reconnects: AtomicUsize,
}
#[async_trait]
impl OmikronClient for FakeOmikron {
    async fn send_message(&self, _: &CommunicationValue) -> Result<(), OmikronError> {
        Ok(())
    }
    async fn await_response(
        &self,
        _: &CommunicationValue,
        _: Duration,
    ) -> Result<CommunicationValue, OmikronError> {
        Err(OmikronError::Disconnected("fake".into()))
    }
    async fn reconnect(&self) -> Result<(), OmikronError> {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn rotate_identity(&self) -> Result<(), OmikronError> {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn is_connected(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn reconnect_uses_the_injected_client() {
    let fake = Arc::new(FakeOmikron {
        reconnects: AtomicUsize::new(0),
    });
    let services = Arc::new(DaemonServices {
        omikron: fake.clone(),
        users: Default::default(),
        config: Default::default(),
        active: true,
    });
    let router = CommandRouter::new(
        Arc::new(DaemonRuntime::new()),
        services,
        Arc::new(Mutex::new(LogBuffer::new(100))),
    );
    assert!(matches!(
        router.route(1, LocalRequest::ReconnectOmikron).await.result,
        ResponseResult::Ok(_)
    ));
    assert_eq!(fake.reconnects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn identity_rotation_is_available_while_omikron_is_offline() {
    let fake = Arc::new(FakeOmikron {
        reconnects: AtomicUsize::new(0),
    });
    let services = Arc::new(DaemonServices {
        omikron: fake.clone(),
        users: Default::default(),
        config: Default::default(),
        active: true,
    });
    let router = CommandRouter::new(
        Arc::new(DaemonRuntime::new()),
        services,
        Arc::new(Mutex::new(LogBuffer::new(100))),
    );
    assert!(matches!(
        router
            .route(1, LocalRequest::RotateIotaIdentity)
            .await
            .result,
        ResponseResult::Ok(_)
    ));
    assert_eq!(fake.reconnects.load(Ordering::SeqCst), 1);
}
