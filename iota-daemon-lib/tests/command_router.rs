use async_trait::async_trait;
use iota_daemon_lib::log_buffer::LogBuffer;
use iota_daemon_lib::{CommandRouter, DaemonRuntime, DaemonServices, IpcRole, PeerContext};
use iota_ipc::{IpcErrorCode, LocalRequest, ResponseResult};
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

fn admin_peer() -> PeerContext {
    PeerContext {
        pid: 1,
        uid: 0,
        role: IpcRole::Admin,
    }
}

fn read_peer() -> PeerContext {
    PeerContext {
        pid: 2,
        uid: 1000,
        role: IpcRole::Read,
    }
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
    let services = DaemonServices::with_centralized_client(fake.clone());
    let router = CommandRouter::new(
        Arc::new(DaemonRuntime::new()),
        services,
        Arc::new(Mutex::new(LogBuffer::new(100))),
    );
    assert!(matches!(
        router
            .route(&admin_peer(), 1, LocalRequest::ReconnectOmikron)
            .await
            .result,
        ResponseResult::Ok(_)
    ));
    assert_eq!(fake.reconnects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn identity_rotation_is_available_while_omikron_is_offline() {
    let fake = Arc::new(FakeOmikron {
        reconnects: AtomicUsize::new(0),
    });
    let services = DaemonServices::with_centralized_client(fake.clone());
    let router = CommandRouter::new(
        Arc::new(DaemonRuntime::new()),
        services,
        Arc::new(Mutex::new(LogBuffer::new(100))),
    );
    assert!(matches!(
        router
            .route(&admin_peer(), 1, LocalRequest::RotateIotaIdentity)
            .await
            .result,
        ResponseResult::Ok(_)
    ));
    assert_eq!(fake.reconnects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn read_role_cannot_execute_an_administrative_request() {
    let fake = Arc::new(FakeOmikron {
        reconnects: AtomicUsize::new(0),
    });
    let services = DaemonServices::with_centralized_client(fake.clone());
    let router = CommandRouter::new(
        Arc::new(DaemonRuntime::new()),
        services,
        Arc::new(Mutex::new(LogBuffer::new(100))),
    );

    assert!(matches!(
        router
            .route(
                &read_peer(),
                9,
                LocalRequest::SetConfig {
                    key: "port".into(),
                    value: "1984".into(),
                },
            )
            .await
            .result,
        ResponseResult::Error(IpcErrorCode::Unauthorized)
    ));
    assert_eq!(fake.reconnects.load(Ordering::SeqCst), 0);
}
