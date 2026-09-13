use async_trait::async_trait;
use iota_daemon_lib::{DaemonRuntime, DaemonServices, IpcServer};
use iota_ipc::{
    ClientMessage, DaemonMessage, ExitIntent, IpcErrorCode, LocalRequest, PROTOCOL_VERSION,
    RequestEnvelope, ResponseResult, read_msg, write_msg,
};
use iota_storage::util::config_util::{self, IotaConfig};
use mtp::codec::CommunicationValue;
use omikron_connector::{OmikronClient, OmikronError};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::{broadcast, watch};

struct ConfigRestore(Arc<IotaConfig>);

impl Drop for ConfigRestore {
    fn drop(&mut self) {
        config_util::CONFIG.store(self.0.clone());
    }
}

fn set_client_limit(limit: usize) -> ConfigRestore {
    let previous = config_util::CONFIG.load_full();
    let mut config = (*previous).clone();
    config.max_ipc_clients = limit;
    config_util::CONFIG.store(Arc::new(config));
    ConfigRestore(previous)
}

async fn start_server(
    path: &Path,
    services: Arc<DaemonServices>,
) -> (Arc<DaemonRuntime>, tokio::task::JoinHandle<()>) {
    let runtime = Arc::new(DaemonRuntime::new());
    let (log_tx, _) = broadcast::channel(32);
    let log_buffer = Arc::new(std::sync::Mutex::new(
        iota_daemon_lib::log_buffer::LogBuffer::new(32),
    ));
    let (_, state_rx) = watch::channel(runtime.snapshot());
    let server = IpcServer::bind(
        path.to_owned(),
        runtime.clone(),
        services,
        log_tx,
        log_buffer,
        state_rx,
    )
    .await
    .expect("IPC server binds");
    let task = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (runtime, task)
}

async fn try_connect_and_await_hello(path: &Path) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(path).await?;
    write_msg(
        &mut stream,
        &ClientMessage::Hello {
            supported_versions: vec![PROTOCOL_VERSION],
        },
    )
    .await?;
    let message: DaemonMessage = read_msg(&mut stream).await?;
    if !matches!(message, DaemonMessage::HelloAck(_)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected HelloAck",
        ));
    }
    Ok(stream)
}

async fn connect_and_await_hello(path: &Path) -> UnixStream {
    try_connect_and_await_hello(path)
        .await
        .expect("IPC connection completes the Hello exchange")
}

#[tokio::test]
async fn active_client_limit_rejects_excess_clients_and_releases_permits() {
    let _config = set_client_limit(1);
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("ipc.sock");
    let (_runtime, server_task) = start_server(&socket, DaemonServices::inactive()).await;

    let first = connect_and_await_hello(&socket).await;
    let mut rejected = UnixStream::connect(&socket)
        .await
        .expect("second connection reaches the Unix listener");
    let rejected_result = tokio::time::timeout(
        Duration::from_secs(2),
        read_msg::<_, DaemonMessage>(&mut rejected),
    )
    .await
    .expect("rejected client is closed promptly");
    assert!(rejected_result.is_err());

    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let _released = loop {
        match try_connect_and_await_hello(&socket).await {
            Ok(stream) => break stream,
            Err(_error) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("client permit was not released: {error}"),
        }
    };
    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn request_with_version_different_from_hello_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("ipc.sock");
    let (_runtime, server_task) = start_server(&socket, DaemonServices::inactive()).await;
    let mut stream = connect_and_await_hello(&socket).await;

    write_msg(
        &mut stream,
        &ClientMessage::Request(RequestEnvelope {
            request_id: 7,
            protocol_version: PROTOCOL_VERSION + 1,
            request: LocalRequest::GetStatus,
        }),
    )
    .await
    .expect("request sends");

    let response = loop {
        match read_msg::<_, DaemonMessage>(&mut stream)
            .await
            .expect("daemon response arrives")
        {
            DaemonMessage::Response(response) => break response,
            _ => continue,
        }
    };
    assert_eq!(response.request_id, 7);
    assert!(matches!(
        response.result,
        ResponseResult::Error(IpcErrorCode::UnsupportedVersion)
    ));

    drop(stream);
    server_task.abort();
    let _ = server_task.await;
}

struct TestOmikron;

#[async_trait]
impl OmikronClient for TestOmikron {
    async fn send_message(&self, _: &CommunicationValue) -> Result<(), OmikronError> {
        Ok(())
    }

    async fn await_response(
        &self,
        _: &CommunicationValue,
        _: Duration,
    ) -> Result<CommunicationValue, OmikronError> {
        Err(OmikronError::Disconnected("test client".into()))
    }

    async fn reconnect(&self) -> Result<(), OmikronError> {
        Ok(())
    }

    async fn rotate_identity(&self) -> Result<(), OmikronError> {
        Ok(())
    }

    async fn is_connected(&self) -> bool {
        true
    }
}

fn active_services() -> Arc<DaemonServices> {
    DaemonServices::with_centralized_client(Arc::new(TestOmikron))
}

#[tokio::test]
async fn shutdown_delivers_response_and_lifecycle_event_before_eof() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("ipc.sock");
    let (runtime, server_task) = start_server(&socket, active_services()).await;
    let mut stream = connect_and_await_hello(&socket).await;

    write_msg(
        &mut stream,
        &ClientMessage::Request(RequestEnvelope {
            request_id: 8,
            protocol_version: PROTOCOL_VERSION,
            request: LocalRequest::RequestProcessExit {
                intent: ExitIntent::Stop,
            },
        }),
    )
    .await
    .expect("shutdown request sends");

    let mut response_seen = false;
    let mut lifecycle_seen = false;
    for _ in 0..4 {
        match tokio::time::timeout(
            Duration::from_secs(2),
            read_msg::<_, DaemonMessage>(&mut stream),
        )
        .await
        .expect("shutdown message arrives")
        .expect("shutdown stream remains readable")
        {
            DaemonMessage::Response(response) => {
                assert_eq!(response.request_id, 8);
                assert!(matches!(response.result, ResponseResult::Ok(_)));
                response_seen = true;
            }
            DaemonMessage::LifecycleEvent(iota_ipc::LifecycleEvent::Shutdown { .. }) => {
                lifecycle_seen = true;
            }
            _ => {}
        }
        if response_seen && lifecycle_seen {
            break;
        }
    }

    assert!(response_seen);
    assert!(lifecycle_seen);
    let eof = tokio::time::timeout(
        Duration::from_secs(2),
        read_msg::<_, DaemonMessage>(&mut stream),
    )
    .await
    .expect("shutdown connection closes after flush");
    assert!(eof.is_err());
    assert!(runtime.is_shutting_down());

    server_task.abort();
    let _ = server_task.await;
}
