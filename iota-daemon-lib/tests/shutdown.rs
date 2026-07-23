use iota_daemon_lib::{DaemonRuntime, ShutdownReason};
use std::time::Duration;

#[tokio::test]
async fn shutdown_reason_is_first_write_wins_and_tasks_join() {
    let runtime = DaemonRuntime::new();
    runtime.shutdown(ShutdownReason::Fatal("first".into()));
    runtime.shutdown(ShutdownReason::Restart);
    assert_eq!(
        runtime.shutdown_reason(),
        Some(ShutdownReason::Fatal("first".into()))
    );
    runtime.tasks.spawn_tracked("quick", async { Ok(()) }).await;
    assert!(
        runtime
            .tasks
            .join_with_timeout(Duration::from_millis(100))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn long_task_is_aborted_at_join_timeout() {
    let runtime = DaemonRuntime::new();
    runtime
        .tasks
        .spawn_tracked("slow", async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        })
        .await;
    assert!(
        runtime
            .tasks
            .join_with_timeout(Duration::from_millis(10))
            .await
            .is_empty()
    );
}
