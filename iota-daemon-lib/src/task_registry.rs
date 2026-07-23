use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

#[derive(Clone, Default)]
pub struct TaskRegistry {
    tasks: Arc<Mutex<JoinSet<(String, Result<(), String>)>>>,
}

impl TaskRegistry {
    pub async fn spawn_tracked<F>(&self, name: impl Into<String>, future: F)
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let name = name.into();
        self.tasks
            .lock()
            .await
            .spawn(async move { (name, future.await) });
    }

    pub async fn join_with_timeout(&self, timeout: Duration) -> Vec<String> {
        let mut tasks = self.tasks.lock().await;
        let mut failures = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        while !tasks.is_empty() {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok((name, Err(error))))) => failures.push(format!("{name}: {error}")),
                Ok(Some(Ok((_, Ok(()))))) | Ok(Some(Err(_))) => {}
                Ok(None) => break,
                Err(_) => {
                    tasks.abort_all();
                    break;
                }
            }
        }
        failures
    }
}
