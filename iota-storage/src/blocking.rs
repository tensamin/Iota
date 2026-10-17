use std::sync::{Arc, LazyLock};

use iota_identity::IdentityError;

static LOOKUPS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(8)));

/// Bound queued and running identity storage work. The closure retains its permit
/// if its async waiter is cancelled; SQLite work completes on the blocking pool.
pub async fn identity_lookup<T: Send + 'static>(
    lookup: impl FnOnce() -> Result<T, IdentityError> + Send + 'static,
) -> Result<T, IdentityError> {
    let permit = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        LOOKUPS.clone().acquire_owned(),
    )
    .await
    .map_err(|_| IdentityError::Unavailable("authentication storage capacity timed out".into()))?
    .map_err(|error| IdentityError::Unavailable(error.to_string()))?;
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        lookup()
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .map_err(|_| IdentityError::Unavailable("authentication storage lookup timed out".into()))?
        .map_err(|error| IdentityError::Storage(error.to_string()))?
}
