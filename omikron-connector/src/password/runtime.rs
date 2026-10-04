use std::{
    path::Path,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use iota_opaque::opaque::{self, PasswordServerSetup, ServerLoginState};
use iota_storage::users::password_credentials;
use mtp::crypto::PublicKeyBundle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

pub(super) struct PendingLogin {
    pub(super) user_id: i64,
    pub(super) participant_id: u64,
    pub(super) contact_key: PublicKeyBundle,
    pub(super) state: Option<ServerLoginState>,
    pub(super) real_record: bool,
    pub(super) record_hash: Option<Vec<u8>>,
    pub(super) created: Instant,
    pub(super) attempt: Option<AttemptLease>,
}

pub(super) struct PendingEnrollment {
    pub(super) user_id: i64,
    pub(super) created: Instant,
    pub(super) _permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
pub(super) struct AccountAttemptState {
    pub(super) window_started: Instant,
    pub(super) failures: u32,
    pub(super) in_flight: u32,
}

pub(super) struct PasswordThrottleConfig {
    pub(super) failure_window: Duration,
    pub(super) soft_delay_step: Duration,
    pub(super) soft_delay_cap: Duration,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum AttemptAdmissionError {
    #[error("password authentication service busy")]
    ServerBusy,
}

pub(super) struct AttemptLease {
    runtime: Weak<PasswordAuthRuntime>,
    user_id: i64,
    settled: bool,
    _global_permit: OwnedSemaphorePermit,
}

impl AttemptLease {
    pub(super) fn success(mut self) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.finish_attempt_success(self.user_id);
        }
        self.settled = true;
    }

    pub(super) fn failure(mut self) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.finish_attempt_failure(self.user_id);
        }
        self.settled = true;
    }

    pub(super) fn cancel(mut self) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.finish_attempt_cancel(self.user_id);
        }
        self.settled = true;
    }
}

impl Drop for AttemptLease {
    fn drop(&mut self) {
        if !self.settled
            && let Some(runtime) = self.runtime.upgrade()
        {
            runtime.finish_attempt_cancel(self.user_id);
        }
    }
}

pub(crate) struct PasswordAuthRuntime {
    pub(super) setup: OnceLock<Arc<PasswordServerSetup>>,
    pub(super) omega_authority: OnceLock<String>,
    pub(super) logins: DashMap<Uuid, PendingLogin>,
    pub(super) enrollments: DashMap<Uuid, PendingEnrollment>,
    pub(super) attempts: DashMap<i64, AccountAttemptState>,
    #[cfg(test)]
    pub(super) max_pending: usize,
    exchange_slots: Arc<Semaphore>,
    enrollment_slots: Arc<Semaphore>,
    blocking_slots: Arc<Semaphore>,
    pub(super) pending_ttl: Duration,
    pub(super) throttle: PasswordThrottleConfig,
}

fn configured_positive<T: std::str::FromStr + PartialOrd + Default>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .filter(|value| *value > T::default())
        .unwrap_or(default)
}

impl Default for PasswordAuthRuntime {
    fn default() -> Self {
        let max_pending = configured_positive("PASSWORD_MAX_PENDING_EXCHANGES", 1024);
        let blocking_workers = configured_positive(
            "PASSWORD_MAX_BLOCKING_WORKERS",
            std::thread::available_parallelism().map_or(1, usize::from),
        )
        .min(max_pending);
        Self {
            setup: OnceLock::new(),
            omega_authority: OnceLock::new(),
            logins: DashMap::new(),
            enrollments: DashMap::new(),
            attempts: DashMap::new(),
            #[cfg(test)]
            max_pending,
            exchange_slots: Arc::new(Semaphore::new(max_pending)),
            enrollment_slots: Arc::new(Semaphore::new(max_pending)),
            blocking_slots: Arc::new(Semaphore::new(blocking_workers)),
            pending_ttl: Duration::from_secs(configured_positive(
                "PASSWORD_PENDING_TTL_SECONDS",
                180,
            )),
            throttle: PasswordThrottleConfig {
                failure_window: Duration::from_secs(configured_positive(
                    "PASSWORD_ATTEMPT_WINDOW_SECONDS",
                    300,
                )),
                soft_delay_step: Duration::from_millis(configured_positive(
                    "PASSWORD_SOFT_DELAY_STEP_MS",
                    250,
                )),
                soft_delay_cap: Duration::from_millis(configured_positive(
                    "PASSWORD_SOFT_DELAY_CAP_MS",
                    3000,
                )),
            },
        }
    }
}

impl PasswordAuthRuntime {
    pub(super) fn begin_enrollment(&self) -> Result<OwnedSemaphorePermit, String> {
        self.enrollment_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| "too many enrollments".into())
    }

    pub(super) async fn run_blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, String> {
        let permit = self
            .blocking_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| error.to_string())?;
        tokio::task::spawn_blocking(move || {
            // Keep capacity reserved even if the awaiting task is cancelled.
            let _permit = permit;
            work()
        })
        .await
        .map_err(|error| error.to_string())
    }

    pub(crate) fn setup(&self) -> Result<Arc<PasswordServerSetup>, PasswordRuntimeError> {
        self.setup
            .get()
            .cloned()
            .ok_or(PasswordRuntimeError::SetupUnavailable)
    }

    pub(crate) fn initialize(&self, identity: &Path) -> Result<(), String> {
        if self.setup.get().is_some() {
            return Ok(());
        }
        let path = identity.with_file_name("password-auth.setup");
        let setup = match std::fs::read(&path) {
            Ok(bytes) => {
                opaque::deserialize_server_setup_owned(bytes).map_err(|error| error.to_string())?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if password_credentials::any().map_err(|error| error.to_string())? {
                    return Err("OPAQUE setup is missing while password credentials exist".into());
                }
                let setup = opaque::generate_server_setup();
                let serialized = opaque::serialize_server_setup(&setup);
                iota_util::atomic_file::replace_private(&path, &serialized, 0)
                    .map_err(|error| error.to_string())?;
                setup
            }
            Err(error) => return Err(error.to_string()),
        };
        let _ = self.setup.set(Arc::new(setup));
        Ok(())
    }

    pub(crate) fn prune(&self) {
        let expired = self
            .logins
            .iter()
            .filter_map(|entry| {
                (entry.created.elapsed() >= self.pending_ttl).then_some(*entry.key())
            })
            .collect::<Vec<_>>();
        for id in expired {
            if let Some((_, pending)) = self.logins.remove(&id)
                && let Some(attempt) = pending.attempt
            {
                attempt.failure();
            }
        }
        self.enrollments
            .retain(|_, pending| pending.created.elapsed() < self.pending_ttl);
        self.attempts.retain(|_, state| {
            state.in_flight > 0 || state.window_started.elapsed() < self.throttle.failure_window
        });
    }

    pub(super) fn begin_attempt(
        self: &Arc<Self>,
        user_id: i64,
    ) -> Result<(AttemptLease, Duration), AttemptAdmissionError> {
        let permit = self
            .exchange_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AttemptAdmissionError::ServerBusy)?;
        let mut state = self
            .attempts
            .entry(user_id)
            .or_insert_with(|| AccountAttemptState {
                window_started: Instant::now(),
                failures: 0,
                in_flight: 0,
            });
        if state.window_started.elapsed() >= self.throttle.failure_window {
            state.window_started = Instant::now();
            state.failures = 0;
        }
        state.in_flight = state.in_flight.saturating_add(1);
        let pressure = state
            .failures
            .saturating_add(state.in_flight.saturating_sub(1));
        let delay = self
            .throttle
            .soft_delay_step
            .saturating_mul(pressure)
            .min(self.throttle.soft_delay_cap);
        Ok((
            AttemptLease {
                runtime: Arc::downgrade(self),
                user_id,
                settled: false,
                _global_permit: permit,
            },
            delay,
        ))
    }

    fn finish_attempt_success(&self, user_id: i64) {
        if let Some(mut state) = self.attempts.get_mut(&user_id) {
            state.in_flight = state.in_flight.saturating_sub(1);
            state.failures = 0;
            // Keep the idle entry until pruning to avoid racing a new reservation.
        }
    }

    fn finish_attempt_failure(&self, user_id: i64) {
        let mut state = self
            .attempts
            .entry(user_id)
            .or_insert_with(|| AccountAttemptState {
                window_started: Instant::now(),
                failures: 0,
                in_flight: 0,
            });
        if state.window_started.elapsed() >= self.throttle.failure_window {
            state.window_started = Instant::now();
            state.failures = 0;
        }
        state.in_flight = state.in_flight.saturating_sub(1);
        state.failures = state.failures.saturating_add(1);
    }

    fn finish_attempt_cancel(&self, user_id: i64) {
        if let Some(mut state) = self.attempts.get_mut(&user_id) {
            state.in_flight = state.in_flight.saturating_sub(1);
        }
    }

    pub(super) fn cancel_logins_for_user(&self, user_id: i64) {
        let ids = self
            .logins
            .iter()
            .filter_map(|entry| (entry.user_id == user_id).then_some(*entry.key()))
            .collect::<Vec<_>>();
        for id in ids {
            if let Some((_, pending)) = self.logins.remove(&id)
                && let Some(attempt) = pending.attempt
            {
                attempt.cancel();
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PasswordRuntimeError {
    #[error("password authentication setup unavailable")]
    SetupUnavailable,
}
