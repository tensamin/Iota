use std::{
    path::Path,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use iota_auth::password::{self, PasswordServerSetup};
use iota_storage::users::password_credentials;
use mtp::crypto::PublicKeyBundle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) struct PendingLogin {
    pub(super) user_id: i64,
    pub(super) participant_id: u64,
    pub(super) contact_key: PublicKeyBundle,
    pub(super) context: Vec<u8>,
    pub(super) state: password::SerializedLoginState,
    pub(super) real_record: bool,
    pub(super) record_hash: Option<Vec<u8>>,
    pub(super) created: Instant,
    pub(super) attempt: Option<AttemptLease>,
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
        if !self.settled {
            if let Some(runtime) = self.runtime.upgrade() {
                runtime.finish_attempt_cancel(self.user_id);
            }
        }
    }
}

pub(crate) struct PasswordAuthRuntime {
    pub(super) setup: OnceLock<Arc<PasswordServerSetup>>,
    pub(super) omega_authority: OnceLock<String>,
    pub(super) logins: DashMap<Uuid, PendingLogin>,
    pub(super) enrollments: DashMap<Uuid, (i64, Instant)>,
    pub(super) attempts: DashMap<i64, AccountAttemptState>,
    pub(super) max_pending: usize,
    exchange_slots: Arc<Semaphore>,
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
        Self {
            setup: OnceLock::new(),
            omega_authority: OnceLock::new(),
            logins: DashMap::new(),
            enrollments: DashMap::new(),
            attempts: DashMap::new(),
            max_pending,
            exchange_slots: Arc::new(Semaphore::new(max_pending)),
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
            Ok(bytes) => password::deserialize_server_setup_owned(bytes)
                .map_err(|error| error.to_string())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if password_credentials::any().map_err(|error| error.to_string())? {
                    return Err("OPAQUE setup is missing while password credentials exist".into());
                }
                let setup = password::generate_server_setup();
                let serialized = Zeroizing::new(password::serialize_server_setup(&setup));
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
            if let Some((_, pending)) = self.logins.remove(&id) {
                if let Some(attempt) = pending.attempt {
                    attempt.failure();
                }
            }
        }
        self.enrollments
            .retain(|_, (_, created)| created.elapsed() < self.pending_ttl);
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
            if let Some((_, pending)) = self.logins.remove(&id) {
                if let Some(attempt) = pending.attempt {
                    attempt.cancel();
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PasswordRuntimeError {
    #[error("password authentication setup unavailable")]
    SetupUnavailable,
}
