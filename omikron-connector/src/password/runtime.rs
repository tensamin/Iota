use std::{
    path::Path,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use iota_opaque::opaque::{self, PasswordServerSetup, ServerLoginState};
use iota_storage::users::password_credentials;
use mtp::crypto::PublicKeyBundle;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordReadiness {
    SetupUnavailable,
    SetupMismatch,
    Initialized,
    CredentialsInvalid,
    IdentityUnverified,
    LegacyUnverified,
    StorageValidationFailure,
    ReenrollmentRequired,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PasswordCredentialCounts {
    pub total: u64,
    pub validated: u64,
    pub invalid: u64,
    pub legacy_unverified: u64,
    pub identity_unverified: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordHealth {
    pub setup_available: bool,
    pub storage_validated: bool,
    pub readiness: PasswordReadiness,
    /// None means no successful full scan, not zero credentials.
    pub credentials: Option<PasswordCredentialCounts>,
}

#[derive(Default)]
pub(crate) struct PasswordMetrics {
    pub(super) accepted: std::sync::atomic::AtomicU64,
    pub(super) rejected: std::sync::atomic::AtomicU64,
    pub(super) expired: std::sync::atomic::AtomicU64,
    pub(super) cancelled: std::sync::atomic::AtomicU64,
}

impl PasswordMetrics {
    pub(crate) fn snapshot(&self) -> [u64; 4] {
        use std::sync::atomic::Ordering::Relaxed;
        [
            self.accepted.load(Relaxed),
            self.rejected.load(Relaxed),
            self.expired.load(Relaxed),
            self.cancelled.load(Relaxed),
        ]
    }
}

pub(super) struct PendingLogin {
    pub(super) connection_generation: u64,
    pub(super) user_id: i64,
    pub(super) participant_id: u64,
    pub(super) contact_key: PublicKeyBundle,
    pub(super) advertised_account_key: Option<Vec<u8>>,
    pub(super) state: Option<ServerLoginState>,
    pub(super) real_record: bool,
    pub(super) record_hash: Option<Vec<u8>>,
    pub(super) principal_fence:
        Option<iota_storage::users::password_credentials::PasswordAuthorization>,
    pub(super) created: Instant,
    pub(super) attempt: Option<AttemptLease>,
}

pub(super) struct PendingEnrollment {
    pub(super) principal_fence: iota_storage::users::password_credentials::PasswordAuthorization,
    pub(super) public_key: String,
    pub(super) authorization_generation: i64,
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
    pub(crate) metrics: PasswordMetrics,
    pub(crate) readiness: std::sync::RwLock<PasswordReadiness>,
    credential_counts: std::sync::RwLock<Option<PasswordCredentialCounts>>,
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
    per_account_limit: u32,
    malformed_requests: std::sync::Mutex<(Instant, u32)>,
    pub(super) pending_ttl: Duration,
    pub(super) throttle: PasswordThrottleConfig,
    #[cfg(test)]
    pub(super) release_gate:
        std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}

fn configured_positive<T: std::str::FromStr + PartialOrd + Default + Copy>(
    name: &str,
    default: T,
    maximum: T,
) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .filter(|value| *value > T::default() && *value <= maximum)
        .unwrap_or(default)
}

impl Default for PasswordAuthRuntime {
    fn default() -> Self {
        let max_pending = configured_positive("PASSWORD_MAX_PENDING_EXCHANGES", 1024, 16384);
        let blocking_workers = configured_positive(
            "PASSWORD_MAX_BLOCKING_WORKERS",
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(256),
            256,
        )
        .min(max_pending);
        Self {
            metrics: PasswordMetrics::default(),
            malformed_requests: std::sync::Mutex::new((Instant::now(), 0)),
            readiness: std::sync::RwLock::new(PasswordReadiness::SetupUnavailable),
            credential_counts: std::sync::RwLock::new(None),
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
            per_account_limit: configured_positive("PASSWORD_MAX_ACCOUNT_EXCHANGES", 4, 64)
                .min((max_pending / 4).max(1) as u32),
            pending_ttl: Duration::from_secs(
                configured_positive("PASSWORD_PENDING_TTL_SECONDS", 180, 600).max(60),
            ),
            throttle: PasswordThrottleConfig {
                failure_window: Duration::from_secs(configured_positive(
                    "PASSWORD_ATTEMPT_WINDOW_SECONDS",
                    300,
                    3600,
                )),
                soft_delay_step: Duration::from_millis(configured_positive(
                    "PASSWORD_SOFT_DELAY_STEP_MS",
                    250,
                    1000,
                )),
                soft_delay_cap: Duration::from_millis(configured_positive(
                    "PASSWORD_SOFT_DELAY_CAP_MS",
                    3000,
                    5000,
                )),
            },
            #[cfg(test)]
            release_gate: std::sync::Mutex::new(None),
        }
    }
}

impl PasswordAuthRuntime {
    pub(super) fn malformed_budget_available(&self) -> bool {
        let mut state = self.malformed_requests.lock().unwrap();
        if state.0.elapsed() >= Duration::from_secs(60) {
            *state = (Instant::now(), 0);
        }
        state.1 < 128
    }

    pub(super) fn malformed_request(&self) {
        self.malformed_requests.lock().unwrap().1 += 1;
        self.metrics
            .rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    pub(super) fn abort_login(&self, id: Uuid, user_id: i64, participant_id: u64, generation: u64) {
        if let Some((_, mut pending)) = self.logins.remove_if(&id, |_, pending| {
            pending.user_id == user_id
                && pending.participant_id == participant_id
                && pending.connection_generation == generation
        }) {
            self.metrics
                .cancelled
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(attempt) = pending.attempt.take() {
                if pending.state.is_some() {
                    attempt.failure();
                } else {
                    attempt.cancel();
                }
            }
        }
    }
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
        let permit = tokio::time::timeout(
            Duration::from_secs(2),
            self.blocking_slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| "password worker queue timed out".to_owned())?
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
        if matches!(
            *self.readiness.read().unwrap(),
            PasswordReadiness::StorageValidationFailure | PasswordReadiness::SetupMismatch
        ) {
            return Err(PasswordRuntimeError::SetupUnavailable);
        }
        self.setup
            .get()
            .cloned()
            .ok_or(PasswordRuntimeError::SetupUnavailable)
    }

    pub(crate) fn initialize(&self, identity: &Path) -> Result<(), String> {
        if self.setup.get().is_some() {
            return self.validate_storage();
        }
        let path = identity.with_file_name("password-auth.setup");
        let setup = match std::fs::read(&path) {
            Ok(bytes) => {
                opaque::deserialize_server_setup_owned(bytes).map_err(|error| error.to_string())?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if password_credentials::any().map_err(|error| {
                    *self.readiness.write().unwrap() = PasswordReadiness::StorageValidationFailure;
                    error.to_string()
                })? {
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
        self.validate_storage()
    }

    pub(crate) fn validate_storage(&self) -> Result<(), String> {
        let setup = self.setup.get().ok_or("OPAQUE setup unavailable")?;
        let fingerprint = Sha256::digest(opaque::serialize_server_setup(setup).as_slice());
        let mut counts = PasswordCredentialCounts::default();
        let iota_id = iota_storage::util::config_util::CONFIG.load().iota_id;
        let authority = self.omega_authority.get();
        let mut setup_mismatch = false;
        let result = password_credentials::inspect_all(|credential, public_key| {
            counts.total += 1;
            setup_mismatch |= credential
                .setup_sha256
                .as_ref()
                .is_some_and(|stored| stored.as_slice() != fingerprint.as_slice());
            let principal =
                authority.map(|authority| format!("{authority}#{}", credential.user_id));
            let valid = public_key.is_some_and(|key| {
                super::credential_ready(
                    credential,
                    key,
                    setup,
                    principal
                        .as_deref()
                        .or(credential.password_principal.as_deref())
                        .unwrap_or(""),
                    iota_id
                        .and_then(|id| i64::try_from(id).ok())
                        .or(credential.password_iota_id)
                        .unwrap_or(0),
                )
            });
            if !valid {
                counts.invalid += 1;
            } else if credential.setup_sha256.is_none() {
                counts.legacy_unverified += 1;
            } else if authority.is_none() || iota_id.is_none() {
                counts.identity_unverified += 1;
            } else {
                counts.validated += 1;
            }
        });
        match result {
            Ok(()) => {
                let mut readiness = self.readiness.write().unwrap();
                *self.credential_counts.write().unwrap() = Some(counts);
                if *readiness != PasswordReadiness::ReenrollmentRequired {
                    *readiness = if setup_mismatch {
                        PasswordReadiness::SetupMismatch
                    } else if counts.invalid > 0 {
                        PasswordReadiness::CredentialsInvalid
                    } else if counts.legacy_unverified > 0 {
                        PasswordReadiness::LegacyUnverified
                    } else if counts.identity_unverified > 0 {
                        PasswordReadiness::IdentityUnverified
                    } else {
                        PasswordReadiness::Initialized
                    };
                }
                if setup_mismatch {
                    Err("OPAQUE setup does not match enrolled credentials".into())
                } else {
                    Ok(())
                }
            }
            Err(error) => {
                let mut readiness = self.readiness.write().unwrap();
                *readiness = PasswordReadiness::StorageValidationFailure;
                *self.credential_counts.write().unwrap() = None;
                Err(error.to_string())
            }
        }
    }

    pub(crate) fn health(&self) -> PasswordHealth {
        let readiness = self.readiness.read().unwrap();
        let credentials = *self.credential_counts.read().unwrap();
        PasswordHealth {
            setup_available: self.setup.get().is_some(),
            storage_validated: credentials.is_some()
                && *readiness != PasswordReadiness::StorageValidationFailure,
            readiness: *readiness,
            credentials,
        }
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
                self.metrics
                    .expired
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            .map_err(|_| {
                self.metrics
                    .rejected
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                AttemptAdmissionError::ServerBusy
            })?;
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
        if state.in_flight >= self.per_account_limit {
            self.metrics
                .rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(AttemptAdmissionError::ServerBusy);
        }
        self.metrics
            .accepted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
