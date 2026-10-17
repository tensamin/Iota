use std::time::Duration;

use mtp::crypto::PublicKeyBundle;

#[cfg(test)]
use iota_opaque::opaque::{self, PasswordLoginBindingV1};
#[cfg(test)]
use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, ProtectedMessageBuilder,
    ProtectedOpenOptions, ProtectionPolicy, open_protected_with_checked,
};
#[cfg(test)]
use mtp::crypto::DualSigner;
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::time::Instant;
#[cfg(test)]
use uuid::Uuid;

use crate::omikron_connection::OmikronConnection;

#[allow(dead_code)]
mod app_protection {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../mtp-type-maps/app_protection.rs"
    ));
}
#[cfg(test)]
use app_protection::{PASSWORD_MANAGEMENT_ENCRYPTION, PASSWORD_MANAGEMENT_SIGNATURE, purpose};

const MAX_OPAQUE_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 256 * 1024;

mod error;
mod management;
mod protected;
mod provisioning;
mod runtime;
use error::PasswordFinishError;

pub(crate) use runtime::PasswordAuthRuntime;
#[cfg(test)]
use runtime::PasswordRuntimeError;
use runtime::PendingLogin;
mod wire;
#[cfg(test)]
use wire::{now_millis, typed};

impl OmikronConnection {
    // Password login uses Omega's key-scoped principal, including for accounts
    // whose older hosted-principal record still uses the legacy host locator.
    async fn password_principal(&self, user_id: i64) -> Result<String, String> {
        if user_id <= 0 {
            return Err("invalid user ID".into());
        }
        let authority = if let Some(cached) = self.password_auth.omega_authority.get() {
            cached.clone()
        } else {
            let url = format!(
                "{}/.well-known/tensamin",
                crate::omega_discovery::api_base()
            );
            let cancellation = self.preparation_cancellation();
            let discovery: serde_json::Value = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err("connection closed".into()),
                result = tokio::time::timeout(Duration::from_secs(10), async {
                    self.http_client.get(url).send().await
                        .map_err(|error| error.to_string())?
                        .error_for_status().map_err(|error| error.to_string())?
                        .json().await.map_err(|error| error.to_string())
                }) => result.map_err(|_| "Omega identity lookup timed out")??,
            };
            let key = discovery
                .get("public_key")
                .and_then(serde_json::Value::as_str)
                .ok_or("Omega discovery is missing its key")?;
            let key = PublicKeyBundle::from_base64(key).map_err(|error| error.to_string())?;
            let authority = iota_identity::AuthorityId::for_omega(&key)
                .map_err(|error| error.to_string())?
                .as_str()
                .to_owned();
            if discovery
                .get("authority_id")
                .and_then(serde_json::Value::as_str)
                != Some(authority.as_str())
            {
                return Err("Omega discovery identity mismatch".into());
            }
            let _ = self.password_auth.omega_authority.set(authority.clone());
            authority
        };
        Ok(format!("{authority}#{user_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp::{codec::InMemoryReplayGuard, crypto::Keyring};

    #[test]
    fn damaged_setup_stays_unavailable() {
        let directory = std::env::temp_dir().join(format!("password-setup-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let identity = directory.join("identity.keyring");
        std::fs::write(directory.join("password-auth.setup"), b"corrupt setup").unwrap();
        let runtime = PasswordAuthRuntime::default();
        assert!(runtime.initialize(&identity).is_err());
        assert!(matches!(
            runtime.setup(),
            Err(PasswordRuntimeError::SetupUnavailable)
        ));
        assert_eq!(
            std::fs::read(directory.join("password-auth.setup")).unwrap(),
            b"corrupt setup"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn limited_runtime() -> std::sync::Arc<PasswordAuthRuntime> {
        std::sync::Arc::new(PasswordAuthRuntime::default())
    }

    fn pending_login(
        user_id: i64,
        attempt: runtime::AttemptLease,
        created: Instant,
    ) -> PendingLogin {
        PendingLogin {
            user_id,
            participant_id: 1,
            contact_key: Keyring::generate().public_key_bundle(),
            state: None,
            real_record: false,
            record_hash: None,
            created,
            attempt: Some(attempt),
        }
    }

    #[test]
    fn issued_ke2_reserves_global_capacity() {
        let runtime = limited_runtime();
        let (_attempt, delay) = runtime.begin_attempt(7).unwrap();
        assert_eq!(delay, Duration::ZERO);
        assert_eq!(runtime.attempts.get(&7).unwrap().in_flight, 1);
    }

    #[test]
    fn global_capacity_is_bounded_independently_of_account() {
        let runtime = limited_runtime();
        let attempts = (0..runtime.max_pending)
            .map(|index| runtime.begin_attempt(index as i64).unwrap().0)
            .collect::<Vec<_>>();
        assert!(runtime.begin_attempt(9999).is_err());
        drop(attempts);
        assert!(runtime.begin_attempt(9999).is_ok());
    }

    #[test]
    fn successful_login_resets_pressure() {
        let runtime = limited_runtime();
        runtime.begin_attempt(7).unwrap().0.failure();
        let (attempt, delay) = runtime.begin_attempt(7).unwrap();
        assert!(delay > Duration::ZERO);
        attempt.success();
        assert_eq!(runtime.attempts.get(&7).unwrap().failures, 0);
        assert_eq!(runtime.begin_attempt(7).unwrap().1, Duration::ZERO);
    }

    #[test]
    fn abandoned_logins_cause_bounded_delay_without_account_lockout() {
        let runtime = limited_runtime();
        for _ in 0..30 {
            runtime.begin_attempt(7).unwrap().0.failure();
        }
        let (attempt, delay) = runtime.begin_attempt(7).unwrap();
        assert_eq!(delay, runtime.throttle.soft_delay_cap);
        attempt.cancel();
    }

    #[test]
    fn preserved_transport_attempt_fails_after_ttl() {
        let runtime = limited_runtime();
        let (attempt, _) = runtime.begin_attempt(7).unwrap();
        let id = Uuid::new_v4();
        runtime.logins.insert(
            id,
            pending_login(
                7,
                attempt,
                Instant::now() - runtime.pending_ttl - Duration::from_secs(1),
            ),
        );
        runtime.prune();
        assert!(!runtime.logins.contains_key(&id));
        assert_eq!(runtime.attempts.get(&7).unwrap().failures, 1);
    }

    #[test]
    fn password_replacement_cancels_pending_attempts() {
        let runtime = limited_runtime();
        let (attempt, _) = runtime.begin_attempt(7).unwrap();
        let id = Uuid::new_v4();
        runtime
            .logins
            .insert(id, pending_login(7, attempt, Instant::now()));
        runtime.cancel_logins_for_user(7);
        assert!(!runtime.logins.contains_key(&id));
        assert_eq!(runtime.attempts.get(&7).unwrap().failures, 0);
        assert_eq!(runtime.attempts.get(&7).unwrap().in_flight, 0);
    }

    #[test]
    fn transport_loss_does_not_forgive_pending_attempt() {
        let runtime = limited_runtime();
        let (attempt, _) = runtime.begin_attempt(7).unwrap();
        let id = Uuid::new_v4();
        runtime
            .logins
            .insert(id, pending_login(7, attempt, Instant::now()));
        assert!(runtime.logins.contains_key(&id));
        assert_eq!(runtime.attempts.get(&7).unwrap().in_flight, 1);
    }

    #[test]
    fn cancellation_preserves_previous_failures() {
        let runtime = limited_runtime();
        runtime.begin_attempt(7).unwrap().0.failure();
        runtime.begin_attempt(7).unwrap().0.cancel();
        assert_eq!(runtime.attempts.get(&7).unwrap().failures, 1);
    }

    #[test]
    fn expired_failure_window_resets_pressure() {
        let runtime = limited_runtime();
        runtime.begin_attempt(7).unwrap().0.failure();
        runtime.attempts.get_mut(&7).unwrap().window_started -= runtime.throttle.failure_window;
        assert_eq!(runtime.begin_attempt(7).unwrap().1, Duration::ZERO);
    }

    #[test]
    fn finish_errors_distinguish_client_failures_from_server_invalidation() {
        for error in [
            PasswordFinishError::Authentication,
            PasswordFinishError::InvalidClientMessage,
            PasswordFinishError::BindingMismatch,
        ] {
            assert!(error.counts_as_guess());
        }
        for error in [
            PasswordFinishError::CredentialChanged,
            PasswordFinishError::CredentialUnavailable,
            PasswordFinishError::Storage,
            PasswordFinishError::NodeUnavailable,
        ] {
            assert!(!error.counts_as_guess());
        }
    }

    #[test]
    fn wrong_password_client_stops_after_ke2_and_expiry_consumes_budget() {
        let setup = opaque::generate_server_setup();
        let principal = "omega-key:example#7";
        let registration = opaque::client_registration_start(b"correct password").unwrap();
        let response =
            opaque::server_registration_start(&setup, &registration.request, principal.as_bytes())
                .unwrap();
        let upload = registration.state.finish(&response, principal, 11).unwrap();
        let record = opaque::server_registration_finish(&upload.upload).unwrap();

        let runtime = limited_runtime();
        let id = Uuid::new_v4();
        let contact_key = Keyring::generate().public_key_bundle();
        let fingerprint = wire::public_key_fingerprint(&contact_key).unwrap();
        let binding = PasswordLoginBindingV1 {
            principal,
            iota_id: 11,
            session_id: id,
            contact_key_sha256: &fingerprint,
        };
        let client = opaque::client_login_start(b"wrong password").unwrap();
        let ke2 =
            opaque::server_login_start(&setup, Some(&record), &client.request, &binding).unwrap();
        let (attempt, _) = runtime.begin_attempt(7).unwrap();
        assert!(client.state.finish(&ke2.response, &binding).is_err());
        runtime.logins.insert(
            id,
            PendingLogin {
                user_id: 7,
                participant_id: 1,
                contact_key,
                state: Some(ke2.state),
                real_record: true,
                record_hash: Some(Sha256::digest(&record).to_vec()),
                created: Instant::now() - runtime.pending_ttl - Duration::from_secs(1),
                attempt: Some(attempt),
            },
        );
        runtime.prune();
        assert!(!runtime.logins.contains_key(&id));
        assert_eq!(runtime.attempts.get(&7).unwrap().failures, 1);
        assert!(runtime.begin_attempt(7).is_ok());
    }

    #[test]
    fn correct_ke3_releases_the_reserved_account_slot() {
        let setup = opaque::generate_server_setup();
        let principal = "omega-key:example#7";
        let registration = opaque::client_registration_start(b"correct password").unwrap();
        let response =
            opaque::server_registration_start(&setup, &registration.request, principal.as_bytes())
                .unwrap();
        let upload = registration.state.finish(&response, principal, 11).unwrap();
        let record = opaque::server_registration_finish(&upload.upload).unwrap();
        let id = Uuid::new_v4();
        let fingerprint =
            wire::public_key_fingerprint(&Keyring::generate().public_key_bundle()).unwrap();
        let binding = PasswordLoginBindingV1 {
            principal,
            iota_id: 11,
            session_id: id,
            contact_key_sha256: &fingerprint,
        };
        let client = opaque::client_login_start(b"correct password").unwrap();
        let ke2 =
            opaque::server_login_start(&setup, Some(&record), &client.request, &binding).unwrap();
        let runtime = limited_runtime();
        let (attempt, _) = runtime.begin_attempt(7).unwrap();
        let ke3 = client.state.finish(&ke2.response, &binding).unwrap();
        opaque::server_login_finish(ke2.state, &ke3.finalization, &binding).unwrap();
        attempt.success();
        assert_eq!(runtime.begin_attempt(7).unwrap().1, Duration::ZERO);
    }

    #[test]
    fn password_management_requires_signed_encrypted_single_use_frames() {
        let account = Keyring::generate();
        let iota = Keyring::generate();
        let signer = DualSigner::new(
            &account.sig_cl_secret_key,
            &account.sig_pq_secret_key,
            &account.sig_pq_public_key,
        )
        .unwrap();
        let frame = ProtectedMessageBuilder::new(
            CommunicationType::PasswordEnrollmentFinish,
            DataValue::Container(vec![
                typed(
                    DataType::EncryptedCredential,
                    DataValue::Bytes(vec![1, 2, 3]),
                )
                .unwrap(),
            ]),
            7,
            11,
            &signer,
            purpose(PASSWORD_MANAGEMENT_SIGNATURE),
            purpose(PASSWORD_MANAGEMENT_ENCRYPTION),
        )
        .message_id(123_u128)
        .created_at(now_millis())
        .recipients(vec![iota.public_key_bundle()])
        .frame_id(42)
        .build()
        .unwrap();
        let options = ProtectedOpenOptions::new(
            Some(11),
            purpose(PASSWORD_MANAGEMENT_SIGNATURE),
            purpose(PASSWORD_MANAGEMENT_ENCRYPTION),
            ProtectionPolicy::dual(),
        );
        let mut guard = InMemoryReplayGuard::default();
        let resolve = |_| Some(vec![account.public_key_bundle()]);
        let opened =
            open_protected_with_checked(&frame, &[&iota], Some(7), resolve, options, &mut guard)
                .unwrap();
        assert_eq!(opened.signer_id(), 7);
        assert!(
            open_protected_with_checked(&frame, &[&iota], Some(7), resolve, options, &mut guard)
                .is_err()
        );
        assert!(
            open_protected_with_checked(
                &frame,
                &[&iota],
                Some(7),
                resolve,
                ProtectedOpenOptions::new(
                    Some(12),
                    purpose(PASSWORD_MANAGEMENT_SIGNATURE),
                    purpose(PASSWORD_MANAGEMENT_ENCRYPTION),
                    ProtectionPolicy::dual()
                ),
                &mut InMemoryReplayGuard::default()
            )
            .is_err()
        );
        let clear = CommunicationValue::new(CommunicationType::PasswordEnrollmentFinish)
            .with_receiver(11)
            .with_id(42);
        assert!(
            open_protected_with_checked(
                &clear,
                &[&iota],
                Some(7),
                resolve,
                options,
                &mut InMemoryReplayGuard::default()
            )
            .is_err()
        );
    }
}
