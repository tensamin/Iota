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

fn credential_ready(
    credential: &iota_storage::users::password_credentials::PasswordCredential,
    public_key: &str,
    setup: &iota_opaque::opaque::PasswordServerSetup,
    principal: &str,
    iota_id: i64,
) -> bool {
    use sha2::{Digest, Sha256};
    let metadata_complete = matches!(
        (
            &credential.setup_sha256,
            &credential.password_principal,
            credential.password_iota_id
        ),
        (None, None, None) | (Some(_), Some(_), Some(_))
    );
    let valid = credential.opaque_profile == iota_opaque::opaque::CURRENT_OPAQUE_PROFILE
        && metadata_complete
        && credential.setup_sha256.as_ref().is_none_or(|fingerprint| {
            fingerprint.as_slice()
                == Sha256::digest(iota_opaque::opaque::serialize_server_setup(setup).as_slice())
                    .as_slice()
        })
        && credential
            .password_principal
            .as_deref()
            .is_none_or(|stored| stored == principal)
        && credential
            .password_iota_id
            .is_none_or(|stored| stored == iota_id)
        && credential.opaque_record.len() <= MAX_OPAQUE_BYTES
        && iota_opaque::opaque::validate_registration_record(&credential.opaque_record).is_ok()
        && credential.encrypted_tu_credential.len() <= MAX_CREDENTIAL_BYTES
        && iota_opaque::credential::validate_envelope(&credential.encrypted_tu_credential).is_ok()
        && wire::key_fingerprint(public_key)
            .is_ok_and(|key| key == credential.account_public_key_sha256);
    if !valid {
        iota_logger::log!(
            "Password credential integrity failure for account {}",
            credential.user_id
        );
    }
    valid
}

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
pub use runtime::{PasswordCredentialCounts, PasswordHealth, PasswordReadiness};
mod timing;
mod wire;
pub use timing::snapshot as password_stage_counts;
#[cfg(test)]
use wire::{now_millis, typed};

pub(crate) struct PasswordIdentity {
    pub(crate) principal: String,
    public_key: String,
    fence: iota_storage::users::password_credentials::PasswordAuthorization,
}

impl OmikronConnection {
    async fn password_document<T: serde::de::DeserializeOwned>(
        &self,
        url: String,
        limit: usize,
        stage: timing::Stage,
    ) -> Result<T, tau::password::Failure> {
        use tau::password::Failure;
        let mut timing = timing::Timing::start(stage);
        let mut response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|_| Failure::DependencyUnavailable)?
            .error_for_status()
            .map_err(|_| Failure::DependencyUnavailable)?;
        if response
            .content_length()
            .is_some_and(|size| size > limit as u64)
        {
            return Err(Failure::Unauthorized);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Failure::DependencyUnavailable)?
        {
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                return Err(Failure::Unauthorized);
            }
            bytes.extend_from_slice(&chunk);
        }
        let document = serde_json::from_slice(&bytes).map_err(|_| Failure::Unauthorized)?;
        timing.success();
        Ok(document)
    }

    pub(crate) async fn password_identity(
        &self,
        user_id: i64,
    ) -> Result<PasswordIdentity, tau::password::Failure> {
        use iota_identity::{
            AuthorityId, AuthorityKind, IotaNodeId, NodeDirectory, PrincipalStore,
        };
        use tau::password::Failure;
        if user_id <= 0 {
            return Err(Failure::InvalidRequest);
        }
        let pinned: String = iota_storage::util::db::with_db(|connection| {
            Ok(connection.query_row(
                "SELECT omega_authority_id FROM identity_configuration WHERE singleton=1",
                [],
                |row| row.get(0),
            )?)
        })
        .map_err(|_| Failure::DependencyUnavailable)?;
        let base = crate::omega_discovery::api_base();
        #[derive(serde::Deserialize)]
        struct Discovery {
            authority_id: String,
            public_key: String,
        }
        let cancellation = self.preparation_cancellation();
        let (discovery, wire): (Discovery, iota_identity::PrincipalDescriptorWireV1) = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(Failure::Cancelled),
            result = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::try_join!(
                    self.password_document(format!("{}/.well-known/tensamin",base.trim_end_matches('/')),64*1024,timing::Stage::Authority),
                    self.password_document(format!("{}/federation/v1/users/id/{user_id}",base.trim_end_matches('/')),256*1024,timing::Stage::Account),
                )
            }) => result.map_err(|_| Failure::DependencyUnavailable)??,
        };
        let keys = PublicKeyBundle::from_base64(&discovery.public_key)
            .map_err(|_| Failure::Unauthorized)?;
        let authority = AuthorityId::for_omega(&keys).map_err(|_| Failure::Unauthorized)?;
        if authority.as_str() != pinned || discovery.authority_id != authority.as_str() {
            *self.password_auth.readiness.write().unwrap() =
                PasswordReadiness::ReenrollmentRequired;
            return Err(Failure::Unauthorized);
        }
        let _ = self
            .password_auth
            .omega_authority
            .set(authority.as_str().to_owned());
        if self.password_auth.omega_authority.get().map(String::as_str) != Some(authority.as_str())
        {
            *self.password_auth.readiness.write().unwrap() =
                PasswordReadiness::ReenrollmentRequired;
            return Err(Failure::Unauthorized);
        }
        let home = wire
            .home_node
            .clone()
            .ok_or(Failure::Unauthorized)?
            .parse()
            .map_err(|_| Failure::Unauthorized)?;
        let signed = wire.parse().map_err(|_| Failure::Unauthorized)?;
        if signed.descriptor.authority_kind != AuthorityKind::Omega
            || signed.descriptor.principal.authority != authority
            || signed.descriptor.principal.user_id != user_id as u64
        {
            return Err(Failure::Unauthorized);
        }
        let local_keys = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or(Failure::DependencyUnavailable)?;
        let local_node = IotaNodeId::from_public_keys(&local_keys.public_key_bundle())
            .map_err(|_| Failure::Unauthorized)?;
        if home.descriptor.node != local_node {
            return Err(Failure::Unauthorized);
        }
        let store = iota_storage::identity::SqlitePrincipalStore;
        let revision = store
            .get_by_canonical_id(&signed.descriptor.principal)
            .map_err(|_| Failure::DependencyUnavailable)?
            .map(|principal| principal.descriptor_revision);
        let now = wire::now_millis() as i64;
        let snapshot = signed
            .verify_snapshot(&keys, revision, home, None, now)
            .map_err(|_| Failure::Unauthorized)?;
        if !snapshot.fresh_for_mutation(now) {
            return Err(Failure::Expired);
        }
        let local_key = iota_storage::users::password_credentials::authorization(user_id)
            .map_err(|_| Failure::Unauthorized)?
            .0;
        if !snapshot
            .principal_descriptor()
            .descriptor()
            .public_keys
            .iter()
            .any(|key| key.try_to_base64().ok().as_deref() == Some(local_key.as_str()))
        {
            return Err(Failure::Unauthorized);
        }
        iota_storage::node_directory::SqliteNodeDirectory
            .upsert_node_descriptor(snapshot.home_descriptor())
            .map_err(|_| Failure::Unauthorized)?;
        let handle = store
            .upsert_remote_descriptor(snapshot.principal_descriptor())
            .map_err(|_| Failure::Unauthorized)?;
        iota_storage::identity::bind_verified_omega_hosted_principal(&snapshot, &local_node)
            .map_err(|_| Failure::Unauthorized)?;
        let resolved = store
            .get_principal(handle)
            .map_err(|_| Failure::DependencyUnavailable)?
            .ok_or(Failure::Unauthorized)?;
        let fence = iota_storage::identity::PrincipalCommitFence::capture(&resolved)
            .map_err(|_| Failure::Unauthorized)?;
        let public_key = iota_storage::users::password_credentials::authorization(user_id)
            .map_err(|_| Failure::Unauthorized)?
            .0;
        if !fence.keys.contains(&public_key)
            || store
                .principal_for_local_user(iota_identity::LocalUserId(user_id))
                .map_err(|_| Failure::DependencyUnavailable)?
                != Some(handle)
        {
            return Err(Failure::Unauthorized);
        }
        let principal = format!("{}#{user_id}", authority.as_str());
        let fence =
            iota_storage::users::password_credentials::PasswordAuthorization::from_snapshot(
                snapshot,
            )
            .map_err(|_| Failure::Unauthorized)?;
        Ok(PasswordIdentity {
            principal,
            public_key,
            fence,
        })
    }
}

#[cfg(test)]
fn password_identity_fixture(
    authority: &mtp::crypto::Keyring,
    home: &iota_identity::LocalNodeIdentity,
    account: PublicKeyBundle,
    revision: i64,
) -> String {
    use iota_identity::*;
    let now = wire::now_millis() as i64;
    let node = SignedNodeDescriptor::sign(
        NodeDescriptor {
            node: home.node_id().clone(),
            public_keys: home.public_keys(),
            direct_endpoints: vec![],
            relay_hints: vec![],
            revision: 1,
            valid_until: Some(now + 300_000),
        },
        home,
    )
    .unwrap();
    let descriptor = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: AuthorityId::for_omega(&authority.public_key_bundle()).unwrap(),
                user_id: 7,
            },
            authority_kind: AuthorityKind::Omega,
            username: Some("alice".into()),
            display_name: None,
            public_keys: vec![account],
            home: PrincipalHome::Iota(home.node_id().clone()),
            revision,
            issued_at: now,
            valid_until: Some(now + 300_000),
        },
        authority,
    )
    .unwrap();
    serde_json::to_string(
        &descriptor
            .to_wire_v1()
            .unwrap()
            .with_home_node(node.to_wire_v1().unwrap()),
    )
    .unwrap()
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
            principal_fence: None,
            connection_generation: 0,
            user_id,
            participant_id: 1,
            contact_key: Keyring::generate().public_key_bundle(),
            advertised_account_key: None,
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
    fn readiness_checks_record_envelope_key_setup_and_identity() {
        use iota_storage::users::password_credentials::PasswordCredential;
        let setup = opaque::generate_server_setup();
        let public_key = Keyring::generate()
            .public_key_bundle()
            .try_to_base64()
            .unwrap();
        let principal = "omega#7";
        let client = opaque::client_registration_start(b"password!").unwrap();
        let response =
            opaque::server_registration_start(&setup, &client.request, principal.as_bytes())
                .unwrap();
        let registration = client.state.finish(&response, principal, 11).unwrap();
        let mut envelope = b"TSCRED\0\0\0\x01".to_vec();
        envelope.resize(50, 0);
        let credential = PasswordCredential {
            user_id: 7,
            opaque_profile: 1,
            opaque_record: opaque::server_registration_finish(&registration.upload).unwrap(),
            encrypted_tu_credential: envelope,
            account_public_key_sha256: wire::key_fingerprint(&public_key).unwrap(),
            created_at: 1,
            updated_at: 1,
            setup_sha256: Some(
                Sha256::digest(opaque::serialize_server_setup(&setup).as_slice()).to_vec(),
            ),
            password_principal: Some(principal.into()),
            password_iota_id: Some(11),
        };
        assert!(credential_ready(
            &credential,
            &public_key,
            &setup,
            principal,
            11
        ));
        for mutation in 0..7 {
            let mut invalid = credential.clone();
            match mutation {
                0 => invalid.opaque_profile = 2,
                1 => invalid.opaque_record = vec![0],
                2 => invalid.encrypted_tu_credential[0] ^= 1,
                3 => invalid.account_public_key_sha256[0] ^= 1,
                4 => invalid.setup_sha256.as_mut().unwrap()[0] ^= 1,
                5 => invalid.password_principal = Some("other#7".into()),
                6 => invalid.password_iota_id = Some(12),
                _ => unreachable!(),
            }
            assert!(!credential_ready(
                &invalid,
                &public_key,
                &setup,
                principal,
                11
            ));
        }
    }

    #[test]
    fn abort_requires_original_binding_and_releases_issued_ke2_once() {
        let runtime = limited_runtime();
        let id = Uuid::new_v4();
        let (attempt, _) = runtime.begin_attempt(7).unwrap();
        let mut pending = pending_login(7, attempt, Instant::now());
        pending.connection_generation = 42;
        let setup = opaque::generate_server_setup();
        let request = opaque::client_login_start(b"wrong password!").unwrap();
        let fingerprint = wire::public_key_fingerprint(&pending.contact_key).unwrap();
        let binding = PasswordLoginBindingV1 {
            principal: "omega#7",
            iota_id: 11,
            session_id: id,
            contact_key_sha256: &fingerprint,
        };
        pending.state = Some(
            opaque::server_login_start(&setup, None, &request.request, &binding)
                .unwrap()
                .state,
        );
        runtime.logins.insert(id, pending);
        for (user, participant, generation) in [(8, 1, 42), (7, 2, 42), (7, 1, 43)] {
            runtime.abort_login(id, user, participant, generation);
            assert!(runtime.logins.contains_key(&id));
            assert_eq!(runtime.attempts.get(&7).unwrap().in_flight, 1);
        }
        runtime.abort_login(id, 7, 1, 42);
        assert!(!runtime.logins.contains_key(&id));
        assert_eq!(runtime.attempts.get(&7).unwrap().in_flight, 0);
        assert_eq!(runtime.attempts.get(&7).unwrap().failures, 1);
        runtime.abort_login(id, 7, 1, 42);
        assert_eq!(runtime.attempts.get(&7).unwrap().failures, 1);
        let attempts = (0..runtime.max_pending)
            .map(|index| runtime.begin_attempt(index as i64).unwrap().0)
            .collect::<Vec<_>>();
        assert!(runtime.begin_attempt(9999).is_err());
        drop(attempts);
    }

    #[test]
    fn targeted_account_cannot_reserve_all_global_capacity() {
        let runtime = limited_runtime();
        let mut leases = Vec::new();
        while let Ok((lease, _)) = runtime.begin_attempt(7) {
            leases.push(lease);
        }
        assert!(!leases.is_empty());
        assert!(leases.len() < runtime.max_pending);
        assert!(runtime.begin_attempt(8).is_ok());
        drop(leases);
        assert!(runtime.begin_attempt(7).is_ok());
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
                principal_fence: None,
                connection_generation: 0,
                user_id: 7,
                participant_id: 1,
                contact_key,
                advertised_account_key: None,
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

#[cfg(test)]
mod recovery_tests;
