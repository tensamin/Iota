use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use dashmap::{DashMap, mapref::entry::Entry};
use iota_auth::password::{self, PasswordServerSetup};
use iota_storage::{
    users::{
        password_credentials::{self, PasswordCredential},
        user_manager,
    },
    util::protected_replay,
};
use mtp::{
    codec::{
        CommunicationType, CommunicationValue, DataType, DataTypeId,
        DataValue, ProtectedMessageBuilder, ProtectedOpenOptions, ProtectionPolicy,
        ReplayError, ReplayGuard, TypeMap, VerifiedProtectedMessage,
        open_protected_with_checked,
    },
    crypto::{DualSigner, PublicKeyBundle},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::omikron_connection::OmikronConnection;

#[allow(dead_code)]
mod app_protection {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../mtp-type-maps/app_protection.rs"));
}
use app_protection::{
    purpose, PASSWORD_MANAGEMENT_SIGNATURE, PASSWORD_MANAGEMENT_ENCRYPTION,
    PASSWORD_RESPONSE_SIGNATURE, PASSWORD_RESPONSE_ENCRYPTION,
    PROVISIONING_CREDENTIAL_SIGNATURE, PROVISIONING_CREDENTIAL_ENCRYPTION,
};

const MAX_OPAQUE_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 256 * 1024;

struct CommandReplayGuard;

impl ReplayGuard for CommandReplayGuard {
    fn accept(
        &mut self,
        signer_id: u64,
        message_id: mtp::common::MessageId,
        created_at: u64,
    ) -> Result<bool, ReplayError> {
        let now = now_millis();
        if created_at < now.saturating_sub(7 * 24 * 60 * 60 * 1000)
            || created_at > now.saturating_add(5 * 60 * 1000)
        {
            return Ok(false);
        }
        let signer =
            i64::try_from(signer_id).map_err(|error| ReplayError::Store(error.to_string()))?;
        let time =
            i64::try_from(created_at).map_err(|error| ReplayError::Store(error.to_string()))?;
        protected_replay::accept(signer, &message_id.to_string(), time)
            .map_err(|error| ReplayError::Store(error.to_string()))
    }
}

pub(super) struct PendingLogin {
    user_id: i64,
    participant_id: u64,
    contact_key: PublicKeyBundle,
    context: Vec<u8>,
    state: Vec<u8>,
    real_record: bool,
    record_hash: Option<Vec<u8>>,
    created: Instant,
}

pub(super) struct PasswordAuthRuntime {
    setup: OnceLock<Arc<PasswordServerSetup>>,
    omega_authority: OnceLock<String>,
    logins: DashMap<Uuid, PendingLogin>,
    enrollments: DashMap<Uuid, (i64, Instant)>,
    attempts: DashMap<i64, (Instant, u32)>,
    max_pending: usize,
    pending_ttl: Duration,
    attempt_window: Duration,
    max_attempts: u32,
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
        Self {
            setup: OnceLock::new(),
            omega_authority: OnceLock::new(),
            logins: DashMap::new(),
            enrollments: DashMap::new(),
            attempts: DashMap::new(),
            max_pending: configured_positive("PASSWORD_MAX_PENDING_EXCHANGES", 1024),
            pending_ttl: Duration::from_secs(configured_positive(
                "PASSWORD_PENDING_TTL_SECONDS",
                180,
            )),
            attempt_window: Duration::from_secs(configured_positive(
                "PASSWORD_ATTEMPT_WINDOW_SECONDS",
                300,
            )),
            max_attempts: configured_positive("PASSWORD_MAX_ATTEMPTS_PER_ACCOUNT", 10),
        }
    }
}

impl PasswordAuthRuntime {
    pub(super) fn initialize(&self, identity: &Path) -> Result<(), String> {
        if self.setup.get().is_some() {
            return Ok(());
        }
        let path = identity.with_file_name("password-auth.setup");
        let setup = match std::fs::read(&path) {
            Ok(bytes) => {
                password::deserialize_server_setup(&bytes).map_err(|error| error.to_string())?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if password_credentials::any().map_err(|error| error.to_string())? {
                    return Err("OPAQUE setup is missing while password credentials exist".into());
                }
                let setup = password::generate_server_setup();
                iota_util::atomic_file::replace_private(
                    &path,
                    &password::serialize_server_setup(&setup),
                    0,
                )
                .map_err(|error| error.to_string())?;
                setup
            }
            Err(error) => return Err(error.to_string()),
        };
        let _ = self.setup.set(Arc::new(setup));
        Ok(())
    }

    pub(super) fn prune(&self) {
        self.logins
            .retain(|_, value| value.created.elapsed() < self.pending_ttl);
        self.enrollments
            .retain(|_, (_, created)| created.elapsed() < self.pending_ttl);
        self.attempts
            .retain(|_, (started, _)| started.elapsed() < self.attempt_window);
    }

    fn allow_attempt(&self, user_id: i64) -> bool {
        let mut attempt = self.attempts.entry(user_id).or_insert((Instant::now(), 0));
        if attempt.0.elapsed() >= self.attempt_window {
            *attempt = (Instant::now(), 0);
        }
        if attempt.1 >= self.max_attempts {
            return false;
        }
        attempt.1 += 1;
        true
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn field<'a>(content: &'a DataValue, kind: DataType) -> Result<&'a DataValue, String> {
    let id = kind
        .try_to_id(&TypeMap::latest())
        .ok_or("unknown data field")?;
    let DataValue::Container(fields) = content else {
        return Err("content is not a container".into());
    };
    fields
        .iter()
        .find_map(|(field_id, value)| (*field_id == id).then_some(value))
        .ok_or_else(|| format!("missing {kind:?}"))
}

fn typed(kind: DataType, value: DataValue) -> Result<(DataTypeId, DataValue), String> {
    Ok((
        kind.try_to_id(&TypeMap::latest()).ok_or("unknown field")?,
        value,
    ))
}

fn bytes(content: &DataValue, kind: DataType, max: usize) -> Result<Vec<u8>, String> {
    let value = field(content, kind)?
        .as_bytes()
        .ok_or("field is not bytes")?;
    if value.is_empty() || value.len() > max {
        return Err("field exceeds size limits".into());
    }
    Ok(value)
}

fn positive(content: &DataValue, kind: DataType) -> Result<i64, String> {
    field(content, kind)?
        .as_number()
        .and_then(|value| i64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("invalid {kind:?}"))
}

fn session(content: &DataValue) -> Result<Uuid, String> {
    Uuid::parse_str(
        field(content, DataType::Uuid)?
            .as_str()
            .ok_or("invalid session UUID")?,
    )
    .map_err(|error| error.to_string())
}

fn public_key(content: &DataValue) -> Result<PublicKeyBundle, String> {
    let encoded = field(content, DataType::PublicKey)?
        .as_str()
        .ok_or("invalid public key")?;
    if encoded.len() > 16 * 1024 {
        return Err("public key too large".into());
    }
    PublicKeyBundle::from_base64(encoded).map_err(|error| error.to_string())
}

fn key_fingerprint(encoded: &str) -> Result<Vec<u8>, String> {
    let bundle = PublicKeyBundle::from_base64(encoded).map_err(|error| error.to_string())?;
    Ok(Sha256::digest(bundle.try_as_bytes().map_err(|error| error.to_string())?).to_vec())
}

impl OmikronConnection {
    // Password login uses Omega's key-scoped principal, including for accounts
    // whose older hosted-principal record still uses the legacy host locator.
    async fn password_principal(&self, user_id: i64) -> Result<String, String> {
        if user_id <= 0
            || user_manager::get_user(user_id)
                .map_err(|error| error.to_string())?
                .is_none()
        {
            return Err("account not hosted".into());
        }
        let authority = if let Some(cached) = self.password_auth.omega_authority.get() {
            cached.clone()
        } else {
            let url = format!(
                "{}/.well-known/tensamin",
                crate::omega_discovery::api_base()
            );
            let response =
                tokio::time::timeout(Duration::from_secs(10), self.http_client.get(url).send())
                    .await
                    .map_err(|_| "Omega identity lookup timed out")?
                    .map_err(|error| error.to_string())?
                    .error_for_status()
                    .map_err(|error| error.to_string())?;
            let discovery: serde_json::Value =
                response.json().await.map_err(|error| error.to_string())?;
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

    async fn open_password_command(
        &self,
        frame: &CommunicationValue,
        kind: CommunicationType,
    ) -> Result<VerifiedProtectedMessage, String> {
        let iota_id = iota_storage::util::config_util::CONFIG
            .load()
            .iota_id
            .ok_or("Iota has no identity")?;
        let keyring = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or("Iota has no keyring")?;
        let mut replay = CommandReplayGuard;
        let opened = open_protected_with_checked(
            frame,
            &[keyring.as_ref()],
            None,
            |signer_id| {
                let id = i64::try_from(signer_id).ok()?;
                let profile = user_manager::get_user(id).ok()??;
                Some(vec![
                    PublicKeyBundle::from_base64(&profile.public_key).ok()?,
                ])
            },
            ProtectedOpenOptions::new(
                Some(iota_id),
                purpose(PASSWORD_MANAGEMENT_SIGNATURE),
                purpose(PASSWORD_MANAGEMENT_ENCRYPTION),
                ProtectionPolicy::dual(),
            ),
            &mut replay,
        )
        .map_err(|error| error.to_string())?;
        if opened.message_type() != kind {
            return Err("wrong protected command type".into());
        }
        Ok(opened)
    }

    async fn protected_response(
        &self,
        frame: &CommunicationValue,
        kind: CommunicationType,
        user_id: i64,
        content: DataValue,
        signature: u8,
        encryption: u8,
    ) -> Result<CommunicationValue, String> {
        let iota_id = iota_storage::util::config_util::CONFIG
            .load()
            .iota_id
            .ok_or("Iota has no identity")?;
        let keyring = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or("Iota has no keyring")?;
        let recipient = PublicKeyBundle::from_base64(
            &user_manager::get_user(user_id)
                .map_err(|error| error.to_string())?
                .ok_or("account not hosted")?
                .public_key,
        )
        .map_err(|error| error.to_string())?;
        self.build_protected(
            frame,
            kind,
            iota_id,
            user_id as u64,
            content,
            recipient,
            signature,
            encryption,
            &keyring,
        )
    }

    fn build_protected(
        &self,
        frame: &CommunicationValue,
        kind: CommunicationType,
        signer_id: u64,
        recipient_id: u64,
        content: DataValue,
        recipient: PublicKeyBundle,
        signature: u8,
        encryption: u8,
        keyring: &mtp::crypto::Keyring,
    ) -> Result<CommunicationValue, String> {
        let signer = DualSigner::new(
            &keyring.sig_cl_secret_key,
            &keyring.sig_pq_secret_key,
            &keyring.sig_pq_public_key,
        )
        .map_err(|error| error.to_string())?;
        let mut rng = OsRng;
        let id = ((rng.next_u64() as u128) << 64) | rng.next_u64() as u128;
        ProtectedMessageBuilder::new(
            kind,
            content,
            signer_id,
            recipient_id,
            &signer,
            purpose(signature),
            purpose(encryption),
        )
        .message_id(id)
        .created_at(now_millis())
        .recipients(vec![recipient])
        .frame_id(frame.id().ok_or("missing request ID")?)
        .build()
        .map_err(|error| error.to_string())
    }

    async fn password_error(&self, frame: &CommunicationValue, kind: CommunicationType) {
        let mut response = CommunicationValue::new(kind);
        if let Some(id) = frame.id() {
            response = response.with_id(id);
        }
        let _ = self.send_message(&response).await;
    }

    pub(super) async fn handle_password_enrollment_start(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        let result = self.enrollment_start(frame).await;
        match result {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password enrollment start failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    async fn enrollment_start(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let opened = self
            .open_password_command(frame, CommunicationType::PasswordEnrollmentStart)
            .await?;
        let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
        if self.password_auth.enrollments.len() >= self.password_auth.max_pending {
            return Err("too many enrollments".into());
        }
        let principal = self.password_principal(user_id).await?;
        let request = bytes(opened.content(), DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let setup = self
            .password_auth
            .setup
            .get()
            .ok_or("OPAQUE setup unavailable")?;
        let response = password::registration_start(setup, &request, principal.as_bytes())
            .map_err(|error| error.to_string())?;
        let enrollment_id = Uuid::new_v4();
        self.password_auth
            .enrollments
            .insert(enrollment_id, (user_id, Instant::now()));
        self.protected_response(
            frame,
            CommunicationType::PasswordEnrollmentResponse,
            user_id,
            DataValue::Container(vec![
                typed(DataType::Uuid, DataValue::Str(enrollment_id.to_string()))?,
                typed(DataType::OpaqueMessage, DataValue::Bytes(response))?,
            ]),
            PASSWORD_RESPONSE_SIGNATURE,
            PASSWORD_RESPONSE_ENCRYPTION,
        )
        .await
    }

    pub(super) async fn handle_password_enrollment_finish(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        match self.enrollment_finish(frame).await {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password enrollment finish failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    async fn enrollment_finish(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let opened = self
            .open_password_command(frame, CommunicationType::PasswordEnrollmentFinish)
            .await?;
        let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
        let enrollment_id = session(opened.content())?;
        let (_, (pending_user, started)) = self
            .password_auth
            .enrollments
            .remove(&enrollment_id)
            .ok_or("enrollment expired")?;
        if pending_user != user_id || started.elapsed() >= self.password_auth.pending_ttl {
            return Err("enrollment mismatch".into());
        }
        let upload = bytes(opened.content(), DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let encrypted = bytes(
            opened.content(),
            DataType::EncryptedCredential,
            MAX_CREDENTIAL_BYTES,
        )?;
        let version = positive(opened.content(), DataType::CredentialFormatVersion)?;
        if version != 1 {
            return Err("unsupported credential format".into());
        }
        let opaque_record =
            password::registration_finish(&upload).map_err(|error| error.to_string())?;
        let profile = user_manager::get_user(user_id)
            .map_err(|error| error.to_string())?
            .ok_or("account not hosted")?;
        let fingerprint = key_fingerprint(&profile.public_key)?;
        let now = now_millis() as i64;
        password_credentials::upsert(&PasswordCredential {
            user_id,
            protocol_version: 1,
            credential_format_version: version,
            opaque_record,
            encrypted_tu_credential: encrypted,
            account_public_key_sha256: fingerprint,
            created_at: now,
            updated_at: now,
        })
        .map_err(|error| error.to_string())?;
        self.password_auth
            .logins
            .retain(|_, pending| pending.user_id != user_id);
        self.protected_response(
            frame,
            CommunicationType::PasswordEnrollmentStatus,
            user_id,
            DataValue::Container(vec![typed(DataType::Enabled, DataValue::Bool(true))?]),
            PASSWORD_RESPONSE_SIGNATURE,
            PASSWORD_RESPONSE_ENCRYPTION,
        )
        .await
    }

    pub(super) async fn handle_password_enrollment_status(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        let result = async {
            let opened = self
                .open_password_command(frame, CommunicationType::PasswordEnrollmentStatus)
                .await?;
            let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
            let enabled =
                password_credentials::exists(user_id).map_err(|error| error.to_string())?;
            self.protected_response(
                frame,
                CommunicationType::PasswordEnrollmentStatus,
                user_id,
                DataValue::Container(vec![typed(DataType::Enabled, DataValue::Bool(enabled))?]),
                PASSWORD_RESPONSE_SIGNATURE,
                PASSWORD_RESPONSE_ENCRYPTION,
            )
            .await
        }
        .await;
        match result {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password status failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    pub(super) async fn handle_password_enrollment_disable(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        let result = async {
            let opened = self
                .open_password_command(frame, CommunicationType::PasswordEnrollmentDisable)
                .await?;
            let user_id = i64::try_from(opened.signer_id()).map_err(|error| error.to_string())?;
            password_credentials::delete(user_id).map_err(|error| error.to_string())?;
            self.password_auth
                .logins
                .retain(|_, pending| pending.user_id != user_id);
            self.protected_response(
                frame,
                CommunicationType::PasswordEnrollmentStatus,
                user_id,
                DataValue::Container(vec![typed(DataType::Enabled, DataValue::Bool(false))?]),
                PASSWORD_RESPONSE_SIGNATURE,
                PASSWORD_RESPONSE_ENCRYPTION,
            )
            .await
        }
        .await;
        match result {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password disable failed: {error}");
                self.password_error(frame, CommunicationType::ErrorInvalidData)
                    .await;
            }
        }
    }

    pub(super) async fn handle_password_provisioning_start(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        match self.provisioning_start(frame).await {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password KE1 failed: {error}");
                self.password_error(frame, CommunicationType::ErrorNotAuthenticated)
                    .await;
            }
        }
    }

    async fn provisioning_start(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let content = frame.payload();
        let id = session(content)?;
        let participant_id = u64::try_from(positive(content, DataType::ProvisioningParticipantId)?)
            .map_err(|error| error.to_string())?;
        let user_id = positive(content, DataType::UserId)?;
        let iota_id = positive(content, DataType::IotaId)?;
        if Some(iota_id as u64) != iota_storage::util::config_util::CONFIG.load().iota_id {
            return Err("wrong Iota".into());
        }
        if self.password_auth.logins.len() >= self.password_auth.max_pending
            || !self.password_auth.allow_attempt(user_id)
        {
            return Err("password attempt limit reached".into());
        }
        let contact_key = public_key(content)?;
        let ke1 = bytes(content, DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let principal = self.password_principal(user_id).await?;
        let context = password::login_context(&principal, iota_id, id, &contact_key)
            .map_err(|error| error.to_string())?;
        let credential = password_credentials::get(user_id).map_err(|error| error.to_string())?;
        let setup = self
            .password_auth
            .setup
            .get()
            .ok_or("OPAQUE setup unavailable")?;
        let response = password::login_start(
            setup,
            credential
                .as_ref()
                .map(|value| value.opaque_record.as_slice()),
            &ke1,
            principal.as_bytes(),
            &password::server_identifier(iota_id),
            &context,
        )
        .map_err(|error| error.to_string())?;
        let pending = PendingLogin {
            user_id,
            participant_id,
            contact_key,
            context,
            state: response.state,
            real_record: credential.is_some(),
            created: Instant::now(),
            record_hash: credential
                .as_ref()
                .map(|value| Sha256::digest(&value.opaque_record).to_vec()),
        };
        match self.password_auth.logins.entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(pending);
            }
            Entry::Occupied(_) => return Err("session already started".into()),
        }
        Ok(
            CommunicationValue::new(CommunicationType::PasswordProvisioningResponse)
                .with_id(frame.id().ok_or("missing request ID")?)
                .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
                .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(response.response)),
        )
    }

    pub(super) async fn handle_password_provisioning_finish(
        self: Arc<Self>,
        frame: &CommunicationValue,
    ) {
        match self.provisioning_finish(frame).await {
            Ok(response) => {
                let _ = self.send_message(&response).await;
            }
            Err(error) => {
                iota_logger::log!("Password KE3 failed: {error}");
                self.password_error(frame, CommunicationType::ErrorNotAuthenticated)
                    .await;
            }
        }
    }

    async fn provisioning_finish(
        &self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let content = frame.payload();
        let id = session(content)?;
        let (_, pending) = self
            .password_auth
            .logins
            .remove(&id)
            .ok_or("OPAQUE session expired")?;
        if pending.created.elapsed() >= self.password_auth.pending_ttl
            || pending.user_id != positive(content, DataType::UserId)?
            || pending.participant_id
                != u64::try_from(positive(content, DataType::ProvisioningParticipantId)?)
                    .map_err(|error| error.to_string())?
            || pending
                .contact_key
                .try_as_bytes()
                .map_err(|error| error.to_string())?
                != public_key(content)?
                    .try_as_bytes()
                    .map_err(|error| error.to_string())?
        {
            return Err("OPAQUE session binding mismatch".into());
        }
        let iota_id = positive(content, DataType::IotaId)?;
        if Some(iota_id as u64) != iota_storage::util::config_util::CONFIG.load().iota_id {
            return Err("wrong Iota".into());
        }
        let ke3 = bytes(content, DataType::OpaqueMessage, MAX_OPAQUE_BYTES)?;
        let principal = self.password_principal(pending.user_id).await?;
        password::login_finish(
            &pending.state,
            &ke3,
            principal.as_bytes(),
            &password::server_identifier(iota_id),
            &pending.context,
        )
        .map_err(|error| error.to_string())?;
        if !pending.real_record {
            return Err("authentication failed".into());
        }
        let credential = password_credentials::get(pending.user_id)
            .map_err(|error| error.to_string())?
            .ok_or("credential unavailable")?;
        if pending.record_hash.as_deref()
            != Some(Sha256::digest(&credential.opaque_record).as_slice())
        {
            return Err("password credential changed during login".into());
        }
        let profile = user_manager::get_user(pending.user_id)
            .map_err(|error| error.to_string())?
            .ok_or("account unavailable")?;
        if credential.account_public_key_sha256 != key_fingerprint(&profile.public_key)?
            || credential.encrypted_tu_credential.is_empty()
            || credential.encrypted_tu_credential.len() > MAX_CREDENTIAL_BYTES
            || credential.credential_format_version != 1
        {
            return Err("credential stale".into());
        }
        let content = DataValue::Container(vec![
            typed(DataType::Uuid, DataValue::Str(id.to_string()))?,
            typed(
                DataType::ProvisioningMethod,
                DataValue::Str("password".into()),
            )?,
            typed(
                DataType::UserId,
                DataValue::SignedNumber(pending.user_id.into()),
            )?,
            typed(DataType::IotaId, DataValue::SignedNumber(iota_id.into()))?,
            typed(
                DataType::EncryptedCredential,
                DataValue::Bytes(credential.encrypted_tu_credential),
            )?,
            typed(
                DataType::CredentialFormatVersion,
                DataValue::SignedNumber(credential.credential_format_version.into()),
            )?,
            typed(
                DataType::Sha256,
                DataValue::Bytes(credential.account_public_key_sha256),
            )?,
        ]);
        let keyring = self
            .keyring
            .read()
            .await
            .clone()
            .ok_or("Iota keyring unavailable")?;
        self.build_protected(
            frame,
            CommunicationType::ProvisioningCredential,
            iota_id as u64,
            pending.participant_id,
            content,
            pending.contact_key,
            PROVISIONING_CREDENTIAL_SIGNATURE,
            PROVISIONING_CREDENTIAL_ENCRYPTION,
            &keyring,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp::{codec::InMemoryReplayGuard, crypto::Keyring};

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
