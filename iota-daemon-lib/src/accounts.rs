use async_trait::async_trait;
use iota_identity::{
    AuthorityKind, LocalNodeIdentity, LocalUserDescriptor, LocalUserId, PrincipalHome,
};
use iota_storage::users::pending_operations::{
    self, PendingUserOperation, PendingUserOperationKind, PendingUserOperationPhase,
};
use iota_storage::users::user_manager;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use omikron_connector::{OmikronClient, OmikronError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateUserRequest {
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAccount {
    pub user: LocalUserId,
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPreview {
    pub user: LocalUserId,
    pub username: String,
    pub assigned_iota_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileResult {
    pub remote_iota_id: Option<i64>,
    pub released_locally: bool,
}

#[derive(Debug)]
pub enum AccountError {
    InvalidRequest(String),
    Unauthorized(String),
    NotFound,
    Conflict(String),
    Timeout(String),
    Unavailable(String),
    Storage(String),
    Internal(String),
}

#[async_trait]
pub trait AccountAuthority: Send + Sync {
    async fn is_available(&self) -> bool;

    async fn create_user(&self, request: CreateUserRequest) -> Result<LocalAccount, AccountError>;

    async fn inspect_credential(
        &self,
        credential: &[u8],
    ) -> Result<CredentialPreview, AccountError>;

    async fn attach_user(&self, credential: &[u8]) -> Result<LocalAccount, AccountError>;

    async fn reconcile_user(&self, user: LocalUserId) -> Result<ReconcileResult, AccountError>;

    async fn release_user(&self, user: LocalUserId) -> Result<(), AccountError>;

    async fn delete_user(&self, user: LocalUserId, credential: &[u8]) -> Result<(), AccountError>;

    async fn reconcile_managed_users(&self) -> Result<(), AccountError>;
}

pub struct OmegaAccountAuthority {
    client: Arc<dyn OmikronClient>,
}

pub struct LocalIotaAccountAuthority {
    identity: LocalNodeIdentity,
    creation_lock: Mutex<()>,
}

impl LocalIotaAccountAuthority {
    pub fn new(identity: LocalNodeIdentity) -> Self {
        Self {
            identity,
            creation_lock: Mutex::new(()),
        }
    }
}

#[async_trait]
impl AccountAuthority for LocalIotaAccountAuthority {
    async fn is_available(&self) -> bool {
        true
    }

    async fn create_user(&self, request: CreateUserRequest) -> Result<LocalAccount, AccountError> {
        if !valid_username(&request.username) {
            return Err(AccountError::InvalidRequest("invalid username".into()));
        }
        let _creation = self
            .creation_lock
            .lock()
            .map_err(|_| AccountError::Internal("local account lock is poisoned".into()))?;
        if user_manager::get_user_by_username(&request.username)
            .map_err(|error| AccountError::Storage(error.to_string()))?
            .is_some()
        {
            return Err(AccountError::Conflict("username is unavailable".into()));
        }
        let user_id = user_manager::allocate_local_user_id(iota_util::tu::MAX_PROTOCOL_ID)
            .map_err(|error| AccountError::Storage(error.to_string()))?;
        let keyring = iota_util::crypto_helper::generate_keyring();
        let public_key =
            iota_util::crypto_helper::public_key_bundle_to_base64(&keyring.public_key_bundle());
        if public_key.is_empty() {
            return Err(AccountError::Internal(
                "generated user public key could not be encoded".into(),
            ));
        }
        let credential = iota_util::tu::TuCredential {
            user_id,
            authority: iota_util::tu::TuAuthority::Iota(self.identity.node_id().clone()),
            keyring,
        };
        iota_util::file_util::write_user_credential(
            &request.username,
            &credential.to_canonical_string(),
        )
        .map_err(|error| AccountError::Storage(error.to_string()))?;
        let profile = iota_storage::users::user_profile::UserProfile::new(
            user_id,
            request.username.clone(),
            None,
            public_key.clone(),
            None,
            None,
        );
        if let Err(error) = user_manager::try_add_user(profile) {
            let _ = iota_util::file_util::remove_user_credential(user_id, Some(&request.username));
            return Err(AccountError::Storage(error.to_string()));
        }
        let principal = iota_storage::identity::SqlitePrincipalStore.ensure_local_principal(
            self.identity.authority_id(),
            AuthorityKind::Iota,
            &LocalUserDescriptor {
                id: LocalUserId(user_id),
                username: request.username.clone(),
                display_name: None,
                public_key,
            },
            PrincipalHome::Iota(self.identity.node_id().clone()),
            now_millis(),
        );
        if let Err(error) = principal {
            let _ = user_manager::remove_user(user_id);
            let _ = iota_util::file_util::remove_user_credential(user_id, Some(&request.username));
            return Err(AccountError::Storage(error.to_string()));
        }
        Ok(LocalAccount {
            user: LocalUserId(user_id),
            username: request.username,
        })
    }

    async fn inspect_credential(
        &self,
        credential: &[u8],
    ) -> Result<CredentialPreview, AccountError> {
        let credential = parse_local_credential(credential, &self.identity)?;
        let user = user_manager::get_user(credential.user_id)
            .map_err(|error| AccountError::Storage(error.to_string()))?
            .ok_or(AccountError::NotFound)?;
        if user.public_key
            != iota_util::crypto_helper::public_key_bundle_to_base64(
                &credential.public_key_bundle(),
            )
        {
            return Err(AccountError::Unauthorized(
                "credential key does not match local account".into(),
            ));
        }
        Ok(CredentialPreview {
            user: LocalUserId(user.user_id),
            username: user.username,
            assigned_iota_id: None,
        })
    }

    async fn attach_user(&self, credential: &[u8]) -> Result<LocalAccount, AccountError> {
        let preview = self.inspect_credential(credential).await?;
        Ok(LocalAccount {
            user: preview.user,
            username: preview.username,
        })
    }

    async fn reconcile_user(&self, user: LocalUserId) -> Result<ReconcileResult, AccountError> {
        if user_manager::get_user(user.0)
            .map_err(|error| AccountError::Storage(error.to_string()))?
            .is_none()
        {
            return Err(AccountError::NotFound);
        }
        Ok(ReconcileResult {
            remote_iota_id: None,
            released_locally: false,
        })
    }

    async fn release_user(&self, _: LocalUserId) -> Result<(), AccountError> {
        Err(AccountError::InvalidRequest(
            "local Iota accounts cannot be released to another authority".into(),
        ))
    }

    async fn delete_user(&self, user: LocalUserId, credential: &[u8]) -> Result<(), AccountError> {
        let parsed = parse_local_credential(credential, &self.identity)?;
        if parsed.user_id != user.0 {
            return Err(AccountError::InvalidRequest(
                "credential user ID does not match deletion target".into(),
            ));
        }
        self.inspect_credential(credential).await?;
        user_manager::purge_user_data(user.0)
            .map_err(|error| AccountError::Storage(error.to_string()))?;
        iota_storage::identity::SqlitePrincipalStore
            .retire_local_principal(user, now_millis())
            .map_err(|error| AccountError::Storage(error.to_string()))?;
        user_manager::remove_user(user.0)
            .map_err(|error| AccountError::Storage(error.to_string()))?;
        iota_util::file_util::remove_user_credential(user.0, None)
            .map_err(|error| AccountError::Storage(error.to_string()))
    }

    async fn reconcile_managed_users(&self) -> Result<(), AccountError> {
        Ok(())
    }
}

fn parse_local_credential(
    credential: &[u8],
    identity: &LocalNodeIdentity,
) -> Result<iota_util::tu::TuCredential, AccountError> {
    let credential = std::str::from_utf8(credential)
        .map_err(|_| AccountError::InvalidRequest("credential is not UTF-8".into()))?;
    let credential = iota_util::tu::TuCredential::parse(credential)
        .map_err(|error| AccountError::InvalidRequest(error.to_string()))?;
    if credential
        .principal()
        .map_err(|error| AccountError::InvalidRequest(error.to_string()))?
        .authority
        != *identity.authority_id()
    {
        return Err(AccountError::Unauthorized(
            "credential belongs to another authority".into(),
        ));
    }
    Ok(credential)
}

fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 15
        && username
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

impl OmegaAccountAuthority {
    pub fn new(client: Arc<dyn OmikronClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AccountAuthority for OmegaAccountAuthority {
    async fn is_available(&self) -> bool {
        self.client.is_connected().await
    }

    async fn create_user(&self, request: CreateUserRequest) -> Result<LocalAccount, AccountError> {
        omikron_connector::user_ops::create_user(self.client.as_ref(), &request.username)
            .await
            .map(|user| LocalAccount {
                user: LocalUserId(user.user_id),
                username: user.username,
            })
            .map_err(map_create_error)
    }

    async fn inspect_credential(
        &self,
        credential: &[u8],
    ) -> Result<CredentialPreview, AccountError> {
        let credential = std::str::from_utf8(credential)
            .map_err(|_| AccountError::InvalidRequest("credential is not UTF-8".into()))?;
        omikron_connector::user_ops::inspect_tu_credential(self.client.as_ref(), credential)
            .await
            .map(|preview| CredentialPreview {
                user: LocalUserId(preview.user_id),
                username: preview.username,
                assigned_iota_id: preview.assigned_iota_id,
            })
            .map_err(map_lifecycle_error)
    }

    async fn attach_user(&self, credential: &[u8]) -> Result<LocalAccount, AccountError> {
        let credential = std::str::from_utf8(credential)
            .map_err(|_| AccountError::InvalidRequest("credential is not UTF-8".into()))?;
        omikron_connector::user_ops::attach_user_from_tu(self.client.as_ref(), credential)
            .await
            .map(|user| LocalAccount {
                user: LocalUserId(user.user_id),
                username: user.username,
            })
            .map_err(map_lifecycle_error)
    }

    async fn reconcile_user(&self, user: LocalUserId) -> Result<ReconcileResult, AccountError> {
        let residency = user_manager::get_residency_by_id(user.0)
            .map_err(|error| AccountError::Storage(error.to_string()))?
            .ok_or(AccountError::NotFound)?;
        let remote_iota_id =
            omikron_connector::user_ops::get_remote_user_assignment(self.client.as_ref(), user.0)
                .await
                .map_err(map_lifecycle_error)?;
        let local_iota_id = iota_storage::util::config_util::CONFIG
            .load()
            .iota_id
            .and_then(|id| i64::try_from(id).ok());
        let released_locally = residency.state == user_manager::LocalUserState::Managed
            && remote_iota_id != local_iota_id;
        if released_locally {
            user_manager::finalize_local_release(user.0, Some(&residency.username))
                .map_err(|error| AccountError::Storage(error.to_string()))?;
        }
        Ok(ReconcileResult {
            remote_iota_id,
            released_locally,
        })
    }

    async fn release_user(&self, user: LocalUserId) -> Result<(), AccountError> {
        let profile = user_manager::get_user(user.0)
            .map_err(|error| AccountError::Storage(error.to_string()))?
            .ok_or(AccountError::NotFound)?;
        pending_operations::upsert(&PendingUserOperation {
            user_id: user.0,
            operation: PendingUserOperationKind::Release,
            username: profile.username,
            public_key: None,
            private_key_hash: None,
            reset_token: None,
            registration_token: None,
            phase: PendingUserOperationPhase::Prepared,
            created_at: now_millis(),
        })
        .map_err(|error| AccountError::Storage(error.to_string()))?;
        let request = CommunicationValue::new(CommunicationType::ReleaseUserFromIota)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user.0.into()));
        match self
            .client
            .await_response(&request, Duration::from_secs(20))
            .await
        {
            Ok(response) if response.is_type(CommunicationType::Success) => {
                user_manager::release_user(user.0)
                    .map_err(|error| AccountError::Storage(error.to_string()))?;
                pending_operations::remove(user.0)
                    .map_err(|error| AccountError::Storage(error.to_string()))
            }
            Ok(response) if response.is_type(CommunicationType::ErrorNotAuthenticated) => {
                let _ = pending_operations::remove(user.0);
                Err(AccountError::Unauthorized(
                    "release was not authorized".into(),
                ))
            }
            Ok(_) => {
                let _ = pending_operations::remove(user.0);
                Err(AccountError::Conflict("release was rejected".into()))
            }
            Err(OmikronError::Timeout(message)) => Err(AccountError::Timeout(message)),
            Err(error) => Err(AccountError::Unavailable(error.to_string())),
        }
    }

    async fn delete_user(&self, user: LocalUserId, credential: &[u8]) -> Result<(), AccountError> {
        let credential = std::str::from_utf8(credential)
            .map_err(|_| AccountError::InvalidRequest("credential is not UTF-8".into()))?;
        omikron_connector::user_ops::complete_delete_user_with_tu(
            self.client.as_ref(),
            credential,
            user.0,
        )
        .await
        .map_err(map_lifecycle_error)
    }

    async fn reconcile_managed_users(&self) -> Result<(), AccountError> {
        omikron_connector::user_ops::reconcile_managed_users(self.client.as_ref()).await;
        Ok(())
    }
}

fn map_create_error(error: omikron_connector::user_ops::CreateUserError) -> AccountError {
    use omikron_connector::user_ops::CreateUserError;
    match error {
        CreateUserError::InvalidUsername => AccountError::InvalidRequest("invalid username".into()),
        CreateUserError::Transport(OmikronError::Timeout(message)) => {
            AccountError::Timeout(message)
        }
        CreateUserError::Transport(error) => AccountError::Unavailable(error.to_string()),
        CreateUserError::RemoteRejected => AccountError::Conflict("username is unavailable".into()),
        CreateUserError::LocalFinalizationPending { user_id } => {
            AccountError::Storage(format!("local finalization is pending for user {user_id}"))
        }
        CreateUserError::LocalPersistence(message) => AccountError::Storage(message),
        CreateUserError::InvalidResponse => {
            AccountError::Internal("Omega returned an invalid create-user response".into())
        }
    }
}

fn map_lifecycle_error(error: omikron_connector::user_ops::LifecycleUserError) -> AccountError {
    use omikron_connector::user_ops::LifecycleUserError;
    match error {
        LifecycleUserError::InvalidCredential(message) => AccountError::Unauthorized(message),
        LifecycleUserError::OmegaHostMismatch => {
            AccountError::Unauthorized("credential belongs to another Omega".into())
        }
        LifecycleUserError::RemoteRejected => {
            AccountError::Unauthorized("credential was rejected".into())
        }
        LifecycleUserError::Transport(OmikronError::Timeout(message)) => {
            AccountError::Timeout(message)
        }
        LifecycleUserError::Transport(error) => AccountError::Unavailable(error.to_string()),
        LifecycleUserError::LocalPersistence(message) => AccountError::Storage(message),
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}
