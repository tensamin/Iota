use iota_identity::{
    AuthorityId, AuthorityKind, IdentityError, LocalDescriptorPublisher, LocalUserDescriptor,
    LocalUserId, LocalUserStore, PrincipalDescriptor, PrincipalHandle, PrincipalHome, PrincipalId,
    PrincipalStore, PublicKeyBundle, ResolvedPrincipal, SignedPrincipalDescriptor,
};
use iota_util::crypto_helper::{public_key_bundle_from_base64, public_key_bundle_to_base64};
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::users::user_manager;
use crate::util::db;

const LOCAL_DESCRIPTOR_LIFETIME_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
const LOCAL_DESCRIPTOR_RENEWAL_MILLIS: i64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Default)]
pub struct SqliteLocalUserStore;

impl LocalUserStore for SqliteLocalUserStore {
    fn get_local_user(
        &self,
        id: LocalUserId,
    ) -> Result<Option<LocalUserDescriptor>, IdentityError> {
        user_manager::get_user(id.0)
            .map_err(storage_error)
            .map(|user| user.map(local_descriptor))
    }

    fn get_local_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<LocalUserDescriptor>, IdentityError> {
        user_manager::get_user_by_username(username)
            .map_err(storage_error)
            .map(|user| user.map(local_descriptor))
    }

    fn is_hosted_here(&self, id: LocalUserId) -> Result<bool, IdentityError> {
        self.get_local_user(id).map(|user| user.is_some())
    }

    fn local_user_for_principal(
        &self,
        principal: PrincipalHandle,
    ) -> Result<Option<LocalUserId>, IdentityError> {
        db::with_db(|connection| {
            connection
                .query_row(
                    "SELECT local_user_id FROM hosted_principals WHERE principal_handle = ?1",
                    [principal.0],
                    |row| row.get::<_, i64>(0).map(LocalUserId),
                )
                .optional()
                .map_err(Into::into)
        })
        .map_err(storage_error)
    }

    fn principal_for_local_user(
        &self,
        user: LocalUserId,
    ) -> Result<Option<PrincipalHandle>, IdentityError> {
        SqlitePrincipalStore.principal_for_local_user(user)
    }
}

fn local_descriptor(user: crate::users::user_profile::UserProfile) -> LocalUserDescriptor {
    LocalUserDescriptor {
        id: LocalUserId(user.user_id),
        username: user.username,
        display_name: user.display_name,
        public_key: user.public_key,
    }
}

#[derive(Default)]
pub struct SqlitePrincipalStore;

impl SqlitePrincipalStore {
    pub fn principal_for_local_user(
        &self,
        user: LocalUserId,
    ) -> Result<Option<PrincipalHandle>, IdentityError> {
        db::with_db(|connection| {
            connection
                .query_row(
                    "SELECT principal_handle FROM hosted_principals WHERE local_user_id = ?1",
                    [user.0],
                    |row| row.get::<_, i64>(0).map(PrincipalHandle),
                )
                .optional()
                .map_err(Into::into)
        })
        .map_err(storage_error)
    }

    pub fn migrate_legacy_omega_authority(
        &self,
        authority: &AuthorityId,
    ) -> Result<(), IdentityError> {
        db::with_immediate_transaction(|transaction| {
            transaction.execute(
                "INSERT INTO identity_configuration (singleton, omega_authority_id) VALUES (1, ?1) ON CONFLICT(singleton) DO UPDATE SET omega_authority_id = excluded.omega_authority_id",
                [authority.as_str()],
            )?;
            let mut statement = transaction.prepare(
                "SELECT principal_pk, remote_user_id FROM principals WHERE authority_id = 'omega:central'",
            )?;
            let legacy = statement
                .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            for (legacy_handle, user_id) in legacy {
                let current_handle = transaction
                    .query_row(
                        "SELECT principal_pk FROM principals WHERE authority_id = ?1 AND remote_user_id = ?2",
                        params![authority.as_str(), user_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?;
                if let Some(current_handle) = current_handle {
                    transaction.execute(
                        "INSERT OR IGNORE INTO principal_keys (principal_pk, public_key, valid_from, valid_until, source_revision) SELECT ?1, public_key, valid_from, valid_until, source_revision FROM principal_keys WHERE principal_pk = ?2",
                        params![current_handle, legacy_handle],
                    )?;
                    for (table, column) in [
                        ("contacts", "principal_handle"),
                        ("messages", "external_principal"),
                        ("relay_replay", "signer_principal"),
                        ("relay_inbox", "signer_principal"),
                        ("pending_relays", "destination_principal"),
                        ("blocked_users", "blocked_principal"),
                    ] {
                        transaction.execute(
                            &format!("UPDATE {table} SET {column} = ?1 WHERE {column} = ?2"),
                            params![current_handle, legacy_handle],
                        )?;
                    }
                    transaction.execute(
                        "DELETE FROM principals WHERE principal_pk = ?1",
                        [legacy_handle],
                    )?;
                } else {
                    transaction.execute(
                        "UPDATE principals SET authority_id = ?1 WHERE principal_pk = ?2",
                        params![authority.as_str(), legacy_handle],
                    )?;
                }
            }
            transaction.execute_batch(
                "CREATE TEMP TABLE IF NOT EXISTS observed_omega_users (user_id INTEGER PRIMARY KEY); DELETE FROM observed_omega_users; INSERT OR IGNORE INTO observed_omega_users SELECT user_id FROM users WHERE user_id > 0; INSERT OR IGNORE INTO observed_omega_users SELECT user_id FROM contacts WHERE user_id > 0; INSERT OR IGNORE INTO observed_omega_users SELECT external_user FROM messages WHERE external_user > 0; INSERT OR IGNORE INTO observed_omega_users SELECT signer_id FROM relay_replay WHERE signer_id > 0; INSERT OR IGNORE INTO observed_omega_users SELECT signer_id FROM relay_inbox WHERE signer_id > 0; INSERT OR IGNORE INTO observed_omega_users SELECT destination_id FROM relay_inbox WHERE destination_id > 0; INSERT OR IGNORE INTO observed_omega_users SELECT relay_signer_id FROM pending_relays WHERE relay_signer_id > 0; INSERT OR IGNORE INTO observed_omega_users SELECT relay_destination_user_id FROM pending_relays WHERE relay_destination_user_id > 0; INSERT OR IGNORE INTO observed_omega_users SELECT blocked_user_id FROM blocked_users WHERE blocked_user_id > 0;"
            )?;
            transaction.execute(
                "INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', ?1, user_id, 0, 0 FROM observed_omega_users",
                [authority.as_str()],
            )?;
            for (table, principal_column, user_column) in [
                ("contacts", "principal_handle", "user_id"),
                ("messages", "external_principal", "external_user"),
                ("relay_replay", "signer_principal", "signer_id"),
                ("relay_inbox", "signer_principal", "signer_id"),
                ("pending_relays", "destination_principal", "relay_destination_user_id"),
                ("blocked_users", "blocked_principal", "blocked_user_id"),
            ] {
                transaction.execute(
                    &format!("UPDATE {table} SET {principal_column} = (SELECT principal_pk FROM principals WHERE authority_id = ?1 AND remote_user_id = {table}.{user_column}) WHERE {principal_column} IS NULL AND {user_column} IS NOT NULL"),
                    [authority.as_str()],
                )?;
            }
            Ok(())
        })
        .map_err(storage_error)
    }

    pub fn ensure_local_principal(
        &self,
        authority: &AuthorityId,
        authority_kind: AuthorityKind,
        user: &LocalUserDescriptor,
        home: PrincipalHome,
        resolved_at: i64,
    ) -> Result<PrincipalHandle, IdentityError> {
        let user_id = u64::try_from(user.id.0)
            .map_err(|_| IdentityError::InvalidDescriptor("negative local user ID".into()))?;
        let key = public_key_bundle_from_base64(&user.public_key)
            .ok_or_else(|| IdentityError::InvalidDescriptor("stored user key is invalid".into()))?;
        let encoded_home = encode_home(&home);
        let current = db::with_db(|connection| {
            connection
                .query_row(
                    r#"SELECT p.authority_kind, p.username, p.display_name, p.home,
                              p.descriptor_revision, p.descriptor_valid_until,
                              COALESCE(p.descriptor_issued_at, p.last_resolved_at), p.retired_at,
                              (SELECT public_key FROM principal_keys
                               WHERE principal_pk = p.principal_pk
                                 AND (valid_until IS NULL OR valid_until > ?3)
                               ORDER BY source_revision DESC LIMIT 1)
                       FROM principals p
                       WHERE p.authority_id = ?1 AND p.remote_user_id = ?2"#,
                    params![authority.as_str(), user.id.0, resolved_at],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<i64>>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Option<i64>>(7)?,
                            row.get::<_, Option<String>>(8)?,
                        ))
                    },
                )
                .optional()
                .map_err(Into::into)
        })
        .map_err(storage_error)?;
        if current.as_ref().is_some_and(|current| current.7.is_some()) {
            return Err(IdentityError::InvalidDescriptor(
                "retired local principal cannot be published".into(),
            ));
        }
        let signed_fields_match = current.as_ref().is_some_and(|current| {
            current.0 == authority_kind.as_str()
                && current.1.as_deref() == Some(user.username.as_str())
                && current.2.as_ref() == user.display_name.as_ref()
                && current.3.as_ref() == encoded_home.as_ref()
                && current.8.as_deref() == Some(user.public_key.as_str())
        });
        let current_valid_until = current.as_ref().and_then(|current| current.5);
        let renew_validity = current_valid_until
            .is_none_or(|valid_until| valid_until <= resolved_at + LOCAL_DESCRIPTOR_RENEWAL_MILLIS);
        let revision = current.as_ref().map_or(0, |current| {
            if signed_fields_match && !renew_validity {
                current.4
            } else {
                current.4.saturating_add(1)
            }
        });
        let issued_at = current.as_ref().map_or(resolved_at, |current| {
            if signed_fields_match && !renew_validity {
                current.6
            } else {
                resolved_at
            }
        });
        let valid_until = if signed_fields_match && !renew_validity {
            current_valid_until
        } else {
            Some(resolved_at.saturating_add(LOCAL_DESCRIPTOR_LIFETIME_MILLIS))
        };
        let descriptor = iota_identity::VerifiedPrincipalDescriptor::from_trusted_authority(
            PrincipalDescriptor {
                principal: PrincipalId {
                    authority: authority.clone(),
                    user_id,
                },
                authority_kind,
                username: Some(user.username.clone()),
                display_name: user.display_name.clone(),
                public_keys: vec![key],
                home,
                revision,
                valid_until,
                issued_at,
            },
        )?;
        let handle = self.upsert_remote_descriptor(&descriptor)?;
        db::with_immediate_transaction(|transaction| {
            transaction.execute(
                "INSERT INTO hosted_principals (local_user_id, principal_handle) VALUES (?1, ?2) ON CONFLICT(local_user_id) DO UPDATE SET principal_handle = excluded.principal_handle",
                params![user.id.0, handle.0],
            )?;
            Ok(())
        })
        .map_err(storage_error)?;
        Ok(handle)
    }

    pub fn local_principal_descriptor(
        &self,
        user: LocalUserId,
    ) -> Result<PrincipalDescriptor, IdentityError> {
        db::with_db(|connection| {
            let row = connection
                .query_row(
                    r#"SELECT p.authority_kind, p.authority_id, p.remote_user_id,
                              p.username, p.display_name, p.home,
                              p.descriptor_revision, p.descriptor_valid_until,
                              COALESCE(p.descriptor_issued_at, p.last_resolved_at)
                       FROM hosted_principals h
                       JOIN principals p ON p.principal_pk = h.principal_handle
                       WHERE h.local_user_id = ?1 AND p.retired_at IS NULL"#,
                    [user.0],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Option<i64>>(7)?,
                            row.get::<_, i64>(8)?,
                        ))
                    },
                )
                .optional()?;
            let Some((kind, authority, remote_user_id, username, display_name, home, revision, valid_until, issued_at)) = row else {
                return Ok(None);
            };
            let principal_pk = connection.query_row(
                "SELECT principal_handle FROM hosted_principals WHERE local_user_id = ?1",
                [user.0],
                |row| row.get::<_, i64>(0),
            )?;
            let mut statement = connection.prepare(
                "SELECT public_key FROM principal_keys WHERE principal_pk = ?1 AND valid_from <= ?2 AND (valid_until IS NULL OR valid_until > ?2) ORDER BY source_revision DESC",
            )?;
            let encoded = statement
                .query_map(params![principal_pk, issued_at], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some((kind, authority, remote_user_id, username, display_name, home, revision, valid_until, issued_at, encoded)))
        })
        .map_err(storage_error)?
        .ok_or(IdentityError::NotFound)
        .and_then(|(kind, authority, remote_user_id, username, display_name, home, revision, valid_until, issued_at, encoded)| {
            let authority_kind = match kind.as_str() {
                "iota" => AuthorityKind::Iota,
                "omega" => AuthorityKind::Omega,
                _ => return Err(IdentityError::InvalidDescriptor("stored authority kind is invalid".into())),
            };
            let public_keys = encoded
                .into_iter()
                .map(|key| public_key_bundle_from_base64(&key).ok_or_else(|| IdentityError::InvalidDescriptor("stored principal key is invalid".into())))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PrincipalDescriptor {
                principal: PrincipalId {
                    authority: AuthorityId::new(authority)?,
                    user_id: u64::try_from(remote_user_id).map_err(|_| IdentityError::InvalidDescriptor("stored principal user ID is negative".into()))?,
                },
                authority_kind,
                username,
                display_name,
                public_keys,
                home: decode_home(home.as_deref()).map_err(storage_error)?,
                revision,
                valid_until,
                issued_at,
            })
        })
    }

    /* Retire hosted identity after its data is purged. Keeping descriptor
     * revision state rejects descriptors issued before account removal. */
    pub fn retire_local_principal(
        &self,
        user: LocalUserId,
        retired_at: i64,
    ) -> Result<(), IdentityError> {
        db::with_immediate_transaction(|transaction| {
            let principal = transaction
                .query_row(
                    "SELECT principal_handle FROM hosted_principals WHERE local_user_id = ?1",
                    [user.0],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    crate::storage_error::StorageError::Other(
                        "hosted principal was not found".into(),
                    )
                })?;
            transaction.execute(
                "UPDATE principals SET descriptor_revision = descriptor_revision + 1, descriptor_valid_until = ?2, last_resolved_at = ?2, retired_at = ?2 WHERE principal_pk = ?1",
                params![principal, retired_at],
            )?;
            transaction.execute(
                "UPDATE principal_keys SET valid_until = MIN(COALESCE(valid_until, ?2), ?2) WHERE principal_pk = ?1",
                params![principal, retired_at],
            )?;
            transaction.execute(
                "DELETE FROM hosted_principals WHERE local_user_id = ?1",
                [user.0],
            )?;
            Ok(())
        })
        .map_err(storage_error)
    }
}

pub struct SqliteLocalDescriptorPublisher {
    identity: iota_identity::LocalNodeIdentity,
}

impl SqliteLocalDescriptorPublisher {
    pub fn new(identity: iota_identity::LocalNodeIdentity) -> Self {
        Self { identity }
    }
}

impl LocalDescriptorPublisher for SqliteLocalDescriptorPublisher {
    fn principal_descriptor(
        &self,
        user: LocalUserId,
    ) -> Result<SignedPrincipalDescriptor, IdentityError> {
        let local_user = SqliteLocalUserStore
            .get_local_user(user)?
            .ok_or(IdentityError::NotFound)?;
        SqlitePrincipalStore.ensure_local_principal(
            self.identity.authority_id(),
            AuthorityKind::Iota,
            &local_user,
            PrincipalHome::Iota(self.identity.node_id().clone()),
            now_millis(),
        )?;
        SignedPrincipalDescriptor::sign(
            SqlitePrincipalStore.local_principal_descriptor(user)?,
            &self.identity.keyring(),
        )
    }
}

pub struct LocalIdentityResolver {
    authority: AuthorityId,
    authority_kind: AuthorityKind,
    home: PrincipalHome,
    local_users: Arc<dyn LocalUserStore>,
    principals: Arc<SqlitePrincipalStore>,
}

impl LocalIdentityResolver {
    pub fn new(
        authority: AuthorityId,
        authority_kind: AuthorityKind,
        home: PrincipalHome,
        local_users: Arc<dyn LocalUserStore>,
        principals: Arc<SqlitePrincipalStore>,
    ) -> Self {
        Self {
            authority,
            authority_kind,
            home,
            local_users,
            principals,
        }
    }

    fn resolve_local(&self, user: LocalUserDescriptor) -> Result<ResolvedPrincipal, IdentityError> {
        let handle = self.principals.ensure_local_principal(
            &self.authority,
            self.authority_kind,
            &user,
            self.home.clone(),
            now_millis(),
        )?;
        self.principals
            .get_principal(handle)?
            .ok_or(IdentityError::NotFound)
    }
}

#[async_trait::async_trait]
impl iota_identity::IdentityResolver for LocalIdentityResolver {
    async fn resolve_address(
        &self,
        address: &iota_identity::UserAddress,
        _: &iota_identity::ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        if let Some(address_authority) = &address.authority {
            let matches_home = matches!(
                &self.home,
                PrincipalHome::Omega(locator) if locator == address_authority
            );
            if address_authority.as_str() != self.authority.as_str() && !matches_home {
                return Err(IdentityError::NotFound);
            }
        }
        let user = match &address.selector {
            iota_identity::UserSelector::UserId(user_id) => {
                let user_id = i64::try_from(*user_id).map_err(|_| {
                    IdentityError::InvalidIdentifier("user ID exceeds local storage range".into())
                })?;
                self.local_users.get_local_user(LocalUserId(user_id))?
            }
            iota_identity::UserSelector::Username(username) => {
                self.local_users.get_local_user_by_username(username)?
            }
        }
        .ok_or(IdentityError::NotFound)?;
        let resolved = self.resolve_local(user)?;
        verify_pin(address.public_key_pin.as_ref(), &resolved.public_keys)?;
        Ok(resolved)
    }

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        if principal.authority != self.authority {
            return Err(IdentityError::NotFound);
        }
        let user_id = i64::try_from(principal.user_id).map_err(|_| {
            IdentityError::InvalidIdentifier("user ID exceeds local storage range".into())
        })?;
        let user = self
            .local_users
            .get_local_user(LocalUserId(user_id))?
            .ok_or(IdentityError::NotFound)?;
        self.resolve_local(user)
    }

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
        _: &iota_identity::ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        self.resolve_principal(principal)
            .await
            .map(|resolved| resolved.public_keys)
    }
}

fn verify_pin(
    pin: Option<&PublicKeyBundle>,
    keys: &[PublicKeyBundle],
) -> Result<(), IdentityError> {
    let Some(pin) = pin else {
        return Ok(());
    };
    let pin = pin
        .try_as_bytes()
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
    let matches = keys.iter().any(|key| {
        key.try_as_bytes()
            .map(|candidate| candidate == pin)
            .unwrap_or(false)
    });
    if matches {
        Ok(())
    } else {
        Err(IdentityError::KeyPinMismatch)
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

impl PrincipalStore for SqlitePrincipalStore {
    fn get_principal(
        &self,
        handle: PrincipalHandle,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        db::with_db(|connection| load_principal(connection, "p.principal_pk = ?1", handle.0))
            .map_err(storage_error)
    }

    fn get_by_canonical_id(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        let remote_user_id = i64::try_from(principal.user_id).map_err(|_| {
            IdentityError::InvalidIdentifier("principal user ID exceeds storage range".into())
        })?;
        db::with_db(|connection| {
            let handle = connection
                .query_row(
                    "SELECT principal_pk FROM principals WHERE authority_id = ?1 AND remote_user_id = ?2",
                    params![principal.authority.as_str(), remote_user_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            match handle {
                Some(handle) => load_principal(connection, "p.principal_pk = ?1", handle),
                None => Ok(None),
            }
        })
        .map_err(storage_error)
    }

    fn get_by_username(
        &self,
        authority: &AuthorityId,
        username: &str,
    ) -> Result<Option<ResolvedPrincipal>, IdentityError> {
        db::with_db(|connection| {
            let handle = connection
                .query_row(
                    "SELECT principal_pk FROM principals WHERE authority_id = ?1 AND username = ?2 AND retired_at IS NULL",
                    params![authority.as_str(), username],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            match handle {
                Some(handle) => load_principal(connection, "p.principal_pk = ?1", handle),
                None => Ok(None),
            }
        })
        .map_err(storage_error)
    }

    fn upsert_remote_descriptor(
        &self,
        descriptor: &iota_identity::VerifiedPrincipalDescriptor,
    ) -> Result<PrincipalHandle, IdentityError> {
        let resolved_at = descriptor.resolved_at();
        let descriptor = descriptor.descriptor();
        if descriptor.public_keys.is_empty() {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor contains no signing keys".into(),
            ));
        }
        if descriptor.revision < 0 {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor revision is negative".into(),
            ));
        }
        if descriptor
            .valid_until
            .is_some_and(|valid_until| valid_until <= resolved_at)
        {
            return Err(IdentityError::InvalidDescriptor(
                "principal descriptor is already expired".into(),
            ));
        }
        let remote_user_id = i64::try_from(descriptor.principal.user_id).map_err(|_| {
            IdentityError::InvalidIdentifier("principal user ID exceeds storage range".into())
        })?;
        let home = encode_home(&descriptor.home);
        db::with_immediate_transaction(|transaction| {
            let current = transaction
                .query_row(
                    "SELECT principal_pk, descriptor_revision, last_resolved_at, retired_at, authority_kind, username, display_name, home, descriptor_valid_until, descriptor_issued_at FROM principals WHERE authority_id = ?1 AND remote_user_id = ?2",
                    params![descriptor.principal.authority.as_str(), remote_user_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, Option<i64>>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<String>>(5)?, row.get::<_, Option<String>>(6)?, row.get::<_, Option<String>>(7)?, row.get::<_, Option<i64>>(8)?, row.get::<_, Option<i64>>(9)?)),
                )
                .optional()?;
            if let Some((handle, revision, current_resolved_at, retired_at, authority_kind, username, display_name, current_home, valid_until, issued_at)) = &current {
                if retired_at.is_some()
                    || *revision > descriptor.revision
                    || (*revision == descriptor.revision && *current_resolved_at > resolved_at)
                {
                    return Err(crate::storage_error::StorageError::Other(
                        "stale principal descriptor update was rejected".into(),
                    ));
                }
                if *revision == descriptor.revision {
                    let mut stored_keys = transaction
                        .prepare("SELECT public_key FROM principal_keys WHERE principal_pk = ?1 AND source_revision = ?2 ORDER BY public_key")?
                        .query_map(params![handle, revision], |row| row.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    let mut descriptor_keys = descriptor
                        .public_keys
                        .iter()
                        .map(public_key_bundle_to_base64)
                        .collect::<Vec<_>>();
                    stored_keys.sort();
                    descriptor_keys.sort();
                    if authority_kind != descriptor.authority_kind.as_str()
                        || username != &descriptor.username
                        || display_name != &descriptor.display_name
                        || current_home != &home
                        || valid_until != &descriptor.valid_until
                        || issued_at.is_some_and(|issued_at| issued_at != descriptor.issued_at)
                        || stored_keys != descriptor_keys
                    {
                        return Err(crate::storage_error::StorageError::Other(
                            "conflicting principal descriptor revision was rejected".into(),
                        ));
                    }
                }
                let mut previous_keys = transaction
                    .prepare("SELECT public_key FROM principal_keys WHERE principal_pk = ?1 AND source_revision = ?2 ORDER BY public_key")?
                    .query_map(params![handle, revision], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                let mut next_keys = descriptor.public_keys.iter().map(public_key_bundle_to_base64).collect::<Vec<_>>();
                previous_keys.sort();
                next_keys.sort();
                if previous_keys != next_keys {
                    transaction.execute(
                        "UPDATE hosted_auth_state SET generation = generation + 1 WHERE local_user_id IN (SELECT local_user_id FROM hosted_principals WHERE principal_handle = ?1)",
                        [handle],
                    )?;
                }
            }
            transaction.execute(
                r#"INSERT INTO principals (
                       authority_kind, authority_id, remote_user_id, username, display_name,
                       home, descriptor_revision, descriptor_valid_until, descriptor_issued_at,
                       last_resolved_at
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                   ON CONFLICT(authority_id, remote_user_id) DO UPDATE SET
                       authority_kind = excluded.authority_kind,
                       username = excluded.username,
                       display_name = excluded.display_name,
                       home = excluded.home,
                       descriptor_revision = excluded.descriptor_revision,
                       descriptor_valid_until = excluded.descriptor_valid_until,
                       descriptor_issued_at = excluded.descriptor_issued_at,
                       last_resolved_at = excluded.last_resolved_at"#,
                params![
                    descriptor.authority_kind.as_str(),
                    descriptor.principal.authority.as_str(),
                    remote_user_id,
                    descriptor.username,
                    descriptor.display_name,
                    home,
                    descriptor.revision,
                    descriptor.valid_until,
                    descriptor.issued_at,
                    resolved_at,
                ],
            )?;
            let handle = transaction.query_row(
                "SELECT principal_pk FROM principals WHERE authority_id = ?1 AND remote_user_id = ?2",
                params![descriptor.principal.authority.as_str(), remote_user_id],
                |row| row.get::<_, i64>(0),
            )?;
            transaction.execute(
                "UPDATE principal_keys SET valid_until = MIN(COALESCE(valid_until, ?2), ?2) WHERE principal_pk = ?1",
                params![handle, resolved_at],
            )?;
            for key in &descriptor.public_keys {
                let encoded = public_key_bundle_to_base64(key);
                if encoded.is_empty() {
                    return Err(crate::storage_error::StorageError::Other(
                        "principal signing key could not be encoded".into(),
                    ));
                }
                transaction.execute(
                    r#"INSERT INTO principal_keys (
                           principal_pk, public_key, valid_from, valid_until, source_revision
                       ) VALUES (?1, ?2, ?3, ?4, ?5)
                       ON CONFLICT(principal_pk, public_key) DO UPDATE SET
                           valid_until = excluded.valid_until,
                           source_revision = excluded.source_revision"#,
                    params![
                        handle,
                        encoded,
                        resolved_at,
                        descriptor.valid_until,
                        descriptor.revision,
                    ],
                )?;
            }
            Ok(PrincipalHandle(handle))
        })
        .map_err(storage_error)
    }

    fn signing_keys(&self, principal: &PrincipalId) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        let resolved = self
            .get_by_canonical_id(principal)?
            .ok_or(IdentityError::NotFound)?;
        if !resolved.is_valid_at(now_millis()) {
            return Err(IdentityError::Unavailable(
                "cached principal descriptor is expired".into(),
            ));
        }
        if resolved.public_keys.is_empty() {
            return Err(IdentityError::InvalidDescriptor(
                "principal has no current signing keys".into(),
            ));
        }
        Ok(resolved.public_keys)
    }
}

fn load_principal(
    connection: &rusqlite::Connection,
    predicate: &str,
    value: i64,
) -> Result<Option<ResolvedPrincipal>, crate::storage_error::StorageError> {
    let query = format!(
        "SELECT p.principal_pk, p.authority_id, p.remote_user_id, p.username, p.home, p.descriptor_revision, p.descriptor_valid_until, p.last_resolved_at FROM principals p WHERE {predicate}"
    );
    let row = connection
        .query_row(&query, [value], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .optional()?;
    let Some((
        handle,
        authority,
        remote_user_id,
        username,
        home,
        descriptor_revision,
        valid_until,
        resolved_at,
    )) = row
    else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT public_key FROM principal_keys WHERE principal_pk = ?1 AND valid_from <= ?2 AND (valid_until IS NULL OR valid_until > ?2) ORDER BY source_revision DESC, valid_from DESC",
    )?;
    let encoded = statement
        .query_map(params![handle, now_millis()], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut public_keys = Vec::with_capacity(encoded.len());
    for value in encoded {
        let key = public_key_bundle_from_base64(&value).ok_or_else(|| {
            crate::storage_error::StorageError::Other("stored principal key is invalid".into())
        })?;
        public_keys.push(key);
    }
    let authority = AuthorityId::new(authority)
        .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()))?;
    let user_id = u64::try_from(remote_user_id).map_err(|_| {
        crate::storage_error::StorageError::Other("stored principal user ID is negative".into())
    })?;
    Ok(Some(ResolvedPrincipal {
        principal: PrincipalId { authority, user_id },
        handle: PrincipalHandle(handle),
        username,
        public_keys,
        home: decode_home(home.as_deref())?,
        descriptor_revision,
        valid_until,
        resolved_at,
    }))
}

fn encode_home(home: &PrincipalHome) -> Option<String> {
    match home {
        PrincipalHome::Iota(id) => Some(format!("iota:{}", id.as_str())),
        PrincipalHome::LegacyOmegaIota { omega, iota_id } => {
            Some(format!("legacy_omega_iota:{}:{iota_id}", omega.as_str()))
        }
        PrincipalHome::Omega(locator) => Some(format!("omega:{}", locator.as_str())),
        PrincipalHome::Unknown => None,
    }
}

fn decode_home(home: Option<&str>) -> Result<PrincipalHome, crate::storage_error::StorageError> {
    let Some(home) = home else {
        return Ok(PrincipalHome::Unknown);
    };
    if let Some(id) = home.strip_prefix("iota:") {
        return iota_identity::IotaNodeId::new(id)
            .map(PrincipalHome::Iota)
            .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()));
    }
    if let Some(value) = home.strip_prefix("legacy_omega_iota:") {
        let (omega, iota_id) = value.rsplit_once(':').ok_or_else(|| {
            crate::storage_error::StorageError::Other(
                "stored legacy Omega Iota home is invalid".into(),
            )
        })?;
        let omega = AuthorityId::new(omega)
            .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()))?;
        let iota_id = iota_id.parse::<u64>().map_err(|_| {
            crate::storage_error::StorageError::Other(
                "stored legacy Omega Iota ID is invalid".into(),
            )
        })?;
        return Ok(PrincipalHome::LegacyOmegaIota { omega, iota_id });
    }
    if let Some(locator) = home.strip_prefix("omega:") {
        return iota_identity::AuthorityLocator::new(locator)
            .map(PrincipalHome::Omega)
            .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()));
    }
    Err(crate::storage_error::StorageError::Other(
        "stored principal home is invalid".into(),
    ))
}

fn storage_error(error: impl std::fmt::Display) -> IdentityError {
    IdentityError::Storage(error.to_string())
}
