use crate::{storage_error::StorageError, users::user_profile::UserProfile, util::db};
use rusqlite::{OptionalExtension, params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationAuthority {
    Omega,
    Iota,
}

impl InvitationAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Omega => "omega",
            Self::Iota => "iota",
        }
    }

    pub fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "omega" => Ok(Self::Omega),
            "iota" => Ok(Self::Iota),
            _ => Err(StorageError::Other("unknown invitation authority".into())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingAction {
    Revoke,
}

impl PendingAction {
    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "revoke" => Ok(Self::Revoke),
            _ => Err(StorageError::Other(
                "unknown pending invitation action".into(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningResult {
    Created,
    AlreadyApplied,
    RevocationPending,
    MissingInvitation,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationState {
    Pending,
    Provisioning,
    Redeemed,
    Revoked,
    Expired,
}

impl InvitationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Provisioning => "provisioning",
            Self::Redeemed => "redeemed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "pending" => Ok(Self::Pending),
            "provisioning" => Ok(Self::Provisioning),
            "redeemed" => Ok(Self::Redeemed),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err(StorageError::Other("unknown invitation state".into())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationSummary {
    pub invitation_id: i64,
    pub authority: InvitationAuthority,
    pub label: Option<String>,
    pub password_protected: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub state: InvitationState,
    pub remote_revision: i64,
    pub redeemed_user_id: Option<i64>,
    pub redeemed_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub pending_action: Option<PendingAction>,
    pub pending_action_at: Option<i64>,
    pub last_synced_at: Option<i64>,
    pub local_provisioned_user_id: Option<i64>,
    pub local_provisioned_at: Option<i64>,
}

pub fn insert(
    summary: &InvitationSummary,
    token_hash: Option<&[u8]>,
    synced_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| insert_in_tx(tx, summary, token_hash, synced_at))
}

pub fn merge_omega_snapshot(
    invitations: &[InvitationSummary],
    synced_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        for invitation in invitations {
            insert_in_tx(tx, invitation, None, synced_at)?;
        }
        Ok(())
    })
}

fn insert_in_tx(
    tx: &rusqlite::Transaction<'_>,
    summary: &InvitationSummary,
    token_hash: Option<&[u8]>,
    synced_at: i64,
) -> Result<(), StorageError> {
    tx.execute(
            "INSERT INTO user_invitations (invitation_id, authority, token_hash, label, password_protected, created_at, expires_at, state, redeemed_user_id, redeemed_at, revoked_at, pending_action, pending_action_at, remote_revision, last_synced_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL, ?12, ?13) ON CONFLICT(invitation_id) DO UPDATE SET authority = excluded.authority, token_hash = excluded.token_hash, label = excluded.label, password_protected = excluded.password_protected, expires_at = excluded.expires_at, state = excluded.state, redeemed_user_id = excluded.redeemed_user_id, redeemed_at = excluded.redeemed_at, revoked_at = excluded.revoked_at, remote_revision = excluded.remote_revision, last_synced_at = excluded.last_synced_at WHERE excluded.remote_revision >= user_invitations.remote_revision",
            params![summary.invitation_id, summary.authority.as_str(), token_hash, summary.label, summary.password_protected, summary.created_at, summary.expires_at, summary.state.as_str(), summary.redeemed_user_id, summary.redeemed_at, summary.revoked_at, summary.remote_revision, synced_at],
        )?;
    Ok(())
}

pub fn list() -> Result<Vec<InvitationSummary>, StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare("SELECT invitation_id, authority, label, password_protected, created_at, expires_at, state, remote_revision, redeemed_user_id, redeemed_at, revoked_at, pending_action, pending_action_at, last_synced_at, local_provisioned_user_id, local_provisioned_at FROM user_invitations ORDER BY created_at DESC")?;
        Ok(statement
            .query_map([], |row| {
                Ok(InvitationSummary {
                    invitation_id: row.get(0)?,
                    authority: InvitationAuthority::parse(&row.get::<_, String>(1)?).map_err(
                        |error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)),
                    )?,
                    label: row.get(2)?,
                    password_protected: row.get(3)?,
                    created_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    state: InvitationState::parse(&row.get::<_, String>(6)?).map_err(|error| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                    })?,
                    remote_revision: row.get(7)?,
                    redeemed_user_id: row.get(8)?,
                    redeemed_at: row.get(9)?,
                    revoked_at: row.get(10)?,
                    pending_action: row
                        .get::<_, Option<String>>(11)?
                        .map(|value| PendingAction::parse(&value))
                        .transpose()
                        .map_err(|error| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                        })?,
                    pending_action_at: row.get(12)?,
                    last_synced_at: row.get(13)?,
                    local_provisioned_user_id: row.get(14)?,
                    local_provisioned_at: row.get(15)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    })
}

pub fn expire_pending(now: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE user_invitations SET state = 'expired' WHERE authority = 'iota' AND state = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        Ok(())
    })
}

pub fn mark_revoke_pending(invitation_id: i64, requested_at: i64) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| mark_revoke_pending_in_tx(tx, invitation_id, requested_at))
}

fn mark_revoke_pending_in_tx(
    tx: &rusqlite::Transaction<'_>,
    invitation_id: i64,
    requested_at: i64,
) -> Result<bool, StorageError> {
    let changed = tx.execute(
        "UPDATE user_invitations SET pending_action = 'revoke', pending_action_at = COALESCE(pending_action_at, ?2) WHERE invitation_id = ?1 AND authority = 'omega' AND state IN ('pending', 'provisioning', 'revoked')",
        params![invitation_id, requested_at],
    )?;
    Ok(changed == 1)
}

pub fn apply_revoke_result(
    invitation_id: i64,
    state: InvitationState,
    remote_revision: i64,
    revoked_at: Option<i64>,
    synced_at: i64,
) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        let changed = tx.execute(
            "UPDATE user_invitations SET state = ?2, remote_revision = ?3, revoked_at = ?4, pending_action = NULL, pending_action_at = NULL, last_synced_at = ?5 WHERE invitation_id = ?1 AND ?3 >= remote_revision",
            params![invitation_id, state.as_str(), remote_revision, revoked_at, synced_at],
        )?;
        Ok(changed == 1)
    })
}

pub fn apply_external_invitation_provisioning(
    invitation_id: i64,
    invitation_revision: i64,
    user: &UserProfile,
    changed_at: i64,
) -> Result<ProvisioningResult, StorageError> {
    db::with_immediate_transaction(|tx| {
        apply_external_invitation_provisioning_in_tx(
            tx,
            invitation_id,
            invitation_revision,
            user,
            changed_at,
        )
    })
}

fn apply_external_invitation_provisioning_in_tx(
    tx: &rusqlite::Transaction<'_>,
    invitation_id: i64,
    invitation_revision: i64,
    user: &UserProfile,
    changed_at: i64,
) -> Result<ProvisioningResult, StorageError> {
    tx.execute(
        "UPDATE user_invitations SET state = 'provisioning', remote_revision = ?2, last_synced_at = ?3 WHERE invitation_id = ?1 AND authority = 'omega' AND ?2 >= remote_revision AND state NOT IN ('revoked', 'expired')",
        params![invitation_id, invitation_revision, changed_at],
    )?;
    let invitation = tx
            .query_row(
                "SELECT state, pending_action, redeemed_user_id FROM user_invitations WHERE invitation_id = ?1 AND authority = 'omega'",
                params![invitation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, Option<i64>>(2)?)),
            )
            .optional()?;
    let Some((state, pending_action, redeemed_user_id)) = invitation else {
        return Ok(ProvisioningResult::MissingInvitation);
    };
    if pending_action.as_deref() == Some("revoke") {
        return Ok(ProvisioningResult::RevocationPending);
    }
    if !matches!(state.as_str(), "pending" | "provisioning" | "redeemed")
        || redeemed_user_id.is_some_and(|id| id != user.user_id)
    {
        return Ok(ProvisioningResult::Conflict);
    }
    let existing = tx
        .query_row(
            "SELECT username, public_key FROM users WHERE user_id = ?1",
            params![user.user_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((username, public_key)) = existing {
        if username != user.username || public_key != user.public_key {
            return Ok(ProvisioningResult::Conflict);
        }
        tx.execute(
                "UPDATE user_invitations SET local_provisioned_user_id = ?2, local_provisioned_at = COALESCE(local_provisioned_at, ?3) WHERE invitation_id = ?1",
                params![invitation_id, user.user_id, changed_at],
            )?;
        return Ok(ProvisioningResult::AlreadyApplied);
    }
    tx.execute(
            "INSERT INTO users (user_id, username, public_key, private_key_hash, reset_token, created_at, display_name) VALUES (?1, ?2, ?3, NULL, NULL, ?4, NULL)",
            params![user.user_id, user.username, user.public_key, user.created_at],
        )?;
    tx.execute(
            "INSERT INTO user_residency (user_id, username, lifecycle_state, data_state, credential_origin, updated_at) VALUES (?1, ?2, 'managed', 'present', 'external', ?3)",
            params![user.user_id, user.username, changed_at],
        )?;
    tx.execute(
            "UPDATE user_invitations SET local_provisioned_user_id = ?2, local_provisioned_at = ?3 WHERE invitation_id = ?1",
            params![invitation_id, user.user_id, changed_at],
        )?;
    Ok(ProvisioningResult::Created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn database() -> Result<Connection, StorageError> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE user_invitations (invitation_id INTEGER PRIMARY KEY, authority TEXT NOT NULL, token_hash BLOB, label TEXT, password_protected INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, state TEXT NOT NULL, redeemed_user_id INTEGER, redeemed_at INTEGER, revoked_at INTEGER, pending_action TEXT, pending_action_at INTEGER, remote_revision INTEGER NOT NULL DEFAULT 0, last_synced_at INTEGER, local_provisioned_user_id INTEGER, local_provisioned_at INTEGER); CREATE TABLE users (user_id INTEGER PRIMARY KEY, username TEXT NOT NULL, public_key TEXT NOT NULL, private_key_hash TEXT, reset_token TEXT, created_at INTEGER NOT NULL, display_name TEXT); CREATE TABLE user_residency (user_id INTEGER PRIMARY KEY, username TEXT NOT NULL, lifecycle_state TEXT NOT NULL, data_state TEXT NOT NULL, credential_origin TEXT NOT NULL, updated_at INTEGER NOT NULL);",
        )?;
        Ok(connection)
    }

    fn summary(revision: i64, state: InvitationState) -> InvitationSummary {
        InvitationSummary {
            invitation_id: 7,
            authority: InvitationAuthority::Omega,
            label: None,
            password_protected: false,
            created_at: 10,
            expires_at: Some(20),
            state,
            remote_revision: revision,
            redeemed_user_id: None,
            redeemed_at: None,
            revoked_at: None,
            pending_action: None,
            pending_action_at: None,
            last_synced_at: None,
            local_provisioned_user_id: None,
            local_provisioned_at: None,
        }
    }

    fn profile(public_key: &str) -> UserProfile {
        UserProfile::new_with_created_at(9, "alice".into(), None, public_key.into(), None, None, 30)
    }

    #[test]
    fn offline_revoke_preserves_authoritative_state() -> Result<(), StorageError> {
        let mut connection = database()?;
        let tx = connection.transaction()?;
        insert_in_tx(&tx, &summary(3, InvitationState::Pending), None, 30)?;
        assert!(mark_revoke_pending_in_tx(&tx, 7, 31)?);
        let row: (String, Option<String>) = tx.query_row(
            "SELECT state, pending_action FROM user_invitations WHERE invitation_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(row, ("pending".into(), Some("revoke".into())));
        Ok(())
    }

    #[test]
    fn stale_snapshot_is_ignored_and_pending_action_is_preserved() -> Result<(), StorageError> {
        let mut connection = database()?;
        let tx = connection.transaction()?;
        insert_in_tx(&tx, &summary(5, InvitationState::Pending), None, 30)?;
        mark_revoke_pending_in_tx(&tx, 7, 31)?;
        insert_in_tx(&tx, &summary(4, InvitationState::Expired), None, 32)?;
        let stale: (String, i64, Option<String>) = tx.query_row(
            "SELECT state, remote_revision, pending_action FROM user_invitations WHERE invitation_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(stale, ("pending".into(), 5, Some("revoke".into())));
        insert_in_tx(&tx, &summary(6, InvitationState::Expired), None, 33)?;
        let fresh: (String, i64, Option<String>) = tx.query_row(
            "SELECT state, remote_revision, pending_action FROM user_invitations WHERE invitation_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(fresh, ("expired".into(), 6, Some("revoke".into())));
        Ok(())
    }

    #[test]
    fn provisioning_replay_is_idempotent_and_conflicts_do_not_overwrite() -> Result<(), StorageError>
    {
        let mut connection = database()?;
        let tx = connection.transaction()?;
        insert_in_tx(&tx, &summary(1, InvitationState::Pending), None, 30)?;
        assert_eq!(
            apply_external_invitation_provisioning_in_tx(&tx, 7, 2, &profile("key-a"), 31)?,
            ProvisioningResult::Created
        );
        assert_eq!(
            apply_external_invitation_provisioning_in_tx(&tx, 7, 2, &profile("key-a"), 32)?,
            ProvisioningResult::AlreadyApplied
        );
        assert_eq!(
            apply_external_invitation_provisioning_in_tx(&tx, 7, 2, &profile("key-b"), 33)?,
            ProvisioningResult::Conflict
        );
        let public_key: String = tx.query_row(
            "SELECT public_key FROM users WHERE user_id = 9",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(public_key, "key-a");
        let invitation: (String, i64, Option<i64>) = tx.query_row(
            "SELECT state, remote_revision, local_provisioned_user_id FROM user_invitations WHERE invitation_id = 7",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(invitation, ("provisioning".into(), 2, Some(9)));
        Ok(())
    }

    #[test]
    fn stale_provisioning_cannot_override_authoritative_revocation() -> Result<(), StorageError> {
        let mut connection = database()?;
        let tx = connection.transaction()?;
        insert_in_tx(&tx, &summary(3, InvitationState::Revoked), None, 30)?;
        assert_eq!(
            apply_external_invitation_provisioning_in_tx(&tx, 7, 2, &profile("key-a"), 31)?,
            ProvisioningResult::Conflict
        );
        let users: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        assert_eq!(users, 0);
        Ok(())
    }

    #[test]
    fn pending_revoke_blocks_provisioning() -> Result<(), StorageError> {
        let mut connection = database()?;
        let tx = connection.transaction()?;
        insert_in_tx(&tx, &summary(1, InvitationState::Pending), None, 30)?;
        mark_revoke_pending_in_tx(&tx, 7, 31)?;
        assert_eq!(
            apply_external_invitation_provisioning_in_tx(&tx, 7, 2, &profile("key-a"), 32)?,
            ProvisioningResult::RevocationPending
        );
        let users: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        assert_eq!(users, 0);
        Ok(())
    }

    #[test]
    fn missing_invitation_is_reported_separately() -> Result<(), StorageError> {
        let mut connection = database()?;
        let tx = connection.transaction()?;
        assert_eq!(
            apply_external_invitation_provisioning_in_tx(&tx, 7, 2, &profile("key-a"), 32)?,
            ProvisioningResult::MissingInvitation
        );
        Ok(())
    }
}
