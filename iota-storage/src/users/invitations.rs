use crate::{storage_error::StorageError, util::db};
use rusqlite::params;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationState {
    Pending,
    Redeemed,
    Revoked,
    Expired,
}

impl InvitationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Redeemed => "redeemed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "pending" => Ok(Self::Pending),
            "redeemed" => Ok(Self::Redeemed),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err(StorageError::Other("unknown invitation state".into())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationSummary {
    pub invitation_id: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub state: InvitationState,
    pub redeemed_user_id: Option<i64>,
    pub redeemed_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub fn insert(summary: &InvitationSummary, token_hash: &[u8]) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "INSERT INTO user_invitations (invitation_id, token_hash, created_at, expires_at, state, redeemed_user_id, redeemed_at, revoked_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![summary.invitation_id, token_hash, summary.created_at, summary.expires_at, summary.state.as_str(), summary.redeemed_user_id, summary.redeemed_at, summary.revoked_at],
        )?;
        Ok(())
    })
}

pub fn list() -> Result<Vec<InvitationSummary>, StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare("SELECT invitation_id, created_at, expires_at, state, redeemed_user_id, redeemed_at, revoked_at FROM user_invitations ORDER BY created_at DESC")?;
        Ok(statement
            .query_map([], |row| {
                Ok(InvitationSummary {
                    invitation_id: row.get(0)?,
                    created_at: row.get(1)?,
                    expires_at: row.get(2)?,
                    state: InvitationState::parse(&row.get::<_, String>(3)?).map_err(|error| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                    })?,
                    redeemed_user_id: row.get(4)?,
                    redeemed_at: row.get(5)?,
                    revoked_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    })
}

pub fn revoke(invitation_id: &str, revoked_at: i64) -> Result<bool, StorageError> {
    db::with_immediate_transaction(|tx| {
        let changed = tx.execute(
            "UPDATE user_invitations SET state = 'revoked', revoked_at = ?2 WHERE invitation_id = ?1 AND state = 'pending'",
            params![invitation_id, revoked_at],
        )?;
        Ok(changed == 1)
    })
}
