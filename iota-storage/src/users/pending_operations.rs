use crate::storage_error::StorageError;
use crate::util::db;
use rusqlite::params;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingUserOperationKind {
    Create,
    Attach,
    Release,
    Purge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingUserOperationPhase {
    Prepared,
    CredentialWritten,
    RemoteCommitted,
    LocalCommitted,
    DatabasePurged,
    E2eePurged,
    FilesystemPurged,
}

impl PendingUserOperationPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::CredentialWritten => "credential_written",
            Self::RemoteCommitted => "remote_committed",
            Self::LocalCommitted => "local_committed",
            Self::DatabasePurged => "database_purged",
            Self::E2eePurged => "e2ee_purged",
            Self::FilesystemPurged => "filesystem_purged",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "credential_written" => Ok(Self::CredentialWritten),
            "remote_committed" => Ok(Self::RemoteCommitted),
            "local_committed" => Ok(Self::LocalCommitted),
            "database_purged" => Ok(Self::DatabasePurged),
            "e2ee_purged" => Ok(Self::E2eePurged),
            "filesystem_purged" => Ok(Self::FilesystemPurged),
            _ => Err(StorageError::Other(
                "unknown pending user operation phase".into(),
            )),
        }
    }
}

impl PendingUserOperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Attach => "attach",
            Self::Release => "release",
            Self::Purge => "purge",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "create" => Ok(Self::Create),
            "attach" => Ok(Self::Attach),
            "release" => Ok(Self::Release),
            "purge" => Ok(Self::Purge),
            _ => Err(StorageError::Other("unknown pending user operation".into())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingUserOperation {
    pub user_id: i64,
    pub operation: PendingUserOperationKind,
    pub username: String,
    pub public_key: Option<String>,
    pub private_key_hash: Option<String>,
    pub reset_token: Option<String>,
    pub registration_token: Option<String>,
    pub phase: PendingUserOperationPhase,
    pub created_at: i64,
}

pub fn upsert(operation: &PendingUserOperation) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            r#"
            INSERT INTO pending_user_operations (
                user_id, operation, username, public_key, private_key_hash,
                reset_token, registration_token, phase, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(user_id) DO UPDATE SET
                operation = excluded.operation,
                username = excluded.username,
                public_key = excluded.public_key,
                private_key_hash = excluded.private_key_hash,
                reset_token = excluded.reset_token,
                registration_token = excluded.registration_token,
                phase = excluded.phase,
                created_at = excluded.created_at
            "#,
            params![
                operation.user_id,
                operation.operation.as_str(),
                operation.username,
                operation.public_key,
                operation.private_key_hash,
                operation.reset_token,
                operation.registration_token,
                operation.phase.as_str(),
                operation.created_at,
            ],
        )?;
        Ok(())
    })
}

pub fn get_all() -> Result<Vec<PendingUserOperation>, StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT user_id, operation, username, public_key, private_key_hash, reset_token, registration_token, phase, created_at FROM pending_user_operations ORDER BY created_at",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })?;
        rows.map(|row| {
            let (
                user_id,
                operation,
                username,
                public_key,
                private_key_hash,
                reset_token,
                registration_token,
                phase,
                created_at,
            ) = row?;
            Ok(PendingUserOperation {
                user_id,
                operation: PendingUserOperationKind::parse(&operation)?,
                username,
                public_key,
                private_key_hash,
                reset_token,
                registration_token,
                phase: PendingUserOperationPhase::parse(&phase)?,
                created_at,
            })
        })
        .collect()
    })
}

pub fn update_phase(user_id: i64, phase: PendingUserOperationPhase) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE pending_user_operations SET phase = ?1 WHERE user_id = ?2",
            params![phase.as_str(), user_id],
        )?;
        Ok(())
    })
}

pub fn remove(user_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "DELETE FROM pending_user_operations WHERE user_id = ?1",
            [user_id],
        )?;
        Ok(())
    })
}

pub fn complete_purge(user_id: i64, updated_at: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let changed = tx.execute(
            "UPDATE user_residency SET data_state = 'empty', updated_at = ?2 WHERE user_id = ?1",
            params![user_id, updated_at],
        )?;
        if changed == 0 {
            return Err(StorageError::Other("user residency was not found".into()));
        }
        tx.execute(
            "DELETE FROM pending_user_operations WHERE user_id = ?1 AND operation = 'purge'",
            [user_id],
        )?;
        Ok(())
    })
}
