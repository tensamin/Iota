use crate::users::pending_operations;
use crate::users::user_profile::UserProfile;
use crate::util::db;
use iota_util::file_util::{delete_user_directory, load_file, remove_user_credential, save_file};
use rusqlite::params;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalUserState {
    Managed,
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialOrigin {
    Local,
    External,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserResidency {
    pub user_id: i64,
    pub username: String,
    pub state: LocalUserState,
    pub data_present: bool,
    pub credential_origin: CredentialOrigin,
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn add_user(user: UserProfile) {
    if let Err(e) = try_add_user(user) {
        eprintln!("Failed to add_user: {}", e);
    }
}

pub fn try_add_user(user: UserProfile) -> Result<(), crate::storage_error::StorageError> {
    try_add_user_with_credential_origin(user, CredentialOrigin::Local)
}

pub fn try_add_user_with_credential_origin(
    user: UserProfile,
    credential_origin: CredentialOrigin,
) -> Result<(), crate::storage_error::StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            r#"
            INSERT INTO users (user_id, username, public_key, private_key_hash, reset_token, created_at, display_name)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                public_key = excluded.public_key,
                private_key_hash = excluded.private_key_hash,
                reset_token = excluded.reset_token,
                display_name = excluded.display_name
            "#,
            params![
                user.user_id,
                user.username,
                user.public_key,
                user.private_key_hash,
                user.reset_token,
                user.created_at,
                user.display_name,
            ],
        )?;

        for (app_id, app_secret) in &user.trusted_apps {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO trusted_apps (user_id, app_id, app_secret)
                VALUES (?1, ?2, ?3)
                "#,
                params![user.user_id, app_id, app_secret],
            )?;
        }
        tx.execute(
            r#"INSERT INTO user_residency (user_id, username, lifecycle_state, data_state, credential_origin, updated_at)
               VALUES (?1, ?2, 'managed', COALESCE((SELECT data_state FROM user_residency WHERE user_id = ?1), 'present'), ?3, ?4)
               ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, lifecycle_state = 'managed', credential_origin = excluded.credential_origin, updated_at = excluded.updated_at"#,
            params![user.user_id, user.username, match credential_origin { CredentialOrigin::Local => "local", CredentialOrigin::External => "external" }, now_millis()],
        )?;
        Ok(())
    })
}

pub fn update_user(user: UserProfile) {
    add_user(user);
}

pub fn get_user_by_username(username: &str) -> Option<UserProfile> {
    match db::with_db(|conn| {
        match conn.query_row(
            "SELECT user_id, username, public_key, private_key_hash, reset_token, created_at, display_name FROM users WHERE username = ?1 LIMIT 1",
            params![username],
            |r| {
                let user_id: i64 = r.get(0)?;
                Ok(UserProfile {
                    user_id,
                    username: r.get(1)?,
                    display_name: r.get(6)?,
                    public_key: r.get(2)?,
                    private_key_hash: r.get(3)?,
                    created_at: r.get(5)?,
                    reset_token: r.get(4)?,
                    trusted_apps: std::collections::HashMap::new(),
                })
            },
        ) {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }) {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error querying user by username: {}", e);
            None
        }
    }
}

pub fn get_user(user_id: i64) -> Result<Option<UserProfile>, crate::storage_error::StorageError> {
    let user = db::with_db(|conn| {
        match conn.query_row(
            "SELECT user_id, username, public_key, private_key_hash, reset_token, created_at, display_name FROM users WHERE user_id = ?1 LIMIT 1",
            params![user_id],
            |r| {
                let user_id: i64 = r.get(0)?;
                Ok(UserProfile {
                    user_id,
                    username: r.get(1)?,
                    display_name: r.get(6)?,
                    public_key: r.get(2)?,
                    private_key_hash: r.get(3)?,
                    created_at: r.get(5)?,
                    reset_token: r.get(4)?,
                    trusted_apps: std::collections::HashMap::new(),
                })
            },
        ) {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })?;
    user.map(|mut user| {
        user.trusted_apps = load_trusted_apps(user_id)?;
        Ok(user)
    })
    .transpose()
}

pub fn get_users() -> Vec<UserProfile> {
    match db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT user_id, username, public_key, private_key_hash, reset_token, created_at, display_name
            FROM users
            ORDER BY username
            "#,
        )?;

        let rows = stmt.query_map([], |r| {
            let user_id: i64 = r.get(0)?;
            let username: String = r.get(1)?;
            let public_key: String = r.get(2)?;
            let private_key_hash: Option<String> = r.get(3)?;
            let reset_token: Option<String> = r.get(4)?;
            let created_at: i64 = r.get(5)?;
            let display_name: Option<String> = r.get(6)?;

            Ok(UserProfile {
                user_id,
                username,
                display_name,
                public_key,
                private_key_hash,
                created_at,
                reset_token,
                trusted_apps: std::collections::HashMap::new(),
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            match row {
                Ok(mut user) => {
                    user.trusted_apps = load_trusted_apps(user.user_id)?;
                    out.push(user);
                }
                Err(e) => eprintln!("Failed to read user row: {}", e),
            }
        }
        Ok(out)
    }) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to query users: {}", e);
            Vec::new()
        }
    }
}

fn load_trusted_apps(
    user_id: i64,
) -> Result<std::collections::HashMap<String, String>, crate::storage_error::StorageError> {
    db::with_db(|conn| {
        let mut stmt =
            conn.prepare("SELECT app_id, app_secret FROM trusted_apps WHERE user_id = ?1")?;
        let rows = stmt.query_map(params![user_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;

        let mut map = std::collections::HashMap::new();
        for row in rows {
            let (key, value) = row?;
            map.insert(key, value);
        }
        Ok(map)
    })
}

pub fn revoke_trusted_app(
    user_id: i64,
    app_id: &str,
) -> Result<bool, crate::storage_error::StorageError> {
    db::with_immediate_transaction(|tx| {
        let removed = tx.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1 AND app_id = ?2",
            params![user_id, app_id],
        )?;
        Ok(removed > 0)
    })
}

pub fn revoke_all_trusted_apps(user_id: i64) -> Result<usize, crate::storage_error::StorageError> {
    db::with_immediate_transaction(|tx| {
        let removed = tx.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        Ok(removed)
    })
}

pub fn remove_user(user_id: i64) {
    if let Err(e) = db::with_db(|conn| {
        conn.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        conn.execute("DELETE FROM users WHERE user_id = ?1", params![user_id])?;
        Ok(())
    }) {
        eprintln!("Failed to remove_user: {}", e);
    }
}

/// Remove only local management authority. Hosted content is intentionally
/// retained and is indexed as released for a later purge operation.
pub fn release_user(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    let username = get_user(user_id)?
        .map(|user| user.username)
        .ok_or_else(|| {
            crate::storage_error::StorageError::Other("managed user was not found".into())
        })?;
    finalize_local_release(user_id, Some(&username))
}

/*
 * Finish local release after Omega has changed assignment. Every step accepts
 * an earlier attempt completing it, so reconciliation can safely retry it.
 */
pub fn finalize_local_release(
    user_id: i64,
    username_hint: Option<&str>,
) -> Result<(), crate::storage_error::StorageError> {
    let username = get_user(user_id)?
        .map(|user| user.username)
        .or_else(|| {
            get_residency_by_id(user_id)
                .ok()
                .flatten()
                .map(|residency| residency.username)
        })
        .or_else(|| username_hint.map(str::to_owned));
    let Some(username) = username else {
        return Err(crate::storage_error::StorageError::Other(
            "user residency was not found".into(),
        ));
    };
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute("DELETE FROM users WHERE user_id = ?1", params![user_id])?;
        tx.execute(
            "UPDATE pending_relays SET delivery_state = 'waiting_client', last_error = 'user_released' WHERE target_kind = 0 AND destination_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            r#"INSERT INTO user_residency (user_id, username, lifecycle_state, data_state, updated_at)
               VALUES (?1, ?2, 'released', COALESCE((SELECT data_state FROM user_residency WHERE user_id = ?1), 'present'), ?3)
               ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, lifecycle_state = 'released', updated_at = excluded.updated_at"#,
            params![user_id, username, now_millis()],
        )?;
        tx.commit()?;
        Ok(())
    })?;
    remove_user_credential(user_id, Some(&username))
        .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()))
}

pub fn force_local_detach(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    finalize_local_release(user_id, None)
}

pub fn forget_released_user(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    let residency = get_residency_by_id(user_id)?.ok_or_else(|| {
        crate::storage_error::StorageError::Other("user residency was not found".into())
    })?;
    if residency.state != LocalUserState::Released || residency.data_present {
        return Err(crate::storage_error::StorageError::Other(
            "only released users with empty hosted data can be forgotten".into(),
        ));
    }
    if pending_operations::get_all()?
        .iter()
        .any(|operation| operation.user_id == user_id)
    {
        return Err(crate::storage_error::StorageError::Other(
            "user has a pending lifecycle operation".into(),
        ));
    }
    db::with_db(|conn| {
        conn.execute(
            "DELETE FROM user_residency WHERE user_id = ?1",
            params![user_id],
        )?;
        Ok(())
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PurgeStage {
    Database,
    E2ee,
    Filesystem,
    Complete,
}

fn remaining_purge_stages(
    phase: pending_operations::PendingUserOperationPhase,
) -> Result<Vec<PurgeStage>, crate::storage_error::StorageError> {
    use pending_operations::PendingUserOperationPhase;
    let stages = match phase {
        PendingUserOperationPhase::Prepared => vec![
            PurgeStage::Database,
            PurgeStage::E2ee,
            PurgeStage::Filesystem,
            PurgeStage::Complete,
        ],
        PendingUserOperationPhase::DatabasePurged => vec![
            PurgeStage::E2ee,
            PurgeStage::Filesystem,
            PurgeStage::Complete,
        ],
        PendingUserOperationPhase::E2eePurged => {
            vec![PurgeStage::Filesystem, PurgeStage::Complete]
        }
        PendingUserOperationPhase::FilesystemPurged => vec![PurgeStage::Complete],
        _ => {
            return Err(crate::storage_error::StorageError::Other(
                "pending purge has an invalid phase".into(),
            ));
        }
    };
    Ok(stages)
}

fn run_purge_stages(
    phase: pending_operations::PendingUserOperationPhase,
    mut run: impl FnMut(PurgeStage) -> Result<(), crate::storage_error::StorageError>,
) -> Result<(), crate::storage_error::StorageError> {
    for stage in remaining_purge_stages(phase)? {
        run(stage)?;
    }
    Ok(())
}

fn purge_database_rows(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM message_receipts WHERE storage_owner = ?1",
            params![user_id],
        )?;
        tx.execute("DELETE FROM message_edits WHERE message_id IN (SELECT id FROM messages WHERE storage_owner = ?1)", params![user_id])?;
        tx.execute("DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE storage_owner = ?1)", params![user_id])?;
        tx.execute(
            "DELETE FROM messages WHERE storage_owner = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM contacts WHERE storage_owner = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM communities WHERE storage_owner = ?1",
            params![user_id],
        )?;
        tx.execute("DELETE FROM settings WHERE user_id = ?1", params![user_id])?;
        tx.execute(
            "DELETE FROM synced_settings WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM user_blobs WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM blocked_users WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM user_receipt_policy WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM user_message_storage_policy WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM sync_events WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM sync_heads WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM client_sync_state WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM client_message_deliveries WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM pending_relays WHERE relay_signer_id = ?1 OR relay_destination_user_id = ?1",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM relay_replay WHERE EXISTS (SELECT 1 FROM relay_inbox WHERE relay_inbox.signer_id = relay_replay.signer_id AND relay_inbox.message_id = relay_replay.message_id AND (relay_inbox.signer_id = ?1 OR relay_inbox.destination_id = ?1))",
            params![user_id],
        )?;
        tx.execute(
            "DELETE FROM relay_inbox WHERE signer_id = ?1 OR destination_id = ?1",
            params![user_id],
        )?;
        tx.commit()?;
        Ok(())
    })
}

/* Keep the residency authoritative until every hosted-data store has been
 * erased. Each completed phase is durable, and every cleanup stage is safe to
 * repeat after a crash between cleanup and phase persistence. */
pub fn purge_user_data(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    use pending_operations::{
        PendingUserOperation, PendingUserOperationKind, PendingUserOperationPhase,
    };

    let residency = get_residency_by_id(user_id)?.ok_or_else(|| {
        crate::storage_error::StorageError::Other("user residency was not found".into())
    })?;
    let existing = pending_operations::get_all()?
        .into_iter()
        .find(|operation| operation.user_id == user_id);
    let phase = match existing {
        Some(operation) if operation.operation == PendingUserOperationKind::Purge => {
            operation.phase
        }
        Some(_) => {
            return Err(crate::storage_error::StorageError::Other(
                "user has another pending lifecycle operation".into(),
            ));
        }
        None if !residency.data_present => return Ok(()),
        None => {
            let operation = PendingUserOperation {
                user_id,
                operation: PendingUserOperationKind::Purge,
                username: residency.username,
                public_key: None,
                private_key_hash: None,
                reset_token: None,
                registration_token: None,
                phase: PendingUserOperationPhase::Prepared,
                created_at: now_millis(),
            };
            pending_operations::upsert(&operation)?;
            PendingUserOperationPhase::Prepared
        }
    };

    run_purge_stages(phase, |stage| {
        match stage {
            PurgeStage::Database => {
                if crate::util::relay_queue::has_unclassified_relays()? {
                    return Err(crate::storage_error::StorageError::PendingRelayOwnershipUnknown);
                }
                purge_database_rows(user_id)?;
                pending_operations::update_phase(
                    user_id,
                    PendingUserOperationPhase::DatabasePurged,
                )?;
            }
            PurgeStage::E2ee => {
                crate::util::e2ee_storage::purge_user(user_id)
                    .map_err(crate::storage_error::StorageError::Other)?;
                pending_operations::update_phase(user_id, PendingUserOperationPhase::E2eePurged)?;
            }
            PurgeStage::Filesystem => {
                delete_user_directory(user_id).map_err(|error| {
                    crate::storage_error::StorageError::Other(error.to_string())
                })?;
                pending_operations::update_phase(
                    user_id,
                    PendingUserOperationPhase::FilesystemPurged,
                )?;
            }
            PurgeStage::Complete => {
                pending_operations::complete_purge(user_id, now_millis())?;
            }
        }
        Ok(())
    })
}

/// Complete local erasure is idempotent and is the target for a durable
/// Omega-hosted erasure request after account deletion.
pub fn erase_user_locally(user_id: i64) -> Result<(), crate::storage_error::StorageError> {
    let username = get_user(user_id)?.map(|user| user.username).or_else(|| {
        get_residency()
            .into_iter()
            .find(|entry| entry.user_id == user_id)
            .map(|entry| entry.username)
    });
    purge_user_data(user_id)?;
    db::with_db(|conn| {
        conn.execute(
            "DELETE FROM trusted_apps WHERE user_id = ?1",
            params![user_id],
        )?;
        conn.execute("DELETE FROM users WHERE user_id = ?1", params![user_id])?;
        conn.execute(
            "DELETE FROM user_residency WHERE user_id = ?1",
            params![user_id],
        )?;
        Ok(())
    })?;
    remove_user_credential(user_id, username.as_deref())
        .map_err(|error| crate::storage_error::StorageError::Other(error.to_string()))
}

pub fn get_residency() -> Vec<UserResidency> {
    db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT user_id, username, lifecycle_state, data_state, credential_origin FROM user_residency ORDER BY username")?;
        let rows = stmt.query_map([], |row| {
            let lifecycle: String = row.get(2)?;
            Ok(UserResidency {
                user_id: row.get(0)?, username: row.get(1)?,
                state: if lifecycle == "managed" { LocalUserState::Managed } else { LocalUserState::Released },
                data_present: row.get::<_, String>(3)? == "present",
                credential_origin: if row.get::<_, String>(4)? == "external" { CredentialOrigin::External } else { CredentialOrigin::Local },
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }).unwrap_or_default()
}

pub fn get_residency_by_id(
    user_id: i64,
) -> Result<Option<UserResidency>, crate::storage_error::StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT user_id, username, lifecycle_state, data_state, credential_origin FROM user_residency WHERE user_id = ?1",
        )?;
        let mut rows = statement.query(params![user_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let lifecycle: String = row.get(2)?;
        Ok(Some(UserResidency {
            user_id: row.get(0)?,
            username: row.get(1)?,
            state: if lifecycle == "managed" {
                LocalUserState::Managed
            } else {
                LocalUserState::Released
            },
            data_present: row.get::<_, String>(3)? == "present",
            credential_origin: if row.get::<_, String>(4)? == "external" {
                CredentialOrigin::External
            } else {
                CredentialOrigin::Local
            },
        }))
    })
}

pub fn clear() {
    if let Err(e) = db::with_db(|conn| {
        conn.execute_batch(
            "DELETE FROM trusted_apps; DELETE FROM users; DELETE FROM user_residency;",
        )?;
        Ok(())
    }) {
        eprintln!("Failed to clear users: {}", e);
    }
}

pub fn save_users() {
    // No-op: users are auto-saved via SQLite.
}

pub fn load_users_sync() -> std::io::Result<()> {
    // Users are loaded from SQLite on demand. This function is kept for API compat.
    // If we need to migrate from a legacy users.json file, we can do so here.
    let content = load_file("", "users.json");
    if content.trim().is_empty() {
        return Ok(());
    }
    if let Ok(parsed) = json::parse(&content) {
        if let json::JsonValue::Array(arr) = parsed {
            for j in arr.iter() {
                if let Some(up) = UserProfile::from_json(j) {
                    add_user(up);
                }
            }
        }
    }
    // Rename the old file so we don't re-import
    let _ = std::fs::rename(
        std::path::PathBuf::from(iota_util::file_util::get_directory()).join("users.json"),
        std::path::PathBuf::from(iota_util::file_util::get_directory()).join("users.json.imported"),
    );
    Ok(())
}

#[cfg(test)]
mod purge_tests {
    use super::{PurgeStage, remaining_purge_stages, run_purge_stages};
    use crate::users::pending_operations::PendingUserOperationPhase;

    #[test]
    fn prepared_purge_runs_every_stage_before_completion() {
        assert_eq!(
            remaining_purge_stages(PendingUserOperationPhase::Prepared).unwrap(),
            vec![
                PurgeStage::Database,
                PurgeStage::E2ee,
                PurgeStage::Filesystem,
                PurgeStage::Complete,
            ]
        );
    }

    #[test]
    fn purge_resumes_after_each_persisted_phase() {
        assert_eq!(
            remaining_purge_stages(PendingUserOperationPhase::DatabasePurged).unwrap(),
            vec![
                PurgeStage::E2ee,
                PurgeStage::Filesystem,
                PurgeStage::Complete,
            ]
        );
        assert_eq!(
            remaining_purge_stages(PendingUserOperationPhase::E2eePurged).unwrap(),
            vec![PurgeStage::Filesystem, PurgeStage::Complete]
        );
        assert_eq!(
            remaining_purge_stages(PendingUserOperationPhase::FilesystemPurged).unwrap(),
            vec![PurgeStage::Complete]
        );
    }

    #[test]
    fn lifecycle_phases_are_rejected_for_pending_purge() {
        assert!(remaining_purge_stages(PendingUserOperationPhase::RemoteCommitted).is_err());
    }

    #[test]
    fn purge_does_not_complete_after_an_interrupted_cleanup_stage() {
        for failed_stage in [
            PurgeStage::Database,
            PurgeStage::E2ee,
            PurgeStage::Filesystem,
        ] {
            let mut data_empty = false;
            let result = run_purge_stages(PendingUserOperationPhase::Prepared, |stage| {
                if stage == failed_stage {
                    return Err(crate::storage_error::StorageError::Other(
                        "interrupted".into(),
                    ));
                }
                if stage == PurgeStage::Complete {
                    data_empty = true;
                }
                Ok(())
            });

            assert!(result.is_err());
            assert!(!data_empty);
        }
    }
}

pub fn save_app_data(user_id: i64, app_identifier: &str, data: &str) {
    let path = format!("users/{}/apps", user_id);
    let name = format!("{}.json", app_identifier);
    save_file(&path, &name, data);
}

pub fn load_app_data(user_id: i64, app_identifier: &str) -> String {
    let path = format!("users/{}/apps", user_id);
    let name = format!("{}.json", app_identifier);
    load_file(&path, &name)
}
