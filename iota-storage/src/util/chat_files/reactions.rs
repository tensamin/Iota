use super::*;

pub fn add_reaction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    user_id: i64,
    reaction: &str,
) -> Result<(), StorageError> {
    add_reaction_with_principal(
        storage_owner,
        external_user,
        None,
        message_time,
        user_id,
        None,
        reaction,
    )
}

pub fn add_reaction_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    add_reaction_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

pub(super) fn add_reaction_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        add_reaction_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            user_id,
            user_principal,
            reaction,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
pub fn add_reaction_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    add_reaction_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
pub(super) fn add_reaction_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    let (msg_id, history_deleted): (i64, i64) = tx
        .query_row(
            r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            ORDER BY id DESC LIMIT 1
            "#,
            params![
                storage_owner,
                external_user,
                message_time,
                external_principal.map(|principal| principal.0)
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(StorageError::MissingRelayDependency)?;
    if history_deleted != 0 {
        return Ok(());
    }

    let reaction_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM reactions WHERE message_id = ?1 AND reaction = ?2)",
        params![msg_id, reaction],
        |row| row.get(0),
    )?;
    if !reaction_exists {
        let unique_reactions: i64 = tx.query_row(
            "SELECT COUNT(DISTINCT reaction) FROM reactions WHERE message_id = ?1",
            [msg_id],
            |row| row.get(0),
        )?;
        if unique_reactions >= MAX_UNIQUE_REACTIONS_PER_MESSAGE as i64 {
            return Err(StorageError::ReactionLimitReached);
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let inserted = tx.execute(
            r#"
            INSERT OR IGNORE INTO reactions (message_id, user_id, user_principal, reaction, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                msg_id,
                user_id,
                user_principal.map(|principal| principal.0),
                reaction,
                now
            ],
        )?;
    if inserted > 0 {
        sync::record_event(
            tx,
            storage_owner,
            EntityType::Message,
            msg_id,
            Operation::Upsert,
        )?;
        Ok(())
    } else {
        Ok(())
    }
}

pub fn remove_reaction(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    user_id: i64,
    reaction: &str,
) -> Result<(), StorageError> {
    remove_reaction_with_principal(
        storage_owner,
        external_user,
        None,
        message_time,
        user_id,
        None,
        reaction,
    )
}

pub fn remove_reaction_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    remove_reaction_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

pub(super) fn remove_reaction_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        remove_reaction_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            user_id,
            user_principal,
            reaction,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
pub fn remove_reaction_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    user_id: i64,
    user_principal: iota_identity::PrincipalHandle,
    reaction: &str,
) -> Result<(), StorageError> {
    remove_reaction_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        user_id,
        Some(user_principal),
        reaction,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit reaction identity and caller transaction"
)]
pub(super) fn remove_reaction_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    user_id: i64,
    user_principal: Option<iota_identity::PrincipalHandle>,
    reaction: &str,
) -> Result<(), StorageError> {
    let (msg_id, history_deleted): (i64, i64) = tx
        .query_row(
            r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            ORDER BY id DESC LIMIT 1
            "#,
            params![
                storage_owner,
                external_user,
                message_time,
                external_principal.map(|principal| principal.0)
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(StorageError::MissingRelayDependency)?;
    if history_deleted != 0 {
        return Ok(());
    }

    tx.execute(
            "DELETE FROM reactions WHERE message_id = ?1 AND ((?3 IS NULL AND user_id = ?2) OR user_principal = ?3) AND reaction = ?4",
            params![
                msg_id,
                user_id,
                user_principal.map(|principal| principal.0),
                reaction
            ],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    Ok(())
}
