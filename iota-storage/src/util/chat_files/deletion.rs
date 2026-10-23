use super::*;

pub fn hard_delete_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    hard_delete_message_with_principal(storage_owner, external_user, None, message_time)
}

pub(super) fn hard_delete_message_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        hard_delete_message_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        )
    })
}

pub(super) fn hard_delete_message_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    let msg_id = tx
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
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(msg_id) = msg_id else {
        return Ok(());
    };

    purge_message_in_tx(tx, storage_owner, msg_id)?;
    Ok(())
}

pub fn purge_message(storage_owner: i64, message_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| purge_message_in_tx(tx, storage_owner, message_id))
}

pub fn remove_message_history(storage_owner: i64, message_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| remove_message_history_in_tx(tx, storage_owner, message_id))
}

/* Resolves the protocol identity retained in a tombstone before removing visible history. */
pub fn remove_message_history_by_relay_identity(
    storage_owner: i64,
    relay_signer_id: i64,
    relay_message_id: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        let message_id = tx.query_row(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_id = ?2 AND relay_message_id = ?3",
            params![storage_owner, relay_signer_id, relay_message_id],
            |row| row.get::<_, i64>(0),
        ).optional()?;
        if let Some(message_id) = message_id {
            remove_message_history_in_tx(tx, storage_owner, message_id)?;
        }
        Ok(())
    })
}

pub fn remove_message_history_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    message_id: i64,
) -> Result<(), StorageError> {
    let message: Option<(i64, Option<i64>, i64)> = tx
        .query_row(
            "SELECT external_user, external_principal, history_deleted FROM messages WHERE id = ?1 AND storage_owner = ?2",
            params![message_id, storage_owner],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((external_user, external_principal, history_deleted)) = message else {
        return Ok(());
    };
    if history_deleted != 0 {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM message_edits WHERE message_id = ?1",
        [message_id],
    )?;
    tx.execute("DELETE FROM reactions WHERE message_id = ?1", [message_id])?;
    tx.execute("DELETE FROM message_receipts WHERE storage_owner = ?1 AND EXISTS (SELECT 1 FROM messages WHERE id = ?2 AND relay_signer_principal = message_receipts.target_signer_principal AND relay_message_id = message_receipts.target_message_id)", params![storage_owner, message_id])?;
    tx.execute("UPDATE messages SET content = '', history_deleted = 1, history_deleted_at = ?2, expires_at = NULL, client_received_at = NULL, client_received_recorded_at = NULL, read_at = NULL, read_recorded_at = NULL WHERE id = ?1", params![message_id, sync::now_millis()])?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Delete,
    )?;
    update_contact_last_message_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal.map(iota_identity::PrincipalHandle),
    )?;
    Ok(())
}

pub(super) fn update_contact_last_message_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE contacts SET last_message_at = (SELECT MAX(COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, message_time)) FROM messages WHERE storage_owner = ?1 AND ((?3 IS NULL AND external_user = ?2) OR external_principal = ?3) AND deleted_by_external = 0 AND history_deleted = 0) WHERE storage_owner = ?1 AND ((?3 IS NULL AND user_id = ?2) OR principal_handle = ?3)",
        params![storage_owner, external_user, external_principal.map(|principal| principal.0)],
    )?;
    Ok(())
}

pub fn purge_message_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    message_id: i64,
) -> Result<(), StorageError> {
    let (external_user, external_principal, relay_signer_principal, relay_message_id) = tx.query_row(
        "SELECT external_user, external_principal, relay_signer_principal, relay_message_id FROM messages WHERE id = ?1 AND storage_owner = ?2",
        params![message_id, storage_owner],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, Option<String>>(3)?)),
    )?;
    if let (Some(relay_signer_principal), Some(relay_message_id)) =
        (relay_signer_principal, relay_message_id)
    {
        tx.execute(
            "DELETE FROM message_receipts WHERE storage_owner = ?1 AND target_signer_principal = ?2 AND target_message_id = ?3",
            params![storage_owner, relay_signer_principal, relay_message_id],
        )?;
    }
    tx.execute(
        "DELETE FROM message_edits WHERE message_id = ?1",
        [message_id],
    )?;
    tx.execute("DELETE FROM reactions WHERE message_id = ?1", [message_id])?;
    tx.execute("DELETE FROM messages WHERE id = ?1", [message_id])?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Delete,
    )?;
    update_contact_last_message_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal.map(iota_identity::PrincipalHandle),
    )?;
    Ok(())
}

/* Deletes a message from the sender's local copy after checking ownership. */
pub fn delete_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    delete_message_with_principal(storage_owner, external_user, None, message_time, true)
}

pub fn delete_message_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
) -> Result<(), StorageError> {
    delete_message_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        true,
    )
}

pub(super) fn delete_message_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        delete_message_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            sent_by_self,
        )
    })
}

pub fn delete_message_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
) -> Result<(), StorageError> {
    delete_message_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        true,
    )
}

pub fn apply_remote_delete_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    sender_id: i64,
) -> Result<(), StorageError> {
    if sender_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    delete_message_with_principal_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        false,
    )
}

pub(super) fn delete_message_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    sent_by_self: bool,
) -> Result<(), StorageError> {
    match ensure_message_direction_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal,
        message_time,
        sent_by_self,
    ) {
        Ok(()) if sent_by_self => hard_delete_message_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        ),
        Ok(()) => flag_deleted_by_external_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        ),
        Err(StorageError::Db(rusqlite::Error::QueryReturnedNoRows)) => Ok(()),
        Err(error) => Err(error),
    }
}

/* Flags the recipient's local copy after validating its sender, preserving its history. */
pub fn apply_remote_delete(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    sender_id: i64,
) -> Result<(), StorageError> {
    if sender_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    delete_message_with_principal(storage_owner, external_user, None, message_time, false)
}

pub fn apply_remote_delete_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    sender_id: i64,
) -> Result<(), StorageError> {
    if sender_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    delete_message_with_principal(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        false,
    )
}

pub(super) fn ensure_message_direction_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    expected_sent_by_self: bool,
) -> Result<(), StorageError> {
    let sent_by_self: i64 = tx.query_row(
        r#"
            SELECT sent_by_self FROM messages
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
        |row| row.get(0),
    )?;
    if (sent_by_self != 0) != expected_sent_by_self {
        return Err(StorageError::MessageUnauthorized);
    }
    Ok(())
}

/*
 * Marks a message as deleted by the external user rather than removing the row,
 * so the storage owner still sees a tombstone in the UI.
 */
pub fn flag_deleted_by_external(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    flag_deleted_by_external_with_principal(storage_owner, external_user, None, message_time)
}

pub(super) fn flag_deleted_by_external_with_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        flag_deleted_by_external_with_principal_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
        )
    })
}

pub(super) fn flag_deleted_by_external_with_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
) -> Result<(), StorageError> {
    let affected = tx.execute(
        r#"
            UPDATE messages
            SET deleted_by_external = 1
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
            "#,
        params![
            storage_owner,
            external_user,
            message_time,
            external_principal.map(|principal| principal.0)
        ],
    )?;
    if affected == 0 {
        return Err(StorageError::Other("Message not found".into()));
    }
    let msg_id: i64 = tx.query_row(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND message_time = ?3 AND ((?4 IS NULL AND external_user = ?2) OR external_principal = ?4) ORDER BY id DESC LIMIT 1",
            params![storage_owner, external_user, message_time, external_principal.map(|principal| principal.0)],
            |r| r.get(0),
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Delete,
    )?;
    update_contact_last_message_in_tx(tx, storage_owner, external_user, external_principal)?;
    Ok(())
}

/*
 * Removes the edit trail but keeps the message with edited_count > 0 so
 * the UI still shows the "edited" indicator.  Only the own user should
 * call this.
 */
pub fn delete_edit_history(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        delete_edit_history_in_tx(tx, storage_owner, external_user, message_time)
    })
}

pub fn delete_edit_history_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<(), StorageError> {
    let (msg_id, history_deleted): (i64, i64) = tx.query_row(
        r#"
            SELECT id, history_deleted FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
        params![storage_owner, external_user, message_time],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if history_deleted != 0 {
        return Ok(());
    }

    tx.execute(
        "DELETE FROM message_edits WHERE message_id = ?1",
        params![msg_id],
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
