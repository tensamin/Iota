use super::*;

/*
 * Each edit is recorded in message_edits with the before/after content and a
 * timestamp. Only the original sender (sent_by_self = 1) may edit.
 */
pub fn edit_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    update_message_content(
        storage_owner,
        external_user,
        None,
        message_time,
        editor_id,
        new_content,
        true,
    )
}

pub fn edit_message_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    update_message_content(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        true,
    )
}

pub fn edit_message_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        true,
        None,
    )
}

/* Applies an edit received from the message sender to the recipient's copy. */
pub fn apply_remote_edit(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }

    update_message_content(
        storage_owner,
        external_user,
        None,
        message_time,
        editor_id,
        new_content,
        false,
    )
}

/// VersionNumber identifies the replacement ciphertext's key, as used by the
/// client's encryptChatText/decryptChatText calls. It may be an older available
/// epoch or a new epoch, independent of the original message's key version.
/// The relay calls require_edit_key_in_tx with the authenticated chat first.
/// See client/packages/chat/src/components/message.tsx and context.tsx in the
/// sibling client repository for edit production and live decryption.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit edit identity, key version and caller transaction"
)]
pub fn edit_message_for_principal_versioned_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    key_version: i64,
) -> Result<(), StorageError> {
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        true,
        Some(key_version),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit edit identity, key version and caller transaction"
)]
pub fn apply_remote_edit_for_principal_versioned_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    key_version: i64,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        false,
        Some(key_version),
    )
}

/// Check the exact ciphertext epoch, rather than the latest chat secret. A
/// missing epoch is recoverable when its secret arrives, including after restart.
pub fn require_edit_key_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    chat_id: &str,
    key_version: i64,
) -> Result<(), StorageError> {
    if key_version <= 0 {
        return Err(StorageError::InvalidRelayPayload("edit key version"));
    }
    crate::util::e2ee_storage::get_chat_secret_on(
        tx,
        &crate::util::e2ee_storage::ChatSecretQuery {
            user_id: storage_owner.to_string(),
            chat_id: chat_id.to_owned(),
            secret_id: Some(crate::util::e2ee_storage::principal_secret_id(chat_id)),
            version: Some(key_version),
        },
    )?
    .ok_or(StorageError::MissingRelayDependency)?;
    Ok(())
}

pub fn apply_remote_edit_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        false,
    )
}

pub(super) fn update_message_content(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    require_sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        update_message_content_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            editor_id,
            new_content,
            require_sent_by_self,
            None,
        )
    })
}

pub fn apply_remote_edit_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        new_content,
        false,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit message identity and caller transaction"
)]
pub(super) fn update_message_content_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    new_content: &str,
    require_sent_by_self: bool,
    key_version: Option<i64>,
) -> Result<(), StorageError> {
    if key_version.is_some_and(|version| version <= 0) {
        return Err(StorageError::InvalidRelayPayload("edit key version"));
    }
    let msg = tx
        .query_row(
            r#"
            SELECT id, content, sent_by_self, history_deleted, key_version
            FROM messages
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
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(StorageError::MissingRelayDependency)?;

    let (msg_id, old_content, sent_by_self, history_deleted, old_key_version) = msg;
    if require_sent_by_self && sent_by_self != 1 {
        return Err(StorageError::MessageUnauthorized);
    }
    if !require_sent_by_self && sent_by_self != 0 {
        return Err(StorageError::MessageUnauthorized);
    }

    if history_deleted != 0 {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    tx.execute(
            r#"
            INSERT INTO message_edits (message_id, content_before, content_after, edited_at, edited_by, content_before_key_version, content_after_key_version)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![msg_id, old_content, new_content, now, editor_id, old_key_version, key_version.unwrap_or(old_key_version)],
        )?;

    tx.execute(
        r#"
            UPDATE messages
            SET content = ?1, edited_count = edited_count + 1,
                key_version = COALESCE(?3, key_version)
            WHERE id = ?2
            "#,
        params![new_content, msg_id, key_version],
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
