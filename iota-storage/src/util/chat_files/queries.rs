use super::*;

pub fn add_message(message: NewMessage<'_>) -> Result<i64, StorageError> {
    db::with_immediate_transaction(|tx| add_message_in_tx(tx, message))
}

pub fn add_message_in_tx(
    tx: &Transaction<'_>,
    message: NewMessage<'_>,
) -> Result<i64, StorageError> {
    let NewMessage {
        relay_signer_id,
        relay_signer_principal,
        relay_message_id,
        authored_at,
        send_time,
        storage_owner,
        external_user,
        external_principal,
        sent_by_self,
        content,
        height,
        key_version,
        reply_to,
        origin_iota_received_at,
        destination_iota_received_at,
        initial_state,
    } = message;
    let stored_at = sync::now_millis();
    let policy = message_storage_policy::get_in_tx(tx, storage_owner)?;
    let expires_at = match policy.retention {
        MessageRetention::Forever => None,
        MessageRetention::Duration { duration_ms } => Some(
            stored_at
                .checked_add(duration_ms)
                .ok_or_else(|| StorageError::Other("message expiry overflow".into()))?,
        ),
    };
    tx.execute(
            r#"
            INSERT INTO messages (
                storage_owner, external_user, message_time, content, sent_by_self,
                message_state, height, key_version, reply_to, relay_signer_id, relay_message_id,
                authored_at, origin_iota_received_at, destination_iota_received_at, stored_at,
                expires_at, external_principal, relay_signer_principal
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
            "#,
            params![
                storage_owner,
                external_user,
                send_time,
                content,
                i64::from(sent_by_self),
                initial_state.as_str(),
                height,
                key_version,
                reply_to,
                relay_signer_id,
                relay_message_id,
                authored_at,
                origin_iota_received_at,
                destination_iota_received_at,
                stored_at,
                expires_at,
                external_principal.0,
                relay_signer_principal.0,
            ],
        )?;
    let msg_id = tx.last_insert_rowid();
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    let mut contact =
        crate::users::contact::Contact::for_principal(external_user, external_principal);
    contact.set_last_message_at(
        destination_iota_received_at
            .or(origin_iota_received_at)
            .unwrap_or(authored_at),
    );
    crate::util::chats_util::upsert_contact(tx, storage_owner, &contact)?;
    if !sent_by_self {
        tx.execute(
                "UPDATE contacts SET notifications = CASE WHEN notifications < 9223372036854775807 THEN notifications + 1 ELSE notifications END WHERE storage_owner = ?1 AND principal_handle = ?2",
                params![storage_owner, external_principal.0],
            )?;
    }
    Ok(msg_id)
}

pub(super) fn load_reactions(
    conn: &rusqlite::Connection,
    msg_ids: &[i64],
) -> Result<std::collections::HashMap<i64, Vec<StoredReaction>>, StorageError> {
    if msg_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let placeholders: Vec<String> = msg_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();
    let query = format!(
        "SELECT message_id, reaction, user_id, user_principal FROM reactions WHERE message_id IN ({}) ORDER BY created_at ASC, id ASC",
        placeholders.join(", ")
    );

    let mut map: std::collections::HashMap<i64, Vec<StoredReaction>> =
        std::collections::HashMap::new();
    let mut stmt = conn.prepare(&query)?;
    let params: Vec<&dyn rusqlite::types::ToSql> = msg_ids
        .iter()
        .map(|id| id as &dyn rusqlite::types::ToSql)
        .collect();
    let rows = stmt.query_map(params.as_slice(), |row| {
        Ok((
            row.get::<_, i64>(0)?,
            StoredReaction {
                reaction: row.get(1)?,
                user_id: row.get(2)?,
                principal: row
                    .get::<_, Option<i64>>(3)?
                    .map(iota_identity::PrincipalHandle),
            },
        ))
    })?;
    for row in rows {
        let row = row?;
        let reactions = map.entry(row.0).or_default();
        if reactions
            .iter()
            .any(|stored: &StoredReaction| stored.reaction == row.1.reaction)
            || reactions.len() < MAX_UNIQUE_REACTIONS_PER_MESSAGE
        {
            reactions.push(row.1);
        }
    }
    Ok(map)
}

pub fn get_messages(
    storage_owner: i64,
    external_user: i64,
    loaded_messages: i64,
    amount: i64,
) -> Result<Vec<StoredMessage>, StorageError> {
    let Some(principal) = crate::util::chats_util::get_user(storage_owner, external_user)?
        .and_then(|contact| contact.principal)
    else {
        return Ok(Vec::new());
    };
    get_messages_for_principal(storage_owner, principal, loaded_messages, amount)
}

pub fn get_messages_for_principal(
    storage_owner: i64,
    external_principal: iota_identity::PrincipalHandle,
    loaded_messages: i64,
    amount: i64,
) -> Result<Vec<StoredMessage>, StorageError> {
    if amount <= 0 || loaded_messages < 0 {
        return Ok(Vec::new());
    }

    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, relay_signer_id, relay_message_id, message_time, authored_at,
                   origin_iota_received_at, destination_iota_received_at,
                   client_received_at, client_received_recorded_at, read_at,
                   read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version,
                   reply_to, edited_count, external_user, relay_signer_principal
            FROM messages
            WHERE storage_owner = ?1 AND external_principal = ?2 AND deleted_by_external = 0 AND history_deleted = 0
            ORDER BY COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) DESC, id DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )?;

        let rows = stmt.query_map(
            params![storage_owner, external_principal.0, amount, loaded_messages],
            |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    external_user: row.get(20)?,
                    external_principal: Some(external_principal),
                    relay_signer_id: row.get(1)?,
                    relay_signer_principal: row
                        .get::<_, Option<i64>>(21)?
                        .map(iota_identity::PrincipalHandle),
                    relay_message_id: row.get(2)?,
                    message_time: row.get(3)?,
                    authored_at: row.get(4)?,
                    origin_iota_received_at: row.get(5)?,
                    destination_iota_received_at: row.get(6)?,
                    client_received_at: row.get(7)?,
                    client_received_recorded_at: row.get(8)?,
                    read_at: row.get(9)?,
                    read_recorded_at: row.get(10)?,
                    delivery_failed_at: row.get(11)?,
                    delivery_failure: row.get(12)?,
                    content: row.get(13)?,
                    sent_by_self: row.get::<_, i64>(14)? != 0,
                    message_state: row.get(15)?,
                    height: row.get(16)?,
                    key_version: row.get(17)?,
                    reply_to: row.get(18)?,
                    edited: row.get::<_, i64>(19)? > 0,
                    reactions: Vec::new(),
                })
            },
        )?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }

        let msg_ids: Vec<i64> = out.iter().map(|m| m.id).collect();
        let reaction_map = load_reactions(conn, &msg_ids)?;
        for msg in &mut out {
            msg.reactions = reaction_map.get(&msg.id).cloned().unwrap_or_default();
        }

        Ok(out)
    })
}

pub fn get_message(
    storage_owner: i64,
    message_time: i64,
    external_user: Option<i64>,
    external_principal: Option<iota_identity::PrincipalHandle>,
) -> Result<Option<StoredMessage>, StorageError> {
    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, relay_signer_id, relay_message_id, message_time, authored_at,
                   origin_iota_received_at, destination_iota_received_at,
                   client_received_at, client_received_recorded_at, read_at,
                   read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version,
                   reply_to, edited_count, external_user, external_principal,
                   relay_signer_principal
            FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?2
              AND deleted_by_external = 0
              AND history_deleted = 0
              AND (
                  ?3 IS NULL
                  OR (?4 IS NULL AND external_user = ?3)
                  OR external_principal = ?4
              )
            ORDER BY id DESC
            "#,
        )?;

        let rows = stmt.query_map(
            params![
                storage_owner,
                message_time,
                external_user,
                external_principal.map(|principal| principal.0)
            ],
            |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    relay_signer_id: row.get(1)?,
                    relay_signer_principal: row
                        .get::<_, Option<i64>>(22)?
                        .map(iota_identity::PrincipalHandle),
                    relay_message_id: row.get(2)?,
                    message_time: row.get(3)?,
                    authored_at: row.get(4)?,
                    origin_iota_received_at: row.get(5)?,
                    destination_iota_received_at: row.get(6)?,
                    client_received_at: row.get(7)?,
                    client_received_recorded_at: row.get(8)?,
                    read_at: row.get(9)?,
                    read_recorded_at: row.get(10)?,
                    delivery_failed_at: row.get(11)?,
                    delivery_failure: row.get(12)?,
                    content: row.get(13)?,
                    sent_by_self: row.get::<_, i64>(14)? != 0,
                    message_state: row.get(15)?,
                    height: row.get(16)?,
                    key_version: row.get(17)?,
                    reply_to: row.get(18)?,
                    edited: row.get::<_, i64>(19)? > 0,
                    external_user: row.get(20)?,
                    external_principal: row
                        .get::<_, Option<i64>>(21)?
                        .map(iota_identity::PrincipalHandle),
                    reactions: Vec::new(),
                })
            },
        )?;

        let messages: Vec<StoredMessage> = rows.collect::<Result<_, _>>()?;
        if messages.is_empty() {
            return Ok(None);
        }
        if external_user.is_none()
            && messages
                .iter()
                .filter_map(|message| message.external_principal)
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1
        {
            return Ok(None);
        }

        let mut message = messages.into_iter().next().expect("checked non-empty");
        let reaction_map = load_reactions(conn, &[message.id])?;
        message.reactions = reaction_map.get(&message.id).cloned().unwrap_or_default();
        Ok(Some(message))
    })
}

pub fn get_message_with_offset(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
) -> Result<Option<(StoredMessage, i64)>, StorageError> {
    let Some(external_principal) = crate::util::chats_util::get_user(storage_owner, external_user)?
        .and_then(|contact| contact.principal)
    else {
        return Ok(None);
    };
    let Some(message) = get_message(
        storage_owner,
        message_time,
        Some(external_user),
        Some(external_principal),
    )?
    else {
        return Ok(None);
    };
    let offset = db::with_db(|conn| {
        conn.query_row(
            r#"
            SELECT COUNT(*)
            FROM messages
            WHERE storage_owner = ?1
              AND external_principal = ?2
              AND deleted_by_external = 0
              AND history_deleted = 0
              AND (
                   COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) >
                       COALESCE(?3, ?4)
                   OR (COALESCE(destination_iota_received_at, origin_iota_received_at, authored_at, id) =
                       COALESCE(?3, ?4) AND id > ?4)
              )
            "#,
            params![
                storage_owner,
                external_principal.0,
                message.destination_iota_received_at.or(message.origin_iota_received_at).or(message.authored_at),
                message.id
            ],
            |row| row.get(0),
        )
        .map_err(StorageError::from)
    })?;
    Ok(Some((message, offset)))
}

pub fn get_messages_by_ids(
    storage_owner: i64,
    ids: &[i64],
) -> Result<Vec<StoredMessage>, StorageError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let wanted: std::collections::HashSet<i64> = ids.iter().copied().collect();
    // A journal id uniquely identifies a row. Load all messages for this owner and retain only
    // those ids; this keeps reaction hydration identical to normal message loading.
    db::with_db(|conn| {
        let mut stmt = conn.prepare("SELECT id, relay_signer_id, relay_message_id, message_time, authored_at, origin_iota_received_at, destination_iota_received_at, client_received_at, client_received_recorded_at, read_at, read_recorded_at, delivery_failed_at, delivery_failure, content, sent_by_self, message_state, height, key_version, reply_to, edited_count, external_user, external_principal, relay_signer_principal FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0 AND history_deleted = 0")?;
        let rows = stmt.query_map([storage_owner], |row| {
            let external_user: i64 = row.get(20)?;
            Ok(StoredMessage {
                id: row.get(0)?,
                external_user,
                external_principal: row
                    .get::<_, Option<i64>>(21)?
                    .map(iota_identity::PrincipalHandle),
                relay_signer_id: row.get(1)?,
                relay_signer_principal: row
                    .get::<_, Option<i64>>(22)?
                    .map(iota_identity::PrincipalHandle),
                relay_message_id: row.get(2)?,
                message_time: row.get(3)?,
                authored_at: row.get(4)?,
                origin_iota_received_at: row.get(5)?,
                destination_iota_received_at: row.get(6)?,
                client_received_at: row.get(7)?,
                client_received_recorded_at: row.get(8)?,
                read_at: row.get(9)?,
                read_recorded_at: row.get(10)?,
                delivery_failed_at: row.get(11)?,
                delivery_failure: row.get(12)?,
                content: row.get(13)?,
                sent_by_self: row.get::<_, i64>(14)? != 0,
                message_state: row.get(15)?,
                height: row.get(16)?,
                key_version: row.get(17)?,
                reply_to: row.get(18)?,
                edited: row.get::<_, i64>(19)? > 0,
                reactions: Vec::new(),
            })
        })?;
        let mut messages = Vec::new();
        for row in rows {
            let message = row?;
            if wanted.contains(&message.id) {
                messages.push(message);
            }
        }
        let reaction_map =
            load_reactions(conn, &messages.iter().map(|m| m.id).collect::<Vec<_>>())?;
        for message in &mut messages {
            message.reactions = reaction_map.get(&message.id).cloned().unwrap_or_default();
        }
        Ok(messages)
    })
}

pub fn get_all_messages(storage_owner: i64) -> Result<Vec<StoredMessage>, StorageError> {
    let ids = db::with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND deleted_by_external = 0 AND history_deleted = 0",
        )?;
        Ok(stmt
            .query_map([storage_owner], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?)
    })?;
    get_messages_by_ids(storage_owner, &ids)
}
