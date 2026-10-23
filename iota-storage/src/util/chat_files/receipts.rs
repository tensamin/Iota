use super::*;

pub fn change_message_state_by_relay_id(
    storage_owner: i64,
    _relay_signer_id: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    new_state: MessageState,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    db::with_immediate_transaction(|tx| {
        change_message_state_by_relay_id_in_tx(
            tx,
            storage_owner,
            relay_signer_principal,
            relay_message_id,
            new_state,
        )
    })
}

pub fn change_message_state_by_relay_id_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    new_state: MessageState,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    let Some((msg_id, current, message_time)) = tx
            .query_row(
                "SELECT id, message_state, message_time FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_principal.0, relay_message_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
    let final_state = MessageState::from_str(&current).upgrade(new_state);
    tx.execute(
        "UPDATE messages SET message_state = ?1 WHERE id = ?2",
        params![final_state.as_str(), msg_id],
    )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        msg_id,
        Operation::Upsert,
    )?;
    Ok(Some(MessageStateUpdate {
        send_time: message_time,
        state: final_state,
    }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit persisted receipt fields"
)]
pub fn record_message_receipt(
    storage_owner: i64,
    target_signer_id: i64,
    target_signer_principal: iota_identity::PrincipalHandle,
    target_message_id: &str,
    receipt_signer_id: i64,
    receipt_signer_principal: iota_identity::PrincipalHandle,
    receipt_message_id: &str,
    receipt_type: MessageState,
    event_at: i64,
    recorded_at: i64,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    db::with_immediate_transaction(|tx| {
        record_message_receipt_in_tx(
            tx,
            storage_owner,
            target_signer_id,
            target_signer_principal,
            target_message_id,
            receipt_signer_id,
            receipt_signer_principal,
            receipt_message_id,
            receipt_type,
            event_at,
            recorded_at,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit persisted receipt fields and caller transaction"
)]
pub fn record_message_receipt_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    target_signer_id: i64,
    target_signer_principal: iota_identity::PrincipalHandle,
    target_message_id: &str,
    receipt_signer_id: i64,
    receipt_signer_principal: iota_identity::PrincipalHandle,
    receipt_message_id: &str,
    receipt_type: MessageState,
    event_at: i64,
    recorded_at: i64,
) -> Result<Option<MessageStateUpdate>, StorageError> {
    let receipt_type = match receipt_type {
        MessageState::Received => "received",
        MessageState::Read => "read",
        _ => return Err(StorageError::Other("invalid message receipt state".into())),
    };
    let Some((message_id, message_time, external_principal, authored_at, history_deleted)) = tx
            .query_row(
                "SELECT id, message_time, external_principal, authored_at, history_deleted FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, target_signer_principal.0, target_message_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(StorageError::MissingRelayDependency);
        };
    if external_principal != receipt_signer_principal.0 {
        return Err(StorageError::MessageUnauthorized);
    }
    if event_at > recorded_at.saturating_add(5 * 60 * 1000)
        || authored_at.is_some_and(|authored_at| event_at < authored_at)
    {
        return Err(StorageError::InvalidRelayPayload(
            "receipt event time outside accepted clock range",
        ));
    }
    if history_deleted != 0 {
        return Ok(None);
    }
    tx.execute(
            "INSERT OR IGNORE INTO message_receipts (storage_owner, target_signer_id, target_signer_principal, target_message_id, receipt_signer_id, receipt_signer_principal, receipt_message_id, receipt_type, event_at, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![storage_owner, target_signer_id, target_signer_principal.0, target_message_id, receipt_signer_id, receipt_signer_principal.0, receipt_message_id, receipt_type, event_at, recorded_at],
        )?;
    let (state_column, recorded_column) = if receipt_type == "read" {
        ("read_at", "read_recorded_at")
    } else {
        ("client_received_at", "client_received_recorded_at")
    };
    let final_state = MessageState::from_str(&tx.query_row(
        "SELECT message_state FROM messages WHERE id = ?1",
        [message_id],
        |row| row.get::<_, String>(0),
    )?)
    .upgrade(MessageState::from_str(receipt_type));
    tx.execute(
            &format!("UPDATE messages SET {state_column} = COALESCE({state_column}, ?1), {recorded_column} = COALESCE({recorded_column}, ?2), message_state = ?3 WHERE id = ?4"),
            params![event_at, recorded_at, final_state.as_str(), message_id],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Upsert,
    )?;
    Ok(Some(MessageStateUpdate {
        send_time: message_time,
        state: final_state,
    }))
}

pub fn record_destination_iota_received(
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    accepted_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        record_destination_iota_received_in_tx(
            tx,
            storage_owner,
            relay_signer_principal,
            relay_message_id,
            accepted_at,
        )
    })
}

pub fn record_destination_iota_received_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    accepted_at: i64,
) -> Result<(), StorageError> {
    let Some(message_id) = tx
            .query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_principal.0, relay_message_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(());
        };
    tx.execute(
            "UPDATE messages SET destination_iota_received_at = COALESCE(destination_iota_received_at, ?1), delivery_failed_at = NULL, delivery_failure = NULL, message_state = CASE WHEN message_state = 'sending' THEN 'sent' ELSE message_state END WHERE id = ?2",
            params![accepted_at, message_id],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn record_delivery_failure(
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    failure: &str,
    failed_at: i64,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        record_delivery_failure_in_tx(
            tx,
            storage_owner,
            relay_signer_principal,
            relay_message_id,
            failure,
            failed_at,
        )
    })
}

pub fn record_delivery_failure_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    relay_signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    failure: &str,
    failed_at: i64,
) -> Result<(), StorageError> {
    let Some(message_id) = tx
            .query_row(
                "SELECT id FROM messages WHERE storage_owner = ?1 AND relay_signer_principal = ?2 AND relay_message_id = ?3",
                params![storage_owner, relay_signer_principal.0, relay_message_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(());
        };
    tx.execute(
            "UPDATE messages SET delivery_failed_at = ?1, delivery_failure = ?2 WHERE id = ?3 AND destination_iota_received_at IS NULL",
            params![failed_at, failure, message_id],
        )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        message_id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn change_message_state(
    timestamp: i64,
    storage_owner: i64,
    external_user: i64,
    new_state: MessageState,
) -> std::io::Result<()> {
    db::with_db(|conn| {
        let current: Option<String> = match conn.query_row(
            r#"
            SELECT message_state
            FROM messages
            WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3
            ORDER BY id DESC LIMIT 1
            "#,
            params![storage_owner, external_user, timestamp],
            |row| row.get(0),
        ) {
            Ok(state) => Some(state),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        let Some(current_state_raw) = current else {
            return Ok(());
        };

        let upgraded = MessageState::from_str(&current_state_raw)
            .upgrade(new_state)
            .as_str()
            .to_string();

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            r#"
            UPDATE messages
            SET message_state = ?1
            WHERE id = (
                SELECT id FROM messages
                WHERE storage_owner = ?2 AND external_user = ?3 AND message_time = ?4
                ORDER BY id DESC LIMIT 1
            )
            "#,
            params![upgraded, storage_owner, external_user, timestamp],
        )?;
        let msg_id: i64 = tx.query_row(
            "SELECT id FROM messages WHERE storage_owner = ?1 AND external_user = ?2 AND message_time = ?3 ORDER BY id DESC LIMIT 1",
            params![storage_owner, external_user, timestamp],
            |row| row.get(0),
        )?;
        sync::record_event(&tx, storage_owner, EntityType::Message, msg_id, Operation::Upsert)?;
        tx.commit()?;
        Ok(())
    })
    .map_err(|e: StorageError| std::io::Error::other(e.to_string()))
}
