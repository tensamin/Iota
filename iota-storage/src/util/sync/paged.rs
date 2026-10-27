//! Materialized, expiring pages. Capture and authorization share one transaction;
//! later writes cannot change an already issued page. Only explicit ack advances a checkpoint.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_identity::relay_protocol::sync::*;
use rusqlite::{Connection, types::ValueRef};
use serde_json::{Value, json};

const TTL_MS: i64 = 10 * 60 * 1000;
const MAX_ITEMS: i64 = 100_000;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const ITEM_BYTES: usize = 256 * 1024;

pub(crate) fn transaction_heads(tx: &Transaction<'_>) -> Result<BTreeMap<i64, i64>, StorageError> {
    tx.prepare("SELECT user_id,version FROM sync_heads")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

/// Freeze post-transaction projections before the transaction can establish
/// acceptance. Multiple changes to one row in a transaction share its final
/// projection. No intermediate state was observable outside that transaction.
pub(crate) fn capture_transaction_events(
    tx: &Transaction<'_>,
    before: &BTreeMap<i64, i64>,
) -> Result<(), StorageError> {
    for (owner, head) in transaction_heads(tx)? {
        let after = before.get(&owner).copied().unwrap_or(0);
        if head <= after {
            continue;
        }
        let identity: Option<(String,i64,i64)> = tx.query_row(
            "SELECT p.authority_id,p.remote_user_id,a.generation FROM hosted_principals h
             JOIN principals p ON p.principal_pk=h.principal_handle JOIN hosted_auth_state a ON a.local_user_id=h.local_user_id
             WHERE h.local_user_id=?1 AND a.enabled=1 AND p.retired_at IS NULL", [owner],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional()?;
        let Some((authority, user_id, generation)) = identity else {
            continue;
        };
        let Ok(principal) =
            iota_identity::relay_protocol::Principal::new(authority, user_id as u64)
        else {
            continue;
        };
        let canonical = String::from_utf8(serialize(&principal)?)
            .map_err(|error| StorageError::Other(error.to_string()))?;
        let mut statement = tx.prepare("SELECT version,entity_type,entity_id FROM sync_events WHERE user_id=?1 AND version>?2 ORDER BY version")?;
        let events = statement
            .query_map(params![owner, after], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (sequence, entity, key) in events {
            let operation: String = tx.query_row("SELECT operation FROM sync_events WHERE user_id=?1 AND entity_type=?2 AND entity_id=?3 ORDER BY version DESC LIMIT 1",
                params![owner,entity,key], |row| row.get(0))?;
            let projection = projection(tx, owner, &entity, key, &principal)?;
            let entity_key = if let Some(record) = &projection {
                record.key.clone()
            } else if matches!(entity.as_str(), "contact" | "blocked_user") {
                let (authority, user_id): (String, i64) = tx.query_row(
                    "SELECT authority_id,remote_user_id FROM principals WHERE principal_pk=?1",
                    [key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let peer = iota_identity::relay_protocol::Principal::new(
                    authority,
                    u64::try_from(user_id)
                        .map_err(|_| protocol_error(SyncError::InvalidRequest))?,
                )
                .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
                String::from_utf8(serialize(&peer)?)
                    .map_err(|error| StorageError::Other(error.to_string()))?
            } else {
                key.to_string()
            };
            let action = match operation.as_str() {
                "upsert" if projection.is_some() => EventAction::Upsert,
                "delete" => EventAction::Delete,
                _ => return Err(protocol_error(SyncError::InvalidRequest)),
            };
            let event = Event {
                sequence,
                event_id: format!("{}:{}:{sequence}", principal.authority, principal.user_id),
                entity: Entity::try_from(entity.as_str()).map_err(protocol_error)?,
                key: entity_key,
                operation: action,
                record: if action == EventAction::Delete {
                    None
                } else {
                    projection
                },
            };
            tx.execute("UPDATE sync_events SET projection=?3,projection_principal=?4,projection_generation=?5,projection_dictionary=?6 WHERE user_id=?1 AND version=?2 AND projection IS NULL",
                params![owner,sequence,serialize(&event)?,canonical,generation,iota_identity::relay_protocol::dictionary_fingerprint("1.0").map_err(|error| StorageError::Other(error.to_string()))?])?;
        }
    }
    Ok(())
}

pub fn execute(owner: i64, request: &Request) -> Result<Response, StorageError> {
    if !request.validate() {
        return Ok(Response::Unavailable {
            error: SyncError::InvalidRequest,
        });
    }
    // Protocol failures must not commit a partially materialized snapshot.
    let outcome = db::with_immediate_transaction(|tx| {
        authorize(tx, owner, request.scope()).map_err(protocol_error)?;
        tx.execute(
            "DELETE FROM account_sync_pages WHERE expires_at<=?1",
            [now_millis()],
        )?;
        match request {
            Request::Snapshot { scope, page, limit } => {
                page_response(tx, owner, scope, "snapshot", 0, page, *limit)
            }
            Request::Delta { after, page, limit } => page_response(
                tx,
                owner,
                &after.scope,
                "delta",
                after.sequence,
                page,
                *limit,
            ),
            Request::Acknowledge { cursor, page_id } => acknowledge(tx, owner, cursor, page_id),
        }
    });
    match outcome {
        Err(StorageError::InvalidRelayPayload(code)) => Ok(Response::Unavailable {
            error: match code {
                "sync_snapshot_required" => SyncError::SnapshotRequired,
                "sync_identity_changed" => SyncError::IdentityChanged,
                "sync_unauthorized" => SyncError::Unauthorized,
                "sync_capacity" => SyncError::Capacity,
                "sync_retryable" => SyncError::Retryable,
                _ => SyncError::InvalidRequest,
            },
        }),
        result => result,
    }
}

fn protocol_error(error: SyncError) -> StorageError {
    StorageError::InvalidRelayPayload(match error {
        SyncError::SnapshotRequired => "sync_snapshot_required",
        SyncError::IdentityChanged => "sync_identity_changed",
        SyncError::Unauthorized => "sync_unauthorized",
        SyncError::Capacity => "sync_capacity",
        SyncError::Retryable => "sync_retryable",
        _ => "sync_invalid_request",
    })
}

fn authorize(connection: &Connection, owner: i64, scope: &Scope) -> Result<(), SyncError> {
    let current: Option<(String,i64,i64,i64)> = connection.query_row(
        "SELECT p.authority_id,p.remote_user_id,a.generation,p.principal_pk FROM hosted_principals h
         JOIN principals p ON p.principal_pk=h.principal_handle JOIN hosted_auth_state a ON a.local_user_id=h.local_user_id
         WHERE h.local_user_id=?1 AND a.enabled=1 AND p.retired_at IS NULL", [owner],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional().map_err(|_| SyncError::Retryable)?;
    let Some((authority, id, generation, handle)) = current else {
        return Err(SyncError::Unauthorized);
    };
    super::super::relay_work::verify_owner_on(
        connection,
        owner,
        iota_identity::PrincipalHandle(handle),
    )
    .map_err(|error| match error {
        StorageError::RelayOwnerUnavailable => SyncError::Unauthorized,
        _ => SyncError::Retryable,
    })?;
    if authority != scope.principal.authority
        || u64::try_from(id).ok() != Some(scope.principal.user_id)
        || generation != scope.authorization_generation
    {
        return Err(SyncError::IdentityChanged);
    }
    Ok(())
}

fn serialize(value: &impl serde::Serialize) -> Result<Vec<u8>, StorageError> {
    serde_json::to_vec(value).map_err(|error| StorageError::Other(error.to_string()))
}

fn page_response(
    tx: &Transaction<'_>,
    owner: i64,
    scope: &Scope,
    kind: &str,
    after: i64,
    token: &Option<PageToken>,
    limit: usize,
) -> Result<Response, StorageError> {
    let scope_json = String::from_utf8(serialize(scope)?)
        .map_err(|error| StorageError::Other(error.to_string()))?;
    let (id, offset) = match token {
        Some(token) => (token.id.clone(), token.offset),
        None => (capture(tx, owner, scope, &scope_json, kind, after)?, 0),
    };
    let boundary: Option<(i64,i64,i64,i64)> = tx.query_row(
        "SELECT head,floor,item_count,issued_through FROM account_sync_pages WHERE id=?1 AND user_id=?2 AND scope=?3 AND kind=?4 AND after_sequence=?5 AND expires_at>?6",
        params![id,owner,scope_json,kind,after,now_millis()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional()?;
    let (head, floor, count, issued) =
        boundary.ok_or_else(|| protocol_error(SyncError::SnapshotRequired))?;
    if offset > issued || offset > count {
        return Err(protocol_error(SyncError::InvalidRequest));
    }
    let mut statement = tx.prepare("SELECT payload FROM account_sync_page_items WHERE page_id=?1 AND position>=?2 ORDER BY position LIMIT ?3")?;
    let mut items = Vec::new();
    let mut size = 0;
    for row in statement.query_map(params![id, offset, limit as i64], |row| {
        row.get::<_, Vec<u8>>(0)
    })? {
        let bytes = row?;
        if size + bytes.len() > PAGE_BYTES / 2 {
            break;
        }
        size += bytes.len();
        items.push(
            serde_json::from_slice::<Value>(&bytes)
                .map_err(|error| StorageError::Other(error.to_string()))?,
        );
    }
    let end = offset + items.len() as i64;
    tx.execute(
        "UPDATE account_sync_pages SET issued_through=MAX(issued_through,?2) WHERE id=?1",
        params![id, end],
    )?;
    let next = (end < count).then(|| PageToken {
        id: id.clone(),
        offset: end,
    });
    if kind == "snapshot" {
        let records = items
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|error| StorageError::Other(error.to_string()))?;
        Ok(Response::Snapshot {
            scope: scope.clone(),
            head,
            floor,
            page_id: id,
            next,
            records,
        })
    } else {
        let events = items
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|error| StorageError::Other(error.to_string()))?;
        Ok(Response::Delta {
            scope: scope.clone(),
            head,
            floor,
            page_id: id,
            next,
            events,
        })
    }
}

fn capture(
    tx: &Transaction<'_>,
    owner: i64,
    scope: &Scope,
    scope_json: &str,
    kind: &str,
    after: i64,
) -> Result<String, StorageError> {
    let head = tx
        .query_row(
            "SELECT version FROM sync_heads WHERE user_id=?1",
            [owner],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    let floor = tx
        .query_row(
            "SELECT sequence FROM account_sync_floors WHERE user_id=?1",
            [owner],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    if kind == "delta" && (after < floor || after > head) {
        return Err(protocol_error(SyncError::SnapshotRequired));
    }
    // Bound disk usage per authenticated account. A new session replaces that
    // device's previous session; reconnect can instead resume its existing token.
    tx.execute(
        "DELETE FROM account_sync_pages WHERE user_id=?1 AND scope=?2",
        params![owner, scope_json],
    )?;
    let sessions: i64 = tx.query_row(
        "SELECT COUNT(*) FROM account_sync_pages WHERE user_id=?1",
        [owner],
        |row| row.get(0),
    )?;
    if sessions >= 8 {
        return Err(protocol_error(SyncError::Capacity));
    }
    let id = uuid::Uuid::new_v4().to_string();
    tx.execute("INSERT INTO account_sync_pages(id,user_id,scope,kind,after_sequence,head,floor,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![id,owner,scope_json,kind,after,head,floor,now_millis()+TTL_MS])?;
    let mut position = 0i64;
    let mut size = 0usize;
    let mut insert = |value: Value| -> Result<(), StorageError> {
        let payload = serialize(&value)?;
        size = size.saturating_add(payload.len());
        if position >= MAX_ITEMS || size > MAX_BYTES || payload.len() > ITEM_BYTES {
            return Err(protocol_error(SyncError::Capacity));
        }
        tx.execute(
            "INSERT INTO account_sync_page_items VALUES(?1,?2,?3)",
            params![id, position, payload],
        )?;
        position += 1;
        Ok(())
    };
    if kind == "snapshot" {
        for (entity, table, owner_column) in TABLES {
            if *entity == "chat_secret" {
                continue;
            }
            let sql = format!(
                "SELECT rowid AS entity_rowid,{} FROM {table} WHERE {owner_column}=?1 ORDER BY rowid",
                columns(entity)
            );
            let mut statement = tx.prepare(&sql)?;
            let mut rows = statement.query([owner])?;
            while let Some(row) = rows.next()? {
                insert(
                    serde_json::to_value(record(tx, row, entity, &scope.principal)?)
                        .map_err(|error| StorageError::Other(error.to_string()))?,
                )?;
            }
        }
        let principal_json = String::from_utf8(serialize(&scope.principal)?)
            .map_err(|error| StorageError::Other(error.to_string()))?;
        let mut statement = tx.prepare("SELECT first_principal,second_principal,version FROM chat_secret_epochs WHERE state='committed' AND (first_principal=?1 OR second_principal=?1) ORDER BY first_principal,second_principal,version")?;
        let mut rows = statement.query([principal_json])?;
        while let Some(row) = rows.next()? {
            let first: String = row.get(0)?;
            let second: String = row.get(1)?;
            let epoch: i64 = row.get(2)?;
            let first = serde_json::from_str(&first)
                .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
            let second = serde_json::from_str(&second)
                .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
            let pair = iota_identity::relay_protocol::ConversationPair::new(first, second)
                .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
            let chat = pair
                .chat_id()
                .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
            let available: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_secrets WHERE user_id=?1 AND chat_id=?2 AND version=?3)",params![owner.to_string(),chat,epoch],|row| row.get(0))?;
            insert(serde_json::to_value(Record { entity:Entity::ChatSecret,key:format!("{chat}:{epoch}"),
                value:json!({"chat_id":chat,"secret_id":iota_identity::relay_protocol::chat_secret_id(&chat),"version":epoch.to_string(),
                    "availability":if available {"owner_envelope_present"} else {"accepted_but_envelope_unavailable"}}) })
                .map_err(|error| StorageError::Other(error.to_string()))?)?;
        }
    } else {
        let principal = String::from_utf8(serialize(&scope.principal)?)
            .map_err(|error| StorageError::Other(error.to_string()))?;
        let mut statement = tx.prepare("SELECT version,projection,projection_principal,projection_generation,projection_dictionary FROM sync_events WHERE user_id=?1 AND version>?2 AND version<=?3 ORDER BY version")?;
        let mut rows = statement.query(params![owner, after, head])?;
        let mut expected = after;
        while let Some(row) = rows.next()? {
            let sequence: i64 = row.get(0)?;
            if expected.checked_add(1) != Some(sequence) {
                return Err(protocol_error(SyncError::SnapshotRequired));
            }
            expected = sequence;
            let payload: Option<Vec<u8>> = row.get(1)?;
            let owner_principal: Option<String> = row.get(2)?;
            let generation: Option<i64> = row.get(3)?;
            let dictionary: Option<String> = row.get(4)?;
            if owner_principal.as_deref() != Some(&principal)
                || generation != Some(scope.authorization_generation)
                || dictionary.as_deref() != Some(scope.dictionary.as_str())
            {
                return Err(protocol_error(SyncError::SnapshotRequired));
            }
            let event: Event = serde_json::from_slice(
                &payload.ok_or_else(|| protocol_error(SyncError::SnapshotRequired))?,
            )
            .map_err(|_| protocol_error(SyncError::SnapshotRequired))?;
            if event.sequence != sequence {
                return Err(protocol_error(SyncError::SnapshotRequired));
            }
            insert(
                serde_json::to_value(event)
                    .map_err(|error| StorageError::Other(error.to_string()))?,
            )?;
        }
        if expected != head {
            return Err(protocol_error(SyncError::SnapshotRequired));
        }
    }
    tx.execute(
        "UPDATE account_sync_pages SET item_count=?2 WHERE id=?1",
        params![id, position],
    )?;
    Ok(id)
}

// Only account application state belongs here. Credentials, proof material,
// pending uploads and filesystem paths are deliberately excluded.
const TABLES: &[(&str, &str, &str)] = &[
    ("message", "messages", "storage_owner"),
    ("contact", "contacts", "storage_owner"),
    ("setting", "synced_settings", "user_id"),
    ("user_blob", "user_blobs", "user_id"),
    ("chat_secret", "chat_secrets", "user_id"),
    ("blocked_user", "blocked_users", "user_id"),
    ("receipt_policy", "user_receipt_policy", "user_id"),
    (
        "message_storage_policy",
        "user_message_storage_policy",
        "user_id",
    ),
    ("user_asset", "user_assets", "user_id"),
];

fn projection(
    tx: &Transaction<'_>,
    owner: i64,
    entity: &str,
    key: i64,
    principal: &iota_identity::relay_protocol::Principal,
) -> Result<Option<Record>, StorageError> {
    let Some((_, table, owner_column)) = TABLES.iter().find(|(kind, _, _)| *kind == entity) else {
        // A new journal entity must receive a snapshot projection before pages
        // can claim to represent it. Never silently skip unknown state.
        return Err(protocol_error(SyncError::SnapshotRequired));
    };
    let mut statement = tx.prepare(&format!(
        "SELECT rowid AS entity_rowid,{} FROM {table} WHERE {owner_column}=?1 AND {}=?2",
        columns(entity),
        match entity {
            "contact" => "principal_handle",
            "blocked_user" => "blocked_principal",
            _ => "rowid",
        }
    ))?;
    let mut rows = statement.query(params![owner, key])?;
    rows.next()?
        .map(|row| record(tx, row, entity, principal))
        .transpose()
}

fn record(
    connection: &Connection,
    row: &rusqlite::Row<'_>,
    entity: &str,
    principal: &iota_identity::relay_protocol::Principal,
) -> Result<Record, StorageError> {
    let mut fields = serde_json::Map::new();
    let mut size = 0usize;
    for index in 0..row.as_ref().column_count() {
        if matches!(
            row.as_ref().column_name(index)?,
            "file_name" | "published_upload_id"
        ) || entity == "chat_secret"
            && matches!(
                row.as_ref().column_name(index)?,
                "encrypted_secret" | "kem_ciphertext"
            )
        {
            continue;
        }
        let value = match row.get_ref(index)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(value) => Value::String(value.to_string()),
            ValueRef::Real(_) => return Err(protocol_error(SyncError::InvalidRequest)),
            ValueRef::Text(bytes) => {
                size += bytes.len();
                if size > ITEM_BYTES {
                    return Err(protocol_error(SyncError::Capacity));
                }
                Value::String(
                    std::str::from_utf8(bytes)
                        .map_err(|error| StorageError::Other(error.to_string()))?
                        .into(),
                )
            }
            ValueRef::Blob(bytes) => {
                size += bytes.len();
                if size > ITEM_BYTES {
                    return Err(protocol_error(SyncError::Capacity));
                }
                json!({"base64":STANDARD.encode(bytes)})
            }
        };
        fields.insert(row.as_ref().column_name(index)?.into(), value);
    }
    let mut key = if entity == "chat_secret" {
        let chat = fields
            .get("chat_id")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol_error(SyncError::InvalidRequest))?;
        let pair = iota_identity::relay_protocol::ConversationPair::from_chat_id(chat)
            .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
        pair.partner(principal)
            .map_err(|_| protocol_error(SyncError::Unauthorized))?;
        let first = iota_identity::PrincipalId::try_from(pair.first.clone())
            .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
        let second = iota_identity::PrincipalId::try_from(pair.second.clone())
            .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
        let epoch = fields
            .get("version")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| protocol_error(SyncError::InvalidRequest))?;
        if super::super::chat_secret_recovery::epoch_state_on(connection, &first, &second, epoch)?
            != Some(super::super::chat_secret_recovery::EpochState::Committed)
        {
            return Err(protocol_error(SyncError::SnapshotRequired));
        }
        if fields.get("secret_id").and_then(Value::as_str)
            != Some(iota_identity::relay_protocol::chat_secret_id(chat).as_str())
        {
            return Err(protocol_error(SyncError::InvalidRequest));
        }
        fields.insert(
            "availability".into(),
            Value::String("owner_envelope_present".into()),
        );
        format!(
            "{}:{}",
            fields
                .get("chat_id")
                .and_then(Value::as_str)
                .ok_or_else(|| protocol_error(SyncError::InvalidRequest))?,
            fields
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| protocol_error(SyncError::InvalidRequest))?
        )
    } else {
        row.get::<_, i64>(0)?.to_string()
    };
    for field in [
        "external_principal",
        "principal_handle",
        "blocked_principal",
        "relay_signer_principal",
    ] {
        if let Some(handle) = fields.get(field).and_then(Value::as_str) {
            let handle = handle
                .parse::<i64>()
                .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
            let (authority, user_id): (String, i64) = connection.query_row(
                "SELECT authority_id,remote_user_id FROM principals WHERE principal_pk=?1",
                [handle],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let peer = iota_identity::relay_protocol::Principal::new(
                authority,
                u64::try_from(user_id).map_err(|_| protocol_error(SyncError::InvalidRequest))?,
            )
            .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
            fields.insert(format!("{field}_identity"), json!(peer));
            if entity == "contact" || entity == "blocked_user" {
                key = serde_json::to_string(&peer)
                    .map_err(|error| StorageError::Other(error.to_string()))?;
            }
            if entity == "message" && field == "external_principal" || entity == "contact" {
                fields.insert(
                    "chat_id".into(),
                    Value::String(iota_identity::relay_protocol::canonical_chat_id(
                        principal, &peer,
                    )),
                );
            }
        }
    }
    if ["deleted", "history_deleted", "deleted_by_external"]
        .iter()
        .any(|field| fields.get(*field).and_then(Value::as_str) == Some("1"))
    {
        fields.remove("content");
        fields.remove("blob");
    } else if entity == "message" {
        let mut statement = connection.prepare("SELECT r.reaction,p.authority_id,p.remote_user_id FROM reactions r LEFT JOIN principals p ON p.principal_pk=r.user_principal WHERE r.message_id=?1 ORDER BY r.id LIMIT 1025")?;
        let mut reactions = Vec::new();
        let mut rows = statement.query([row.get::<_, i64>(0)?])?;
        while let Some(row) = rows.next()? {
            let reaction: String = row.get(0)?;
            size = size.saturating_add(reaction.len());
            if reactions.len() >= 1024 || size > ITEM_BYTES {
                return Err(protocol_error(SyncError::Capacity));
            }
            let authority: String = row.get(1)?;
            let user_id: i64 = row.get(2)?;
            let principal = iota_identity::relay_protocol::Principal::new(
                authority,
                u64::try_from(user_id).map_err(|_| protocol_error(SyncError::InvalidRequest))?,
            )
            .map_err(|_| protocol_error(SyncError::InvalidRequest))?;
            reactions.push(json!({"reaction":reaction,"principal":principal}));
        }
        fields.insert("reactions".into(), Value::Array(reactions));
    }
    Ok(Record {
        entity: Entity::try_from(entity).map_err(protocol_error)?,
        key,
        value: Value::Object(fields),
    })
}

fn columns(entity: &str) -> &'static str {
    match entity {
        "message" => {
            "id,external_principal,relay_signer_principal,relay_message_id,message_time,authored_at,content,sent_by_self,message_state,height,key_version,reply_to,edited_count,deleted_by_external,history_deleted"
        }
        "contact" => {
            "id,principal_handle,user_name,created_at,last_message_at,notifications,notifications_read_at"
        }
        "setting" => "id,scope_type,scope_key,name,payload,revision,deleted",
        "user_blob" => "id,blob_id,blob,revision,deleted,updated_at",
        "chat_secret" => "chat_id,secret_id,version,wrapping_scheme,created_at,updated_at",
        "blocked_user" => "id,blocked_principal,revision,created_at",
        "receipt_policy" => "user_id,send_read_receipts,send_received_receipts,revision,updated_at",
        "message_storage_policy" => {
            "user_id,history_mode,retention_mode,retention_duration_ms,revision,updated_at"
        }
        "user_asset" => "id,asset_id,size,sha256,mime_type,revision,created_at,updated_at,deleted",
        _ => unreachable!("only the fixed application table list calls columns"),
    }
}

fn acknowledge(
    tx: &Transaction<'_>,
    owner: i64,
    cursor: &Cursor,
    page_id: &str,
) -> Result<Response, StorageError> {
    let scope = String::from_utf8(serialize(&cursor.scope)?)
        .map_err(|error| StorageError::Other(error.to_string()))?;
    let complete: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM account_sync_pages WHERE id=?1 AND user_id=?2 AND scope=?3 AND head=?4 AND issued_through=item_count AND expires_at>?5)",
        params![page_id,owner,scope,cursor.sequence,now_millis()], |row| row.get(0))?;
    if !complete {
        return Err(protocol_error(SyncError::SnapshotRequired));
    }
    super::super::relay_work::fault_point("before_sync_acknowledgment", page_id);
    tx.execute("INSERT INTO account_sync_checkpoints VALUES(?1,?2,?3,?4) ON CONFLICT(user_id,scope) DO UPDATE SET sequence=MAX(sequence,excluded.sequence),updated_at=excluded.updated_at", params![owner,scope,cursor.sequence,now_millis()])?;
    // Existing retention workers use the same checkpoint. Neither page issuance
    // nor notification dispatch updates it.
    tx.execute("INSERT INTO client_device_sync_state(user_id,device_id,acknowledged_version,cache_schema_version,updated_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(user_id,device_id) DO UPDATE SET acknowledged_version=MAX(acknowledged_version,excluded.acknowledged_version),cache_schema_version=excluded.cache_schema_version,updated_at=excluded.updated_at", params![owner,cursor.scope.device_id,cursor.sequence,CACHE_SCHEMA_VERSION,now_millis()])?;
    super::super::relay_work::fault_point("after_sync_acknowledgment", page_id);
    Ok(Response::Acknowledged {
        cursor: cursor.clone(),
    })
}
