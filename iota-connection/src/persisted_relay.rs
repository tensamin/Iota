//! The V1 storage contract is independent of the application types. Keep old
//! DTOs readable when changing runtime operations or introducing another version.
use crate::prepared_relay::{
    ApplicationOperation, DeliveryTarget, LocalEffect, PreparedRelayOperation, SecretCopy,
};
use iota_identity::{IotaNodeId, LocalUserId, PrincipalHandle};
use iota_storage::{storage_error::StorageError, util::chat_files::MessageState};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "schema_version", content = "operation")]
enum StoredPreparedRelay {
    #[serde(rename = "1")]
    V1(PreparedRelayV1),
}

#[derive(Serialize, Deserialize)]
struct PreparedRelayV1 {
    signer: i64,
    recipient: i64,
    message_id: String,
    signer_id: u64,
    recipient_id: u64,
    signer_identity: PrincipalV1,
    recipient_identity: PrincipalV1,
    created_at: u64,
    accepted_at: i64,
    frame: Vec<u8>,
    frame_id: u32,
    type_map_version: String,
    operation: OperationV1,
    effects: Vec<EffectV1>,
    delivery: DeliveryV1,
}

#[derive(Serialize, Deserialize)]
struct PrincipalV1 {
    authority: String,
    user_id: u64,
}

#[derive(Serialize, Deserialize)]
struct EffectV1 {
    owner: i64,
    principal: i64,
    sent_by_self: bool,
}

#[derive(Serialize, Deserialize)]
enum DeliveryV1 {
    Local(i64),
    Remote(String),
}

#[derive(Serialize, Deserialize)]
struct SecretV1 {
    encrypted_secret: Vec<u8>,
    kem_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum StateV1 {
    Read,
    Received,
    Sent,
    Sending,
}

#[derive(Serialize, Deserialize)]
enum OperationV1 {
    MessageSend {
        content: String,
        send_time: i64,
        height: i64,
        version: i64,
        reply_to: Option<i64>,
    },
    MessageEdit {
        content: String,
        send_time: i64,
        version: i64,
    },
    MessageReactionAdd {
        reaction: String,
        send_time: i64,
    },
    MessageReactionRemove {
        reaction: String,
        send_time: i64,
    },
    MessageDelete {
        send_time: i64,
    },
    MessageDeleteLive {
        send_time: i64,
    },
    MessageState {
        message_id: String,
        state: StateV1,
        event_at: i64,
    },
    MessageReceived {
        message_id: String,
        event_at: i64,
    },
    SetChatSecret {
        chat_id: String,
        legacy_chat_id: Option<String>,
        version: i64,
        wrapping_scheme: String,
        sender: SecretV1,
        recipient: SecretV1,
    },
    AddConversation {
        name: Option<String>,
    },
}

// List the unchanged fields explicitly, so a runtime field addition cannot
// silently change the persisted schema.
macro_rules! convert_operation {
    ($value:expr, $from:ident, $to:ident, $state:expr, $secret:expr) => {
        match $value {
            $from::MessageSend {
                content,
                send_time,
                height,
                version,
                reply_to,
            } => $to::MessageSend {
                content,
                send_time,
                height,
                version,
                reply_to,
            },
            $from::MessageEdit {
                content,
                send_time,
                version,
            } => $to::MessageEdit {
                content,
                send_time,
                version,
            },
            $from::MessageReactionAdd {
                reaction,
                send_time,
            } => $to::MessageReactionAdd {
                reaction,
                send_time,
            },
            $from::MessageReactionRemove {
                reaction,
                send_time,
            } => $to::MessageReactionRemove {
                reaction,
                send_time,
            },
            $from::MessageDelete { send_time } => $to::MessageDelete { send_time },
            $from::MessageDeleteLive { send_time } => $to::MessageDeleteLive { send_time },
            $from::MessageReceived {
                message_id,
                event_at,
            } => $to::MessageReceived {
                message_id,
                event_at,
            },
            $from::MessageState {
                message_id,
                state,
                event_at,
            } => $to::MessageState {
                message_id,
                state: ($state)(state),
                event_at,
            },
            $from::SetChatSecret {
                chat_id,
                legacy_chat_id,
                version,
                wrapping_scheme,
                sender,
                recipient,
            } => $to::SetChatSecret {
                chat_id,
                legacy_chat_id,
                version,
                wrapping_scheme,
                sender: ($secret)(sender),
                recipient: ($secret)(recipient),
            },
            $from::AddConversation { name } => $to::AddConversation { name },
        }
    };
}

impl From<PreparedRelayOperation> for PreparedRelayV1 {
    fn from(value: PreparedRelayOperation) -> Self {
        Self {
            signer: value.signer.0,
            recipient: value.recipient.0,
            message_id: value.message_id,
            signer_id: value.signer_id,
            recipient_id: value.recipient_id,
            signer_identity: PrincipalV1 {
                authority: value.signer_identity.authority,
                user_id: value.signer_identity.user_id,
            },
            recipient_identity: PrincipalV1 {
                authority: value.recipient_identity.authority,
                user_id: value.recipient_identity.user_id,
            },
            created_at: value.created_at,
            accepted_at: value.accepted_at,
            frame: value.frame,
            frame_id: value.frame_id,
            type_map_version: value.type_map_version,
            operation: convert_operation!(
                value.operation,
                ApplicationOperation,
                OperationV1,
                |state| match state {
                    MessageState::Read => StateV1::Read,
                    MessageState::Received => StateV1::Received,
                    MessageState::Sent => StateV1::Sent,
                    MessageState::Sending => StateV1::Sending,
                },
                |secret: SecretCopy| SecretV1 {
                    encrypted_secret: secret.encrypted_secret,
                    kem_ciphertext: secret.kem_ciphertext
                }
            ),
            effects: value
                .effects
                .into_iter()
                .map(|e| EffectV1 {
                    owner: e.owner.0,
                    principal: e.principal.0,
                    sent_by_self: e.sent_by_self,
                })
                .collect(),
            delivery: match value.delivery {
                DeliveryTarget::Local(owner) => DeliveryV1::Local(owner.0),
                DeliveryTarget::Remote(node) => DeliveryV1::Remote(node.as_str().to_owned()),
            },
        }
    }
}

impl TryFrom<PreparedRelayV1> for PreparedRelayOperation {
    type Error = StorageError;
    fn try_from(value: PreparedRelayV1) -> Result<Self, Self::Error> {
        let operation = Self {
            signer: PrincipalHandle(value.signer),
            recipient: PrincipalHandle(value.recipient),
            message_id: value.message_id,
            signer_id: value.signer_id,
            recipient_id: value.recipient_id,
            signer_identity: tau_relay_protocol::Principal {
                authority: value.signer_identity.authority,
                user_id: value.signer_identity.user_id,
            },
            recipient_identity: tau_relay_protocol::Principal {
                authority: value.recipient_identity.authority,
                user_id: value.recipient_identity.user_id,
            },
            created_at: value.created_at,
            accepted_at: value.accepted_at,
            frame: value.frame,
            frame_id: value.frame_id,
            type_map_version: value.type_map_version,
            operation: convert_operation!(
                value.operation,
                OperationV1,
                ApplicationOperation,
                |state| match state {
                    StateV1::Read => MessageState::Read,
                    StateV1::Received => MessageState::Received,
                    StateV1::Sent => MessageState::Sent,
                    StateV1::Sending => MessageState::Sending,
                },
                |secret: SecretV1| SecretCopy {
                    encrypted_secret: secret.encrypted_secret,
                    kem_ciphertext: secret.kem_ciphertext
                }
            ),
            effects: value
                .effects
                .into_iter()
                .map(|e| LocalEffect {
                    owner: LocalUserId(e.owner),
                    principal: PrincipalHandle(e.principal),
                    sent_by_self: e.sent_by_self,
                })
                .collect(),
            delivery: match value.delivery {
                DeliveryV1::Local(owner) => DeliveryTarget::Local(LocalUserId(owner)),
                DeliveryV1::Remote(node) => {
                    let parsed =
                        IotaNodeId::new(&node).map_err(|_| invalid("persisted relay route"))?;
                    if parsed.as_str() != node {
                        return Err(invalid("noncanonical persisted relay route"));
                    }
                    DeliveryTarget::Remote(parsed)
                }
            },
        };
        validate_persisted_operation_identity(&operation)?;
        Ok(operation)
    }
}

fn invalid(reason: &'static str) -> StorageError {
    StorageError::InvalidRelayPayload(reason)
}

pub(crate) fn encode_prepared_operation(
    operation: &PreparedRelayOperation,
) -> Result<Vec<u8>, StorageError> {
    validate_persisted_operation_identity(operation)?;
    serde_json::to_vec(&StoredPreparedRelay::V1(operation.clone().into()))
        .map_err(|_| invalid("persisted relay encoding"))
}

pub(crate) fn decode_prepared_operation(
    bytes: &[u8],
) -> Result<PreparedRelayOperation, StorageError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("corrupt persisted relay JSON"))?;
    let dto = if value.get("schema_version").is_some() {
        if value.get("schema_version").and_then(|v| v.as_str()) != Some("1") {
            return Err(invalid("unsupported persisted relay schema version"));
        }
        let StoredPreparedRelay::V1(dto) =
            serde_json::from_value(value).map_err(|_| invalid("invalid persisted relay V1"))?;
        dto
    } else {
        serde_json::from_value(value).map_err(|_| invalid("invalid legacy persisted relay"))?
    };
    dto.try_into()
}

pub(crate) fn validate_persisted_operation_identity(
    operation: &PreparedRelayOperation,
) -> Result<(), StorageError> {
    let p = operation;
    if p.signer.0 <= 0
        || p.recipient.0 <= 0
        || p.signer == p.recipient
        || p.signer_identity == p.recipient_identity
        || p.signer_id == 0
        || p.recipient_id == 0
        || i64::try_from(p.signer_id).is_err()
        || i64::try_from(p.recipient_id).is_err()
        || p.signer_identity.user_id != p.signer_id
        || p.recipient_identity.user_id != p.recipient_id
        || p.signer_identity.authority.trim().is_empty()
        || p.recipient_identity.authority.trim().is_empty()
        || p.message_id.is_empty()
        || p.message_id.len() > 256
        || p.effects.is_empty()
        || p.effects.len() > 2
    {
        return Err(invalid("persisted relay identity"));
    }
    for (index, effect) in p.effects.iter().enumerate() {
        if effect.owner.0 <= 0
            || effect.principal
                != if effect.sent_by_self {
                    p.signer
                } else {
                    p.recipient
                }
            || p.effects[..index].iter().any(|other| {
                other.owner == effect.owner || other.sent_by_self == effect.sent_by_self
            })
        {
            return Err(invalid("persisted relay effect identity"));
        }
    }
    match &p.delivery {
        DeliveryTarget::Local(owner)
            if !p
                .effects
                .iter()
                .any(|e| !e.sent_by_self && e.owner == *owner) =>
        {
            return Err(invalid("persisted relay local delivery identity"));
        }
        DeliveryTarget::Remote(_) if p.effects.iter().any(|e| !e.sent_by_self) => {
            return Err(invalid("persisted relay remote delivery identity"));
        }
        _ => (),
    }
    Ok(())
}

/// Run after storage initialization and receipt backfill, before recovery starts.
/// Each fenced update commits independently. The wrapper itself is the progress
/// marker, so interruption never requires replaying a global migration step.
pub(crate) fn migrate_on(connection: &Connection) -> Result<(), StorageError> {
    iota_storage::util::relay_work::block_invalid_metadata_on(connection)?;
    let mut cursor: Option<(i64, String)> = None;
    loop {
        let rows = {
            let mut statement = connection.prepare(
                "SELECT signer_principal, message_id, prepared_operation, processing_generation, state,
                 signer_id, destination_id, frame, created_at, type_map_version, frame_id
                  FROM relay_inbox WHERE prepared_operation IS NOT NULL AND recovery_error_code IS NOT 'invalid_persisted_metadata'
                 AND (?1 IS NULL OR (signer_principal, message_id) > (?1, ?2))
                 ORDER BY signer_principal, message_id LIMIT 100")?;
            statement
                .query_map(
                    params![cursor.as_ref().map(|c| c.0), cursor.as_ref().map(|c| &c.1)],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                            row.get::<_, i64>(8)?,
                            row.get::<_, String>(9)?,
                            row.get::<_, u32>(10)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        if rows.is_empty() {
            return Ok(());
        }
        for (
            signer,
            message_id,
            bytes,
            generation,
            state,
            signer_id,
            recipient_id,
            frame,
            created_at,
            type_map_version,
            frame_id,
        ) in rows
        {
            cursor = Some((signer, message_id.clone()));
            let converted = decode_prepared_operation(&bytes).and_then(|p| {
                if p.signer.0 != signer || p.message_id != message_id || p.signer_id != signer_id as u64
                    || p.recipient_id != recipient_id as u64 || p.frame != frame || p.created_at != created_at as u64
                    || p.type_map_version != type_map_version || p.frame_id != frame_id {
                    return Err(invalid("persisted relay record identity"));
                }
                for (handle, identity) in [(p.signer, &p.signer_identity), (p.recipient, &p.recipient_identity)] {
                    let matches: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_pk = ?1 AND authority_id = ?2 AND remote_user_id = ?3)", params![handle.0, identity.authority, identity.user_id as i64], |r| r.get(0))?;
                    if !matches { return Err(invalid("persisted relay principal mapping")); }
                }
                encode_prepared_operation(&p)
            });
            match converted {
                Ok(versioned) => {
                    // Already-versioned valid records need no write.
                    if serde_json::from_slice::<serde_json::Value>(&bytes)
                        .ok()
                        .is_some_and(|v| v.get("schema_version").is_some())
                    {
                        continue;
                    }
                    connection.execute("UPDATE relay_inbox SET prepared_operation = ?6 WHERE signer_principal = ?1 AND message_id = ?2 AND prepared_operation = ?3 AND processing_generation = ?4 AND state = ?5", params![signer, message_id, bytes, generation, state, versioned])?;
                }
                Err(error @ StorageError::InvalidRelayPayload(_)) => {
                    iota_logger::log!(
                        "Persisted relay migration blocked for {message_id}: {error}"
                    );
                    let tx = connection.unchecked_transaction()?;
                    let changed = tx.execute("UPDATE relay_inbox SET recovery_status = 'blocked', recovery_error_code = 'persisted_migration_invalid' WHERE signer_principal = ?1 AND message_id = ?2 AND prepared_operation = ?3 AND processing_generation = ?4 AND state = ?5", params![signer, message_id, bytes, generation, state])?;
                    if changed > 0 && matches!(state.as_str(), "applied" | "queued" | "delivered") {
                        iota_storage::util::relay_acceptance_receipts::block_backfill_for_record_on(&tx, signer, &message_id)?;
                    }
                    tx.commit()?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // A fixed historical JSON shape, deliberately independent of runtime serde.
    fn legacy(message_id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "signer": 1, "recipient": 2, "message_id": message_id,
            "signer_id": 11, "recipient_id": 22,
            "signer_identity": {"authority": "authority-a", "user_id": 11},
            "recipient_identity": {"authority": "authority-b", "user_id": 22},
            "created_at": 100, "accepted_at": 101, "frame": [1,2,3],
            "frame_id": 7, "type_map_version": "0.1.0",
            "operation": {"MessageSend": {"content": "ciphertext", "send_time": 100,
                "height": 0, "version": 1, "reply_to": null}},
            "effects": [{"owner": 5, "principal": 2, "sent_by_self": false}],
            "delivery": {"Local": 5}
        }))
        .unwrap()
    }

    #[test]
    fn legacy_and_v1_round_trip() {
        let old = legacy("message");
        let prepared = decode_prepared_operation(&old).unwrap();
        assert_eq!(prepared.signer, PrincipalHandle(1));
        let bytes = encode_prepared_operation(&prepared).unwrap();
        let wrapper: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(wrapper["schema_version"], "1");
        assert_eq!(
            wrapper["operation"],
            serde_json::from_slice::<serde_json::Value>(&old).unwrap()
        );
        let restored = decode_prepared_operation(&bytes).unwrap();
        assert_eq!(encode_prepared_operation(&restored).unwrap(), bytes);
    }

    #[test]
    fn unsupported_and_corrupt_fail_explicitly() {
        assert!(matches!(
            decode_prepared_operation(br#"{"schema_version":"2","operation":{}}"#),
            Err(StorageError::InvalidRelayPayload(
                "unsupported persisted relay schema version"
            ))
        ));
        assert!(matches!(
            decode_prepared_operation(br#"{"schema_version":null,"operation":{}}"#),
            Err(StorageError::InvalidRelayPayload(
                "unsupported persisted relay schema version"
            ))
        ));
        assert!(matches!(
            decode_prepared_operation(b"not JSON"),
            Err(StorageError::InvalidRelayPayload(
                "corrupt persisted relay JSON"
            ))
        ));
    }

    #[test]
    fn identity_and_effect_corruption_are_rejected() {
        let original: serde_json::Value = serde_json::from_slice(&legacy("message")).unwrap();
        for path in [
            "/signer_identity/user_id",
            "/effects/0/principal",
            "/delivery/Local",
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(path).unwrap() = json!(99);
            assert!(
                decode_prepared_operation(&serde_json::to_vec(&changed).unwrap()).is_err(),
                "{path}"
            );
        }
        let mut runtime = decode_prepared_operation(&legacy("message")).unwrap();
        runtime.signer_id = 0;
        assert!(encode_prepared_operation(&runtime).is_err());
    }

    #[test]
    fn every_operation_has_an_independent_v1_representation() {
        let operations = [
            json!({"MessageEdit":{"content":"new","send_time":100,"version":1}}),
            json!({"MessageReactionAdd":{"reaction":"+","send_time":100}}),
            json!({"MessageReactionRemove":{"reaction":"+","send_time":100}}),
            json!({"MessageDelete":{"send_time":100}}),
            json!({"MessageDeleteLive":{"send_time":100}}),
            json!({"MessageState":{"message_id":"target","state":"Read","event_at":101}}),
            json!({"MessageReceived":{"message_id":"target","event_at":101}}),
            json!({"SetChatSecret":{"chat_id":"chat","legacy_chat_id":null,"version":1,
                "wrapping_scheme":"kem","sender":{"encrypted_secret":[1],"kem_ciphertext":[2]},
                "recipient":{"encrypted_secret":[3],"kem_ciphertext":[4]}}}),
            json!({"AddConversation":{"name":null}}),
        ];
        for operation in operations {
            let mut value: serde_json::Value = serde_json::from_slice(&legacy("message")).unwrap();
            value["operation"] = operation;
            let p = decode_prepared_operation(&serde_json::to_vec(&value).unwrap()).unwrap();
            let bytes = encode_prepared_operation(&p).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["operation"],
                value
            );
            decode_prepared_operation(&bytes).unwrap();
        }
    }

    fn database() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE principals(principal_pk INTEGER PRIMARY KEY, authority_id TEXT, remote_user_id INTEGER);
            INSERT INTO principals VALUES (1, 'authority-a', 11), (2, 'authority-b', 22);
            CREATE TABLE relay_inbox(signer_principal INTEGER, message_id TEXT, prepared_operation BLOB,
            processing_generation INTEGER DEFAULT 0, state TEXT DEFAULT 'received', signer_id INTEGER DEFAULT 11,
            destination_id INTEGER DEFAULT 22, frame BLOB DEFAULT X'010203', created_at INTEGER DEFAULT 100,
            type_map_version TEXT DEFAULT '0.1.0', frame_id INTEGER DEFAULT 7,
            recovery_status TEXT DEFAULT 'ready', recovery_error_code TEXT,
            recovery_attempts INTEGER DEFAULT 0, processing_owner TEXT, processing_deadline INTEGER,
            recovery_next_at INTEGER DEFAULT 0, recovery_last_attempt_at INTEGER,
            accepted_at INTEGER DEFAULT 101,
            PRIMARY KEY(signer_principal, message_id));").unwrap();
        c.execute_batch(iota_storage::util::relay_acceptance_receipts::SCHEMA)
            .unwrap();
        c
    }

    fn insert(c: &Connection, message_id: &str, bytes: &[u8]) {
        c.execute("INSERT INTO relay_inbox(signer_principal,message_id,prepared_operation) VALUES (1,?1,?2)", params![message_id, bytes]).unwrap();
    }

    fn record(c: &Connection, message_id: &str) -> (Vec<u8>, String, Option<String>, String, i64) {
        c.query_row("SELECT prepared_operation,recovery_status,recovery_error_code,state,processing_generation FROM relay_inbox WHERE message_id=?1", [message_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap()
    }

    #[test]
    fn migration_resumes_preserving_invalid_bytes_and_state() {
        let c = database();
        insert(&c, "old", &legacy("old"));
        let versioned =
            encode_prepared_operation(&decode_prepared_operation(&legacy("done")).unwrap())
                .unwrap();
        insert(&c, "done", &versioned);
        let bad = b"\xffnot JSON";
        insert(&c, "bad", bad);
        insert(&c, "wrong-identity", &legacy("another-message"));
        c.execute("UPDATE relay_inbox SET state='processing', processing_generation=8 WHERE message_id='bad'", []).unwrap();
        migrate_on(&c).unwrap();
        assert_eq!(record(&c, "done").0, versioned);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&record(&c, "old").0).unwrap()["schema_version"],
            "1"
        );
        assert_eq!(
            record(&c, "bad"),
            (
                bad.to_vec(),
                "blocked".into(),
                Some("persisted_migration_invalid".into()),
                "processing".into(),
                8
            )
        );
        assert_eq!(record(&c, "wrong-identity").1, "blocked");
        let old_after = record(&c, "old");
        // Simulate another legacy record remaining after an interrupted pass.
        insert(&c, "remaining", &legacy("remaining"));
        migrate_on(&c).unwrap();
        assert_eq!(record(&c, "old"), old_after);
        assert!(record(&c, "remaining").0 != legacy("remaining"));
    }

    #[test]
    fn migration_checks_database_principal_mapping() {
        let c = database();
        let bytes = legacy("message");
        insert(&c, "message", &bytes);
        c.execute(
            "UPDATE principals SET authority_id='different' WHERE principal_pk=2",
            [],
        )
        .unwrap();
        migrate_on(&c).unwrap();
        assert_eq!(record(&c, "message").0, bytes);
        assert_eq!(record(&c, "message").1, "blocked");
    }

    #[test]
    fn interrupted_migration_keeps_committed_progress() {
        let c = database();
        insert(&c, "a", &legacy("a"));
        insert(&c, "b", &legacy("b"));
        c.execute_batch(
            "CREATE TRIGGER interrupt BEFORE UPDATE OF prepared_operation ON relay_inbox
            WHEN OLD.message_id='b' BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
        )
        .unwrap();
        assert!(migrate_on(&c).is_err());
        let first = record(&c, "a").0;
        assert_ne!(first, legacy("a"));
        assert_eq!(record(&c, "b").0, legacy("b"));
        c.execute_batch("DROP TRIGGER interrupt;").unwrap();
        migrate_on(&c).unwrap();
        assert_eq!(record(&c, "a").0, first);
        assert_ne!(record(&c, "b").0, legacy("b"));
    }

    #[test]
    fn migration_fences_each_observed_record() {
        let c = database();
        for id in ["a", "bytes", "generation", "state"] {
            insert(&c, id, &legacy(id));
        }
        // The migration has already read this batch when its first update fires.
        c.execute_batch(
            "CREATE TRIGGER concurrent_work AFTER UPDATE OF prepared_operation ON relay_inbox
            WHEN OLD.message_id='a' BEGIN
                UPDATE relay_inbox SET prepared_operation=X'FF' WHERE message_id='bytes';
                UPDATE relay_inbox SET processing_generation=1 WHERE message_id='generation';
                UPDATE relay_inbox SET state='applied' WHERE message_id='state';
            END;",
        )
        .unwrap();
        migrate_on(&c).unwrap();
        assert_eq!(record(&c, "bytes").0, vec![255]);
        assert_eq!(record(&c, "generation").0, legacy("generation"));
        assert_eq!(record(&c, "state").0, legacy("state"));
        assert_eq!(record(&c, "generation").4, 1);
        assert_eq!(record(&c, "state").3, "applied");
    }
}
