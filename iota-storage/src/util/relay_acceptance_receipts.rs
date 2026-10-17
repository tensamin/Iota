//! Durable snapshot coverage. Retained until owner erasure, never age-pruned.
use crate::storage_error::StorageError;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub const PAGE_LIMIT: usize = 128;
pub const SCHEMA: &str = "
CREATE TABLE relay_acceptance_receipts (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 storage_owner INTEGER NOT NULL,
 signer_principal INTEGER NOT NULL,
 message_id TEXT NOT NULL,
 accepted_at INTEGER NOT NULL,
 UNIQUE(storage_owner, signer_principal, message_id)
);
CREATE INDEX relay_acceptance_receipts_owner_sequence
 ON relay_acceptance_receipts(storage_owner, sequence);
CREATE TABLE relay_receipt_backfill_blocks (
 signer_principal INTEGER NOT NULL,
 message_id TEXT NOT NULL,
 storage_owner INTEGER NOT NULL,
 reason TEXT NOT NULL,
 PRIMARY KEY(signer_principal, message_id, storage_owner)
);
CREATE INDEX relay_receipt_backfill_blocks_owner ON relay_receipt_backfill_blocks(storage_owner);";

/// Run once inside schema migration 59, before publishing the database pool.
/// Completed historical effects are imported only for still-hosted owners. The
/// migration transaction and schema version prevent repeat imports after erasure.
/// Invalid historical bytes remain untouched. A separate durable block gates
/// receipt reads until an operator verifies and repairs their missing coverage.
pub fn migrate_on(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(SCHEMA)?;
    let mut statement = conn.prepare("SELECT rowid, signer_principal, message_id, accepted_at, prepared_operation
        FROM relay_inbox WHERE prepared_operation IS NOT NULL AND state IN ('applied','queued','delivered')
        ORDER BY accepted_at, signer_principal, message_id")?;
    let mut sources = statement.query([])?;
    while let Some(row) = sources.next()? {
        let rowid: i64 = row.get(0)?;
        // SQLite affinity does not enforce these storage types. A poisoned row
        // must not abort migration before recovery can isolate it. Read failures
        // here describe that source only; SQLite iteration/write failures still
        // abort the migration transaction.
        let source = (|| -> rusqlite::Result<_> {
            Ok((
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })();
        let Some((signer, message_id, accepted_at, bytes)) =
            source.ok().filter(|(signer, message_id, accepted_at, _)| {
                *signer > 0
                    && !message_id.is_empty()
                    && message_id.len() <= 256
                    && accepted_at.is_some_and(|value| value >= 0)
            })
        else {
            // Use a row locator when even the canonical key cannot be decoded.
            // The original key, storage types and payload remain in relay_inbox.
            conn.execute("INSERT INTO relay_receipt_backfill_blocks(signer_principal,message_id,storage_owner,reason)
                SELECT CASE WHEN typeof(signer_principal)='integer' AND signer_principal>0 THEN signer_principal ELSE 0 END,
                  CASE WHEN typeof(message_id)='text' AND length(message_id)>0 THEN message_id ELSE printf('invalid-source-row:%lld',rowid) END,
                  0,'invalid_persisted_metadata'
                FROM relay_inbox WHERE rowid=?1 ON CONFLICT DO NOTHING", [rowid])?;
            continue;
        };
        let block = |owners: &[i64], reason: &str| -> Result<(), StorageError> {
            // Owner zero is an explicit subsystem-wide block when corrupt bytes
            // make the affected owners unknowable. It never blocks DB startup.
            for owner in if owners.is_empty() { &[0] } else { owners } {
                conn.execute(
                    "INSERT INTO relay_receipt_backfill_blocks VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING",
                    params![signer, message_id, owner, reason],
                )?;
            }
            Ok(())
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            block(&[], "invalid_json")?;
            continue;
        };
        let operation = match value.get("schema_version") {
            None => &value,
            Some(version) if version.as_str() == Some("1") => &value["operation"],
            Some(_) => {
                block(&[], "unsupported_schema")?;
                continue;
            }
        };
        let effects = operation
            .get("effects")
            .and_then(|v| v.as_array())
            .filter(|v| !v.is_empty() && v.len() <= 2)
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| {
                        Some((
                            value.get("owner")?.as_i64().filter(|v| *v > 0)?,
                            value.get("principal")?.as_i64().filter(|v| *v > 0)?,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()
            });
        let Some(effects) = effects else {
            block(&[], "invalid_effects")?;
            continue;
        };
        let owners = effects
            .iter()
            .map(|effect| effect.0)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let kind = operation
            .get("operation")
            .and_then(|v| v.as_object())
            .filter(|v| v.len() == 1)
            .and_then(|v| v.keys().next())
            .map(String::as_str);
        match kind {
            Some("SetChatSecret" | "AddConversation") => continue,
            Some(
                "MessageSend"
                | "MessageEdit"
                | "MessageReactionAdd"
                | "MessageReactionRemove"
                | "MessageDelete"
                | "MessageDeleteLive"
                | "MessageState"
                | "MessageReceived",
            ) => {}
            _ => {
                block(&owners, "invalid_operation")?;
                continue;
            }
        }
        let Some(accepted_at) = accepted_at.filter(|value| *value >= 0) else {
            block(&owners, "invalid_acceptance")?;
            continue;
        };
        for (owner, principal) in effects {
            conn.execute("INSERT INTO relay_acceptance_receipts(storage_owner, signer_principal, message_id, accepted_at)
                SELECT ?1,?2,?3,?4 WHERE EXISTS(SELECT 1 FROM hosted_principals h JOIN users u ON u.user_id=h.local_user_id
                  WHERE h.local_user_id=?1 AND h.principal_handle=?5)
                ON CONFLICT(storage_owner, signer_principal, message_id) DO NOTHING", params![owner, signer, message_id, accepted_at, principal])?;
            let matches: Option<bool> = conn.query_row("SELECT accepted_at = ?4 FROM relay_acceptance_receipts WHERE storage_owner=?1 AND signer_principal=?2 AND message_id=?3", params![owner, signer, message_id, accepted_at], |row| row.get(0)).optional()?;
            if matches == Some(false) {
                block(&[owner], "conflicting_acceptance")?;
            }
        }
    }
    Ok(())
}

pub fn backfill_block_count() -> Result<i64, StorageError> {
    super::db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM relay_receipt_backfill_blocks",
            [],
            |row| row.get(0),
        )?)
    })
}

/// The application codec calls this when its stricter DTO validation finds a
/// completed source that the storage-only migration could not fully validate.
/// Unknown ownership blocks receipt publication, not recovery of unrelated work.
pub fn block_backfill_for_record_on(
    conn: &Connection,
    signer: i64,
    message_id: &str,
) -> Result<(), StorageError> {
    conn.execute("INSERT INTO relay_receipt_backfill_blocks(signer_principal,message_id,storage_owner,reason)
        VALUES(?1,?2,0,'persisted_migration_invalid') ON CONFLICT DO NOTHING", params![signer, message_id])?;
    Ok(())
}

fn ensure_backfill_complete_on(conn: &Connection, owner: i64) -> Result<(), StorageError> {
    let blocked: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_receipt_backfill_blocks WHERE storage_owner IN (0, ?1))",
        [owner],
        |row| row.get(0),
    )?;
    if blocked {
        return Err(StorageError::Other(
            "receipt_backfill_incomplete: historical coverage requires operator repair".into(),
        ));
    }
    Ok(())
}

pub fn insert_in_tx(
    tx: &Transaction<'_>,
    owner: i64,
    signer: i64,
    message_id: &str,
    accepted_at: i64,
) -> Result<(), StorageError> {
    tx.execute("INSERT INTO relay_acceptance_receipts(storage_owner, signer_principal, message_id, accepted_at)
        VALUES (?1, ?2, ?3, ?4) ON CONFLICT(storage_owner, signer_principal, message_id) DO NOTHING",
        params![owner, signer, message_id, accepted_at])?;
    let matches: bool = tx.query_row(
        "SELECT accepted_at = ?4 FROM relay_acceptance_receipts
        WHERE storage_owner = ?1 AND signer_principal = ?2 AND message_id = ?3",
        params![owner, signer, message_id, accepted_at],
        |row| row.get(0),
    )?;
    if !matches {
        return Err(StorageError::PendingRelayConflict);
    }
    Ok(())
}

#[derive(Debug)]
pub struct Receipt {
    pub sequence: i64,
    pub principal: String,
    pub message_id: String,
    pub accepted_at: i64,
}

#[derive(Debug)]
pub struct ReceiptPage {
    pub cursor: i64,
    pub upper: i64,
    pub more: bool,
    pub records: Vec<Receipt>,
}

pub fn upper_on(conn: &Connection, owner: i64) -> Result<i64, StorageError> {
    ensure_backfill_complete_on(conn, owner)?;
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM relay_acceptance_receipts WHERE storage_owner = ?1",
        [owner],
        |row| row.get(0),
    )?)
}

pub fn receipt_page_on(
    conn: &Connection,
    owner: i64,
    after: i64,
    upper: i64,
    limit: usize,
) -> Result<ReceiptPage, StorageError> {
    if after < 0 || upper < after || limit == 0 || limit > PAGE_LIMIT {
        return Err(StorageError::InvalidRelayPayload("receipt page bounds"));
    }
    if upper > upper_on(conn, owner)? {
        return Err(StorageError::InvalidRelayPayload(
            "receipt upper exceeds owner boundary",
        ));
    }
    let mut statement = conn.prepare(
        "SELECT r.sequence, p.authority_id, p.remote_user_id, r.message_id, r.accepted_at
        FROM relay_acceptance_receipts r LEFT JOIN principals p ON p.principal_pk = r.signer_principal
        WHERE r.storage_owner = ?1 AND r.sequence > ?2 AND r.sequence <= ?3
        ORDER BY r.sequence LIMIT ?4",
    )?;
    let mut records = statement
        .query_map(params![owner, after, upper, (limit + 1) as i64], |row| {
            let authority: String = row.get(1)?;
            let user_id: i64 = row.get(2)?;
            Ok(Receipt {
                sequence: row.get(0)?,
                principal: serde_json::json!({"authority": authority, "user_id": user_id})
                    .to_string(),
                message_id: row.get(3)?,
                accepted_at: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let more = records.len() > limit;
    records.truncate(limit);
    let cursor = if more {
        records.last().expect("nonempty bounded page").sequence
    } else {
        upper
    };
    Ok(ReceiptPage {
        cursor,
        upper,
        more,
        records,
    })
}

pub fn receipt_page(
    owner: i64,
    after: i64,
    upper: Option<i64>,
    limit: usize,
) -> Result<ReceiptPage, StorageError> {
    super::db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        let page = receipt_page_on(
            &tx,
            owner,
            after,
            upper.map_or_else(|| upper_on(&tx, owner), Ok)?,
            limit,
        )?;
        tx.commit()?;
        Ok(page)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE principals(principal_pk INTEGER PRIMARY KEY, authority_id TEXT, remote_user_id INTEGER);
            INSERT INTO principals VALUES(7, 'peer', 99);
            CREATE TABLE users(user_id INTEGER PRIMARY KEY);
            INSERT INTO users VALUES(1); INSERT INTO users VALUES(2);
            CREATE TABLE hosted_principals(local_user_id INTEGER, principal_handle INTEGER);
            INSERT INTO hosted_principals VALUES(1, 11); INSERT INTO hosted_principals VALUES(2, 22);
            CREATE TABLE relay_inbox(signer_principal INTEGER, message_id TEXT, accepted_at INTEGER, state TEXT, prepared_operation BLOB);").unwrap();
        conn
    }

    #[test]
    fn publication_is_atomic_and_conflicting_metadata_rolls_back() {
        let mut conn = database();
        migrate_on(&conn).unwrap();
        {
            let tx = conn.transaction().unwrap();
            tx.execute("INSERT INTO users VALUES(3)", []).unwrap();
            insert_in_tx(&tx, 1, 7, "operation", 123).unwrap();
            // Simulate failure after application and receipt publication.
        }
        assert_eq!(upper_on(&conn, 1).unwrap(), 0);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM users WHERE user_id=3", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        let tx = conn.transaction().unwrap();
        insert_in_tx(&tx, 1, 7, "operation", 123).unwrap();
        insert_in_tx(&tx, 1, 7, "operation", 123).unwrap();
        tx.commit().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("INSERT INTO users VALUES(3)", []).unwrap();
        assert!(matches!(
            insert_in_tx(&tx, 1, 7, "operation", 124),
            Err(StorageError::PendingRelayConflict)
        ));
        tx.rollback().unwrap();
        assert_eq!(
            receipt_page_on(&conn, 1, 0, upper_on(&conn, 1).unwrap(), 128)
                .unwrap()
                .records
                .len(),
            1
        );
    }

    #[test]
    fn pages_are_bounded_indexed_and_ignore_concurrent_acceptance_and_history() {
        let mut conn = database();
        migrate_on(&conn).unwrap();
        let tx = conn.transaction().unwrap();
        for n in 0..385 {
            insert_in_tx(&tx, 1, 7, &format!("operation-{n}"), n).unwrap();
        }
        insert_in_tx(&tx, 2, 7, "other-owner", 400).unwrap();
        tx.commit().unwrap();
        let upper = upper_on(&conn, 1).unwrap();
        // History is deliberately unreadable. Live reads must use only the
        // normalized receipt index, even after inbox pruning or codec changes.
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'broken',1,'applied',x'ffff')",
            [],
        )
        .unwrap();
        let first = receipt_page_on(&conn, 1, 0, upper, 128).unwrap();
        assert_eq!(first.records.len(), 128);
        assert!(first.more);
        let tx = conn.transaction().unwrap();
        insert_in_tx(&tx, 1, 7, "concurrent", 401).unwrap();
        tx.commit().unwrap();
        let mut cursor = first.cursor;
        let mut sequences = first.records.iter().map(|r| r.sequence).collect::<Vec<_>>();
        loop {
            let page = receipt_page_on(&conn, 1, cursor, upper, 128).unwrap();
            assert!(page.records.len() <= 128);
            sequences.extend(page.records.iter().map(|r| r.sequence));
            cursor = page.cursor;
            if !page.more {
                break;
            }
        }
        assert_eq!(cursor, upper);
        assert_eq!(sequences.len(), 385);
        assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
        let later = receipt_page_on(&conn, 1, upper, upper_on(&conn, 1).unwrap(), 128).unwrap();
        assert_eq!(later.records[0].message_id, "concurrent");
        assert!(receipt_page_on(&conn, 1, 0, upper, 129).is_err());
        let plan: String = conn.query_row("EXPLAIN QUERY PLAN SELECT sequence FROM relay_acceptance_receipts WHERE storage_owner=1 AND sequence>0 AND sequence<=100 ORDER BY sequence LIMIT 129", [], |row| row.get(3)).unwrap();
        assert!(
            plan.contains("relay_acceptance_receipts_owner_sequence"),
            "{plan}"
        );
    }

    #[test]
    fn backfill_excludes_bootstrap_and_erased_or_rebound_owners() {
        let mut conn = database();
        for (id, operation, owner, principal, state) in [
            ("message", "MessageDelete", 1, 11, "delivered"),
            ("secret", "SetChatSecret", 1, 11, "queued"),
            ("conversation", "AddConversation", 1, 11, "applied"),
            ("unapplied", "MessageEdit", 1, 11, "processing"),
            ("erased", "MessageDelete", 3, 33, "delivered"),
            ("rebound", "MessageDelete", 2, 99, "delivered"),
        ] {
            let source = serde_json::json!({ "effects": [{ "owner": owner, "principal": principal }], "operation": { operation: {} } }).to_string();
            conn.execute(
                "INSERT INTO relay_inbox VALUES(7,?1,123,?2,?3)",
                params![id, state, source.as_bytes()],
            )
            .unwrap();
        }
        let versioned = serde_json::json!({"schema_version":"1", "operation": {
            "effects":[{"owner":1,"principal":11}], "operation":{"MessageEdit":{}}
        }})
        .to_string();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'versioned',124,'delivered',?1)",
            [versioned.as_bytes()],
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        migrate_on(&tx).unwrap();
        tx.commit().unwrap();
        let page = receipt_page_on(&conn, 1, 0, upper_on(&conn, 1).unwrap(), 128).unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0].message_id, "message");
        assert_eq!(page.records[1].message_id, "versioned");
        assert_eq!(upper_on(&conn, 2).unwrap(), 0);
        conn.execute(
            "DELETE FROM relay_acceptance_receipts WHERE storage_owner=1",
            [],
        )
        .unwrap();
        assert_eq!(upper_on(&conn, 1).unwrap(), 0);
        // The migration completion marker prevents the surviving inbox from
        // being imported again on startup after erasure.
    }

    #[test]
    fn malformed_sqlite_source_types_are_isolated_without_rewriting_original_values() {
        let mut conn = database();
        let valid = serde_json::json!({"effects":[{"owner":1,"principal":11}], "operation":{"MessageDelete":{}}}).to_string();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'healthy',123,'applied',?1)",
            [valid.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'bad-time','corrupt','applied',?1)",
            [valid.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,x'ffff',123,'applied',?1)",
            [valid.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'text-payload',123,'applied',?1)",
            [valid.as_str()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO relay_inbox VALUES('corrupt','bad-signer',123,'applied',?1)",
            [valid.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,NULL,123,'applied',?1)",
            [valid.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'null-time',NULL,'applied',?1)",
            [valid.as_bytes()],
        )
        .unwrap();
        // A genuine malformed source can share the diagnostic locator used for
        // the BLOB message ID above. Diagnostic deduplication must not abort.
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'invalid-source-row:3',123,'applied',x'ffff')",
            [],
        )
        .unwrap();
        let originals = |conn: &Connection| {
            conn.prepare("SELECT quote(signer_principal),quote(message_id),quote(accepted_at),quote(prepared_operation) FROM relay_inbox ORDER BY rowid").unwrap()
                .query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?))).unwrap().collect::<Result<Vec<_>,_>>().unwrap()
        };
        let before = originals(&conn);
        let tx = conn.transaction().unwrap();
        migrate_on(&tx).unwrap();
        tx.commit().unwrap();
        assert_eq!(originals(&conn), before);
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM relay_acceptance_receipts WHERE message_id='healthy'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM relay_receipt_backfill_blocks WHERE storage_owner=0",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            6
        );
        assert!(upper_on(&conn, 1).is_err());
    }

    #[test]
    fn corrupt_source_is_preserved_and_blocks_receipts_without_blocking_database_startup() {
        let mut conn = database();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'invalid',1,'applied',x'ffff')",
            [],
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        migrate_on(&tx).unwrap();
        tx.commit().unwrap();
        assert!(upper_on(&conn, 1).is_err());
        assert!(receipt_page_on(&conn, 2, 0, 0, 128).is_err());
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT prepared_operation FROM relay_inbox WHERE message_id='invalid'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bytes, [255, 255]);
        // Unrelated accepted work can still commit and later recover. The
        // durable receipt gate does not depend on F's recovery diagnostics.
        let tx = conn.transaction().unwrap();
        insert_in_tx(&tx, 2, 7, "later", 10).unwrap();
        tx.commit().unwrap();
        conn.execute_batch("ALTER TABLE relay_inbox ADD COLUMN recovery_error_code TEXT; UPDATE relay_inbox SET recovery_error_code='persisted_migration_invalid';").unwrap();
        assert!(receipt_page_on(&conn, 2, 0, 1, 128).is_err());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM relay_acceptance_receipts",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn invalid_operation_blocks_only_known_owners_and_preserves_valid_later_backfill() {
        let conn = database();
        for (id, owner, principal, operation) in [
            ("bad", 1, 11, "UnsupportedOperation"),
            ("later", 2, 22, "MessageDelete"),
        ] {
            let source = serde_json::json!({"effects":[{"owner":owner,"principal":principal}], "operation":{operation:{}}}).to_string();
            conn.execute(
                "INSERT INTO relay_inbox VALUES(7,?1,123,'applied',?2)",
                params![id, source.as_bytes()],
            )
            .unwrap();
        }
        migrate_on(&conn).unwrap();
        assert!(upper_on(&conn, 1).is_err());
        let page = receipt_page_on(&conn, 2, 0, upper_on(&conn, 2).unwrap(), 128).unwrap();
        assert_eq!(page.records[0].message_id, "later");
    }

    #[test]
    fn unsupported_schema_is_durable_and_future_or_erased_bounds_are_rejected() {
        let mut conn = database();
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'future',1,'applied',?1)",
            [br#"{"schema_version":"99","operation":{}}"#.as_slice()],
        )
        .unwrap();
        migrate_on(&conn).unwrap();
        assert!(upper_on(&conn, 1).is_err());
        let reason: String = conn
            .query_row(
                "SELECT reason FROM relay_receipt_backfill_blocks",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reason, "unsupported_schema");
        conn.execute("DELETE FROM relay_receipt_backfill_blocks", [])
            .unwrap();
        let tx = conn.transaction().unwrap();
        insert_in_tx(&tx, 1, 7, "valid", 1).unwrap();
        tx.commit().unwrap();
        let upper = upper_on(&conn, 1).unwrap();
        assert!(receipt_page_on(&conn, 1, upper, upper + 1, 128).is_err());
        assert!(receipt_page_on(&conn, 1, upper + 1, upper + 1, 128).is_err());
        conn.execute("DELETE FROM principals WHERE principal_pk=7", [])
            .unwrap();
        assert!(receipt_page_on(&conn, 1, 0, upper, 128).is_err());
        conn.execute(
            "DELETE FROM relay_acceptance_receipts WHERE storage_owner=1",
            [],
        )
        .unwrap();
        assert!(receipt_page_on(&conn, 1, 0, upper, 128).is_err());
    }
}
