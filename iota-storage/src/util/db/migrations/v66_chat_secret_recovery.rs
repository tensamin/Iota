use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 66 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(crate::util::chat_secret_recovery::SCHEMA)?;
    tx.execute_batch(crate::hosted_auth::FORWARDED_REVOCATION_SCHEMA)?;
    let inbox: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='relay_inbox')",
        [],
        |row| row.get(0),
    )?;
    if inbox {
        let indexed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_xinfo('relay_inbox') WHERE name='initial_secret_chat_id')", [], |row| row.get(0))?;
        if !indexed {
            tx.execute_batch(include_str!(
                "../../chat_secret_recovery/relay_initialization.sql"
            ))?;
        }
    }
    // Partial historical schema fixtures need not have hosted identity tables.
    let hosted: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='hosted_principals')",[],|row| row.get(0))?;
    if hosted {
        let cleanup = |owner: &str| {
            format!("INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id={owner}
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner={owner} OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner={owner} OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences);")
        };
        for (table, trigger) in [
            (
                "hosted_principals",
                format!(
                    "CREATE TRIGGER IF NOT EXISTS chat_secret_hosted_delete BEFORE DELETE ON hosted_principals BEGIN {} END;",
                    cleanup("OLD.local_user_id")
                ),
            ),
            (
                "hosted_principals",
                format!(
                    "CREATE TRIGGER IF NOT EXISTS chat_secret_hosted_reassign BEFORE UPDATE OF principal_handle,local_user_id ON hosted_principals WHEN OLD.principal_handle != NEW.principal_handle OR OLD.local_user_id != NEW.local_user_id BEGIN {} END;",
                    cleanup("OLD.local_user_id")
                ),
            ),
            (
                "users",
                format!(
                    "CREATE TRIGGER IF NOT EXISTS chat_secret_user_delete BEFORE DELETE ON users BEGIN {} END;",
                    cleanup("OLD.user_id")
                ),
            ),
            (
                "users",
                format!(
                    "CREATE TRIGGER IF NOT EXISTS chat_secret_user_rekey BEFORE UPDATE OF public_key ON users WHEN OLD.public_key != NEW.public_key BEGIN {} END;",
                    cleanup("OLD.user_id")
                ),
            ),
            (
                "user_residency",
                format!(
                    "CREATE TRIGGER IF NOT EXISTS chat_secret_residency_erasure BEFORE UPDATE ON user_residency WHEN NEW.data_state='empty' BEGIN {} END;",
                    cleanup("OLD.user_id")
                ),
            ),
            (
                "pending_user_operations",
                format!(
                    "CREATE TRIGGER IF NOT EXISTS chat_secret_pending_purge AFTER INSERT ON pending_user_operations WHEN NEW.operation='purge' BEGIN {} END;",
                    cleanup("NEW.user_id")
                ),
            ),
            (
                "pending_user_operations",
                format!(
                    "CREATE TRIGGER IF NOT EXISTS chat_secret_pending_purge_update AFTER UPDATE OF operation ON pending_user_operations WHEN NEW.operation='purge' BEGIN {} END;",
                    cleanup("NEW.user_id")
                ),
            ),
        ] {
            if tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get::<_, bool>(0),
            )? {
                tx.execute_batch(&trigger)?;
            }
        }
    }
    tx.pragma_update(None, "user_version", 66)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::chat_secret_recovery::{
        self as recovery,
        tests::{database, escrow},
    };
    use iota_identity::LocalUserId;

    #[test]
    fn initialization_index_backfills_duplicate_keys_into_blocker_bucket() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE relay_inbox(signer_principal INTEGER,message_id TEXT,state TEXT,prepared_operation BLOB,PRIMARY KEY(signer_principal,message_id));").unwrap();
        for (index, document) in recovery::tests::DUPLICATE_KEY_DOCUMENTS.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO relay_inbox VALUES(101,?1,'queued',?2)",
                    rusqlite::params![index.to_string(), document.as_bytes()],
                )
                .unwrap();
        }
        migrate(&connection, 65).unwrap();
        for (index, document) in recovery::tests::DUPLICATE_KEY_DOCUMENTS.iter().enumerate() {
            let metadata: (bool,String,Vec<u8>) = connection.query_row("SELECT initial_secret_ambiguous,initial_secret_chat_id,prepared_operation FROM relay_inbox WHERE message_id=?1", [index.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
            assert_eq!(
                metadata,
                (true, String::new(), document.as_bytes().to_vec())
            );
        }
    }

    #[test]
    fn initialization_index_backfills_historical_payloads_without_rewriting_them() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE relay_inbox(signer_principal INTEGER,message_id TEXT,state TEXT,prepared_operation BLOB,PRIMARY KEY(signer_principal,message_id));
            INSERT INTO relay_inbox VALUES
                (1,'legacy','queued',CAST('{\"operation\":{\"SetChatSecret\":{\"chat_id\":\"11:22\"}}}' AS BLOB)),
                (1,'wrapped','queued',CAST('{\"schema_version\":\"1\",\"operation\":{\"operation\":{\"SetChatSecret\":{\"chat_id\":\"principal:pair\"}}}}' AS BLOB)),
                (1,'ordinary','queued',CAST('{\"operation\":{\"MessageSend\":{}}}' AS BLOB)),
                (1,'future','queued',CAST('{\"schema_version\":\"2\",\"operation\":{}}' AS BLOB)),
                (1,'corrupt','queued',X'ffff');").unwrap();
        let original: Vec<(String, Vec<u8>)> = connection
            .prepare("SELECT message_id,prepared_operation FROM relay_inbox ORDER BY message_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        migrate(&connection, 65).unwrap();
        let rows: Vec<(String, Vec<u8>, Option<String>)> = connection.prepare("SELECT message_id,prepared_operation,initial_secret_chat_id FROM relay_inbox ORDER BY message_id").unwrap()
            .query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap();
        assert_eq!(
            rows.iter()
                .map(|(id, bytes, _)| (id.clone(), bytes.clone()))
                .collect::<Vec<_>>(),
            original
        );
        assert_eq!(
            rows.into_iter().map(|(_, _, key)| key).collect::<Vec<_>>(),
            [
                Some("".into()),
                Some("".into()),
                Some("11:22".into()),
                None,
                Some("principal:pair".into())
            ]
        );
    }

    #[test]
    fn initialization_index_migration_allows_minimal_fixtures_without_inbox() {
        let connection = Connection::open_in_memory().unwrap();
        migrate(&connection, 65).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            66
        );
    }

    #[test]
    fn lifecycle_removal_and_reassignment_fence_original_global_identity() {
        for mutation in [
            "DELETE FROM hosted_principals WHERE local_user_id=7",
            "UPDATE hosted_principals SET principal_handle=202 WHERE local_user_id=7",
            "DELETE FROM users WHERE user_id=7",
            "UPDATE users SET public_key='new-key' WHERE user_id=7",
            "INSERT INTO pending_user_operations VALUES(7,'purge')",
            "UPDATE user_residency SET data_state='empty' WHERE user_id=7",
        ] {
            let mut connection = database();
            migrate(&connection, 65).unwrap();
            connection
                .execute(
                    "INSERT INTO user_residency VALUES(7,'managed','present')",
                    [],
                )
                .unwrap();
            let evidence = escrow(1);
            let tx = connection.transaction().unwrap();
            recovery::commit_escrow_in_tx(&tx, &evidence).unwrap();
            recovery::recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
            recovery::enqueue_recovery_in_tx(
                &tx,
                LocalUserId(8),
                &evidence.first,
                &evidence.second,
                None,
                &[1; 32],
                0,
            )
            .unwrap();
            tx.commit().unwrap();
            connection.execute_batch(mutation).unwrap();
            for table in [
                "chat_secret_escrows",
                "chat_secret_outbox",
                "chat_secret_recovery_jobs",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "{mutation}: {table}");
            }
            let tx = connection.transaction().unwrap();
            assert!(
                matches!(
                    recovery::stage_escrow_in_tx(&tx, &evidence),
                    Err(StorageError::RelayOwnerUnavailable)
                ),
                "{mutation}"
            );
        }
    }

    #[test]
    fn schema_version_and_prior_password_table_survive() {
        let connection = database();
        connection.execute_batch("CREATE TABLE user_password_mutations(operation_id TEXT); INSERT INTO user_password_mutations VALUES('existing'); PRAGMA user_version=65;").unwrap();
        migrate(&connection, 65).unwrap();
        migrate(&connection, 66).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            66
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT operation_id FROM user_password_mutations",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "existing"
        );
    }
}
