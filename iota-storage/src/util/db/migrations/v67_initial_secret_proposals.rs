use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 67 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(include_str!(
        "../../chat_secret_recovery/initial_proposals.sql"
    ))?;
    tx.pragma_update(None, "user_version", 67)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_is_resumable_and_proposals_are_immutable_pair_qualified_and_erased() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(crate::util::chat_secret_recovery::SCHEMA)
            .unwrap();
        migrate(&connection, 66).unwrap();
        migrate(&connection, 66).unwrap();
        migrate(&connection, 67).unwrap();
        connection.execute("INSERT INTO initial_secret_proposals(signer_principal,message_id,first_principal,second_principal,version,operation_digest,verified_prepared_operation,original_type_map_version,first_revision,second_revision,first_home,second_home,state,next_at,created_at) VALUES('first','original','first','second',1,?1,X'01','1.0',1,1,'iota:a','iota:b','awaiting_peer_proof',0,0)",[vec![1;32]]).unwrap();
        assert!(connection.execute("INSERT INTO initial_secret_proposals SELECT 'second','competing',first_principal,second_principal,version,?1,verified_prepared_operation,original_type_map_version,first_revision,second_revision,first_home,second_home,state,attempt_generation,claim_owner,claim_deadline,next_at,created_at,last_error FROM initial_secret_proposals",[vec![2;32]]).is_err());
        for change in [
            "operation_digest=zeroblob(32)",
            "verified_prepared_operation=X'02'",
            "original_type_map_version='1.1'",
            "first_revision=2",
        ] {
            assert!(
                connection
                    .execute(&format!("UPDATE initial_secret_proposals SET {change}"), [])
                    .is_err()
            );
        }
        connection
            .execute(
                "UPDATE initial_secret_proposals SET state='rejected',last_error='conflict'",
                [],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE initial_secret_proposals SET state='awaiting_peer_proof'",
                    []
                )
                .is_err()
        );
        connection
            .execute(
                "INSERT INTO chat_secret_erasure_fences VALUES('second',0)",
                [],
            )
            .unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM initial_secret_proposals", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
