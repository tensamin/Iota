use super::*;

fn principal(authority: &str, user_id: u64) -> PrincipalId {
    PrincipalId {
        authority: AuthorityId::new(authority).unwrap(),
        user_id,
    }
}

pub(crate) fn database() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch("CREATE TABLE principals(principal_pk INTEGER PRIMARY KEY,authority_id TEXT,remote_user_id INTEGER);
        INSERT INTO principals VALUES(101,'authority-a',11),(202,'authority-b',22);
        CREATE TABLE users(user_id INTEGER PRIMARY KEY,public_key TEXT);
        INSERT INTO users VALUES(7,'key-a'),(8,'key-b');
        CREATE TABLE hosted_principals(local_user_id INTEGER PRIMARY KEY,principal_handle INTEGER);
        INSERT INTO hosted_principals VALUES(7,101),(8,202);
        CREATE TABLE user_residency(user_id INTEGER,lifecycle_state TEXT,data_state TEXT);
        CREATE TABLE pending_user_operations(user_id INTEGER,operation TEXT);
        CREATE TABLE relay_inbox(signer_principal INTEGER,message_id TEXT,state TEXT,prepared_operation BLOB,PRIMARY KEY(signer_principal,message_id));
        CREATE TABLE relay_deferred_secrets(signer_principal INTEGER,message_id TEXT,completed_at INTEGER);
        CREATE TABLE chat_secrets(user_id TEXT,chat_id TEXT,secret_id TEXT,version INTEGER,
            encrypted_secret BLOB,kem_ciphertext BLOB,wrapping_scheme TEXT,created_at INTEGER,updated_at INTEGER,
            PRIMARY KEY(user_id,chat_id,secret_id,version));").unwrap();
    connection.execute_batch(SCHEMA).unwrap();
    connection
        .execute_batch(include_str!("relay_initialization.sql"))
        .unwrap();
    connection
}

pub(crate) fn escrow(version: i64) -> Escrow {
    let first = principal("authority-a", 11);
    let second = principal("authority-b", 22);
    let original_frame = vec![5, 6, version as u8];
    Escrow {
        first: first.clone(),
        second: second.clone(),
        version,
        namespace: WrappingNamespace {
            chat_id: "11:22".into(),
            secret_id: "chat:11:22:main".into(),
        },
        wrapping_scheme: "ml-kem-test".into(),
        signer: first.clone(),
        message_id: format!("epoch-{version}"),
        operation_digest: operation_digest(RelayFormat::NativeMtpSealedV1, &original_frame),
        original_frame,
        original_type_map_version: "1.0".into(),
        format: RelayFormat::NativeMtpSealedV1,
        envelopes: [
            RecipientEnvelope {
                owner: first,
                recipient_id: OriginalRecipientId::Numeric(11),
                encrypted_secret: vec![version as u8, 11],
                kem_ciphertext: vec![11, 1],
            },
            RecipientEnvelope {
                owner: second,
                recipient_id: OriginalRecipientId::Numeric(22),
                encrypted_secret: vec![version as u8, 22],
                kem_ciphertext: vec![22, 2],
            },
        ],
        created_at: 100,
    }
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn pending_is_not_recovery_authority_and_rollback_does_not_promote() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    stage_escrow_in_tx(&tx, &evidence).unwrap();
    stage_escrow_in_tx(&tx, &evidence).unwrap();
    assert!(
        escrow_for_recovery_on(
            &tx,
            &evidence.first,
            &evidence.second,
            &evidence.first,
            None
        )
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence),
        Err(StorageError::MissingRelayDependency)
    ));
    tx.commit().unwrap();
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
    tx.rollback().unwrap();
    assert_eq!(count(&connection, "chat_secrets"), 0);
    assert_eq!(count(&connection, "chat_secret_outbox"), 0);
    assert!(
        escrow_for_recovery_on(
            &connection,
            &evidence.first,
            &evidence.second,
            &evidence.first,
            None
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn exact_owner_copy_restores_deleted_historical_epoch_without_rewrapping() {
    let mut connection = database();
    let evidence = escrow(3);
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    let first = recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
    let second = recover_owner_envelope_in_tx(&tx, LocalUserId(8), &evidence).unwrap();
    assert_eq!(
        first.encrypted_secret,
        evidence.envelopes[0].encrypted_secret
    );
    assert_eq!(
        second.encrypted_secret,
        evidence.envelopes[1].encrypted_secret
    );
    assert_ne!(first.encrypted_secret, second.encrypted_secret);
    assert_eq!(
        first.chat_id,
        canonical_chat_id(&evidence.first, &evidence.second).unwrap()
    );
    tx.commit().unwrap();
    let old_id: i64 = connection
        .query_row(
            "SELECT id FROM chat_secret_outbox WHERE storage_owner=7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute("DELETE FROM chat_secrets WHERE user_id='7'", [])
        .unwrap();
    let tx = connection.transaction().unwrap();
    let restored = recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
    assert_eq!(restored.encrypted_secret, first.encrypted_secret);
    assert_eq!(restored.kem_ciphertext, first.kem_ciphertext);
    assert_eq!(restored.version, 3);
    let new_id: i64 = tx
        .query_row(
            "SELECT id FROM chat_secret_outbox WHERE storage_owner=7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(new_id > old_id);
    recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
    let replay_id: i64 = tx
        .query_row(
            "SELECT id FROM chat_secret_outbox WHERE storage_owner=7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(new_id, replay_id);
    let read = escrow_for_recovery_on(
        &tx,
        &evidence.second,
        &evidence.first,
        &evidence.first,
        Some(3),
    )
    .unwrap()
    .unwrap();
    assert_eq!(read, evidence);
    assert_eq!(read.namespace.chat_id, "11:22");
    tx.commit().unwrap();
}

#[test]
fn different_envelope_namespace_or_provenance_conflicts_without_writes() {
    let mut connection = database();
    let original = escrow(1);
    let tx = connection.transaction().unwrap();
    stage_escrow_in_tx(&tx, &original).unwrap();
    tx.commit().unwrap();
    let mut changes = vec![original.clone(); 5];
    changes[0].envelopes[1].encrypted_secret.push(99);
    changes[1].namespace.chat_id = "another-namespace".into();
    changes[2].message_id = "alternate-proof".into();
    changes[3].original_frame.push(7);
    changes[3].operation_digest = operation_digest(changes[3].format, &changes[3].original_frame);
    changes[4].original_type_map_version = "1.1".into();
    for changed in changes {
        let tx = connection.transaction().unwrap();
        assert!(commit_escrow_in_tx(&tx, &changed).is_err());
        tx.rollback().unwrap();
        let bytes: Vec<u8> = connection
            .query_row("SELECT evidence FROM chat_secret_escrows", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(serde_json::from_slice::<Escrow>(&bytes).unwrap(), original);
        assert_eq!(count(&connection, "chat_secrets"), 0);
        assert_eq!(count(&connection, "chat_secret_outbox"), 0);
    }
}

#[test]
fn restoration_conflict_preserves_existing_owner_row() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
    tx.execute("UPDATE chat_secrets SET encrypted_secret=X'ff'", [])
        .unwrap();
    assert!(matches!(
        recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence),
        Err(StorageError::ChatSecretConflict)
    ));
    let stored: Vec<u8> = tx
        .query_row("SELECT encrypted_secret FROM chat_secrets", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stored, vec![255]);
}

#[test]
fn erasure_fence_removes_both_copies_jobs_events_and_rejects_old_proof() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
    enqueue_recovery_in_tx(
        &tx,
        LocalUserId(8),
        &evidence.first,
        &evidence.second,
        Some(1),
        &[4; 32],
        0,
    )
    .unwrap();
    purge_owner_in_tx(&tx, LocalUserId(7)).unwrap();
    tx.commit().unwrap();
    for table in [
        "chat_secret_escrows",
        "chat_secret_recovery_jobs",
        "chat_secret_outbox",
    ] {
        assert_eq!(count(&connection, table), 0);
    }
    let tx = connection.transaction().unwrap();
    assert!(matches!(
        stage_escrow_in_tx(&tx, &evidence),
        Err(StorageError::RelayOwnerUnavailable)
    ));
    assert!(
        escrow_for_recovery_on(
            &tx,
            &evidence.first,
            &evidence.second,
            &evidence.second,
            None
        )
        .is_err()
    );
}

#[test]
fn interrupted_owner_restore_rolls_back_promotion_owner_row_and_outbox() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    stage_escrow_in_tx(&tx, &evidence).unwrap();
    tx.commit().unwrap();
    connection.execute_batch("CREATE TRIGGER interrupt BEFORE INSERT ON chat_secret_outbox BEGIN SELECT RAISE(ABORT,'crash boundary'); END;").unwrap();
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    assert!(recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).is_err());
    tx.rollback().unwrap();
    assert_eq!(count(&connection, "chat_secrets"), 0);
    assert_eq!(count(&connection, "chat_secret_outbox"), 0);
    assert!(
        escrow_for_recovery_on(
            &connection,
            &evidence.first,
            &evidence.second,
            &evidence.first,
            None
        )
        .unwrap()
        .is_none()
    );
    connection.execute_batch("DROP TRIGGER interrupt;").unwrap();
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
    tx.commit().unwrap();
    assert_eq!(count(&connection, "chat_secrets"), 1);
    assert_eq!(count(&connection, "chat_secret_outbox"), 1);
}

#[test]
fn recovery_jobs_deduplicate_latest_and_exact_versions_with_durable_nonces() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    let latest = enqueue_recovery_in_tx(
        &tx,
        LocalUserId(7),
        &evidence.first,
        &evidence.second,
        None,
        &[1; 32],
        10,
    )
    .unwrap();
    let duplicate = enqueue_recovery_in_tx(
        &tx,
        LocalUserId(7),
        &evidence.second,
        &evidence.first,
        None,
        &[2; 32],
        20,
    )
    .unwrap();
    assert_eq!(latest, duplicate);
    let nonce: Vec<u8> = tx
        .query_row(
            "SELECT nonce FROM chat_secret_recovery_jobs WHERE id=?1",
            [latest],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(nonce, vec![1; 32]);
    let exact = enqueue_recovery_in_tx(
        &tx,
        LocalUserId(7),
        &evidence.first,
        &evidence.second,
        Some(1),
        &[3; 32],
        10,
    )
    .unwrap();
    assert_ne!(latest, exact);
    let job = RecoveryJob {
        id: latest,
        owner: LocalUserId(7),
        first: evidence.first,
        second: evidence.second,
        version: None,
        nonce: vec![1; 32],
        attempts: 0,
        next_at: 10,
    };
    let mut forged = job.clone();
    forged.nonce = vec![99; 32];
    assert!(!complete_recovery_job_in_tx(&tx, &forged).unwrap());
    assert!(complete_recovery_job_in_tx(&tx, &job).unwrap());
    assert!(!complete_recovery_job_in_tx(&tx, &job).unwrap());
    let reactivated = enqueue_recovery_in_tx(
        &tx,
        LocalUserId(7),
        &job.first,
        &job.second,
        None,
        &[5; 32],
        30,
    )
    .unwrap();
    assert_eq!(reactivated, latest);
    assert!(!complete_recovery_job_in_tx(&tx, &job).unwrap());
    let refreshed: (Vec<u8>, Option<i64>, i64) = tx
        .query_row(
            "SELECT nonce,done_at,attempts FROM chat_secret_recovery_jobs WHERE id=?1",
            [latest],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(refreshed, (vec![5; 32], None, 0));
    tx.commit().unwrap();
}

#[test]
fn missing_hosted_state_and_purge_intent_fail_closed() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    tx.execute("INSERT INTO pending_user_operations VALUES(7,'purge')", [])
        .unwrap();
    assert!(matches!(
        recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence),
        Err(StorageError::RelayOwnerUnavailable)
    ));
    tx.execute("DELETE FROM pending_user_operations", [])
        .unwrap();
    tx.execute("DELETE FROM hosted_principals WHERE local_user_id=7", [])
        .unwrap();
    assert!(matches!(
        recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence),
        Err(StorageError::RelayOwnerUnavailable)
    ));
}

#[test]
fn global_storage_namespace_is_independent_of_local_handles() {
    let connection = database();
    let first = e2ee_storage::principal_chat_id_on(
        &connection,
        iota_identity::PrincipalHandle(101),
        iota_identity::PrincipalHandle(202),
    )
    .unwrap();
    connection
        .execute(
            "UPDATE principals SET principal_pk=909 WHERE principal_pk=101",
            [],
        )
        .unwrap();
    let second = e2ee_storage::principal_chat_id_on(
        &connection,
        iota_identity::PrincipalHandle(202),
        iota_identity::PrincipalHandle(909),
    )
    .unwrap();
    assert_eq!(first, second);
}

#[test]
fn digest_is_format_bound_and_each_original_recipient_is_checked() {
    let evidence = escrow(1);
    assert_ne!(
        operation_digest(RelayFormat::NativeMtpSealedV1, &evidence.original_frame),
        operation_digest(RelayFormat::TauSignedRelayV1, &evidence.original_frame)
    );
    let mut changed = evidence.clone();
    changed.envelopes[1].recipient_id = OriginalRecipientId::Numeric(11);
    assert!(changed.validate().is_err());
    let mut changed = evidence;
    changed.envelopes.swap(0, 1);
    assert!(changed.validate().is_err());
}

#[test]
fn acceptance_marker_survives_lost_escrow_and_rejects_reinitialization() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    stage_escrow_in_tx(&tx, &evidence).unwrap();
    let pending = pair_acceptance_on(&tx, &evidence.first, &evidence.second).unwrap();
    assert!(pending.has_pending);
    assert_eq!(pending.latest_committed_version, None);
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    tx.commit().unwrap();
    // Simulate lost storage independently of normal SQL erasure protections.
    connection
        .execute_batch(
            "DROP TRIGGER chat_secret_escrows_accepted_delete; DELETE FROM chat_secret_escrows;",
        )
        .unwrap();
    let status = pair_acceptance_on(&connection, &evidence.first, &evidence.second).unwrap();
    assert_eq!(status.latest_committed_version, Some(1));
    assert!(!status.has_pending);
    assert!(
        escrow_for_recovery_on(
            &connection,
            &evidence.first,
            &evidence.second,
            &evidence.first,
            None
        )
        .unwrap()
        .is_none()
    );
    let mut alternate = evidence.clone();
    alternate.envelopes[0].encrypted_secret.push(99);
    let tx = connection.transaction().unwrap();
    assert!(matches!(
        stage_escrow_in_tx(&tx, &alternate),
        Err(StorageError::ChatSecretConflict)
    ));
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    assert_eq!(
        escrow_for_recovery_on(
            &tx,
            &evidence.first,
            &evidence.second,
            &evidence.first,
            None
        )
        .unwrap()
        .unwrap(),
        evidence
    );
}

#[test]
fn legacy_numeric_collisions_fail_without_partially_staged_evidence() {
    let mut connection = database();
    connection
        .execute("INSERT INTO principals VALUES(303,'authority-c',11)", [])
        .unwrap();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    assert!(matches!(
        stage_escrow_in_tx(&tx, &evidence),
        Err(StorageError::MessageUnauthorized)
    ));
    assert_eq!(count(&tx, "chat_secret_epochs"), 0);
    assert_eq!(count(&tx, "chat_secret_escrows"), 0);
}

#[test]
fn initialization_distinguishes_empty_exact_pending_conflict_and_accepted() {
    let mut connection = database();
    let evidence = escrow(1);
    assert_eq!(
        initialization_state_on(&connection, &evidence.first, &evidence.second, None).unwrap(),
        InitializationState::Empty
    );
    let tx = connection.transaction().unwrap();
    stage_escrow_in_tx(&tx, &evidence).unwrap();
    assert_eq!(
        initialization_state_on(
            &tx,
            &evidence.first,
            &evidence.second,
            Some(&evidence.operation_digest)
        )
        .unwrap(),
        InitializationState::ExactPendingProposal
    );
    assert_eq!(
        initialization_state_on(&tx, &evidence.first, &evidence.second, None).unwrap(),
        InitializationState::Conflict
    );
    assert_eq!(
        initialization_state_on(&tx, &evidence.first, &evidence.second, Some(&[7; 32])).unwrap(),
        InitializationState::Conflict
    );
    assert!(
        escrow_for_recovery_on(
            &tx,
            &evidence.first,
            &evidence.second,
            &evidence.first,
            None
        )
        .unwrap()
        .is_none()
    );
    commit_escrow_in_tx(&tx, &evidence).unwrap();
    assert_eq!(
        initialization_state_on(&tx, &evidence.first, &evidence.second, None).unwrap(),
        InitializationState::Accepted
    );
}

fn inbox_proposal(evidence: &Escrow, remote: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"schema_version":"1","operation": {
        "signer_identity":evidence.signer,"recipient_identity":evidence.second,
        "operation":{"SetChatSecret":{"version":1}},"secret_escrow":evidence,
        "delivery":if remote {serde_json::json!({"Remote":"node"})} else {serde_json::json!({"Local":7})}
    }})).unwrap()
}

pub(crate) const DUPLICATE_KEY_DOCUMENTS: &[&str] = &[
    r#"{"operation":{"MessageSend":{}},"operation":{"SetChatSecret":{"chat_id":"11:22"}}}"#,
    r#"{"schema_version":"1","schema_version":"2","operation":{"operation":{"MessageSend":{}}}}"#,
    r#"{"schema_version":"1","operation":{"operation":{"MessageSend":{}}},"operation":{"operation":{"SetChatSecret":{"chat_id":"11:22"}}}}"#,
    r#"{"schema_version":"1","operation":{"operation":{"MessageSend":{}},"operation":{"SetChatSecret":{"chat_id":"11:22"}}}}"#,
    r#"{"operation":{"SetChatSecret":{"chat_id":"other-pair","chat_id":"11:22"}}}"#,
    r#"{"operation":{"SetChatSecret":{"chat_id":"other-pair"},"SetChatSecret":{"chat_id":"11:22"}}}"#,
    r#"{"operation":{"MessageSend":{}},"signer_identity":{"authority":"other","authority":"authority-a","user_id":11}}"#,
    r#"{"operation":{"MessageSend":{}},"recipient_identity":{"authority":"authority-b","user_id":99,"user_id":22}}"#,
    r#"{"operation":{"MessageSend":{}},"oper\u0061tion":{"SetChatSecret":{"chat_id":"11:22"}}}"#,
    r#"{"operation":{"SetChatSecret":{"chat_id":"other-pair","chat\u005fid":"11:22"}}}"#,
    r#"{"operation":{"MessageSend":{}},"arbitrary":[{"nested":{"unrelated":1,"unrel\u0061ted":2}}]}"#,
    r#"{"operation":{"MessageSend":{}},"arbitrary":{"":1,"":2}}"#,
];

#[test]
fn duplicate_keys_anywhere_remain_indexed_blockers_on_insert_and_update() {
    let connection = database();
    let evidence = escrow(1);
    let ordinary = br#"{"operation":{"MessageSend":{"content":"\"key\":1,\"key\":2"}},"separate":[{"same":1},{"same":2}]}"#;
    for document in DUPLICATE_KEY_DOCUMENTS {
        for insert_duplicate in [true, false] {
            connection.execute("INSERT INTO relay_inbox(signer_principal,message_id,state,prepared_operation) VALUES(101,'duplicate','queued',?1)",
                [if insert_duplicate { document.as_bytes() } else { ordinary.as_slice() }]).unwrap();
            if !insert_duplicate {
                assert_eq!(
                    initialization_state_on(&connection, &evidence.first, &evidence.second, None)
                        .unwrap(),
                    InitializationState::Empty
                );
                connection
                    .execute(
                        "UPDATE relay_inbox SET prepared_operation=?1",
                        [document.as_bytes()],
                    )
                    .unwrap();
            }
            let metadata: (bool,String,Vec<u8>) = connection.query_row("SELECT initial_secret_ambiguous,initial_secret_chat_id,prepared_operation FROM relay_inbox", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
            assert_eq!(
                metadata,
                (true, String::new(), document.as_bytes().to_vec())
            );
            assert_eq!(
                initialization_state_on(&connection, &evidence.first, &evidence.second, None)
                    .unwrap(),
                InitializationState::Conflict,
                "{document}"
            );
            connection
                .execute(
                    "UPDATE relay_inbox SET prepared_operation=?1",
                    [ordinary.as_slice()],
                )
                .unwrap();
            assert_eq!(
                initialization_state_on(&connection, &evidence.first, &evidence.second, None)
                    .unwrap(),
                InitializationState::Empty
            );
            connection.execute("DELETE FROM relay_inbox", []).unwrap();
        }
    }
}

#[test]
fn initialization_history_scan_filters_unrelated_work_and_rejects_overflow() {
    use rusqlite::{StatementStatus, TransactionBehavior};

    let mut connection = database();
    let evidence = escrow(1);
    let chat_id = canonical_chat_id(&evidence.first, &evidence.second).unwrap();
    let mut steps = Vec::new();
    for index in 0..10_000 {
        for (kind, operation) in [
            ("message", serde_json::json!({"MessageSend": {}})),
            (
                "other-pair",
                serde_json::json!({"SetChatSecret": {"chat_id": "other-pair", "version": 1}}),
            ),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema_version": "1", "operation": {"operation": operation}
            }))
            .unwrap();
            connection
                .execute(
                    "INSERT INTO relay_inbox(signer_principal,message_id,state,prepared_operation) VALUES(101,?1,'queued',?2)",
                    params![format!("{kind}-{index}"), bytes],
                )
                .unwrap();
        }
        if index == 999 || index == 9_999 {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let mut statement = tx.prepare(INITIALIZATION_INBOX_SQL).unwrap();
            assert!(
                !statement
                    .query(params![101, 202, chat_id, "principal:101:202", "11:22"])
                    .unwrap()
                    .next()
                    .unwrap()
                    .is_some()
            );
            steps.push(statement.get_status(StatementStatus::VmStep));
            assert_eq!(statement.get_status(StatementStatus::FullscanStep), 0);
            assert_eq!(statement.get_status(StatementStatus::Sort), 0);
            assert_eq!(statement.get_status(StatementStatus::AutoIndex), 0);
            assert_eq!(
                initialization_state_on(&tx, &evidence.first, &evidence.second, None).unwrap(),
                InitializationState::Empty,
            );
        }
    }
    assert_eq!(
        steps[0], steps[1],
        "unrelated histories changed VM work: {steps:?}"
    );
    assert!(steps[1] < 250, "unexpected query work: {steps:?}");
    let plan: Vec<String> = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {INITIALIZATION_INBOX_SQL}"))
        .unwrap()
        .query_map(
            params![101, 202, chat_id, "principal:101:202", "11:22"],
            |row| row.get(3),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(plan.len(), 1, "{plan:?}");
    assert!(plan[0].contains("SEARCH relay_inbox USING INDEX relay_inbox_initial_secret (signer_principal=? AND initial_secret_chat_id=?)"), "{plan:?}");
    let functions: Vec<String> = connection
        .prepare(&format!("EXPLAIN {INITIALIZATION_INBOX_SQL}"))
        .unwrap()
        .query_map(
            params![101, 202, chat_id, "principal:101:202", "11:22"],
            |row| row.get(1),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        !functions
            .iter()
            .any(|opcode| opcode == "Function" || opcode == "PureFunc")
    );
    eprintln!(
        "initialization inbox query VM steps at 1,000/10,000 messages plus other-pair secrets: {steps:?}; plan: {plan:?}"
    );
    for index in 0..501 {
        connection
            .execute(
                "INSERT INTO relay_inbox(signer_principal,message_id,state,prepared_operation) VALUES(101,?1,'queued',?2)",
                params![format!("matching-{index}"), inbox_proposal(&evidence, true)],
            )
            .unwrap();
    }
    assert!(matches!(
        initialization_state_on(&connection, &evidence.first, &evidence.second, None),
        Err(StorageError::Other(_)),
    ));
}

#[test]
fn initialization_index_tracks_mutations_and_keeps_corrupt_evidence_fail_closed() {
    let connection = database();
    let evidence = escrow(1);
    for bytes in [
        vec![0xff, 0xfe],
        b"{broken".to_vec(),
        br#"{"schema_version":"2","operation":{"operation":{"MessageSend":{}}}}"#.to_vec(),
        br#"{"schema_version":1,"operation":{}}"#.to_vec(),
        br#"{"schema_version":"1","operation":"invalid"}"#.to_vec(),
        br#"{}"#.to_vec(),
        br#"{"operation":{"UnknownOperation":{}}}"#.to_vec(),
        br#"{"operation":{"SetChatSecret":{"chat_id":42}}}"#.to_vec(),
    ] {
        connection
            .execute(
                "INSERT INTO relay_inbox(signer_principal,message_id,state,prepared_operation) VALUES(101,'mutated','queued',?1)",
                [&bytes],
            )
            .unwrap();
        assert_eq!(
            initialization_state_on(&connection, &evidence.first, &evidence.second, None).unwrap(),
            InitializationState::Conflict,
            "{bytes:?}"
        );
        connection
            .execute("UPDATE relay_inbox SET state='rejected'", [])
            .unwrap();
        assert_eq!(
            initialization_state_on(&connection, &evidence.first, &evidence.second, None).unwrap(),
            InitializationState::Empty
        );
        connection
            .execute(
                "UPDATE relay_inbox SET state='queued',prepared_operation=?1",
                [inbox_proposal(&evidence, false)],
            )
            .unwrap();
        assert_eq!(
            initialization_state_on(&connection, &evidence.first, &evidence.second, None).unwrap(),
            InitializationState::Accepted
        );
        connection
            .execute(
                "UPDATE relay_inbox SET prepared_operation=?1",
                [br#"{"operation":{"MessageSend":{}}}"#.as_slice()],
            )
            .unwrap();
        assert_eq!(
            initialization_state_on(&connection, &evidence.first, &evidence.second, None).unwrap(),
            InitializationState::Empty
        );
        connection.execute("DELETE FROM relay_inbox", []).unwrap();
    }
    // Legacy unwrapped evidence uses the same index and still reaches the
    // canonical-principal proof check rather than trusting its namespace alone.
    let wrapped: serde_json::Value =
        serde_json::from_slice(&inbox_proposal(&evidence, false)).unwrap();
    connection
        .execute(
            "INSERT INTO relay_inbox(signer_principal,message_id,state,prepared_operation) VALUES(101,'legacy','queued',?1)",
            [serde_json::to_vec(&wrapped["operation"]).unwrap()],
        )
        .unwrap();
    assert_eq!(
        initialization_state_on(&connection, &evidence.first, &evidence.second, None).unwrap(),
        InitializationState::Accepted
    );
}

#[test]
fn accepted_inbox_owner_rows_and_finalized_origin_prevent_reinitialization() {
    for source in ["destination", "finalized-origin", "owner-row"] {
        let mut connection = database();
        let evidence = escrow(1);
        if source == "owner-row" {
            let tx = connection.transaction().unwrap();
            commit_escrow_in_tx(&tx, &evidence).unwrap();
            recover_owner_envelope_in_tx(&tx, LocalUserId(7), &evidence).unwrap();
            tx.commit().unwrap();
            connection.execute_batch("DROP TRIGGER chat_secret_escrows_accepted_delete; DROP TRIGGER chat_secret_epochs_accepted_delete; DELETE FROM chat_secret_escrows; DELETE FROM chat_secret_epochs;").unwrap();
        } else {
            connection
                .execute(
                    "INSERT INTO relay_inbox(signer_principal,message_id,state,prepared_operation) VALUES(101,?1,'queued',?2)",
                    params![
                        evidence.message_id,
                        inbox_proposal(&evidence, source == "finalized-origin")
                    ],
                )
                .unwrap();
            if source == "finalized-origin" {
                connection
                    .execute(
                        "INSERT INTO relay_deferred_secrets VALUES(101,?1,100)",
                        [&evidence.message_id],
                    )
                    .unwrap();
            }
        }
        assert_eq!(
            initialization_state_on(&connection, &evidence.first, &evidence.second, None).unwrap(),
            InitializationState::Accepted,
            "{source}"
        );
    }
}

#[test]
fn exact_rejection_releases_only_losing_pending_provenance_for_peer_recovery() {
    let mut connection = database();
    let original = escrow(1);
    let mut losing = original.clone();
    losing.original_frame.push(99);
    losing.operation_digest = operation_digest(losing.format, &losing.original_frame);
    losing.envelopes[0].encrypted_secret = vec![99, 11];
    losing.envelopes[1].encrypted_secret = vec![99, 22];
    losing.message_id = "losing-proposal".into();
    connection
        .execute(
            "INSERT INTO relay_inbox(signer_principal,message_id,state,prepared_operation) VALUES(101,?1,'queued',?2)",
            params![losing.message_id, inbox_proposal(&losing, true)],
        )
        .unwrap();
    let tx = connection.transaction().unwrap();
    stage_escrow_in_tx(&tx, &losing).unwrap();
    assert!(matches!(
        commit_escrow_in_tx(&tx, &original),
        Err(StorageError::ChatSecretConflict)
    ));
    quarantine_pending_escrow_in_tx(&tx, iota_identity::PrincipalHandle(101), &losing.message_id)
        .unwrap();
    assert_eq!(count(&tx, "chat_secret_escrows"), 0);
    assert_eq!(count(&tx, "chat_secret_epochs"), 0);
    assert_eq!(count(&tx, "chat_secret_rejected_proposals"), 1);
    assert_eq!(
        initialization_state_on(
            &tx,
            &original.first,
            &original.second,
            Some(&original.operation_digest)
        )
        .unwrap(),
        InitializationState::Empty
    );
    commit_escrow_in_tx(&tx, &original).unwrap();
    let restored = recover_owner_envelope_in_tx(&tx, LocalUserId(7), &original).unwrap();
    assert_eq!(
        restored.encrypted_secret,
        original.envelopes[0].encrypted_secret
    );
    quarantine_pending_escrow_in_tx(
        &tx,
        iota_identity::PrincipalHandle(101),
        &original.message_id,
    )
    .unwrap();
    assert_eq!(count(&tx, "chat_secret_escrows"), 1);
    assert_eq!(count(&tx, "chat_secret_epochs"), 1);
    assert!(tx.execute("DELETE FROM chat_secret_escrows", []).is_err());
    assert!(tx.execute("DELETE FROM chat_secret_epochs", []).is_err());
    tx.commit().unwrap();
    assert_eq!(
        initialization_state_on(&connection, &original.first, &original.second, None).unwrap(),
        InitializationState::Accepted
    );
}

#[test]
fn rejection_cleanup_and_peer_import_share_a_rollback_boundary() {
    let mut connection = database();
    let evidence = escrow(1);
    let tx = connection.transaction().unwrap();
    stage_escrow_in_tx(&tx, &evidence).unwrap();
    tx.commit().unwrap();
    let tx = connection.transaction().unwrap();
    quarantine_pending_escrow_in_tx(
        &tx,
        iota_identity::PrincipalHandle(101),
        &evidence.message_id,
    )
    .unwrap();
    assert_eq!(count(&tx, "chat_secret_escrows"), 0);
    tx.rollback().unwrap();
    assert_eq!(count(&connection, "chat_secret_rejected_proposals"), 0);
    assert_eq!(count(&connection, "chat_secret_escrows"), 1);
    assert!(
        escrow_for_recovery_on(
            &connection,
            &evidence.first,
            &evidence.second,
            &evidence.first,
            None
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn latest_recovery_never_falls_back_to_an_older_remaining_escrow() {
    let mut connection = database();
    let first = escrow(1);
    let second = escrow(2);
    let tx = connection.transaction().unwrap();
    commit_escrow_in_tx(&tx, &first).unwrap();
    commit_escrow_in_tx(&tx, &second).unwrap();
    tx.commit().unwrap();
    connection.execute_batch("DROP TRIGGER chat_secret_escrows_accepted_delete; DELETE FROM chat_secret_escrows WHERE version=2;").unwrap();
    assert!(
        escrow_for_recovery_on(&connection, &first.first, &first.second, &first.first, None)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        escrow_for_recovery_on(
            &connection,
            &first.first,
            &first.second,
            &first.first,
            Some(1)
        )
        .unwrap()
        .unwrap(),
        first
    );
}
