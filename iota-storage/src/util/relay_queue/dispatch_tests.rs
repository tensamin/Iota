use super::*;
use rusqlite::{Connection, TransactionBehavior};

pub(crate) fn setup(connection: &Connection) {
    connection.execute_batch(
            "CREATE TABLE pending_relays (
                id INTEGER PRIMARY KEY, destination_id INTEGER NOT NULL, target_kind INTEGER NOT NULL,
                frame BLOB NOT NULL, created_at INTEGER NOT NULL, frame_id INTEGER NOT NULL,
                type_map_version TEXT NOT NULL, relay_signer_id INTEGER, relay_destination_user_id INTEGER,
                relay_message_id TEXT, delivery_state TEXT NOT NULL DEFAULT 'ready', last_error TEXT,
                destination_principal INTEGER, signer_principal INTEGER, destination_node_id TEXT,
                destination_authority_id TEXT, attempt_count INTEGER NOT NULL DEFAULT 0,
                last_attempt_at INTEGER, next_attempt_at INTEGER NOT NULL DEFAULT 0,
                dispatch_generation INTEGER NOT NULL DEFAULT 0, dispatch_owner TEXT, dispatch_deadline INTEGER
            );
             CREATE TABLE users (user_id INTEGER PRIMARY KEY);
             CREATE TABLE hosted_principals (local_user_id INTEGER, principal_handle INTEGER);
             CREATE TABLE user_residency (user_id INTEGER PRIMARY KEY, lifecycle_state TEXT);
             CREATE TABLE hosted_auth_state (local_user_id INTEGER PRIMARY KEY, generation INTEGER, enabled INTEGER);
             CREATE TABLE principals (principal_pk INTEGER PRIMARY KEY, retired_at INTEGER);
             INSERT INTO users VALUES (7);
             INSERT INTO hosted_principals VALUES (7, 70);
             INSERT INTO hosted_auth_state VALUES (7, 1, 1), (8, 1, 1);
             INSERT INTO principals VALUES (70, NULL), (71, NULL);
             INSERT INTO user_residency VALUES (7, 'managed');",
        ).unwrap();
    connection.execute(
            "INSERT INTO pending_relays (destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, destination_principal, signer_principal, destination_node_id) VALUES (0, 2, X'0102', 10, 42, '1.0', 7, 8, 'first', 71, 70, ?1)",
            [format!("iota:v1:{}", "01".repeat(32))],
        ).unwrap();
}

pub(crate) fn claim(tx: &Transaction<'_>, now: i64) -> ClaimedPendingRelay {
    claim_ready_in_tx(tx, 1, 100, now).unwrap().remove(0)
}

#[test]
fn concurrent_connections_claim_disjoint_work() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dispatch.sqlite");
    let connection = Connection::open(&path).unwrap();
    setup(&connection);
    connection.execute("INSERT INTO pending_relays SELECT 2, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, 'second', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1", []).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut connection = Connection::open(path).unwrap();
                connection
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                barrier.wait();
                let tx = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                let work = claim(&tx, 10);
                tx.commit().unwrap();
                work
            })
        })
        .collect();
    let claims: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_ne!(claims[0].pending.id, claims[1].pending.id);
    assert_ne!(claims[0].claim.owner, claims[1].claim.owner);
    let tx = connection.unchecked_transaction().unwrap();
    assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
}

#[test]
fn takeover_fences_retry_quarantine_and_release() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let first = claim(&tx, 10);
    assert!(claim_ready_in_tx(&tx, 1, 100, 109).unwrap().is_empty());
    assert!(!verify_claim_in_tx(&tx, &first, 110).unwrap());
    let second = claim(&tx, 110);
    assert_eq!(second.claim.generation, first.claim.generation + 1);
    assert_ne!(second.claim.owner, first.claim.owner);
    assert!(!record_retry_claimed_in_tx(&tx, &first, 110, "stale", 110).unwrap());
    assert!(!quarantine_claimed_in_tx(&tx, &first, "stale", 110).unwrap());
    assert!(!release_claim_in_tx(&tx, &first, 110).unwrap());
    assert!(record_retry_claimed_in_tx(&tx, &second, 110, "offline", 110).unwrap());
    assert!(!verify_claim_in_tx(&tx, &second, 110).unwrap());
    assert!(claim_ready_in_tx(&tx, 1, 100, 5109).unwrap().is_empty());
    let third = claim(&tx, 5110);
    assert_eq!(third.pending.attempt_count, 1);
    assert_eq!(third.pending.last_error.as_deref(), Some("offline"));
    assert!(release_claim_in_tx(&tx, &third, 5110).unwrap());
    assert!(!release_claim_in_tx(&tx, &third, 5110).unwrap());
    let fourth = claim(&tx, 5110);
    assert!(quarantine_claimed_in_tx(&tx, &fourth, "invalid", 5110).unwrap());
    assert!(claim_ready_in_tx(&tx, 1, 100, 10000).unwrap().is_empty());
    assert_eq!(
        load_in_tx(&tx, 1).unwrap().unwrap().delivery_state,
        PendingRelayDeliveryState::Quarantined
    );
}

#[test]
fn exact_identity_and_owner_are_required() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection.transaction().unwrap();
    let original = claim(&tx, 10);
    let mut wrong = original.clone();
    wrong.claim.owner.push('x');
    assert!(!verify_claim_in_tx(&tx, &wrong, 10).unwrap());
    wrong = original.clone();
    wrong.claim.deadline += 1;
    assert!(!verify_claim_in_tx(&tx, &wrong, 10).unwrap());
    wrong = original.clone();
    wrong.pending.frame.push(3);
    assert!(matches!(
        verify_claim_in_tx(&tx, &wrong, 10),
        Err(StorageError::PendingRelayConflict)
    ));
    tx.execute("DELETE FROM pending_relays", []).unwrap();
    assert!(!verify_claim_in_tx(&tx, &original, 10).unwrap());
}

#[test]
fn claims_exclude_users_unauthorized_and_not_ready_rows() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection.transaction().unwrap();
    for update in [
        "target_kind = 0, destination_id = 8",
        "target_kind = 2, signer_principal = NULL",
        "signer_principal = 70, delivery_state = 'waiting_client'",
        "delivery_state = 'quarantined'",
        "delivery_state = 'ready', next_attempt_at = 11",
    ] {
        tx.execute(&format!("UPDATE pending_relays SET {update}"), [])
            .unwrap();
        assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
    }
    tx.execute("UPDATE pending_relays SET next_attempt_at = 0, target_kind = 1, destination_authority_id = 'omega:test'", []).unwrap();
    assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
    tx.execute("UPDATE pending_relays SET target_kind = 2", [])
        .unwrap();
    assert_eq!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().len(), 1);
}

#[test]
fn historical_targets_are_not_decoded_claimed_or_reenqueued() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection.transaction().unwrap();
    let current = load_in_tx(&tx, 1).unwrap().unwrap();
    // Old authority-scoped numeric targets do not carry a node identity.
    tx.execute("UPDATE pending_relays SET target_kind = 1, destination_id = 42, destination_authority_id = 'omega:historical', destination_node_id = NULL", []).unwrap();
    assert!(load_in_tx(&tx, 1).unwrap().is_none());
    assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
    assert!(matches!(
        enqueue_in_tx(
            &tx,
            current.target,
            &RelayIdentity {
                signer: PrincipalHandle(70),
                recipient: PrincipalHandle(71),
                message_id: "first".into(),
                legacy_signer_id: Some(7),
                legacy_recipient_id: Some(8),
            },
            &current.frame,
            current.created_at,
            current.frame_id,
            &current.type_map_version
        ),
        Err(StorageError::PendingRelayConflict)
    ));
    let historical: (i64, i64, String, Option<String>, i64) = tx.query_row(
            "SELECT target_kind, destination_id, destination_authority_id, destination_node_id, dispatch_generation FROM pending_relays WHERE id = 1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap();
    assert_eq!(historical, (1, 42, "omega:historical".into(), None, 0));
}

#[test]
fn active_targets_keep_their_persisted_kind_mapping() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection.transaction().unwrap();
    let node = IotaNodeId::new(format!("iota:v1:{}", "02".repeat(32))).unwrap();
    for (target, kind, message_id) in [
        (RelayTarget::User(8), 0, "user"),
        (RelayTarget::Iota(node), 2, "node"),
    ] {
        let id = enqueue_in_tx(
            &tx,
            target.clone(),
            &RelayIdentity {
                signer: PrincipalHandle(70),
                recipient: PrincipalHandle(71),
                message_id: message_id.into(),
                legacy_signer_id: Some(7),
                legacy_recipient_id: Some(8),
            },
            &[3],
            20,
            43,
            "1.0",
        )
        .unwrap();
        assert_eq!(load_in_tx(&tx, id).unwrap().unwrap().target, target);
        assert_eq!(
            tx.query_row(
                "SELECT target_kind FROM pending_relays WHERE id = ?1",
                [id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            kind
        );
    }
}

#[test]
fn user_claims_require_current_hosting_and_fence_takeover() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    connection.execute_batch(
            "INSERT INTO users VALUES (8);
             INSERT INTO hosted_principals VALUES (8, 71);
             INSERT INTO user_residency VALUES (8, 'managed');
             UPDATE pending_relays SET target_kind = 0, destination_id = 8, destination_node_id = NULL;
             INSERT INTO pending_relays SELECT 2, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, 'second', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1;",
        ).unwrap();
    let tx = connection.transaction().unwrap();
    assert!(claim_ready_in_tx(&tx, 500, 100, 10).unwrap().is_empty());
    assert!(
        claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(72), 100, 10)
            .unwrap()
            .is_none()
    );
    assert!(
        claim_ready_for_user_in_tx(&tx, 9, PrincipalHandle(71), 100, 10)
            .unwrap()
            .is_none()
    );
    for duration in [0, -1, i64::MAX] {
        assert!(claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), duration, 10).is_err());
    }
    let first = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
        .unwrap()
        .unwrap();
    let second = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
        .unwrap()
        .unwrap();
    assert_ne!(first.pending.id, second.pending.id);
    assert!(
        claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
            .unwrap()
            .is_none()
    );
    assert!(verify_claim_in_tx(&tx, &first, 10).unwrap());
    tx.execute_batch("SAVEPOINT key_rotation").unwrap();
    tx.execute(
        "UPDATE hosted_auth_state SET generation = generation + 1 WHERE local_user_id = 8",
        [],
    )
    .unwrap();
    assert!(verify_claim_in_tx(&tx, &first, 10).unwrap());
    assert!(release_claim_in_tx(&tx, &first, 10).unwrap());
    assert!(
        claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
            .unwrap()
            .is_some()
    );
    tx.execute_batch("ROLLBACK TO key_rotation; RELEASE key_rotation")
        .unwrap();
    for update in [
        "UPDATE user_residency SET lifecycle_state = 'released'",
        "UPDATE hosted_principals SET principal_handle = 72",
        "UPDATE hosted_auth_state SET enabled = 0 WHERE local_user_id = 8",
        "UPDATE principals SET retired_at = 10 WHERE principal_pk = 71",
        "DELETE FROM users",
    ] {
        tx.execute_batch("SAVEPOINT ownership_change").unwrap();
        tx.execute(update, []).unwrap();
        assert!(!verify_claim_in_tx(&tx, &first, 10).unwrap());
        assert!(!record_retry_claimed_in_tx(&tx, &first, 10, "offline", 10).unwrap());
        assert!(!quarantine_claimed_in_tx(&tx, &first, "invalid", 10).unwrap());
        assert!(!release_claim_in_tx(&tx, &first, 10).unwrap());
        assert!(
            claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 110)
                .unwrap()
                .is_none()
        );
        tx.execute_batch("ROLLBACK TO ownership_change; RELEASE ownership_change")
            .unwrap();
    }
    assert!(!verify_claim_in_tx(&tx, &first, 110).unwrap());
    let takeover = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 110)
        .unwrap()
        .unwrap();
    assert_eq!(takeover.pending.id, first.pending.id);
    assert_eq!(takeover.claim.generation, first.claim.generation + 1);
    assert!(!record_retry_claimed_in_tx(&tx, &first, 110, "stale", 110).unwrap());
    assert!(!quarantine_claimed_in_tx(&tx, &first, "stale", 110).unwrap());
    assert!(!release_claim_in_tx(&tx, &first, 110).unwrap());
    assert!(record_retry_claimed_in_tx(&tx, &takeover, 110, "offline", 110).unwrap());
    assert!(!verify_claim_in_tx(&tx, &takeover, 110).unwrap());
    assert_eq!(
        load_in_tx(&tx, first.pending.id)
            .unwrap()
            .unwrap()
            .attempt_count,
        1
    );
}

#[test]
fn exhausted_generations_and_invalid_leases_do_not_acquire() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection.transaction().unwrap();
    for duration in [0, -1, i64::MAX] {
        assert!(claim_ready_in_tx(&tx, 1, duration, 10).is_err());
    }
    for generation in [i64::MAX, -1] {
        tx.execute(
            "UPDATE pending_relays SET dispatch_generation = ?1",
            [generation],
        )
        .unwrap();
        tx.execute("UPDATE pending_relays SET delivery_state = 'ready'", [])
            .unwrap();
        assert!(claim_ready_in_tx(&tx, 1, 100, 10).unwrap().is_empty());
        let pending = load_in_tx(&tx, 1).unwrap().unwrap();
        assert_eq!(
            pending.delivery_state,
            PendingRelayDeliveryState::Quarantined
        );
        assert_eq!(
            pending.last_error.as_deref(),
            Some("dispatch_generation_exhausted")
        );
        assert_eq!(
            tx.query_row("SELECT dispatch_owner FROM pending_relays", [], |row| {
                row.get::<_, Option<String>>(0)
            })
            .unwrap(),
            None
        );
    }
    tx.execute("UPDATE pending_relays SET delivery_state = 'ready', dispatch_generation = 0, attempt_count = 9223372036854775807", []).unwrap();
    let claimed = claim(&tx, 10);
    assert!(record_retry_claimed_in_tx(&tx, &claimed, 10, "offline", 10).unwrap());
    assert!(!verify_claim_in_tx(&tx, &claimed, 10).unwrap());
    let pending = load_in_tx(&tx, 1).unwrap().unwrap();
    assert_eq!(pending.attempt_count, i64::MAX);
    assert_eq!(pending.frame, claimed.pending.frame);
    assert_eq!(
        pending.last_error.as_deref(),
        Some("dispatch_attempts_exhausted")
    );
    assert_eq!(
        pending.delivery_state,
        PendingRelayDeliveryState::Quarantined
    );
    let lease: (Option<String>, Option<i64>) = tx
        .query_row(
            "SELECT dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(lease, (None, None));
}

#[test]
fn poison_oldest_rows_do_not_starve_healthy_work() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    connection.execute("INSERT INTO pending_relays SELECT 2, destination_id, target_kind, X'03', created_at, -1, type_map_version, relay_signer_id, relay_destination_user_id, 'malformed', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1", []).unwrap();
    connection.execute("INSERT INTO pending_relays SELECT 3, destination_id, target_kind, X'04', created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, 'healthy', delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at, dispatch_generation, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = 1", []).unwrap();
    connection
        .execute(
            "UPDATE pending_relays SET dispatch_generation = 9223372036854775807 WHERE id = 1",
            [],
        )
        .unwrap();
    // Exercise both selectors. The limit counts healthy work, not poison rows.
    for local in [false, true] {
        let tx = connection.transaction().unwrap();
        let healthy = if local {
            tx.execute_batch("INSERT INTO users VALUES (8); INSERT INTO hosted_principals VALUES (8, 71); INSERT INTO user_residency VALUES (8, 'managed'); UPDATE pending_relays SET target_kind = 0, destination_id = 8;").unwrap();
            claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
                .unwrap()
                .unwrap()
        } else {
            claim_ready_in_tx(&tx, 1, 100, 10).unwrap().remove(0)
        };
        assert_eq!(healthy.pending.id, 3);
        for (id, bytes, code) in [
            (1, vec![1, 2], "dispatch_generation_exhausted"),
            (2, vec![3], "dispatch_malformed_pending"),
        ] {
            let row: (Vec<u8>, String, String, Option<String>, Option<i64>) = tx.query_row("SELECT frame, delivery_state, last_error, dispatch_owner, dispatch_deadline FROM pending_relays WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).unwrap();
            assert_eq!(row, (bytes, "quarantined".into(), code.into(), None, None));
        }
        // Roll back so the other selector sees the same poison rows.
    }
}

#[test]
fn remote_claims_require_canonical_current_origin_ownership() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection.transaction().unwrap();
    // The legacy signer number need not match the canonical local owner.
    tx.execute("UPDATE pending_relays SET relay_signer_id = 999", [])
        .unwrap();
    let now = now_millis();
    let work = claim_ready_in_tx(&tx, 1, 60_000, now).unwrap().remove(0);
    assert!(verify_claim_in_tx(&tx, &work, now).unwrap());
    tx.execute_batch("SAVEPOINT key_rotation").unwrap();
    tx.execute(
        "UPDATE hosted_auth_state SET generation = generation + 1 WHERE local_user_id = 7",
        [],
    )
    .unwrap();
    assert!(verify_claim_in_tx(&tx, &work, now).unwrap());
    assert!(release_claim_in_tx(&tx, &work, now).unwrap());
    assert_eq!(claim_ready_in_tx(&tx, 1, 60_000, now).unwrap().len(), 1);
    tx.execute_batch("ROLLBACK TO key_rotation; RELEASE key_rotation")
        .unwrap();
    for update in [
        "UPDATE user_residency SET lifecycle_state = 'released'",
        "UPDATE hosted_principals SET principal_handle = 999",
        "UPDATE hosted_auth_state SET enabled = 0 WHERE local_user_id = 7",
        "UPDATE principals SET retired_at = 10 WHERE principal_pk = 70",
        "DELETE FROM users",
    ] {
        tx.execute_batch("SAVEPOINT ownership").unwrap();
        tx.execute(update, []).unwrap();
        assert!(!verify_claim_in_tx(&tx, &work, now).unwrap());
        assert!(!record_retry_claimed_in_tx(&tx, &work, now, "offline", now).unwrap());
        assert!(!quarantine_claimed_in_tx(&tx, &work, "invalid", now).unwrap());
        assert!(!release_claim_in_tx(&tx, &work, now).unwrap());
        assert!(
            !super::super::downstream_relay::acknowledge_claimed_pending_delivery_in_tx(
                &tx, &work, "first", now
            )
            .unwrap()
        );
        assert!(
            !super::super::downstream_relay::reject_claimed_pending_delivery_in_tx(
                &tx, &work, "rejected"
            )
            .unwrap()
        );
        assert_eq!(
            load_in_tx(&tx, work.pending.id).unwrap().unwrap(),
            work.pending
        );
        assert!(
            claim_ready_in_tx(&tx, 1, 100, now + 60_000)
                .unwrap()
                .is_empty()
        );
        tx.execute_batch("ROLLBACK TO ownership; RELEASE ownership")
            .unwrap();
    }
    assert!(release_claim_in_tx(&tx, &work, now).unwrap());
    tx.execute(
        "UPDATE pending_relays SET signer_principal = 999, relay_signer_id = 7",
        [],
    )
    .unwrap();
    assert!(claim_ready_in_tx(&tx, 1, 100, 10).unwrap().is_empty());
}

#[test]
fn pause_and_resume_cannot_revive_client_claim() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    let tx = connection.transaction().unwrap();
    tx.execute_batch("INSERT INTO users VALUES (8); INSERT INTO hosted_principals VALUES (8, 71); INSERT INTO user_residency VALUES (8, 'managed'); UPDATE pending_relays SET target_kind = 0, destination_id = 8;").unwrap();
    let old = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
        .unwrap()
        .unwrap();
    pause_client_deliveries_in_tx(&tx, 8).unwrap();
    assert!(!verify_claim_in_tx(&tx, &old, 10).unwrap());
    tx.execute("UPDATE pending_relays SET delivery_state = 'ready', last_error = NULL WHERE delivery_state = 'waiting_client'", []).unwrap();
    assert!(!verify_claim_in_tx(&tx, &old, 10).unwrap());
    assert!(!record_retry_claimed_in_tx(&tx, &old, 10, "stale", 10).unwrap());
    assert!(!quarantine_claimed_in_tx(&tx, &old, "stale", 10).unwrap());
    let new = claim_ready_for_user_in_tx(&tx, 8, PrincipalHandle(71), 100, 10)
        .unwrap()
        .unwrap();
    assert_eq!(new.claim.generation, old.claim.generation + 1);
    assert!(verify_claim_in_tx(&tx, &new, 10).unwrap());
    assert!(!verify_claim_in_tx(&tx, &old, 10).unwrap());
}

#[test]
fn reused_frames_are_ambiguous_before_mutation() {
    let mut connection = Connection::open_in_memory().unwrap();
    setup(&connection);
    connection.execute("INSERT INTO pending_relays (destination_id, target_kind, frame, created_at, frame_id, type_map_version) VALUES (0, 2, X'03', 20, 42, '1.0')", []).unwrap();
    let tx = connection.transaction().unwrap();
    assert!(matches!(
        ensure_unique_frame_in_tx(&tx, 0, 2, 42),
        Err(StorageError::AmbiguousRelayDelivery)
    ));
    assert_eq!(
        tx.query_row("SELECT count(*) FROM pending_relays", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
}
