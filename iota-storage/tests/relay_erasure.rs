use iota_identity::{
    AuthorityKind, LocalNodeIdentity, LocalUserDescriptor, LocalUserId, PrincipalHome,
};
use iota_storage::{
    identity::SqlitePrincipalStore,
    storage_error::StorageError,
    users::{user_manager, user_profile::UserProfile},
    util::{db, relay_replay, relay_work, sync},
};
use rusqlite::params;
use serde_json::json;

#[test]
fn purge_and_erase_fence_accepted_work_without_touching_unrelated_corruption() {
    let storage = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(storage.path().to_owned());
    db::initialize_database().unwrap();
    let node = LocalNodeIdentity::from_keyring(mtp::crypto::Keyring::generate()).unwrap();

    for (owner, erase) in [(1, false), (2, true)] {
        let user = LocalUserDescriptor {
            id: LocalUserId(owner),
            username: format!("user-{owner}"),
            display_name: None,
            public_key: node.public_keys().try_to_base64().unwrap(),
        };
        let profile = UserProfile::new_with_created_at(
            owner,
            user.username.clone(),
            None,
            user.public_key.clone(),
            None,
            None,
            1,
        );
        user_manager::try_add_user(profile.clone()).unwrap();
        let store = SqlitePrincipalStore;
        let home = PrincipalHome::Iota(node.node_id().clone());
        store
            .ensure_local_principal(
                node.authority_id(),
                AuthorityKind::Iota,
                &user,
                home.clone(),
                1,
            )
            .unwrap();
        let principal = store.principal_for_local_user(user.id).unwrap().unwrap();
        let now = sync::now_millis();
        let mut claims = Vec::new();
        for (message_id, state, bytes) in [
            ("v1-processing", "processing", None),
            ("v1-received", "received", None),
            (
                "legacy",
                "received",
                Some(
                    json!({"effects": [{"owner": owner}]})
                        .to_string()
                        .into_bytes(),
                ),
            ),
            ("applied", "applied", None),
            (
                "corrupt",
                "processing",
                Some(b"{broken unrelated prepared bytes".to_vec()),
            ),
            (
                "unrelated",
                "processing",
                Some(
                    json!({"schema_version": "1", "operation": {"effects": [{"owner": 900}]}})
                        .to_string()
                        .into_bytes(),
                ),
            ),
            (
                "scalar-effect",
                "processing",
                Some(br#"{"effects":["unrelated",null,42]}"#.to_vec()),
            ),
        ] {
            let claim = match relay_replay::acquire(
                relay_replay::RelayReservationRequest {
                    signer_principal: principal,
                    signer_id: owner as u64,
                    message_id,
                    created_at: now as u64,
                    accepted_at: now,
                    destination_id: owner as u64,
                    frame: b"accepted-frame",
                    frame_id: 42,
                    type_map_version: "1.0",
                },
                now - 1,
            )
            .unwrap()
            {
                relay_replay::AcquireResult::Claimed(claim) => claim,
                other => panic!("expected a claim, got {other:?}"),
            };
            let prepared = bytes.unwrap_or_else(|| {
                json!({
                    "schema_version": "1",
                    "operation": {
                        "signer": principal.0, "recipient": principal.0,
                        "message_id": message_id, "signer_id": owner, "recipient_id": owner,
                        "signer_identity": {"authority": node.authority_id().as_str(), "user_id": owner},
                        "recipient_identity": {"authority": node.authority_id().as_str(), "user_id": owner},
                        "created_at": now, "accepted_at": now, "frame": [1], "frame_id": 42,
                        "type_map_version": "1.0", "operation": {"AddConversation": {"name": null}},
                        "effects": [{"owner": owner, "principal": principal.0, "sent_by_self": true}],
                        "delivery": {"Local": owner}
                    }
                }).to_string().into_bytes()
            });
            db::with_immediate_transaction(|tx| {
                tx.execute(
                    "UPDATE relay_inbox SET prepared_operation = ?3 WHERE signer_principal = ?1 AND message_id = ?2",
                    params![principal.0, message_id, prepared],
                )?;
                if state == "applied" {
                    relay_replay::complete_application_in_tx(tx, &claim)?;
                } else if state == "received" {
                    tx.execute(
                        "UPDATE relay_inbox SET state = 'received', processing_owner = NULL, processing_deadline = NULL WHERE signer_principal = ?1 AND message_id = ?2",
                        params![principal.0, message_id],
                    )?;
                }
                Ok(())
            }).unwrap();
            claims.push(claim);
        }
        let before = relay_work::incomplete(100).unwrap();
        db::with_immediate_transaction(|tx| {
            for storage_owner in [0, owner, 900] {
                tx.execute(
                    "INSERT INTO relay_receipt_backfill_blocks VALUES (?1, 'backfill', ?2, 'invalid_json')",
                    params![principal.0, storage_owner],
                )?;
            }
            tx.execute(
                "INSERT INTO relay_acceptance_receipts(storage_owner, signer_principal, message_id, accepted_at) VALUES (?1, ?2, 'receipt', ?3)",
                params![owner, principal.0, now],
            )?;
            Ok(())
        }).unwrap();
        if erase {
            user_manager::erase_user_locally(owner).unwrap();
            assert!(user_manager::get_user(owner).unwrap().is_none());
        } else {
            user_manager::purge_user_data(owner).unwrap();
            assert!(
                !user_manager::get_residency_by_id(owner)
                    .unwrap()
                    .unwrap()
                    .data_present
            );
        }
        db::with_db(|connection| {
            let mut statement = connection.prepare(
                "SELECT storage_owner FROM relay_receipt_backfill_blocks WHERE signer_principal = ?1 ORDER BY storage_owner",
            )?;
            let owners = statement.query_map([principal.0], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(owners, vec![0, 900]);
            let receipts: i64 = connection.query_row(
                "SELECT COUNT(*) FROM relay_acceptance_receipts WHERE storage_owner = ?1",
                [owner], |row| row.get(0),
            )?;
            assert_eq!(receipts, 0);
            Ok(())
        }).unwrap();

        // Restore hosting eligibility to prove the durable inbox fence, rather
        // than a missing account or binding, prevents reconstruction.
        user_manager::try_add_user(profile).unwrap();
        db::with_immediate_transaction(|tx| {
            tx.execute(
                "UPDATE user_residency SET data_state = 'present' WHERE user_id = ?1",
                [owner],
            )?;
            tx.execute(
                "DELETE FROM hosted_principals WHERE local_user_id = ?1",
                [owner],
            )?;
            Ok(())
        })
        .unwrap();
        store
            .ensure_local_principal(node.authority_id(), AuthorityKind::Iota, &user, home, now)
            .unwrap();
        db::with_immediate_transaction(|tx| relay_work::verify_owner_in_tx(tx, owner, principal))
            .unwrap();

        for claim in &claims {
            let affected = matches!(
                claim.message_id.as_str(),
                "v1-processing" | "v1-received" | "legacy" | "applied"
            );
            db::with_immediate_transaction(|tx| {
                let (state, status, prepared, applied_at, rejected_at): (String, String, Vec<u8>, Option<i64>, Option<i64>) = tx.query_row(
                    "SELECT state, recovery_status, prepared_operation, applied_at, rejected_at FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2",
                    params![principal.0, claim.message_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )?;
                let observed = before.iter().find(|work| work.signer == principal && work.message_id == claim.message_id).unwrap();
                assert_eq!(prepared, observed.prepared);
                if affected {
                    assert_eq!(status, "blocked");
                    assert!(matches!(relay_replay::verify_claim_in_tx(tx, claim), Err(StorageError::StaleRelayClaim)));
                    assert!(matches!(relay_replay::complete_application_in_tx(tx, claim), Err(StorageError::StaleRelayClaim)));
                    if claim.message_id == "applied" {
                        assert_eq!(state, "applied");
                        assert!(applied_at.is_some());
                        assert!(rejected_at.is_none());
                    } else {
                        assert_eq!(state, "rejected");
                        assert!(rejected_at.is_some());
                    }
                } else {
                    assert_eq!(state, "processing");
                    assert_eq!(status, "ready");
                    relay_replay::verify_claim_in_tx(tx, claim)?;
                }
                Ok(())
            }).unwrap();
            if affected && claim.message_id != "applied" {
                let observed = before
                    .iter()
                    .find(|work| work.signer == principal && work.message_id == claim.message_id)
                    .unwrap();
                assert!(
                    relay_work::take_over_abandoned_processing(observed, now + 30_000)
                        .unwrap()
                        .is_none()
                );
            }
        }
        assert!(relay_work::incomplete(100).unwrap().iter().all(|work| {
            work.signer != principal
                || matches!(
                    work.message_id.as_str(),
                    "corrupt" | "unrelated" | "scalar-effect"
                )
        }));
    }
}
