#![cfg(feature = "relay-fault-injection")]

use iota_storage::util::{db, sync};
use tau::sync::{Cursor, Request, Response, Scope};

#[test]
fn sync_acknowledgments_commit_once_across_process_loss() {
    if let Ok(root) = std::env::var("IOTA_SYNC_ACK_CRASH_ROOT") {
        iota_util::file_util::configure_storage_directory(root.clone().into());
        db::initialize_database().unwrap();
        let request: Request = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(&root).join("ack.json")).unwrap(),
        )
        .unwrap();
        sync::paged::execute(7, &request).unwrap();
        panic!("the selected crash boundary did not terminate the process");
    }

    let root = std::path::Path::new("/tmp/opencode")
        .join(format!("sync-ack-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    iota_util::file_util::configure_storage_directory(root.clone());
    db::initialize_database().unwrap();
    let authority = format!("omega-key:{}", "a".repeat(64));
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,descriptor_revision,last_resolved_at) VALUES(101,'omega',?1,42,1,0)", [&authority])?;
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'sync-owner','fixture-key',0)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,101)", [])?;
        tx.execute("INSERT INTO hosted_auth_state(local_user_id,generation,enabled) VALUES(7,1,1) ON CONFLICT(local_user_id) DO NOTHING", [])?;
        tx.execute("INSERT INTO synced_settings(id,user_id,scope_type,scope_key,name,payload,revision,deleted) VALUES(1,7,'user','','setting','original',1,0)", [])?;
        sync::record_event(tx,7,sync::EntityType::Setting,1,sync::Operation::Upsert)?;
        Ok(())
    }).unwrap();
    let scope = Scope {
        principal: tau::relay_protocol::Principal::new(authority, 42).unwrap(),
        device_id: "crash-device".into(),
        authorization_generation: iota_storage::hosted_auth::resolve(iota_identity::LocalUserId(7))
            .unwrap()
            .0
            .auth_generation,
        schema: tau::sync::SCHEMA.into(),
        dictionary: tau::relay_protocol::dictionary_fingerprint("1.0").unwrap(),
    };
    let snapshot_request = Request::Snapshot {
        scope: scope.clone(),
        page: None,
        limit: 128,
    };
    let Response::Snapshot {
        head,
        page_id,
        next: None,
        records,
        ..
    } = sync::paged::execute(7, &snapshot_request).unwrap()
    else {
        panic!("expected a complete bounded snapshot");
    };
    assert_eq!(head, 1);
    assert_eq!(records.len(), 1);
    let request = Request::Acknowledge {
        cursor: Cursor {
            scope,
            sequence: head,
        },
        page_id: page_id.clone(),
    };
    std::fs::write(root.join("ack.json"), serde_json::to_vec(&request).unwrap()).unwrap();

    for boundary in [
        "before_sync_acknowledgment",
        "after_sync_acknowledgment",
        "after_sync_acknowledgment_commit",
    ] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sync_acknowledgments_commit_once_across_process_loss",
                "--nocapture",
            ])
            .env("IOTA_SYNC_ACK_CRASH_ROOT", &root)
            .env("IOTA_RELAY_FAULT_POINT", boundary)
            .env("IOTA_RELAY_FAULT_MESSAGE_ID", &page_id)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86), "{boundary}");
        let committed = boundary == "after_sync_acknowledgment_commit";
        assert_eq!(
            sync::acknowledged_version(7, "crash-device").unwrap(),
            committed.then_some(head)
        );
        db::with_db(|connection| {
            let checkpoints: i64 = connection.query_row(
                "SELECT COUNT(*) FROM account_sync_checkpoints WHERE user_id=7",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(checkpoints, i64::from(committed));
            let events: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sync_events WHERE user_id=7",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(events, 1);
            Ok(())
        })
        .unwrap();
    }
    for _ in 0..2 {
        assert!(
            matches!(sync::paged::execute(7, &request).unwrap(), Response::Acknowledged { cursor } if cursor.sequence == head && cursor.scope.device_id == "crash-device")
        );
    }
    assert_eq!(sync::head(7).unwrap(), head);
    db::with_db(|connection| {
        let checkpoints: i64 = connection.query_row(
            "SELECT COUNT(*) FROM account_sync_checkpoints WHERE user_id=7",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(checkpoints, 1);
        Ok(())
    })
    .unwrap();
}
