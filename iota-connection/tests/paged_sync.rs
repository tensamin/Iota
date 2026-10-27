use iota_connection::message_handlers::handle_account_state_request;
use iota_storage::util::{db, sync};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use rusqlite::params;
use tau::sync::{Cursor, Request, Response, Scope, SyncError};

fn exchange(request: Request) -> Response {
    let frame = CommunicationValue::new(CommunicationType::AccountStateRequest)
        .with_sender(7)
        .with_id(9)
        .add_typed_default(
            DataType::Json,
            DataValue::Bytes(serde_json::to_vec(&request).unwrap()),
        );
    let response = handle_account_state_request(&frame);
    assert_eq!(response.id(), Some(9));
    assert_eq!(response.type_map(), frame.type_map());
    tau::sync::decode_response(&response, &frame).unwrap()
}

#[test]
fn pages_pin_state_authorize_scope_and_require_explicit_complete_acknowledgment() {
    let directory =
        std::path::Path::new("/tmp/opencode").join(format!("paged-sync-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    iota_util::file_util::configure_storage_directory(directory.clone());
    db::initialize_database().unwrap();
    let authority = format!("omega-key:{}", "a".repeat(64));
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,descriptor_revision,last_resolved_at) VALUES(101,'omega',?1,42,1,0)", [&authority])?;
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'sync-owner','fixture-key',0)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,101)", [])?;
        tx.execute("INSERT INTO hosted_auth_state(local_user_id,generation,enabled) VALUES(7,1,1) ON CONFLICT(local_user_id) DO NOTHING", [])?;
        for index in 1..=3 {
            tx.execute("INSERT INTO synced_settings(id,user_id,scope_type,scope_key,name,payload,revision,deleted) VALUES(?1,7,'user','',?2,'original',1,0)", params![index,format!("setting{index}")])?;
            sync::record_event(tx,7,sync::EntityType::Setting,index,sync::Operation::Upsert)?;
        }
        Ok(())
    }).unwrap();
    let scope = Scope {
        principal: tau::relay_protocol::Principal::new(authority, 42).unwrap(),
        device_id: "device-a".into(),
        authorization_generation: iota_storage::hosted_auth::resolve(iota_identity::LocalUserId(7))
            .unwrap()
            .0
            .auth_generation,
        schema: tau::sync::SCHEMA.into(),
        dictionary: tau::relay_protocol::dictionary_fingerprint("1.0").unwrap(),
    };
    let response = exchange(Request::Snapshot {
        scope: scope.clone(),
        page: None,
        limit: 1,
    });
    let Response::Snapshot {
        head,
        page_id,
        next: Some(next),
        records,
        ..
    } = response
    else {
        panic!("expected first bounded page: {response:?}");
    };
    assert_eq!(head, 3);
    assert_eq!(records.len(), 1);
    assert!(matches!(
        exchange(Request::Acknowledge {
            cursor: Cursor {
                scope: scope.clone(),
                sequence: head
            },
            page_id: page_id.clone()
        }),
        Response::Unavailable {
            error: SyncError::SnapshotRequired
        }
    ));
    assert_eq!(sync::acknowledged_version(7, "device-a").unwrap(), None);
    db::with_immediate_transaction(|tx| {
        let revision =
            sync::record_event(tx, 7, sync::EntityType::Setting, 2, sync::Operation::Upsert)?;
        tx.execute(
            "UPDATE synced_settings SET payload='changed',revision=?1 WHERE id=2",
            [revision],
        )?;
        Ok(())
    })
    .unwrap();
    let Response::Snapshot {
        next: None,
        records,
        head: still_head,
        ..
    } = exchange(Request::Snapshot {
        scope: scope.clone(),
        page: Some(next.clone()),
        limit: 128,
    })
    else {
        panic!("expected pinned continuation");
    };
    assert_eq!(still_head, 3);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].value["payload"], "original");
    let Response::Snapshot { records: again, .. } = exchange(Request::Snapshot {
        scope: scope.clone(),
        page: Some(next),
        limit: 128,
    }) else {
        panic!("expected idempotent page replay");
    };
    assert_eq!(
        serde_json::to_vec(&again).unwrap(),
        serde_json::to_vec(&records).unwrap()
    );
    let mut other_device = scope.clone();
    other_device.device_id = "device-b".into();
    assert!(matches!(
        exchange(Request::Snapshot {
            scope: other_device,
            page: Some(tau::sync::PageToken {
                id: page_id.clone(),
                offset: 1
            }),
            limit: 128
        }),
        Response::Unavailable {
            error: SyncError::SnapshotRequired
        }
    ));
    assert!(matches!(
        exchange(Request::Acknowledge {
            cursor: Cursor {
                scope: scope.clone(),
                sequence: head
            },
            page_id
        }),
        Response::Acknowledged { .. }
    ));
    assert_eq!(sync::acknowledged_version(7, "device-a").unwrap(), Some(3));
    let Response::Delta {
        events,
        head,
        next: None,
        ..
    } = exchange(Request::Delta {
        after: Cursor {
            scope: scope.clone(),
            sequence: 3,
        },
        page: None,
        limit: 128,
    })
    else {
        panic!("expected ordered delta");
    };
    assert_eq!(head, 4);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, 4);
    assert_eq!(
        events[0].record.as_ref().unwrap().value["payload"],
        "changed"
    );
    db::with_immediate_transaction(|tx| {
        let revision =
            sync::record_event(tx, 7, sync::EntityType::Setting, 2, sync::Operation::Upsert)?;
        tx.execute(
            "UPDATE synced_settings SET payload='later',revision=?1 WHERE id=2",
            [revision],
        )?;
        Ok(())
    })
    .unwrap();
    db::with_immediate_transaction(|tx| {
        sync::record_event(tx, 7, sync::EntityType::Setting, 2, sync::Operation::Delete)?;
        tx.execute("DELETE FROM synced_settings WHERE id=2", [])?;
        Ok(())
    })
    .unwrap();
    let Response::Delta { events, head, .. } = exchange(Request::Delta {
        after: Cursor {
            scope: scope.clone(),
            sequence: 3,
        },
        page: None,
        limit: 128,
    }) else {
        panic!("expected immutable historical projections");
    };
    assert_eq!(head, 6);
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![4, 5, 6]
    );
    assert_eq!(
        events[0].record.as_ref().unwrap().value["payload"],
        "changed"
    );
    assert_eq!(events[1].record.as_ref().unwrap().value["payload"], "later");
    assert_eq!(events[2].operation, tau::sync::EventAction::Delete);
    assert!(events[2].record.is_none());
    assert!(
        db::with_immediate_transaction(|tx| {
            tx.execute(
                "UPDATE sync_events SET projection=X'00' WHERE user_id=7 AND version=4",
                [],
            )?;
            Ok(())
        })
        .is_err()
    );
    assert!(
        db::with_immediate_transaction(|tx| {
            sync::record_event(tx, 7, sync::EntityType::Setting, 1, sync::Operation::Upsert)?;
            tx.execute(
                "UPDATE synced_settings SET payload='rolled back' WHERE id=1",
                [],
            )?;
            Err::<(), _>(iota_storage::storage_error::StorageError::MessageUnauthorized)
        })
        .is_err()
    );
    assert_eq!(sync::head(7).unwrap(), 6);
    sync::compact_user_sync_state(7).unwrap();
    assert!(matches!(
        exchange(Request::Delta {
            after: Cursor {
                scope: scope.clone(),
                sequence: 0
            },
            page: None,
            limit: 128
        }),
        Response::Unavailable {
            error: SyncError::SnapshotRequired
        }
    ));
    let Response::Snapshot {
        page_id: expired, ..
    } = exchange(Request::Snapshot {
        scope: scope.clone(),
        page: None,
        limit: 128,
    })
    else {
        panic!("expected fresh snapshot");
    };
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE account_sync_pages SET expires_at=0 WHERE id=?1",
            [&expired],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        exchange(Request::Snapshot {
            scope: scope.clone(),
            page: Some(tau::sync::PageToken {
                id: expired,
                offset: 0
            }),
            limit: 128
        }),
        Response::Unavailable {
            error: SyncError::SnapshotRequired
        }
    ));
    let mut changed = scope.clone();
    changed.authorization_generation += 1;
    assert!(matches!(
        exchange(Request::Snapshot {
            scope: changed,
            page: None,
            limit: 128
        }),
        Response::Unavailable {
            error: SyncError::IdentityChanged
        }
    ));
    let mut other = scope;
    other.principal.user_id = 43;
    assert!(matches!(
        exchange(Request::Snapshot {
            scope: other,
            page: None,
            limit: 128
        }),
        Response::Unavailable {
            error: SyncError::IdentityChanged
        }
    ));
    std::fs::remove_dir_all(directory).unwrap();
}
