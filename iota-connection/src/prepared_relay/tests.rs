use super::*;
use iota_identity::{AuthorityId, HostedAuthorizationLease, IotaNodeId, PrincipalId};
use iota_storage::hosted_auth;

fn operation(message_id: &str) -> PreparedRelayOperation {
    let signer = PrincipalId {
        authority: AuthorityId::new("authority-a").unwrap(),
        user_id: 11,
    };
    let recipient = PrincipalId {
        authority: AuthorityId::new("authority-b").unwrap(),
        user_id: 22,
    };
    let frame = CommunicationValue::new(CommunicationType::Relay).with_id(1);
    let map_version = frame.type_map().unwrap().version.to_string();
    let frame = frame.without_id().to_bytes().unwrap();
    let chat_id = chat_secret_recovery::canonical_chat_id(&signer, &recipient).unwrap();
    let sender_copy = SecretCopy {
        encrypted_secret: vec![1],
        kem_ciphertext: vec![11],
    };
    let recipient_copy = SecretCopy {
        encrypted_secret: vec![2],
        kem_ciphertext: vec![22],
    };
    let format = chat_secret_recovery::RelayFormat::NativeMtpSealedV1;
    let created_at = now_millis_i64();
    // Cryptographic ingress has separate integration coverage. This fixture
    // exercises the authorization/transaction boundary before any application.
    let escrow = chat_secret_recovery::Escrow {
        first: signer.clone(),
        second: recipient.clone(),
        version: 1,
        namespace: chat_secret_recovery::WrappingNamespace {
            chat_id: chat_id.clone(),
            secret_id: e2ee_storage::principal_secret_id(&chat_id),
        },
        wrapping_scheme: "fixture".into(),
        signer: signer.clone(),
        message_id: message_id.into(),
        original_frame: frame.clone(),
        original_type_map_version: map_version.clone(),
        format,
        operation_digest: chat_secret_recovery::operation_digest(format, &frame),
        envelopes: [(&signer, &sender_copy), (&recipient, &recipient_copy)].map(|(owner, copy)| {
            chat_secret_recovery::RecipientEnvelope {
                owner: owner.clone(),
                recipient_id: chat_secret_recovery::OriginalRecipientId::Principal(
                    chat_secret_recovery::principal_key(owner).unwrap(),
                ),
                encrypted_secret: copy.encrypted_secret.clone(),
                kem_ciphertext: copy.kem_ciphertext.clone(),
            }
        }),
        created_at,
    };
    PreparedRelayOperation {
        origin_lease: None,
        secret_escrow: Some(escrow),
        signer: PrincipalHandle(101),
        recipient: PrincipalHandle(202),
        message_id: message_id.into(),
        signer_id: 11,
        recipient_id: 22,
        signer_identity: crate::federated_relay::protocol_principal(&signer),
        recipient_identity: crate::federated_relay::protocol_principal(&recipient),
        created_at: created_at as u64,
        accepted_at: created_at,
        frame,
        frame_id: 1,
        type_map_version: map_version,
        operation: ApplicationOperation::SetChatSecret {
            chat_id,
            legacy_chat_id: None,
            version: 1,
            wrapping_scheme: "fixture".into(),
            sender: sender_copy,
            recipient: recipient_copy,
        },
        effects: vec![LocalEffect {
            owner: LocalUserId(7),
            principal: PrincipalHandle(101),
            sent_by_self: true,
        }],
        delivery: DeliveryTarget::Remote(
            IotaNodeId::new(format!("iota:v1:{}", "0".repeat(64))).unwrap(),
        ),
    }
}

fn acquire(
    operation: &PreparedRelayOperation,
    lease: &HostedAuthorizationLease,
) -> relay_replay::ProcessingClaim {
    let bytes = crate::persisted_relay::encode_prepared_operation(operation).unwrap();
    db::with_immediate_transaction(|tx| {
        let relay_replay::AcquireResult::Claimed(claim)=relay_replay::acquire_hosted_relay_in_tx(tx,lease,operation.request(),i64::MAX)? else {panic!("expected an exclusive hosted claim");};
        tx.execute("UPDATE relay_inbox SET prepared_operation=?3 WHERE signer_principal=?1 AND message_id=?2",params![claim.signer.0,claim.message_id,bytes])?;
        Ok(claim)
    }).unwrap()
}

fn assert_no_application_writes() {
    db::with_db(|connection| {
        for table in [
            "chat_secret_epochs",
            "chat_secret_escrows",
            "chat_secrets",
            "chat_secret_outbox",
            "pending_relays",
            "relay_deferred_secrets",
            "messages",
            "commit_guard_probe",
        ] {
            let count: i64 =
                connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            assert_eq!(count, 0, "{table}");
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn actual_commit_and_recovery_recheck_origin_lease() {
    if std::env::var_os("IOTA_PREPARED_COMMIT_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "prepared_relay::tests::actual_commit_and_recovery_recheck_origin_lease",
                "--nocapture",
            ])
            .env("IOTA_PREPARED_COMMIT_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let path = std::path::PathBuf::from("/tmp/opencode").join(format!(
        "prepared-commit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    iota_util::file_util::configure_storage_directory(path.clone());
    db::initialize_database().unwrap();
    db::with_immediate_transaction(|tx| {
        tx.execute_batch("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,home,last_resolved_at) VALUES(101,'iota','authority-a',11,'local',1),(202,'iota','authority-b',22,'remote',1);
            INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'owner','fixture-key',1);
            INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,101);
            CREATE TABLE commit_guard_probe(id INTEGER);")?;
        Ok(())
    }).unwrap();
    hosted_auth::maintain_server("prepared-test-server", true).unwrap();
    let (identity, _) = hosted_auth::resolve(LocalUserId(7)).unwrap();
    let lease = HostedAuthorizationLease {
        connection_id: "omikron-relay:00000000-0000-4000-8000-000000000003".into(),
        server_instance: "prepared-test-server".into(),
        identity,
    };
    hosted_auth::register(&lease).unwrap();
    let mut pending = operation("revoked-after-acquire");
    pending.bind_origin_lease(&lease).unwrap();
    let claim = acquire(&pending, &lease);
    hosted_auth::revoke_forwarded(&lease.connection_id).unwrap();
    assert!(matches!(
        pending.commit_checked(&claim, |_| Ok(())),
        Err(StorageError::HostedAuthorizationDenied)
    ));
    assert_no_application_writes();

    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE relay_inbox SET processing_deadline=0 WHERE message_id=?1",
            [&claim.message_id],
        )?;
        Ok(())
    })
    .unwrap();
    let work = relay_work::incomplete(1).unwrap().pop().unwrap();
    let replacement = relay_work::take_over_abandoned_processing(&work, i64::MAX)
        .unwrap()
        .unwrap();
    let persisted = crate::persisted_relay::decode_prepared_operation(&work.prepared).unwrap();
    assert!(matches!(
        persisted.commit_checked(&replacement, |_| Ok(())),
        Err(StorageError::HostedAuthorizationDenied)
    ));
    assert_no_application_writes();

    let active = HostedAuthorizationLease {
        connection_id: "omikron-relay:00000000-0000-4000-8000-000000000004".into(),
        ..lease
    };
    hosted_auth::register(&active).unwrap();
    let mut checked = operation("guard-rejected");
    checked.bind_origin_lease(&active).unwrap();
    let claim = acquire(&checked, &active);
    let mut invoked = false;
    assert!(matches!(
        checked.commit_checked(&claim, |tx| {
            invoked = true;
            tx.execute("INSERT INTO commit_guard_probe VALUES(1)", [])?;
            Err(StorageError::MessageUnauthorized)
        }),
        Err(StorageError::MessageUnauthorized)
    ));
    assert!(invoked);
    assert_no_application_writes();
    std::fs::remove_dir_all(path).unwrap();
}
