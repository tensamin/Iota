#[allow(dead_code)]
mod relay_support;

use iota_connection::message_handlers::{
    handle_get_chat_secret, validated_chat_secret_read_target,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use relay_support::{Fixture, execute, initialize};

fn request(user: &str, chat: &str) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::GetChatSecret)
        .with_id(71)
        .with_sender(1)
        .add_typed_default(DataType::UserId, DataValue::Str(user.into()))
        .add_typed_default(DataType::ChatId, DataValue::Str(chat.into()))
        .add_typed_default(
            DataType::SecretId,
            DataValue::Str(format!("chat:{chat}:main")),
        )
}

#[test]
fn numeric_reads_bind_original_owner_and_reject_ambiguous_or_forged_namespaces() {
    let path = std::env::temp_dir().join(format!("chat-secret-reads-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    initialize(&path);
    let fixture = Fixture::new(true);
    let valid = request("1", "1:2");
    let (owner, peer, version) = validated_chat_secret_read_target(&valid).unwrap();
    assert_eq!(owner, fixture.ids[0]);
    assert_eq!(peer, fixture.ids[1]);
    assert_eq!(version, None);
    assert!(handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInternal));

    use iota_storage::util::chat_secret_recovery as recovery;
    iota_storage::util::e2ee_storage::put_chat_secret(
        iota_storage::util::e2ee_storage::StoredChatSecret {
            user_id: "1".into(),
            chat_id: "1:2".into(),
            secret_id: "chat:1:2:main".into(),
            version: 1,
            encrypted_secret: vec![0, 7],
            kem_ciphertext: vec![0, 8],
            wrapping_scheme: "fixture".into(),
            created_at: 1,
            updated_at: 1,
        },
    )
    .unwrap();
    let historical = handle_get_chat_secret(&valid);
    assert!(historical.is_type(CommunicationType::ChatSecretResponse));
    assert_eq!(
        historical.get_data(DataType::ChatId),
        Some(&DataValue::Str("1:2".into()))
    );
    assert!(
        recovery::escrow_for_recovery(&owner, &peer, &owner, None)
            .unwrap()
            .is_none(),
        "own legacy read must not invent peer evidence"
    );
    assert!(
        handle_get_chat_secret(&request("2", "1:2").with_sender(2))
            .is_type(CommunicationType::ErrorInternal),
        "the missing other recipient is still unrecoverable"
    );
    let original_frame = vec![1, 2, 3];
    let format = recovery::RelayFormat::NativeMtpSealedV1;
    let escrow = recovery::Escrow {
        original_type_map_version: "1.0".into(),
        first: fixture.ids[0].clone(),
        second: fixture.ids[1].clone(),
        version: 1,
        namespace: recovery::WrappingNamespace {
            chat_id: "1:2".into(),
            secret_id: "chat:1:2:main".into(),
        },
        wrapping_scheme: "fixture".into(),
        signer: fixture.ids[0].clone(),
        message_id: "read-fixture".into(),
        operation_digest: recovery::operation_digest(format, &original_frame),
        original_frame,
        format,
        envelopes: std::array::from_fn(|index| recovery::RecipientEnvelope {
            owner: fixture.ids[index].clone(),
            recipient_id: recovery::OriginalRecipientId::Numeric(index as u64 + 1),
            encrypted_secret: vec![index as u8, 7],
            kem_ciphertext: vec![index as u8, 8],
        }),
        created_at: 1,
    };
    iota_storage::util::db::with_immediate_transaction(|tx| {
        recovery::stage_escrow_in_tx(tx, &escrow)?;
        Ok(())
    })
    .unwrap();
    assert!(
        handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInternal),
        "pending escrow is not accepted"
    );
    iota_storage::util::db::with_immediate_transaction(|tx| {
        recovery::commit_escrow_in_tx(tx, &escrow)?;
        recovery::recover_owner_envelope_in_tx(tx, iota_identity::LocalUserId(1), &escrow)?;
        Ok(())
    })
    .unwrap();
    let response = handle_get_chat_secret(&valid);
    assert!(response.is_type(CommunicationType::ChatSecretResponse));
    assert_eq!(
        response.get_data(DataType::UserId),
        Some(&DataValue::Str("1".into()))
    );
    assert_eq!(
        response.get_data(DataType::ChatId),
        Some(&DataValue::Str("1:2".into()))
    );
    assert_eq!(
        response.get_data(DataType::SecretId),
        Some(&DataValue::Str("chat:1:2:main".into()))
    );
    assert_eq!(
        response.get_data(DataType::EncryptedSecret),
        Some(&DataValue::Bytes(vec![0, 7]))
    );
    execute("DELETE FROM chat_secrets WHERE user_id='1'");
    assert!(
        handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInternal),
        "accepted but missing envelope is not a new conversation"
    );
    let mut duplicate_payload = valid.payload().clone();
    duplicate_payload.container_entries_mut().unwrap().push((
        DataType::UserId
            .try_to_id(valid.type_map().unwrap())
            .unwrap(),
        DataValue::Str("1".into()),
    ));
    assert!(
        validated_chat_secret_read_target(&valid.clone().with_payload(duplicate_payload)).is_err()
    );

    for invalid in [
        request("2", "1:2"),
        request("01", "1:2"),
        request("1", "2:1"),
        request("1", "1:1"),
        request("1", "01:2"),
        request("1", "1:2:3"),
        valid
            .clone()
            .with_data(DataType::SecretId, DataValue::Str("chat:2:1:main".into())),
        valid
            .clone()
            .with_data(DataType::VersionNumber, DataValue::SignedNumber(0)),
        valid
            .clone()
            .with_data(DataType::RecipientUserId, DataValue::UnsignedNumber(2)),
    ] {
        assert!(validated_chat_secret_read_target(&invalid).is_err());
    }
    let canonical = tau_relay_protocol::canonical_chat_id(
        &iota_connection::federated_relay::protocol_principal(&fixture.ids[0]),
        &iota_connection::federated_relay::protocol_principal(&fixture.ids[1]),
    );
    assert!(
        validated_chat_secret_read_target(&request(
            &serde_json::to_string(&fixture.ids[0]).unwrap(),
            &canonical,
        ))
        .is_ok()
    );
    let mut canonical_escrow = escrow.clone();
    canonical_escrow.version = 2;
    canonical_escrow.message_id = "read-fixture-v2".into();
    canonical_escrow.original_frame = vec![2, 2, 3];
    canonical_escrow.operation_digest =
        recovery::operation_digest(canonical_escrow.format, &canonical_escrow.original_frame);
    canonical_escrow.namespace = recovery::WrappingNamespace {
        chat_id: canonical.clone(),
        secret_id: format!("chat:{canonical}:main"),
    };
    for copy in &mut canonical_escrow.envelopes {
        copy.recipient_id =
            recovery::OriginalRecipientId::Principal(serde_json::to_string(&copy.owner).unwrap());
    }
    iota_storage::util::db::with_immediate_transaction(|tx| {
        recovery::commit_escrow_in_tx(tx, &canonical_escrow)?;
        recovery::recover_owner_envelope_in_tx(
            tx,
            iota_identity::LocalUserId(1),
            &canonical_escrow,
        )?;
        Ok(())
    })
    .unwrap();
    assert!(
        handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInternal),
        "canonical-wrapped ciphertext must not be returned under numeric identifiers"
    );
    let canonical_response = handle_get_chat_secret(&request(
        &serde_json::to_string(&fixture.ids[0]).unwrap(),
        &canonical,
    ));
    assert!(canonical_response.is_type(CommunicationType::ChatSecretResponse));
    assert_eq!(
        canonical_response.get_data(DataType::ChatId),
        Some(&DataValue::Str(canonical.clone()))
    );
    iota_storage::util::e2ee_storage::put_chat_secret(
        iota_storage::util::e2ee_storage::StoredChatSecret {
            user_id: "1".into(),
            chat_id: "1:2".into(),
            secret_id: "chat:1:2:main".into(),
            version: 1,
            encrypted_secret: vec![0, 7],
            kem_ciphertext: vec![0, 8],
            wrapping_scheme: "fixture".into(),
            created_at: 1,
            updated_at: 1,
        },
    )
    .unwrap();
    execute("DELETE FROM chat_secrets WHERE user_id='1' AND version=2");
    assert!(
        handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInternal),
        "known higher committed epoch forbids stale latest fallback"
    );
    let old_epoch = valid
        .clone()
        .with_data(DataType::VersionNumber, DataValue::SignedNumber(1));
    assert!(handle_get_chat_secret(&old_epoch).is_type(CommunicationType::ChatSecretResponse));
    iota_storage::util::db::with_immediate_transaction(|tx| {
        recovery::recover_owner_envelope_in_tx(tx, iota_identity::LocalUserId(1), &escrow)?;
        Ok(())
    })
    .unwrap();
    // Simulate external corruption, not an authorized erasure. The epoch ledger
    // must still prevent an older surviving escrow from becoming "latest".
    execute("DROP TRIGGER chat_secret_escrows_accepted_delete; DELETE FROM chat_secret_escrows WHERE version=2");
    for latest in [
        valid.clone(),
        request(&serde_json::to_string(&fixture.ids[0]).unwrap(), &canonical),
    ] {
        assert!(
            handle_get_chat_secret(&latest).is_type(CommunicationType::ErrorInternal),
            "lost latest evidence must not expose a surviving older epoch as latest"
        );
    }
    assert!(handle_get_chat_secret(&old_epoch).is_type(CommunicationType::ChatSecretResponse));
    execute("UPDATE users SET public_key='rekeyed' WHERE user_id=1");
    assert!(
        handle_get_chat_secret(&old_epoch).is_type(CommunicationType::ErrorInternal),
        "a retained legacy row cannot bypass the rekey erasure fence"
    );
    // Local storage handles are not the owner's original remote numeric ID.
    execute("UPDATE principals SET remote_user_id=11 WHERE remote_user_id=1");
    assert!(validated_chat_secret_read_target(&valid).is_err());
    let shifted = request("11", "2:11");
    let (owner, peer, _) = validated_chat_secret_read_target(&shifted).unwrap();
    assert_eq!(owner.user_id, 11);
    assert_eq!(peer.user_id, 2);
    execute(
        "INSERT INTO principals (authority_id, remote_user_id, authority_kind, home, descriptor_revision, last_resolved_at) SELECT authority_id || '-collision', remote_user_id, authority_kind, home, descriptor_revision, last_resolved_at FROM principals WHERE remote_user_id = 2",
    );
    assert!(validated_chat_secret_read_target(&shifted).is_err());
    std::fs::remove_dir_all(path).unwrap();
}
