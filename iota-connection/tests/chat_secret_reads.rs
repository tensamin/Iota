#[allow(dead_code)]
mod relay_support;

use iota_connection::message_handlers::{
    handle_get_chat_secret, validated_chat_secret_read_target,
};
use iota_storage::util::{chat_secret_recovery as recovery, db};
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
fn canonical_reads_require_committed_owner_evidence_and_never_downgrade() {
    let path = std::env::temp_dir().join(format!("chat-secret-reads-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    initialize(&path);
    let fixture = Fixture::new(true);
    let chat = recovery::canonical_chat_id(&fixture.ids[0], &fixture.ids[1]).unwrap();
    let owner = recovery::principal_key(&fixture.ids[0]).unwrap();
    let valid = request(&owner, &chat);
    let (resolved_owner, peer, epoch) = validated_chat_secret_read_target(&valid).unwrap();
    assert_eq!(resolved_owner, fixture.ids[0]);
    assert_eq!(peer, fixture.ids[1]);
    assert_eq!(epoch, None);
    assert!(handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorNotSet));

    // Even a retained numeric row cannot authorize a numeric read or a canonical read.
    iota_storage::util::e2ee_storage::put_chat_secret(
        iota_storage::util::e2ee_storage::StoredChatSecret {
            user_id: "1".into(),
            chat_id: "1:2".into(),
            secret_id: "chat:1:2:main".into(),
            version: 1,
            encrypted_secret: vec![99],
            kem_ciphertext: vec![99],
            wrapping_scheme: "fixture".into(),
            created_at: 1,
            updated_at: 1,
        },
    )
    .unwrap();
    assert!(validated_chat_secret_read_target(&request("1", "1:2")).is_err());
    assert!(validated_chat_secret_read_target(&request(&owner, "1:2")).is_err());
    assert!(validated_chat_secret_read_target(&request("1", &chat)).is_err());
    assert!(handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorNotSet));

    let evidence = |version: i64| {
        let original_frame = vec![version as u8, 2, 3];
        let format = recovery::RelayFormat::NativeMtpSealedV1;
        recovery::Escrow {
            original_type_map_version: "1.0".into(),
            original_type_map_fingerprint: tau_relay_protocol::dictionary_fingerprint("1.0")
                .unwrap(),
            first: fixture.ids[0].clone(),
            second: fixture.ids[1].clone(),
            version,
            namespace: recovery::WrappingNamespace {
                chat_id: chat.clone(),
                secret_id: format!("chat:{chat}:main"),
            },
            wrapping_scheme: "fixture".into(),
            signer: fixture.ids[0].clone(),
            message_id: format!("read-fixture-{version}"),
            operation_digest: recovery::operation_digest(format, &original_frame),
            original_frame,
            format,
            envelopes: std::array::from_fn(|index| recovery::RecipientEnvelope {
                owner: fixture.ids[index].clone(),
                recipient_id: recovery::OriginalRecipientId::Principal(
                    recovery::principal_key(&fixture.ids[index]).unwrap(),
                ),
                encrypted_secret: vec![version as u8, index as u8],
                kem_ciphertext: vec![index as u8, 8],
            }),
            created_at: 1,
        }
    };
    let first = evidence(1);
    db::with_immediate_transaction(|tx| recovery::stage_escrow_in_tx(tx, &first)).unwrap();
    assert!(
        handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInvalidData),
        "pending is not accepted"
    );
    let commit = |escrow: &recovery::Escrow| {
        db::with_immediate_transaction(|tx| {
            recovery::commit_escrow_in_tx(tx, escrow)?;
            recovery::recover_owner_envelope_in_tx(tx, iota_identity::LocalUserId(1), escrow)
        })
        .unwrap();
    };
    commit(&first);
    let response = handle_get_chat_secret(&valid);
    assert!(response.is_type(CommunicationType::ChatSecretResponse));
    assert_eq!(response.id(), valid.id());
    assert_eq!(response.type_map(), valid.type_map());
    assert_eq!(
        response.get_data(DataType::UserId),
        Some(&DataValue::Str(owner.clone()))
    );
    assert_eq!(
        response.get_data(DataType::ChatId),
        Some(&DataValue::Str(chat.clone()))
    );
    assert_eq!(
        response.get_data(DataType::EncryptedSecret),
        Some(&DataValue::Bytes(vec![1, 0]))
    );
    let other = request(&recovery::principal_key(&fixture.ids[1]).unwrap(), &chat).with_sender(2);
    assert!(
        handle_get_chat_secret(&other).is_type(CommunicationType::ErrorInternal),
        "cannot invent the other owner's stored envelope"
    );

    commit(&evidence(2));
    execute("DELETE FROM chat_secrets WHERE user_id='1' AND version=2");
    assert!(
        handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInternal),
        "latest must not fall back to epoch 1"
    );
    let historical = valid
        .clone()
        .with_data(DataType::VersionNumber, DataValue::SignedNumber(1));
    assert!(handle_get_chat_secret(&historical).is_type(CommunicationType::ChatSecretResponse));
    execute(
        "DROP TRIGGER chat_secret_escrows_accepted_delete; DELETE FROM chat_secret_escrows WHERE version=2",
    );
    assert!(handle_get_chat_secret(&valid).is_type(CommunicationType::ErrorInternal));
    assert!(handle_get_chat_secret(&historical).is_type(CommunicationType::ChatSecretResponse));

    for invalid in [
        request(&owner, &format!("{chat}=")),
        request(&recovery::principal_key(&fixture.ids[1]).unwrap(), &chat),
        valid
            .clone()
            .with_data(DataType::SecretId, DataValue::Str("chat:1:2:main".into())),
        valid
            .clone()
            .with_data(DataType::VersionNumber, DataValue::SignedNumber(0)),
        valid
            .clone()
            .with_data(DataType::RecipientUserId, DataValue::UnsignedNumber(2)),
    ] {
        assert!(validated_chat_secret_read_target(&invalid).is_err());
    }
    let mut payload = valid.payload().clone();
    payload.container_entries_mut().unwrap().push((
        DataType::UserId
            .try_to_id(valid.type_map().unwrap())
            .unwrap(),
        DataValue::Str(owner),
    ));
    assert!(validated_chat_secret_read_target(&valid.clone().with_payload(payload)).is_err());
    execute("UPDATE users SET public_key='rekeyed' WHERE user_id=1");
    assert!(
        handle_get_chat_secret(&historical).is_type(CommunicationType::ErrorNotAuthenticated),
        "rekey fences protected reads"
    );
    std::fs::remove_dir_all(path).unwrap();
}
