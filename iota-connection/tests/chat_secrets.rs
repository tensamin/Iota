use iota_connection::message_common::typed_container;
use iota_connection::message_handlers::{apply_verified_relay_content, handle_get_chat_secret};
use iota_connection::relay::VerifiedRelayContext;
use iota_identity::{
    AuthorityKind, LocalNodeIdentity, LocalUserDescriptor, LocalUserId, PrincipalHome,
};
use iota_storage::identity::SqlitePrincipalStore;
use iota_storage::util::{chats_util, db};
use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, VerifiedRelayContent,
};
use mtp::crypto::Keyring;

fn proposal(
    signer: u64,
    version: i128,
    marker: u8,
) -> (VerifiedRelayContext, VerifiedRelayContent) {
    let recipient = if signer == 1 { 2 } else { 1 };
    let frame = CommunicationValue::new(CommunicationType::SetChatSecret)
        .add_typed_default(DataType::ChatId, DataValue::Str("1:2".into()))
        .add_typed_default(DataType::SecretId, DataValue::Str("chat:1:2:main".into()))
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(version))
        .add_typed_default(
            DataType::WrappingScheme,
            DataValue::Str("test-envelope".into()),
        )
        .add_typed_default(
            DataType::Recipients,
            DataValue::Array(
                [1, 2]
                    .map(|id| {
                        typed_container(vec![
                            (DataType::UserId, DataValue::Str(id.to_string())),
                            (
                                DataType::EncryptedSecret,
                                DataValue::Bytes(vec![marker, id]),
                            ),
                            (
                                DataType::KemCiphertext,
                                DataValue::Bytes(vec![marker, id, 3]),
                            ),
                        ])
                    })
                    .to_vec(),
            ),
        );
    let context = VerifiedRelayContext {
        signer_id: signer,
        final_recipient_id: recipient,
        message_id: format!("secret-{signer}-{version}-{marker}"),
        created_at: 1,
        type_map: frame.type_map().unwrap().clone(),
    };
    let content = VerifiedRelayContent {
        signer_id: signer,
        final_recipient_id: recipient,
        message_type: CommunicationType::SetChatSecret,
        content: frame.payload().clone(),
    };
    (context, content)
}

#[test]
fn offline_shared_iota_initialization_preserves_identity_versions_and_existing_keys() {
    let storage = std::env::temp_dir().join(format!(
        "tensamin-chat-secrets-{}-{}",
        std::process::id(),
        iota_storage::util::sync::now_millis(),
    ));
    std::fs::create_dir_all(&storage).unwrap();
    iota_util::file_util::configure_storage_directory(storage.clone());
    db::initialize_database().unwrap();
    let node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let handles = [1, 2].map(|id| {
        let user = LocalUserDescriptor {
            id: LocalUserId(id),
            username: format!("user{id}"),
            display_name: None,
            public_key: Keyring::generate().public_key_bundle().try_to_base64().unwrap(),
        };
        db::with_db(|connection| {
            connection.execute("INSERT INTO users (user_id, username, public_key, created_at) VALUES (?1, ?2, ?3, 1)", (id, &user.username, &user.public_key))?;
            Ok(())
        }).unwrap();
        SqlitePrincipalStore.ensure_local_principal(node.authority_id(), AuthorityKind::Iota, &user, PrincipalHome::Iota(node.node_id().clone()), 1).unwrap()
    });
    for (owner, partner, principal) in [(1, 2, handles[1]), (2, 1, handles[0])] {
        let mut contact = iota_storage::users::contact::Contact::new(partner);
        contact.principal = Some(principal);
        chats_util::mod_user(owner, &contact).unwrap();
    }

    // No client session is created for the lower-ID recipient.
    let (context, content) = proposal(2, 1, 7);
    apply_verified_relay_content(&context, &content, handles[1], handles[0], 1, 2, true).unwrap();
    apply_verified_relay_content(&context, &content, handles[1], handles[0], 1, 1, false).unwrap();
    let read = |owner: u64, version: i128| {
        let request = CommunicationValue::new(CommunicationType::GetChatSecret)
            .with_id(1)
            .with_sender(owner)
            .add_typed_default(DataType::UserId, DataValue::Str(owner.to_string()))
            .add_typed_default(DataType::ChatId, DataValue::Str("1:2".into()))
            .add_typed_default(DataType::SecretId, DataValue::Str("chat:1:2:main".into()))
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(version));
        handle_get_chat_secret(&request)
    };
    for owner in [1, 2] {
        let response = read(owner, 1);
        assert!(response.is_type(CommunicationType::ChatSecretResponse));
        assert_eq!(
            response.get_data(DataType::EncryptedSecret),
            Some(&DataValue::Bytes(vec![7, owner as u8]))
        );
    }
    let (conflict, conflicting_content) = proposal(1, 1, 9);
    assert!(
        apply_verified_relay_content(
            &conflict,
            &conflicting_content,
            handles[0],
            handles[1],
            1,
            1,
            true
        )
        .is_err()
    );
    let (rotation, rotation_content) = proposal(2, 2, 8);
    assert!(
        apply_verified_relay_content(
            &rotation,
            &rotation_content,
            handles[1],
            handles[0],
            1,
            2,
            true
        )
        .is_err()
    );
    assert!(read(2, 2).is_type(CommunicationType::ErrorNotSet));
    assert!(read(3, 1).is_type(CommunicationType::ErrorInvalidData));

    let (outsider, outsider_content) = proposal(3, 1, 6);
    assert!(
        apply_verified_relay_content(
            &outsider,
            &outsider_content,
            handles[1],
            handles[0],
            1,
            2,
            true
        )
        .is_err()
    );
    assert!(
        apply_verified_relay_content(&context, &content, handles[1], handles[0], 1, 3, true)
            .is_err()
    );
    let impersonation = CommunicationValue::new(CommunicationType::GetChatSecret)
        .with_id(2)
        .with_sender(1)
        .add_typed_default(DataType::UserId, DataValue::Str("2".into()))
        .add_typed_default(DataType::ChatId, DataValue::Str("1:2".into()));
    assert!(handle_get_chat_secret(&impersonation).is_type(CommunicationType::ErrorNotFound));

    let (rotation, rotation_content) = proposal(1, 2, 8);
    apply_verified_relay_content(
        &rotation,
        &rotation_content,
        handles[0],
        handles[1],
        1,
        1,
        true,
    )
    .unwrap();
    for owner in [1, 2] {
        assert_eq!(
            read(owner, 1).get_data(DataType::EncryptedSecret),
            Some(&DataValue::Bytes(vec![7, owner as u8]))
        );
        assert_eq!(
            read(owner, 2).get_data(DataType::EncryptedSecret),
            Some(&DataValue::Bytes(vec![8, owner as u8]))
        );
    }

    // The relaxed initial authority must never apply to separate Iotas.
    db::with_db(|connection| {
        connection.execute("DELETE FROM hosted_principals WHERE local_user_id = 1", [])?;
        Ok(())
    })
    .unwrap();
    assert!(
        apply_verified_relay_content(&context, &content, handles[1], handles[0], 1, 2, true)
            .is_err()
    );
    assert_eq!(
        read(2, 1).get_data(DataType::EncryptedSecret),
        Some(&DataValue::Bytes(vec![7, 2]))
    );
    std::fs::remove_dir_all(storage).unwrap();
}
