use async_trait::async_trait;
use iota_connection::message_handlers::*;
use iota_identity::*;
use iota_storage::{
    identity::SqlitePrincipalStore,
    util::{db, e2ee_storage},
};
use iota_util::mtp_compat::OptionalDataValueExt;
use mtp::{
    codec::{CommunicationType as C, CommunicationValue, DataType as D, DataValue},
    crypto::Keyring,
};

struct Resolver;
#[async_trait]
impl IdentityResolver for Resolver {
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }
    async fn resolve_principal(
        &self,
        id: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        SqlitePrincipalStore
            .get_by_canonical_id(id)?
            .ok_or(IdentityError::NotFound)
    }
    async fn signing_keys(
        &self,
        id: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        SqlitePrincipalStore.signing_keys(id)
    }
}

fn request(ty: C) -> CommunicationValue {
    CommunicationValue::new(ty).with_sender(1)
}
fn string(frame: &CommunicationValue, field: D) -> String {
    frame.get_data(field).as_string().unwrap()
}

#[tokio::test]
async fn canonical_reads_bind_owner_aliases_secrets_and_node_keys() {
    let path = std::env::temp_dir().join(format!("canonical-reads-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    iota_util::file_util::configure_storage_directory(path);
    db::initialize_database().unwrap();
    let node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let now = iota_storage::util::sync::now_millis();
    let directory = iota_storage::node_directory::SqliteNodeDirectory;
    directory
        .ensure_local_descriptor(&node, vec![], vec![], now)
        .unwrap();
    let ids = [
        PrincipalId {
            authority: node.authority_id().clone(),
            user_id: 1,
        },
        PrincipalId {
            authority: node.authority_id().clone(),
            user_id: 7,
        },
        PrincipalId {
            authority: AuthorityId::new("other-authority").unwrap(),
            user_id: 7,
        },
    ];
    let mut handles = vec![PrincipalHandle(0); ids.len()];
    // Allocate the peer alias first so it collides with the authenticated owner ID.
    for index in [1, 0, 2] {
        let id = &ids[index];
        let verified = VerifiedPrincipalDescriptor::from_trusted_authority(PrincipalDescriptor {
            principal: id.clone(),
            authority_kind: AuthorityKind::Iota,
            username: None,
            display_name: None,
            public_keys: vec![node.public_keys()],
            home: PrincipalHome::Iota(node.node_id().clone()),
            revision: 1,
            valid_until: Some(now + 600_000),
            issued_at: now,
        })
        .unwrap();
        handles[index] = SqlitePrincipalStore
            .upsert_remote_descriptor(&verified)
            .unwrap();
    }
    assert_eq!(handles[1].0, 1);
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO users(user_id, username, public_key, created_at) VALUES(1, 'owner', 'unused', 1)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id, principal_handle) VALUES(1, ?1)", [handles[0].0])?;
        for (index, handle) in handles.iter().enumerate().skip(1) {
            iota_storage::util::chats_util::add_conversation_in_tx(tx, 1, 7, *handle, None)?;
            tx.execute("INSERT INTO messages(storage_owner, external_user, external_principal, message_time, content, sent_by_self, message_state, relay_signer_id) VALUES(1, 7, ?1, 100, ?2, 0, 'sent', 7)", rusqlite::params![handle.0, format!("peer{index}")])?;
        }
        Ok(())
    }).unwrap();
    iota_storage::util::chat_files::add_reaction_for_principal(
        1, 7, handles[1], 100, 1, handles[1], "peer",
    )
    .unwrap();
    iota_storage::util::chat_files::add_reaction_for_principal(
        1, 7, handles[1], 100, 1, handles[0], "owner",
    )
    .unwrap();
    let owner_json = serde_json::to_string(&ids[0]).unwrap();
    let snapshot = handle_account_state_request(&request(C::AccountStateRequest));
    assert!(snapshot.is_type(C::AccountStateSnapshot), "{snapshot:?}");
    assert_eq!(string(&snapshot, D::Principal), owner_json);
    assert_eq!(string(&snapshot, D::UserAddress), owner_json);
    assert_eq!(
        snapshot
            .get_data(D::AcceptedIds)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let contacts = snapshot.get_data(D::Contacts).unwrap().as_array().unwrap();
    assert_eq!(contacts.len(), 2);
    let map = mtp::codec::TypeMap::latest();
    for contact in contacts {
        let field = |ty: D| contact.get_field(ty.try_to_id(&map).unwrap()).unwrap();
        let alias = field(D::UserId).as_signed_number().unwrap() as i64;
        let index = handles.iter().position(|handle| handle.0 == alias).unwrap();
        assert_eq!(
            field(D::Principal).as_str().unwrap(),
            serde_json::to_string(&ids[index]).unwrap()
        );
        assert_eq!(field(D::Principal), field(D::UserAddress));
        assert_eq!(field(D::Messages).as_array().unwrap().len(), 1);
        let expected_principal = serde_json::to_string(&ids[index]).unwrap();
        let assert_message = |message: &DataValue| {
            assert_eq!(
                message
                    .get_field(D::Principal.try_to_id(&map).unwrap())
                    .unwrap()
                    .as_str(),
                Some(expected_principal.as_str())
            );
            if index == 1 {
                let reactions = message
                    .get_field(D::Reactions.try_to_id(&map).unwrap())
                    .unwrap()
                    .as_array()
                    .unwrap();
                assert_eq!(reactions.len(), 2);
                for reaction in reactions {
                    let text = reaction
                        .get_field(D::Reaction.try_to_id(&map).unwrap())
                        .unwrap()
                        .as_str()
                        .unwrap();
                    let expected = if text == "owner" {
                        &owner_json
                    } else {
                        &expected_principal
                    };
                    assert_eq!(
                        reaction
                            .get_field(D::Principal.try_to_id(&map).unwrap())
                            .unwrap()
                            .as_str(),
                        Some(expected.as_str())
                    );
                }
            }
        };
        assert_message(&field(D::Messages).as_array().unwrap()[0]);
        let snapshot_messages = snapshot.get_data(D::Messages).unwrap().as_array().unwrap();
        let snapshot_message = snapshot_messages
            .iter()
            .find(|message| {
                message
                    .get_field(D::ChatPartnerId.try_to_id(&map).unwrap())
                    .unwrap()
                    .as_signed_number()
                    == Some(alias.into())
            })
            .unwrap();
        assert_message(snapshot_message);
        let history = handle_messages_get(
            &request(C::MessagesGet)
                .add_typed_default(D::UserId, DataValue::SignedNumber(alias.into()))
                .add_typed_default(D::Offset, DataValue::SignedNumber(0))
                .add_typed_default(D::Amount, DataValue::SignedNumber(10)),
        );
        let messages = history.get_data(D::Messages).unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_message(&messages[0]);
        let single = handle_message_get(
            &request(C::MessageGet)
                .add_typed_default(D::ChatPartnerId, DataValue::SignedNumber(alias.into()))
                .add_typed_default(D::SendTime, DataValue::SignedNumber(100)),
        );
        assert!(single.is_type(C::MessageGet), "{single:?}");
        assert_eq!(string(&single, D::Principal), expected_principal);
        assert_eq!(
            messages[0]
                .get_field(D::SenderId.try_to_id(&map).unwrap())
                .unwrap()
                .as_unsigned_number(),
            Some(alias as u128)
        );
    }
    // Self-authored rows use the canonical owner even if the peer alias is also 1.
    db::with_db(|conn| {
        conn.execute(
            "UPDATE messages SET sent_by_self = 1 WHERE external_principal = ?1",
            [handles[1].0],
        )?;
        Ok(())
    })
    .unwrap();
    let own_message = handle_message_get(
        &request(C::MessageGet)
            .add_typed_default(
                D::ChatPartnerId,
                DataValue::SignedNumber(handles[1].0.into()),
            )
            .add_typed_default(D::SendTime, DataValue::SignedNumber(100)),
    );
    assert_eq!(string(&own_message, D::Principal), owner_json);
    // A retired numeric-only reaction must never acquire a guessed actor identity.
    db::with_db(|conn| {
        conn.execute(
            "UPDATE reactions SET user_principal = NULL WHERE reaction = 'peer'",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(
        handle_message_get(
            &request(C::MessageGet)
                .add_typed_default(
                    D::ChatPartnerId,
                    DataValue::SignedNumber(handles[1].0.into())
                )
                .add_typed_default(D::SendTime, DataValue::SignedNumber(100))
        )
        .is_type(C::ErrorInternal)
    );
    assert!(
        handle_account_state_request(&request(C::AccountStateRequest)).is_type(C::ErrorInternal)
    );
    let wire = |index: usize| tau_relay_protocol::Principal {
        authority: ids[index].authority.as_str().into(),
        user_id: ids[index].user_id,
    };
    let chat = tau_relay_protocol::canonical_chat_id(&wire(0), &wire(2));
    let secret = tau_relay_protocol::chat_secret_id(&chat);
    let local_chat = e2ee_storage::principal_chat_id(handles[0], handles[2]).unwrap();
    e2ee_storage::put_chat_secret(e2ee_storage::StoredChatSecret {
        user_id: "1".into(),
        chat_id: local_chat.clone(),
        secret_id: e2ee_storage::principal_secret_id(&local_chat),
        version: 1,
        encrypted_secret: vec![1, 2],
        kem_ciphertext: vec![3, 4],
        wrapping_scheme: "test".into(),
        created_at: now,
        updated_at: now,
    })
    .unwrap();
    let read = request(C::GetChatSecret)
        .add_typed_default(D::UserId, DataValue::Str(owner_json.clone()))
        .add_typed_default(D::ChatId, DataValue::Str(chat.clone()))
        .add_typed_default(D::SecretId, DataValue::Str(secret.clone()));
    let response = handle_get_chat_secret(&read);
    assert!(response.is_type(C::ChatSecretResponse), "{response:?}");
    assert_eq!(string(&response, D::ChatId), chat);
    assert_eq!(string(&response, D::SecretId), secret);
    assert_eq!(string(&response, D::UserId), owner_json);
    let wrong_owner = read.clone().with_sender(7);
    assert!(!handle_get_chat_secret(&wrong_owner).is_type(C::ChatSecretResponse));
    let forged_owner = read.clone().add_typed_default(
        D::UserId,
        DataValue::Str(serde_json::to_string(&ids[2]).unwrap()),
    );
    assert!(handle_get_chat_secret(&forged_owner).is_type(C::ErrorNotFound));
    let invalid_version = read
        .clone()
        .add_typed_default(D::VersionNumber, DataValue::SignedNumber(0));
    assert!(handle_get_chat_secret(&invalid_version).is_type(C::ErrorInvalidData));
    let not_owner_chat = tau_relay_protocol::canonical_chat_id(&wire(1), &wire(2));
    let not_owner_read = request(C::GetChatSecret)
        .add_typed_default(D::UserId, DataValue::Str(owner_json.clone()))
        .add_typed_default(D::ChatId, DataValue::Str(not_owner_chat.clone()))
        .add_typed_default(
            D::SecretId,
            DataValue::Str(tau_relay_protocol::chat_secret_id(&not_owner_chat)),
        );
    assert!(handle_get_chat_secret(&not_owner_read).is_type(C::ErrorNotFound));
    let other_chat = tau_relay_protocol::canonical_chat_id(&wire(0), &wire(1));
    let other_read = request(C::GetChatSecret)
        .add_typed_default(D::UserId, DataValue::Str(owner_json.clone()))
        .add_typed_default(D::ChatId, DataValue::Str(other_chat.clone()))
        .add_typed_default(
            D::SecretId,
            DataValue::Str(tau_relay_protocol::chat_secret_id(&other_chat)),
        );
    assert!(handle_get_chat_secret(&other_read).is_type(C::ErrorNotSet));
    // An ambiguous numeric legacy secret must not become readable by either authority.
    e2ee_storage::put_chat_secret(e2ee_storage::StoredChatSecret {
        user_id: "1".into(),
        chat_id: "1:7".into(),
        secret_id: "chat:1:7:main".into(),
        version: 1,
        encrypted_secret: vec![99],
        kem_ciphertext: vec![98],
        wrapping_scheme: "legacy".into(),
        created_at: now,
        updated_at: now,
    })
    .unwrap();
    assert!(handle_get_chat_secret(&other_read).is_type(C::ErrorNotSet));
    // A second version in the cross-authority numeric namespace is never imported.
    e2ee_storage::put_chat_secret(e2ee_storage::StoredChatSecret {
        user_id: "1".into(),
        chat_id: "1:7".into(),
        secret_id: "chat:1:7:main".into(),
        version: 2,
        encrypted_secret: vec![97],
        kem_ciphertext: vec![96],
        wrapping_scheme: "legacy".into(),
        created_at: now,
        updated_at: now,
    })
    .unwrap();
    let cross_version = read
        .clone()
        .add_typed_default(D::VersionNumber, DataValue::SignedNumber(2));
    assert!(handle_get_chat_secret(&cross_version).is_type(C::ErrorNotSet));
    let resolve =
        request(C::UserResolve).add_typed_default(D::UserAddress, DataValue::Str(owner_json));
    let resolved = handle_user_resolve(&resolve, &Resolver).await;
    assert!(resolved.is_type(C::UserResolved), "{resolved:?}");
    assert_eq!(
        string(&resolved, D::PublicKey),
        node.public_keys().try_to_base64().unwrap()
    );
    let bare =
        request(C::UserResolve).add_typed_default(D::UserAddress, DataValue::Str("7".into()));
    assert!(
        handle_user_resolve(&bare, &Resolver)
            .await
            .is_type(C::ErrorInvalidData)
    );
    db::with_db(|conn| {
        conn.execute("UPDATE node_directory SET descriptor_valid_until = 1", [])?;
        Ok(())
    })
    .unwrap();
    assert!(
        !handle_user_resolve(&resolve, &Resolver)
            .await
            .is_type(C::UserResolved)
    );
    db::with_db(|conn| {
        conn.execute(
            "UPDATE node_directory SET descriptor_valid_until = ?1",
            [now + 600_000],
        )?;
        Ok(())
    })
    .unwrap();
    let wrong_key = Keyring::generate()
        .public_key_bundle()
        .try_to_base64()
        .unwrap();
    db::with_db(|conn| {
        conn.execute("UPDATE node_keys SET public_key = ?1", [wrong_key])?;
        Ok(())
    })
    .unwrap();
    assert!(
        !handle_user_resolve(&resolve, &Resolver)
            .await
            .is_type(C::UserResolved)
    );
}
