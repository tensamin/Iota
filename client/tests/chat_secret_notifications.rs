use async_trait::async_trait;
use client::ClientConnectionManager;
use iota_auth::{HostedSessionRegistrar, SessionManager};
use iota_connection::{
    connection_handler::{PeerRouter, RouteDestination, RouteError, RouteOutcome},
    relay_service::RelayService,
};
use iota_identity::*;
use iota_storage::{
    identity::{SqliteLocalUserStore, SqlitePrincipalStore},
    util::{chat_secret_recovery as recovery, db},
};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    crypto::Keyring,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
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
struct NoRoute;
#[async_trait]
impl PeerRouter for NoRoute {
    async fn route(
        &self,
        _: &RouteDestination,
        _: CommunicationValue,
    ) -> Result<RouteOutcome, RouteError> {
        panic!("notification must not route a secret")
    }
}

fn assert_hint(frame: CommunicationValue, version: i128) {
    assert!(
        frame.is_type(CommunicationType::ChatSecretForward),
        "{frame:?}"
    );
    assert_eq!(frame.sender(), Some(22));
    assert_eq!(frame.receiver(), Some(11));
    assert_eq!(
        frame.get_data(DataType::SenderUserId),
        Some(&DataValue::UnsignedNumber(22))
    );
    assert_eq!(
        frame.get_data(DataType::RecipientUserId),
        Some(&DataValue::UnsignedNumber(11))
    );
    assert_eq!(
        frame.get_data(DataType::Payload),
        Some(&DataValue::Str("available".into()))
    );
    assert_eq!(
        frame.get_data(DataType::VersionNumber),
        Some(&DataValue::SignedNumber(version))
    );
    assert_eq!(
        frame.get_data(DataType::ChatId),
        Some(&DataValue::Str("11:22".into()))
    );
    assert!(frame.get_data(DataType::EncryptedSecret).is_none());
    assert!(frame.get_data(DataType::KemCiphertext).is_none());
    assert!(frame.get_data(DataType::Recipients).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_hints_fan_out_reconcile_reconnect_dedup_and_obey_revocation() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().into());
    db::initialize_database().unwrap();
    let node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let keys = [Keyring::generate(), Keyring::generate()];
    let mut handles = Vec::new();
    for (index, id) in [11, 22].into_iter().enumerate() {
        let user = LocalUserDescriptor {
            id: LocalUserId(id),
            username: format!("user{id}"),
            display_name: None,
            public_key: keys[index].public_key_bundle().try_to_base64().unwrap(),
        };
        db::with_db(|connection| {
            connection.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES (?1,?2,?3,1)", [&id.to_string(), &user.username, &user.public_key])?;
            connection.execute("INSERT INTO user_residency(user_id,username,lifecycle_state,data_state,updated_at) VALUES (?1,?2,'managed','present',1)", [&id.to_string(), &user.username])?;
            Ok(())
        }).unwrap();
        handles.push(
            SqlitePrincipalStore
                .ensure_local_principal(
                    node.authority_id(),
                    AuthorityKind::Iota,
                    &user,
                    PrincipalHome::Iota(node.node_id().clone()),
                    iota_storage::util::sync::now_millis(),
                )
                .unwrap(),
        );
    }
    let ids = [11, 22].map(|user_id| PrincipalId {
        authority: node.authority_id().clone(),
        user_id,
    });
    let escrow = |version| {
        let format = recovery::RelayFormat::NativeMtpSealedV1;
        let frame = vec![version as u8, 8];
        recovery::Escrow {
            original_type_map_version: "1.0".into(),
            first: ids[0].clone(),
            second: ids[1].clone(),
            version,
            namespace: recovery::WrappingNamespace {
                chat_id: "11:22".into(),
                secret_id: "chat:11:22:main".into(),
            },
            wrapping_scheme: "fixture".into(),
            signer: ids[0].clone(),
            message_id: format!("notification-{version}"),
            operation_digest: recovery::operation_digest(format, &frame),
            original_frame: frame,
            format,
            envelopes: std::array::from_fn(|index| recovery::RecipientEnvelope {
                owner: ids[index].clone(),
                recipient_id: recovery::OriginalRecipientId::Numeric(ids[index].user_id),
                encrypted_secret: vec![version as u8, index as u8],
                kem_ciphertext: vec![version as u8, index as u8, 1],
            }),
            created_at: 1,
        }
    };
    let commit = |e: &recovery::Escrow| {
        db::with_immediate_transaction(|tx| {
            recovery::commit_escrow_in_tx(tx, e)?;
            recovery::recover_owner_envelope_in_tx(tx, LocalUserId(11), e)?;
            Ok(())
        })
        .unwrap()
    };
    let sessions = Arc::new(SessionManager::default());
    let manager = Arc::new(ClientConnectionManager::new(
        Arc::new(Resolver),
        Arc::new(HostedSessionRegistrar::new(sessions.clone())),
        sessions.clone(),
        Arc::new(RelayService::new(
            Arc::new(SqliteLocalUserStore),
            Arc::new(NoRoute),
        )),
    ));
    let certificate_key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .unwrap()
        .self_signed(&certificate_key)
        .unwrap()
        .pem()
        .into_bytes();
    let public = keys[0].public_key_bundle();
    let host = mtp::host::HostConfig::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        certificate.clone(),
        certificate_key.serialize_pem().into_bytes(),
    )
    .with_authentication(
        Keyring::from_bytes(&node.keyring().try_to_bytes().unwrap()).unwrap(),
        Box::new(move |_, _| {
            let public = public.clone();
            Box::pin(async move { Some(public) })
        }),
        Box::new(|_, _| Box::pin(async { 0 })),
    )
    .with_authentication_policy(mtp::host::AuthenticationPolicy::ForceAuthentication);
    let mut server =
        mtp::webserver::MTPWebServer::new(host, mtp::webserver::WebServerConfig::new())
            .await
            .unwrap();
    let address = server.local_addr();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server_manager = manager.clone();
    let server_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let connection = tokio::select! { _ = server_shutdown.cancelled() => break, result = server.accept() => result.unwrap().unwrap() };
            let manager = server_manager.clone();
            let shutdown = server_shutdown.clone();
            tasks.spawn(async move {
                web_server::MtpConnectionHandler::accept_until_shutdown(
                    manager.as_ref(),
                    connection,
                    shutdown,
                )
                .await
            });
        }
        server.shutdown().await;
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let config = || {
        mtp::client::ClientConfig::new(format!("https://{address}/"))
            .with_client_id(11)
            .with_description("client")
            .with_pinned_pem(certificate.clone())
    };
    let first = mtp::client::MTPClient::auth_connect(config(), &keys[0], &node.public_keys())
        .await
        .unwrap();
    let second = mtp::client::MTPClient::auth_connect(config(), &keys[0], &node.public_keys())
        .await
        .unwrap();
    for client in [&first, &second] {
        assert!(
            client
                .request(
                    &CommunicationValue::new(CommunicationType::AccountStateRequest).with_id(1),
                    None
                )
                .await
                .unwrap()
                .is_type(CommunicationType::AccountStateSnapshot)
        );
    }
    // A staged but uncommitted transaction must not publish a hint.
    let initial = escrow(1);
    db::with_immediate_transaction(|tx| {
        recovery::stage_escrow_in_tx(tx, &initial)?;
        Ok(())
    })
    .unwrap();
    recovery::notify_change();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), first.receive())
            .await
            .is_err()
    );
    commit(&initial);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), first.receive())
            .await
            .is_err(),
        "snapshot application gates delivery"
    );
    for client in [&first, &second] {
        assert!(
            client
                .request(
                    &CommunicationValue::new(CommunicationType::AccountStateApplied).with_id(2),
                    None
                )
                .await
                .unwrap()
                .is_type(CommunicationType::Success)
        );
        assert_hint(
            tokio::time::timeout(Duration::from_secs(2), client.receive())
                .await
                .unwrap()
                .unwrap(),
            1,
        );
    }
    let read = CommunicationValue::new(CommunicationType::GetChatSecret)
        .with_id(15)
        .with_sender(999)
        .add_typed_default(DataType::UserId, DataValue::Str("11".into()))
        .add_typed_default(DataType::ChatId, DataValue::Str("11:22".into()))
        .add_typed_default(DataType::SecretId, DataValue::Str("chat:11:22:main".into()));
    let response = first.request(&read, None).await.unwrap();
    assert!(response.is_type(CommunicationType::ChatSecretResponse));
    assert_eq!(
        response.get_data(DataType::UserId),
        Some(&DataValue::Str("11".into()))
    );
    assert_eq!(
        response.get_data(DataType::EncryptedSecret),
        Some(&DataValue::Bytes(vec![1, 0]))
    );
    assert!(
        first
            .request(
                &read.with_data(DataType::UserId, DataValue::Str("22".into())),
                None
            )
            .await
            .unwrap()
            .is_type(CommunicationType::ErrorNotFound)
    );
    commit(&initial);
    recovery::notify_change();
    other_iota::LocalDeliverySink::deliver(
        manager.as_ref(),
        handles[0],
        CommunicationValue::new(CommunicationType::ChatSecretForward)
            .add_typed_default(DataType::EncryptedSecret, DataValue::Bytes(vec![99])),
    )
    .await;
    for client in [&first, &second] {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.receive())
                .await
                .is_err()
        );
    }
    let rotation = escrow(2);
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let pending_rotation = rotation.clone();
    let transaction = tokio::task::spawn_blocking(move || {
        db::with_immediate_transaction(|tx| {
            recovery::commit_escrow_in_tx(tx, &pending_rotation)?;
            recovery::recover_owner_envelope_in_tx(tx, LocalUserId(11), &pending_rotation)?;
            entered.send(()).unwrap();
            resume.recv().unwrap();
            Ok(())
        })
        .unwrap();
    });
    ready.await.unwrap();
    // Even an explicit wake cannot expose a transaction's uncommitted outbox.
    recovery::notify_change();
    for client in [&first, &second] {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.receive())
                .await
                .is_err()
        );
    }
    release.send(()).unwrap();
    transaction.await.unwrap();
    for client in [&first, &second] {
        assert_hint(
            tokio::time::timeout(Duration::from_secs(2), client.receive())
                .await
                .unwrap()
                .unwrap(),
            2,
        );
    }
    // Restoring a deleted row is a fresh availability transition for this epoch.
    db::with_db(|connection| {
        connection.execute(
            "DELETE FROM chat_secrets WHERE user_id='11' AND version=2",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    commit(&rotation);
    for client in [&first, &second] {
        assert_hint(
            tokio::time::timeout(Duration::from_secs(2), client.receive())
                .await
                .unwrap()
                .unwrap(),
            2,
        );
    }
    // A new session reconciles even globally dispatched outbox records.
    let third = mtp::client::MTPClient::auth_connect(config(), &keys[0], &node.public_keys())
        .await
        .unwrap();
    third
        .request(
            &CommunicationValue::new(CommunicationType::AccountStateRequest).with_id(3),
            None,
        )
        .await
        .unwrap();
    third
        .request(
            &CommunicationValue::new(CommunicationType::AccountStateApplied).with_id(4),
            None,
        )
        .await
        .unwrap();
    assert_hint(
        tokio::time::timeout(Duration::from_secs(2), third.receive())
            .await
            .unwrap()
            .unwrap(),
        1,
    );
    assert_hint(
        tokio::time::timeout(Duration::from_secs(2), third.receive())
            .await
            .unwrap()
            .unwrap(),
        2,
    );
    manager.revoke_principal(handles[0]).unwrap();
    commit(&escrow(3));
    for client in [&first, &second, &third] {
        assert!(
            !matches!(tokio::time::timeout(Duration::from_millis(200),client.receive()).await,Ok(Ok(frame)) if frame.is_type(CommunicationType::ChatSecretForward))
        );
    }
    shutdown.cancel();
    server_task.await.unwrap();
}
