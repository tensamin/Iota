use iota_storage::{
    users::{user_manager, user_profile::UserProfile},
    util::{
        call_envelopes::{
            self, CallEnvelope,
            epochs::{self, CallId, Key, Mutation, Principal, Stage, State},
        },
        db,
    },
};
use std::sync::{Arc, Barrier};
use uuid::Uuid;

#[test]
fn epoch_ciphertext_is_atomic_durable_and_independent_of_legacy_envelopes() {
    if let Ok(root) = std::env::var("IOTA_CALL_EPOCH_REOPEN") {
        iota_util::file_util::configure_storage_directory(root.into());
        db::initialize_database().unwrap();
        let staged: Stage =
            serde_json::from_str(&std::env::var("IOTA_CALL_EPOCH_STAGE").unwrap()).unwrap();
        let delivery = epochs::get(&staged.key, 3, 7, 1000).unwrap();
        if std::env::var("IOTA_CALL_EPOCH_STATE").unwrap() == "available" {
            assert_eq!(delivery.state, State::Available);
            assert_eq!(delivery.envelope.unwrap(), staged);
        } else {
            assert_eq!(delivery.state, State::Revoked);
            assert!(delivery.envelope.is_none());
            assert!(
                epochs::mutate(
                    &Mutation {
                        operation_id: Uuid::new_v4(),
                        key: staged.key
                    },
                    true,
                    3,
                    7,
                    1000
                )
                .is_err()
            );
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(root.path().to_owned());
    db::initialize_database().unwrap();
    user_manager::try_add_user(UserProfile::new(
        7,
        "epoch-user".into(),
        None,
        "public-key".into(),
        None,
        None,
    ))
    .unwrap();
    let value = Stage {
        operation_id: Uuid::new_v4(),
        key: Key {
            call_id: CallId {
                owner_authority: format!("omikron-key:{}", "a".repeat(64)),
                id: Uuid::new_v4(),
            },
            recipient: Principal {
                authority: format!("omega-key:{}", "b".repeat(64)),
                user_id: 7,
            },
            epoch: 1,
        },
        created_at_ms: 1000,
        expires_at_ms: 5000,
        secret_id: "secret-id".into(),
        wrapping_scheme: epochs::WRAPPING_SCHEME.into(),
        encrypted_secret: vec![1; 64],
        kem_ciphertext: vec![2; 1088],
    };
    let barrier = Arc::new(Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|byte| {
            let mut attempt = value.clone();
            attempt.operation_id = Uuid::new_v4();
            attempt.encrypted_secret[0] = byte;
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                epochs::stage(&attempt, 3, 7, 1000).ok().map(|_| attempt)
            })
        })
        .collect();
    let winners: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(winners.len(), 1);
    let staged = &winners[0];
    assert!(
        epochs::get(&staged.key, 3, 7, 1000)
            .unwrap()
            .envelope
            .is_none()
    );
    assert!(epochs::get(&staged.key, 4, 7, 1000).is_err());
    assert!(epochs::stage(staged, 4, 7, 1000).is_err());
    epochs::mutate(
        &Mutation {
            operation_id: Uuid::new_v4(),
            key: staged.key.clone(),
        },
        true,
        3,
        7,
        1000,
    )
    .unwrap();
    let reopen = |state: &str| {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "epoch_ciphertext_is_atomic_durable_and_independent_of_legacy_envelopes"
                ])
                .env("IOTA_CALL_EPOCH_REOPEN", root.path())
                .env(
                    "IOTA_CALL_EPOCH_STAGE",
                    serde_json::to_string(staged).unwrap()
                )
                .env("IOTA_CALL_EPOCH_STATE", state)
                .status()
                .unwrap()
                .success()
        );
    };
    reopen("available");
    let legacy = CallEnvelope {
        recipient_id: 7,
        call_id: staged.key.call_id.id.to_string(),
        owner_omikron_id: 3,
        inviter_id: 9,
        created_at: 1000,
        expires_at: 5000,
        secret_id: "legacy".into(),
        version_number: 0,
        encrypted_secret: vec![8],
        kem_ciphertext: vec![9],
        wrapping_scheme: "legacy-scheme".into(),
    };
    assert!(call_envelopes::store(&legacy, 1000).unwrap());
    assert!(call_envelopes::store(&legacy, 1000).unwrap());
    assert_eq!(
        call_envelopes::get(7, &legacy.call_id, 3, 1000)
            .unwrap()
            .unwrap()
            .encrypted_secret,
        vec![8]
    );
    epochs::mutate(
        &Mutation {
            operation_id: Uuid::new_v4(),
            key: staged.key.clone(),
        },
        false,
        3,
        7,
        1000,
    )
    .unwrap();
    reopen("revoked");
    assert!(
        call_envelopes::get(7, &legacy.call_id, 3, 1000)
            .unwrap()
            .is_some()
    );
    assert!(
        call_envelopes::get(7, &legacy.call_id, 4, 1000)
            .unwrap()
            .is_none()
    );
    let mut historical = legacy.clone();
    historical.call_id = historical.call_id.to_uppercase();
    assert!(call_envelopes::store(&historical, 1000).unwrap());
    let mut legacy_key = staged.key.clone();
    legacy_key.epoch = 0;
    let revoke = Mutation {
        operation_id: Uuid::new_v4(),
        key: legacy_key.clone(),
    };
    assert!(epochs::get(&legacy_key, 3, 7, 1000).is_err());
    assert!(epochs::mutate(&revoke, true, 3, 7, 1000).is_err());
    let mut invalid_stage = staged.clone();
    invalid_stage.key.epoch = 0;
    assert!(epochs::stage(&invalid_stage, 3, 7, 1000).is_err());
    assert_eq!(
        epochs::mutate(&revoke, false, 3, 7, 1000).unwrap().state,
        State::Revoked
    );
    assert_eq!(
        epochs::mutate(&revoke, false, 3, 7, 1000).unwrap().state,
        State::Revoked
    );
    assert!(
        call_envelopes::get(7, &legacy.call_id, 3, 1000)
            .unwrap()
            .is_none()
    );
    assert!(!call_envelopes::store(&legacy, 1000).unwrap());
    assert!(!call_envelopes::store(&historical, 1000).unwrap());
    db::with_db(|conn| {
        let remaining: i64 = conn.query_row(
            "SELECT count(*) FROM call_envelopes WHERE recipient_id = 7",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(remaining, 0);
        Ok(())
    })
    .unwrap();
}
