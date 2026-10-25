use super::*;

fn fixture() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE users(user_id INTEGER PRIMARY KEY);
        CREATE TABLE user_residency(user_id INTEGER PRIMARY KEY, lifecycle_state TEXT);
        CREATE TABLE hosted_auth_state(local_user_id INTEGER PRIMARY KEY, enabled INTEGER);
        INSERT INTO users VALUES (7), (8);
        INSERT INTO user_residency VALUES (7, 'managed'), (8, 'released');
        INSERT INTO hosted_auth_state VALUES (7, 1), (8, 0);",
    )
    .unwrap();
    migrate(&conn).unwrap();
    conn
}

fn envelope() -> Stage {
    Stage {
        operation_id: Uuid::new_v4(),
        key: Key {
            call_id: CallId {
                owner_authority: format!("omikron-key:{}", "a".repeat(64)),
                id: Uuid::new_v4(),
            },
            recipient: Principal {
                authority: format!("omega-key:{}", "a".repeat(64)),
                user_id: 7,
            },
            epoch: 1,
        },
        created_at_ms: 1000,
        expires_at_ms: 5000,
        secret_id: "secret-id".into(),
        wrapping_scheme: WRAPPING_SCHEME.into(),
        encrypted_secret: vec![11; 64],
        kem_ciphertext: vec![22; 1088],
    }
}

fn stage_test(conn: &Connection, value: &Stage) -> Result<Delivery, Error> {
    assert!(value.validate(1000));
    let payload = serde_json::to_string(value).unwrap();
    let mut identity = value.clone();
    identity.operation_id = Uuid::nil();
    let fingerprint = Sha256::digest(serde_json::to_vec(&identity).unwrap());
    stage_in(conn, value, 3, 7, 1000, &payload, &fingerprint).unwrap()
}

fn change(
    conn: &Connection,
    value: &Stage,
    id: Uuid,
    activate: bool,
    now: i64,
) -> Result<Delivery, Error> {
    let mutation = Mutation {
        operation_id: id,
        key: value.key.clone(),
    };
    let payload = serde_json::to_string(&mutation).unwrap();
    mutate_in(conn, &mutation, activate, 3, 7, now, &payload).unwrap()
}

#[test]
fn staged_keys_are_hidden_until_activation_and_revocation_is_terminal() {
    let conn = fixture();
    let value = envelope();
    assert_eq!(stage_test(&conn, &value).unwrap().state, State::Staged);
    assert!(
        read(&conn, &value.key, 3, 7)
            .unwrap()
            .unwrap()
            .envelope
            .is_none()
    );
    assert!(read(&conn, &value.key, 4, 7).unwrap().is_none());
    assert!(read(&conn, &value.key, 3, 8).unwrap().is_none());
    let activate = Uuid::new_v4();
    assert_eq!(
        change(&conn, &value, activate, true, 1000).unwrap().state,
        State::Available
    );
    assert_eq!(
        change(&conn, &value, activate, true, 1000).unwrap().state,
        State::Available
    );
    assert_eq!(
        read(&conn, &value.key, 3, 7)
            .unwrap()
            .unwrap()
            .envelope
            .unwrap(),
        value
    );
    let revoke = Uuid::new_v4();
    assert_eq!(
        change(&conn, &value, revoke, false, 1000).unwrap().state,
        State::Revoked
    );
    assert_eq!(
        change(&conn, &value, revoke, false, 1000).unwrap().state,
        State::Revoked
    );
    assert!(
        read(&conn, &value.key, 3, 7)
            .unwrap()
            .unwrap()
            .envelope
            .is_none()
    );
    assert!(matches!(
        change(&conn, &value, activate, true, 1000),
        Err(Error::Conflict)
    ));
    assert!(matches!(stage_test(&conn, &value), Err(Error::Conflict)));
    let payload: Option<String> = conn
        .query_row("SELECT payload FROM call_epoch_envelopes", [], |r| r.get(0))
        .unwrap();
    assert!(payload.is_none());
}

#[test]
fn identical_stage_retries_succeed_but_ciphertext_metadata_and_operation_conflicts_fail() {
    let conn = fixture();
    let value = envelope();
    stage_test(&conn, &value).unwrap();
    stage_test(&conn, &value).unwrap();
    let mut retry = value.clone();
    retry.operation_id = Uuid::new_v4();
    stage_test(&conn, &retry).unwrap();
    retry.encrypted_secret[0] ^= 1;
    assert!(matches!(stage_test(&conn, &retry), Err(Error::Conflict)));
    retry = value.clone();
    retry.expires_at_ms += 1;
    assert!(matches!(stage_test(&conn, &retry), Err(Error::Conflict)));
    retry = value.clone();
    retry.key.epoch += 1;
    assert!(matches!(stage_test(&conn, &retry), Err(Error::Conflict)));
    assert!(matches!(
        change(&conn, &value, value.operation_id, true, 1000),
        Err(Error::Conflict)
    ));
    assert_eq!(
        read(&conn, &value.key, 3, 7).unwrap().unwrap().state,
        State::Staged
    );
}

#[test]
fn revocation_before_staging_fences_delayed_ciphertext() {
    let conn = fixture();
    let value = envelope();
    let operation = Uuid::new_v4();
    assert_eq!(
        change(&conn, &value, operation, false, 1000).unwrap().state,
        State::Revoked
    );
    assert_eq!(
        change(&conn, &value, operation, false, 1000).unwrap().state,
        State::Revoked
    );
    assert!(matches!(stage_test(&conn, &value), Err(Error::Conflict)));
    assert!(matches!(
        change(&conn, &value, Uuid::new_v4(), true, 1000),
        Err(Error::Conflict)
    ));
}

#[test]
fn epoch_call_and_principal_namespaces_are_independent() {
    let conn = fixture();
    let value = envelope();
    stage_test(&conn, &value).unwrap();
    for variant in 0..4 {
        let mut other = value.clone();
        other.operation_id = Uuid::new_v4();
        match variant {
            0 => other.key.epoch += 1,
            1 => other.key.call_id.id = Uuid::new_v4(),
            2 => other.key.call_id.owner_authority = format!("omikron-key:{}", "b".repeat(64)),
            _ => other.key.recipient.authority = format!("omega-key:{}", "c".repeat(64)),
        }
        other.encrypted_secret[0] = variant;
        stage_test(&conn, &other).unwrap();
    }
    assert_eq!(
        conn.query_row("SELECT count(*) FROM call_epoch_envelopes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        5
    );
}

#[test]
fn expiry_scrubs_ciphertext_and_survives_schema_reinitialization() {
    let conn = fixture();
    let value = envelope();
    stage_test(&conn, &value).unwrap();
    change(&conn, &value, Uuid::new_v4(), true, 1000).unwrap();
    assert_eq!(expire_in(&conn, 5000).unwrap(), 1);
    migrate(&conn).unwrap();
    let delivery = read(&conn, &value.key, 3, 7).unwrap().unwrap();
    assert_eq!(delivery.state, State::Expired);
    assert!(delivery.envelope.is_none());
    assert!(matches!(
        change(&conn, &value, Uuid::new_v4(), true, 5000),
        Err(Error::Conflict)
    ));
    assert!(matches!(stage_test(&conn, &value), Err(Error::Conflict)));
}

#[test]
fn disabled_or_released_accounts_cannot_stage_or_activate() {
    let conn = fixture();
    let value = envelope();
    stage_test(&conn, &value).unwrap();
    conn.execute(
        "UPDATE hosted_auth_state SET enabled = 0 WHERE local_user_id = 7",
        [],
    )
    .unwrap();
    assert!(matches!(stage_test(&conn, &value), Err(Error::Invalid)));
    assert!(matches!(
        change(&conn, &value, Uuid::new_v4(), true, 1000),
        Err(Error::Invalid)
    ));
    assert!(!hosted(&conn, 8).unwrap());
    conn.execute(
        "UPDATE hosted_auth_state SET enabled = 1 WHERE local_user_id = 7",
        [],
    )
    .unwrap();
    conn.execute(
        "UPDATE user_residency SET lifecycle_state = 'released' WHERE user_id = 7",
        [],
    )
    .unwrap();
    assert!(!hosted(&conn, 7).unwrap());
}

#[test]
fn wire_shape_roundtrips_and_validation_rejects_unsupported_keys_and_limits() {
    let value = envelope();
    let json = serde_json::to_value(&value).unwrap();
    assert!(json.get("key").is_none());
    assert!(json.get("call_id").is_some());
    assert_eq!(
        serde_json::from_value::<Stage>(json.clone()).unwrap(),
        value
    );
    let mut unknown = json;
    unknown["plaintext_key"] = serde_json::json!("no");
    assert!(serde_json::from_value::<Stage>(unknown).is_err());
    let mut other = value.clone();
    other.wrapping_scheme = "unknown".into();
    assert!(!other.validate(1000));
    other = value.clone();
    other.encrypted_secret.clear();
    assert!(!other.validate(1000));
    other = value.clone();
    other.kem_ciphertext.resize(4097, 0);
    assert!(!other.validate(1000));
    other = value.clone();
    other.expires_at_ms = other.created_at_ms + MAX_TTL_MS + 1;
    assert!(!other.validate(1000));
    other = value.clone();
    other.created_at_ms = 61_001;
    assert!(!other.validate(1000));
    other = value.clone();
    other.key.epoch = 0;
    assert!(!other.validate(1000));
    other = value.clone();
    other.key.call_id.owner_authority = "omega:example.org".into();
    assert!(!other.validate(1000));
    other = value;
    other.operation_id = Uuid::nil();
    assert!(!other.validate(1000));
}

#[test]
fn recipient_limit_does_not_evict_existing_keys() {
    let conn = fixture();
    let value = envelope();
    for epoch in 1..=256 {
        let mut next = value.clone();
        next.key.epoch = epoch;
        next.operation_id = Uuid::new_v4();
        stage_test(&conn, &next).unwrap();
    }
    let mut overflow = value.clone();
    overflow.key.epoch = 257;
    overflow.operation_id = Uuid::new_v4();
    assert!(matches!(stage_test(&conn, &overflow), Err(Error::Invalid)));
    assert_eq!(
        read(&conn, &value.key, 3, 7).unwrap().unwrap().state,
        State::Staged
    );
}
