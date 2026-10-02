use super::*;
use generic_array::GenericArray;
use opaque_ke::ksf::Ksf;
use uuid::Uuid;

fn binding() -> PasswordLoginBindingV1<'static> {
    PasswordLoginBindingV1 {
        principal: "omega-key:example#7",
        iota_id: 11,
        session_id: Uuid::from_bytes([0x33; 16]),
        contact_key_sha256: &[0x11; 32],
    }
}

fn enroll(setup: &PasswordServerSetup) -> RegistrationFinish {
    let client = client_registration_start(b"correct horse").unwrap();
    let response =
        server_registration_start(setup, &client.request, binding().principal.as_bytes()).unwrap();
    client
        .state
        .finish(&response, binding().principal, 11)
        .unwrap()
}

#[test]
fn profile_matches_pre_extraction_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/profile_v1.json")).unwrap();
    assert_eq!(CURRENT_OPAQUE_PROFILE, vectors["profile"].as_i64().unwrap());
    assert_eq!(
        hex::encode(server_identifier(11)),
        vectors["server_identifier"]["expected_hex"]
    );
    let vector = &vectors["login_context"];
    let fingerprint: [u8; 32] = hex::decode(vector["contact_key_sha256_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let context = login_context(&PasswordLoginBindingV1 {
        principal: vector["principal"].as_str().unwrap(),
        iota_id: vector["iota_id"].as_i64().unwrap(),
        session_id: Uuid::parse_str(vector["session_id"].as_str().unwrap()).unwrap(),
        contact_key_sha256: &fingerprint,
    })
    .unwrap();
    assert_eq!(hex::encode(context), vector["expected_hex"]);
    let input: [u8; 64] = hex::decode(vectors["ksf"]["input_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        hex::encode(
            PasswordKsfV1::default()
                .hash(GenericArray::from(input))
                .unwrap()
        ),
        vectors["ksf"]["expected_hex"]
    );
}

#[test]
fn registration_and_login_preserve_export_key_and_setup() {
    let setup = generate_server_setup();
    let bytes = serialize_server_setup(&setup);
    let restored = deserialize_server_setup_owned(bytes.to_vec()).unwrap();
    assert_eq!(*bytes, *serialize_server_setup(&restored));
    assert!(deserialize_server_setup(b"damaged").is_err());
    let registration = enroll(&restored);
    let record = server_registration_finish(&registration.upload).unwrap();
    let client = client_login_start(b"correct horse").unwrap();
    validate_login_request(&client.request).unwrap();
    let response =
        server_login_start(&restored, Some(&record), &client.request, &binding()).unwrap();
    let finish = client.state.finish(&response.response, &binding()).unwrap();
    assert_eq!(
        registration.export_key.as_bytes(),
        finish.export_key.as_bytes()
    );
    server_login_finish(response.state, &finish.finalization, &binding()).unwrap();
}

#[test]
fn login_rejects_wrong_password_bindings_missing_record_and_unrelated_setup() {
    let setup = generate_server_setup();
    let unrelated = generate_server_setup();
    let record = server_registration_finish(&enroll(&setup).upload).unwrap();
    let original = binding();
    let variants = [
        PasswordLoginBindingV1 {
            principal: "omega-key:example#8",
            ..original
        },
        PasswordLoginBindingV1 {
            iota_id: 12,
            ..original
        },
        PasswordLoginBindingV1 {
            session_id: Uuid::from_bytes([0x44; 16]),
            ..original
        },
        PasswordLoginBindingV1 {
            contact_key_sha256: &[0x22; 32],
            ..original
        },
    ];
    for changed in variants {
        assert_ne!(
            login_context(&original).unwrap(),
            login_context(&changed).unwrap()
        );
        let client = client_login_start(b"correct horse").unwrap();
        let response =
            server_login_start(&setup, Some(&record), &client.request, &changed).unwrap();
        assert!(client.state.finish(&response.response, &original).is_err());
    }
    for (server, record, password) in [
        (&setup, Some(record.as_slice()), b"wrong horse".as_slice()),
        (&setup, None, b"correct horse".as_slice()),
        (
            &unrelated,
            Some(record.as_slice()),
            b"correct horse".as_slice(),
        ),
    ] {
        let client = client_login_start(password).unwrap();
        let response = server_login_start(server, record, &client.request, &original).unwrap();
        assert!(client.state.finish(&response.response, &original).is_err());
    }
}

#[test]
fn malformed_messages_and_failed_proofs_are_distinct() {
    let setup = generate_server_setup();
    assert!(validate_login_request(b"not KE1").is_err());
    assert!(server_registration_start(&setup, b"bad", b"principal").is_err());
    assert!(server_registration_finish(b"bad").is_err());
    assert!(server_login_start(&setup, None, b"bad", &binding()).is_err());
    let registration = enroll(&setup);
    let record = server_registration_finish(&registration.upload).unwrap();
    let client = client_login_start(b"correct horse").unwrap();
    let response = server_login_start(&setup, Some(&record), &client.request, &binding()).unwrap();
    assert!(matches!(
        server_login_finish(response.state, b"bad", &binding()),
        Err(LoginFinishError::InvalidMessage)
    ));
    let client = client_login_start(b"correct horse").unwrap();
    let response = server_login_start(&setup, Some(&record), &client.request, &binding()).unwrap();
    let mut finish = client.state.finish(&response.response, &binding()).unwrap();
    finish.finalization[0] ^= 1;
    assert!(matches!(
        server_login_finish(response.state, &finish.finalization, &binding()),
        Err(LoginFinishError::AuthenticationFailed)
    ));
    let client = client_login_start(b"correct horse").unwrap();
    let response = server_login_start(&setup, Some(&record), &client.request, &binding()).unwrap();
    let finish = client.state.finish(&response.response, &binding()).unwrap();
    assert!(matches!(
        server_login_finish(
            response.state,
            &finish.finalization,
            &PasswordLoginBindingV1 {
                iota_id: 12,
                ..binding()
            }
        ),
        Err(LoginFinishError::AuthenticationFailed)
    ));
}
