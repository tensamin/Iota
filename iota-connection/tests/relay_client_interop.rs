use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_connection::federated_relay::{decode_and_verify_for_ingress, protocol};
use iota_identity::*;
use mtp::{
    codec::{CommunicationValue, DataType, DataValue, TypeMap},
    crypto::Keyring,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientFixture {
    producer: String,
    wire: String,
    frame: Vec<u8>,
    application: Vec<u8>,
    signer_keys: Vec<String>,
    recipient_key: Vec<u8>,
    canonical: Vec<u8>,
}

struct FixtureResolver(Vec<ResolvedPrincipal>);

#[async_trait]
impl IdentityResolver for FixtureResolver {
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
        self.0
            .iter()
            .find(|p| &p.principal == id)
            .cloned()
            .ok_or(IdentityError::NotFound)
    }
    async fn signing_keys(
        &self,
        id: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        Ok(self.resolve_principal(id).await?.public_keys)
    }
}

async fn verify_fixture(json: &[u8], expected_producer: &str) {
    let f: ClientFixture = serde_json::from_slice(json).unwrap();
    assert_eq!(f.producer, expected_producer);
    let raw: serde_json::Value = serde_json::from_str(&f.wire).unwrap();
    if raw.get("version").is_some() {
        // Production clients are outside this migration. Their frozen signed fixtures
        // prove that the old format is rejected, rather than being rewritten in place.
        assert_eq!(raw["version"], 2);
        assert!(protocol::RelayWire::from_json(f.wire.as_bytes()).is_err());
        let map = TypeMap::new(
            mtp::type_map::Version::parse(raw["type_map_version"].as_str().unwrap()).unwrap(),
        );
        let frame = CommunicationValue::try_from_bytes_with(&f.frame, &map).unwrap();
        assert!(iota_connection::federated_relay::parse_wire(&frame).is_err());
        return;
    }
    let wire = protocol::RelayWire::from_json(f.wire.as_bytes()).unwrap();
    let signer_keys = f
        .signer_keys
        .iter()
        .map(|s| PublicKeyBundle::from_base64(s).unwrap())
        .collect::<Vec<_>>();
    let key = Keyring::from_bytes(&f.recipient_key).unwrap();
    let destination = IotaNodeId::new(&wire.destination).unwrap();
    let map = TypeMap::new(mtp::type_map::Version::parse(&wire.type_map_version).unwrap());
    // Decode the actual client's outer SDK frame rather than rebuilding it in Rust.
    let frame = CommunicationValue::try_from_bytes_with(&f.frame, &map).unwrap();
    assert!(
        matches!(frame.get_data(DataType::SecurePayload), Some(DataValue::Bytes(bytes)) if bytes == f.wire.as_bytes())
    );
    assert_eq!(
        protocol::canonical_bytes(&wire, &STANDARD.decode(&wire.content).unwrap()).unwrap(),
        f.canonical
    );
    let resolved = |id: &protocol::Principal, handle, keys| ResolvedPrincipal {
        principal: PrincipalId {
            authority: AuthorityId::new(&id.authority).unwrap(),
            user_id: id.user_id,
        },
        handle: PrincipalHandle(handle),
        username: None,
        public_keys: keys,
        home: PrincipalHome::Iota(destination.clone()),
        descriptor_revision: 1,
        valid_until: None,
        resolved_at: 0,
    };
    let resolver = FixtureResolver(vec![
        resolved(&wire.signer, 1, signer_keys.clone()),
        resolved(&wire.recipient, 2, vec![key.public_key_bundle()]),
    ]);
    let opened = decode_and_verify_for_ingress(frame.clone(), &resolver, Some(&destination), &key)
        .await
        .unwrap();
    assert_eq!(opened.content.unwrap().to_bytes().unwrap(), f.application);
    assert_eq!(opened.message_id, wire.message_id);
    assert_eq!(opened.created_at, wire.created_at);
    assert_eq!(opened.destination, destination);

    // The fixture must prove authentication and recipient encryption, not merely
    // structural acceptance of JSON produced by another process.
    assert!(
        decode_and_verify_for_ingress(
            frame.clone(),
            &resolver,
            Some(&destination),
            &Keyring::generate()
        )
        .await
        .is_err()
    );
    let wrong_destination = IotaNodeId::new(format!("iota:v1:{}", "b".repeat(64))).unwrap();
    assert!(
        decode_and_verify_for_ingress(frame, &resolver, Some(&wrong_destination), &key)
            .await
            .is_err()
    );
    let mut changed = wire.clone();
    changed.message_id.push_str("-tampered");
    assert!(
        decode_and_verify_for_ingress(
            changed.into_frame(1).unwrap(),
            &resolver,
            Some(&destination),
            &key
        )
        .await
        .is_err()
    );
    let mut changed = wire;
    let mut signature = STANDARD.decode(&changed.signature).unwrap();
    signature[0] ^= 1;
    changed.signature = STANDARD.encode(signature);
    assert!(
        decode_and_verify_for_ingress(
            changed.into_frame(1).unwrap(),
            &resolver,
            Some(&destination),
            &key
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn chromium_fixture_obeys_selected_federation_format() {
    let fixture = std::env::var("RELAY_BROWSER_INTEROP_FIXTURE")
        .ok()
        .map(std::fs::read)
        .transpose()
        .unwrap()
        .unwrap_or_else(|| include_bytes!("fixtures/relay_browser_v2.json").to_vec());
    verify_fixture(&fixture, "chromium-sendFederatedRelay").await;
}

#[tokio::test]
async fn desktop_fixture_obeys_selected_federation_format() {
    let path = std::env::var("RELAY_DESKTOP_INTEROP_FIXTURE").unwrap_or_else(|_| {
        format!(
            "{}/tests/fixtures/relay_desktop_v2.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let fixture =
        std::fs::read(path).expect("generate the actual desktop fixture with relay_interop first");
    verify_fixture(&fixture, "desktop-federated_relay-sign").await;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeClientFixture {
    producer: String,
    sdk: String,
    frame: String,
    signer_public_key: String,
    node_keys: [String; 2],
    chat_id: String,
    secret_id: String,
    encrypted_secrets: [String; 2],
    kem_ciphertexts: [String; 2],
}

#[test]
fn native_rust_peer_metadata_and_content_open_at_both_iotas() {
    use iota_connection::federated_relay::decode_and_verify_native_for_ingress;
    use mtp::codec::{CommunicationType, ProtectionPolicy, relay::RelayOpenOptions};

    let mut fixture: NativeClientFixture =
        serde_json::from_slice(include_bytes!("fixtures/relay_native_client.json")).unwrap();
    assert_eq!(fixture.producer, "pinned-MTPClient.sendSealedRelay");
    assert_eq!(
        fixture.sdk,
        "https://github.com/nonanium/MTP/releases/download/0.4.0-dev-b678361/mtp-0.4.0.tgz"
    );
    let nodes = fixture.node_keys.map(|key| {
        LocalNodeIdentity::from_keyring(
            Keyring::from_bytes(&STANDARD.decode(key).unwrap()).unwrap(),
        )
        .unwrap()
    });
    // Keep the fixture's opaque recipient bytes, but generate a new operation
    // with current Rust codecs. This is not a migration of its old signed frame.
    let signing_keys = Keyring::generate();
    fixture.signer_public_key = signing_keys.public_key_bundle().try_to_base64().unwrap();
    let signer_key = PublicKeyBundle::from_base64(&fixture.signer_public_key).unwrap();
    let authority = AuthorityId::for_omega(&nodes[0].public_keys()).unwrap();
    let principal = |user_id, handle, home, keys| ResolvedPrincipal {
        principal: PrincipalId {
            authority: authority.clone(),
            user_id,
        },
        handle: PrincipalHandle(handle),
        username: None,
        public_keys: keys,
        home: PrincipalHome::Iota(home),
        descriptor_revision: 1,
        valid_until: None,
        resolved_at: 0,
    };
    let signer = principal(11, 91, nodes[0].node_id().clone(), vec![signer_key]);
    let recipient = principal(22, 92, nodes[1].node_id().clone(), Vec::new());
    let map = TypeMap::new(mtp::type_map::Version::parse("1.0").unwrap());
    let principals = [&signer.principal, &recipient.principal]
        .map(|principal| tau_relay_protocol::Principal::try_from(principal).unwrap());
    fixture.chat_id = tau_relay_protocol::canonical_chat_id(&principals[0], &principals[1]);
    fixture.secret_id = tau_relay_protocol::chat_secret_id(&fixture.chat_id);
    let copies = (0..2)
        .map(|index| {
            tau::typed_container(
                &map,
                vec![
                    (
                        DataType::UserId,
                        DataValue::Str(serde_json::to_string(&principals[index]).unwrap()),
                    ),
                    (
                        DataType::EncryptedSecret,
                        DataValue::Bytes(
                            STANDARD.decode(&fixture.encrypted_secrets[index]).unwrap(),
                        ),
                    ),
                    (
                        DataType::KemCiphertext,
                        DataValue::Bytes(STANDARD.decode(&fixture.kem_ciphertexts[index]).unwrap()),
                    ),
                ],
            )
            .unwrap()
        })
        .collect();
    let application = CommunicationValue::new_with_type_map(CommunicationType::SetChatSecret, &map)
        .add_typed_default(DataType::ChatId, DataValue::Str(fixture.chat_id.clone()))
        .add_typed_default(
            DataType::SecretId,
            DataValue::Str(fixture.secret_id.clone()),
        )
        .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(1))
        .add_typed_default(DataType::WrappingScheme, DataValue::Str("fixture".into()))
        .add_typed_default(DataType::Recipients, DataValue::Array(copies));
    let route = tau_relay_protocol::NativeRelayRoute {
        signer: principals[0].clone(),
        recipient: principals[1].clone(),
        destination: nodes[1].node_id().as_str().into(),
        type_map_version: "1.0".into(),
        type_map_fingerprint: map.fingerprint_hex().unwrap(),
    };
    let signing = mtp::crypto::Ed25519Signer::new(&signing_keys.sig_cl_secret_key).unwrap();
    fixture.frame = STANDARD.encode(
        mtp::codec::relay::SealedRelayBuilder::new(
            CommunicationType::SetChatSecret,
            application.payload().clone(),
            11,
            22,
            nodes[0].node_id().mtp_authentication_hint(),
            &signing,
        )
        .type_map(&map)
        .message_id(1u128)
        .created_at(iota_storage::util::sync::now_millis() as u64)
        .metadata(route.to_metadata(&map).unwrap())
        .metadata_recipients(
            nodes
                .each_ref()
                .map(LocalNodeIdentity::public_keys)
                .to_vec(),
        )
        .content_recipients(
            nodes
                .each_ref()
                .map(LocalNodeIdentity::public_keys)
                .to_vec(),
        )
        .build()
        .unwrap()
        .to_bytes()
        .unwrap(),
    );
    let bytes = STANDARD.decode(&fixture.frame).unwrap();
    let frame = CommunicationValue::try_from_bytes_with(&bytes, &map).unwrap();
    assert!(frame.payload().as_encrypted().is_some());
    // Native sealed relays are not the frozen JSON Relay V2 format.
    assert!(iota_connection::federated_relay::parse_wire(&frame).is_err());
    let options = RelayOpenOptions::new(ProtectionPolicy::ed25519());
    let mut message_id = None;
    for node in &nodes {
        let opened = decode_and_verify_native_for_ingress(
            frame.clone(),
            signer.clone(),
            recipient.clone(),
            nodes[1].node_id(),
            &node.keyring(),
            options,
        )
        .unwrap();
        assert_eq!(opened.frame.to_bytes().unwrap(), bytes);
        assert!(opened.message_id.starts_with("mtp-sealed-v1:"));
        if let Some(expected) = &message_id {
            assert_eq!(&opened.message_id, expected);
        } else {
            message_id = Some(opened.message_id.clone());
        }
        let application = opened.content.unwrap();
        assert!(application.is_type(CommunicationType::SetChatSecret));
        assert_eq!(
            application
                .get_data(DataType::ChatId)
                .and_then(DataValue::as_str),
            Some(fixture.chat_id.as_str())
        );
        assert_eq!(
            application
                .get_data(DataType::SecretId)
                .and_then(DataValue::as_str),
            Some(fixture.secret_id.as_str())
        );
        let copies = application
            .get_data(DataType::Recipients)
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(copies.len(), 2);
        for (index, copy) in copies.iter().enumerate() {
            let field = |kind: DataType| copy.get_field(kind.try_to_id(&map).unwrap());
            assert_eq!(
                field(DataType::EncryptedSecret)
                    .unwrap()
                    .as_bytes()
                    .unwrap(),
                STANDARD.decode(&fixture.encrypted_secrets[index]).unwrap()
            );
            assert_eq!(
                field(DataType::KemCiphertext).unwrap().as_bytes().unwrap(),
                STANDARD.decode(&fixture.kem_ciphertexts[index]).unwrap()
            );
        }
    }
    assert!(
        decode_and_verify_native_for_ingress(
            frame.clone(),
            signer.clone(),
            recipient.clone(),
            nodes[1].node_id(),
            &Keyring::generate(),
            options,
        )
        .is_err()
    );
    assert!(
        decode_and_verify_native_for_ingress(
            frame.clone(),
            signer.clone(),
            recipient.clone(),
            nodes[0].node_id(),
            &nodes[0].keyring(),
            options,
        )
        .is_err()
    );
    assert!(
        decode_and_verify_native_for_ingress(
            frame.clone(),
            recipient.clone(),
            signer.clone(),
            nodes[0].node_id(),
            &nodes[0].keyring(),
            options,
        )
        .is_err()
    );
    let mut forged_signer = signer.clone();
    forged_signer.principal.user_id = 33;
    assert!(
        decode_and_verify_native_for_ingress(
            frame.clone(),
            forged_signer,
            recipient.clone(),
            nodes[1].node_id(),
            &nodes[0].keyring(),
            options,
        )
        .is_err()
    );
    let mut forged_recipient = recipient.clone();
    forged_recipient.principal.user_id = 33;
    assert!(
        decode_and_verify_native_for_ingress(
            frame.clone(),
            signer.clone(),
            forged_recipient,
            nodes[1].node_id(),
            &nodes[0].keyring(),
            options,
        )
        .is_err()
    );
    let mut bounded = options;
    bounded.decode_limits.max_blob_size = 1;
    assert!(
        decode_and_verify_native_for_ingress(
            frame.clone(),
            signer.clone(),
            recipient.clone(),
            nodes[1].node_id(),
            &nodes[0].keyring(),
            bounded,
        )
        .is_err()
    );
    // A stricter configured policy must not inherit the SDK's Ed25519 default.
    assert!(
        decode_and_verify_native_for_ingress(
            frame.clone(),
            signer.clone(),
            recipient.clone(),
            nodes[1].node_id(),
            &nodes[0].keyring(),
            RelayOpenOptions::new(ProtectionPolicy::dual()),
        )
        .is_err()
    );
    let mut wrong_keys = signer.clone();
    wrong_keys.public_keys = vec![Keyring::generate().public_key_bundle()];
    assert!(
        decode_and_verify_native_for_ingress(
            frame,
            wrong_keys,
            recipient.clone(),
            nodes[1].node_id(),
            &nodes[0].keyring(),
            options,
        )
        .is_err()
    );
    let mut tampered = bytes;
    *tampered.last_mut().unwrap() ^= 1;
    let tampered = CommunicationValue::try_from_bytes_with(&tampered, &map).unwrap();
    assert!(
        decode_and_verify_native_for_ingress(
            tampered,
            signer,
            recipient,
            nodes[1].node_id(),
            &nodes[0].keyring(),
            options,
        )
        .is_err()
    );
}
