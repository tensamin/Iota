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
