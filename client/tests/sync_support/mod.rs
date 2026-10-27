use iota_identity::{LocalUserId, PrincipalStore};
use mtp::codec::{CommunicationValue, DataType, DataValue, TypeMap};

pub fn snapshot(owner: i64, id: u32) -> CommunicationValue {
    let store = iota_storage::identity::SqlitePrincipalStore;
    let principal = store
        .get_principal(
            store
                .principal_for_local_user(LocalUserId(owner))
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .unwrap();
    let generation = iota_storage::hosted_auth::resolve(LocalUserId(owner))
        .unwrap()
        .0
        .auth_generation;
    tau::sync::encode_request(
        &tau::sync::Request::Snapshot {
            scope: tau::sync::Scope {
                principal: tau::relay_protocol::Principal::try_from(&principal.principal).unwrap(),
                device_id: uuid::Uuid::new_v4().to_string(),
                authorization_generation: generation,
                schema: tau::sync::SCHEMA.into(),
                dictionary: tau::relay_protocol::dictionary_fingerprint("1.0").unwrap(),
            },
            page: None,
            limit: 128,
        },
        &TypeMap::new(mtp::type_map::Version(1, 0)),
        id,
    )
    .unwrap()
}

pub fn acknowledge(snapshot: &CommunicationValue, id: u32) -> CommunicationValue {
    let response: tau::sync::Response = serde_json::from_slice(
        snapshot
            .get_data(DataType::Json)
            .and_then(DataValue::as_bytes_slice)
            .unwrap(),
    )
    .unwrap();
    let tau::sync::Response::Snapshot {
        scope,
        head,
        page_id,
        next: None,
        ..
    } = response
    else {
        panic!("expected complete snapshot: {response:?}");
    };
    tau::sync::encode_request(
        &tau::sync::Request::Acknowledge {
            cursor: tau::sync::Cursor {
                scope,
                sequence: head,
            },
            page_id,
        },
        snapshot.type_map().unwrap(),
        id,
    )
    .unwrap()
}
