#[allow(dead_code)]
mod relay_support;

use async_trait::async_trait;
use iota_auth::{AuthenticatedSession, SessionCapabilities, SessionIdentity};
use iota_connection::relay_service::{
    IngressSource, RelayNodeIdentity, RelayOutcome, RelayService,
};
use iota_identity::{HostedAuthorizationLease, IotaNodeId, LocalUserId};
use iota_storage::{identity::SqliteLocalUserStore, util::db};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    crypto::Keyring,
};
use relay_support::*;
use std::sync::Arc;

struct NoSecret(IotaNodeId);
#[async_trait]
impl RelayNodeIdentity for NoSecret {
    async fn keyring(&self) -> Option<Arc<Keyring>> {
        None
    }
    fn node_id(&self) -> Option<IotaNodeId> {
        Some(self.0.clone())
    }
}

fn acceptance(outcome: RelayOutcome, expected: &str, recipient: i64) -> i64 {
    let RelayOutcome::Accepted {
        ingress_response,
        local_deliveries,
    } = outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(
        ingress_response
            .get_data(DataType::Status)
            .and_then(DataValue::as_str),
        Some(expected)
    );
    if expected == "already_accepted" {
        assert!(local_deliveries.is_empty());
    }
    assert_eq!(
        ingress_response
            .get_data(DataType::ChatPartnerId)
            .and_then(DataValue::as_number),
        Some(recipient as i128)
    );
    ingress_response
        .get_data(DataType::RelayAcceptedAt)
        .and_then(DataValue::as_number)
        .unwrap() as i64
}

fn fresh_hosted_source(fixture: &Fixture) -> IngressSource {
    let connection_id = uuid::Uuid::new_v4();
    let lease = HostedAuthorizationLease {
        connection_id: connection_id.to_string(),
        server_instance: "test".into(),
        identity: iota_storage::hosted_auth::resolve(LocalUserId(1))
            .unwrap()
            .0,
    };
    iota_storage::hosted_auth::register(&lease).unwrap();
    IngressSource::HostedClient {
        session: AuthenticatedSession {
            connection_id,
            identity: SessionIdentity::Hosted {
                local_user: LocalUserId(1),
                principal: fixture.handles[0],
            },
            capabilities: SessionCapabilities::hosted(),
            hosted_lease: Some(lease),
        },
    }
}

#[tokio::test]
async fn exact_durable_wire_survives_key_revocation_release_and_rehosting() {
    initialize(
        &std::env::temp_dir().join(format!("iota-durable-duplicates-{}", uuid::Uuid::new_v4())),
    );
    let fixture = Fixture::new(true);
    let application = CommunicationValue::new(CommunicationType::AddConversation)
        .add_typed_default(DataType::ChatPartnerId, DataValue::SignedNumber(2));
    let frame = fixture.frame(0, "durable-add", application.clone());
    for (error, kind, status) in [
        (
            iota_connection::relay_service::RelayServiceError::Rejected("private rejection".into()),
            CommunicationType::ErrorInvalidData,
            "rejected",
        ),
        (
            iota_connection::relay_service::RelayServiceError::Internal(
                "private database failure".into(),
            ),
            CommunicationType::ErrorInternal,
            "recoverable_failure",
        ),
    ] {
        let response = iota_connection::relay_service::relay_error_response(&frame, &error);
        assert!(response.is_type(kind));
        assert_eq!(response.id(), frame.id());
        assert_eq!(
            response.type_map().unwrap().version,
            frame.type_map().unwrap().version
        );
        assert_eq!(
            response
                .get_data(DataType::Status)
                .and_then(DataValue::as_str),
            Some(status)
        );
        assert_eq!(
            response
                .get_data(DataType::RelayMessageId)
                .and_then(DataValue::as_str),
            Some("durable-add")
        );
    }
    let raced_preparation = fixture
        .service
        .prepare_relay(&fixture.sources[0], frame.clone())
        .await
        .unwrap();
    let accepted_at = acceptance(
        fixture
            .service
            .accept_relay(fixture.sources[0].clone(), frame.clone())
            .await
            .unwrap(),
        "accepted",
        fixture.handles[1].0,
    );
    let before = (
        count("SELECT COUNT(*) FROM contacts"),
        count("SELECT COUNT(*) FROM pending_relays"),
        count("SELECT COUNT(*) FROM relay_inbox"),
    );
    let collision = fixture.frame(
        0,
        "durable-add",
        application.clone().add_typed_default(
            DataType::ChatPartnerName,
            DataValue::Str("collision".into()),
        ),
    );
    assert!(matches!(
        fixture
            .service
            .accept_relay(fixture.sources[0].clone(), collision)
            .await
            .unwrap(),
        RelayOutcome::Rejected { .. }
    ));

    // Old session clones are insufficient. A newly authorized session can retrieve the old result.
    execute(
        "UPDATE users SET public_key = 'rotated' WHERE user_id = 1; DELETE FROM principal_keys;",
    );
    let fresh = fresh_hosted_source(&fixture);
    assert_eq!(
        acceptance(
            fixture
                .service
                .accept_verified_relay(fresh.clone(), raced_preparation)
                .await
                .unwrap(),
            "already_accepted",
            fixture.handles[1].0
        ),
        accepted_at
    );
    assert!(matches!(
        fixture
            .service
            .accept_relay(fixture.sources[0].clone(), frame.clone())
            .await
            .unwrap(),
        RelayOutcome::Rejected { .. }
    ));
    let no_secret = Arc::new(
        RelayService::new(Arc::new(SqliteLocalUserStore), Arc::new(Router(true))).with_federation(
            Arc::new(Resolver),
            Arc::new(NoSecret(fixture.node.node_id().clone())),
        ),
    );
    let prepared = no_secret
        .prepare_relay(&fresh, frame.clone().with_id(88))
        .await
        .unwrap();
    assert!(prepared.content.is_none());
    assert_eq!(
        acceptance(
            no_secret
                .accept_verified_relay(fresh, prepared)
                .await
                .unwrap(),
            "already_accepted",
            fixture.handles[1].0
        ),
        accepted_at
    );

    let peer = IngressSource::DirectPeer {
        node_id: fixture.destination.node_id().clone(),
    };
    let changed = fixture.frame(
        0,
        "durable-add",
        application
            .clone()
            .add_typed_default(DataType::Username, DataValue::Str("changed".into())),
    );
    let unseen = fixture.frame(0, "unseen", application);
    assert!(
        no_secret
            .prepare_relay(&peer, changed.clone())
            .await
            .is_err()
    );
    assert!(fixture.service.prepare_relay(&peer, changed).await.is_err());
    assert!(fixture.service.prepare_relay(&peer, unseen).await.is_err());

    // Key rotation does not invalidate accepted bytes. Outcome disclosure still requires the current home.
    let moved = iota_identity::LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    db::with_db(|c| {
        c.execute(
            "UPDATE principals SET home = ?1, retired_at = 1",
            [format!("iota:{}", moved.node_id().as_str())],
        )?;
        c.execute_batch("DELETE FROM hosted_principals; DELETE FROM users;")?;
        Ok(())
    })
    .unwrap();
    assert!(no_secret.accept_relay(peer, frame.clone()).await.is_err());
    let peer = IngressSource::DirectPeer {
        node_id: moved.node_id().clone(),
    };
    assert_eq!(
        acceptance(
            no_secret
                .accept_relay(peer.clone(), frame.clone().with_id(99))
                .await
                .unwrap(),
            "already_accepted",
            fixture.handles[1].0
        ),
        accepted_at
    );
    for state in ["applied", "queued", "delivered"] {
        execute(&format!("UPDATE relay_inbox SET state = '{state}'"));
        assert_eq!(
            acceptance(
                no_secret
                    .accept_relay(peer.clone(), frame.clone())
                    .await
                    .unwrap(),
                "already_accepted",
                fixture.handles[1].0
            ),
            accepted_at
        );
    }
    assert_eq!(
        before,
        (
            count("SELECT COUNT(*) FROM contacts"),
            count("SELECT COUNT(*) FROM pending_relays"),
            count("SELECT COUNT(*) FROM relay_inbox")
        )
    );

    execute("UPDATE relay_inbox SET state = 'rejected', rejection_reason = 'unauthorized'");
    let RelayOutcome::Rejected { response } = no_secret
        .accept_relay(peer.clone(), frame.clone())
        .await
        .unwrap()
    else {
        panic!("expected recorded rejection");
    };
    assert!(response.is_type(CommunicationType::ErrorNotAuthenticated));
    assert_eq!(
        response
            .get_data(DataType::RelayMessageId)
            .and_then(DataValue::as_str),
        Some("durable-add")
    );
    execute("UPDATE relay_inbox SET state = 'received', rejection_reason = NULL");
    let RelayOutcome::RetryLater { response } = no_secret
        .accept_relay(peer.clone(), frame.clone())
        .await
        .unwrap()
    else {
        panic!("expected processing result");
    };
    assert_eq!(
        response
            .get_data(DataType::Status)
            .and_then(DataValue::as_str),
        Some("processing")
    );
    execute(
        "UPDATE relay_inbox SET state = 'processing', processing_owner = 'original-claim', processing_deadline = 1, processing_generation = 7",
    );
    let RelayOutcome::RetryLater { response } = no_secret
        .accept_relay(peer.clone(), frame.clone())
        .await
        .unwrap()
    else {
        panic!("expected recorded processing result");
    };
    assert_eq!(
        response
            .get_data(DataType::Status)
            .and_then(DataValue::as_str),
        Some("processing")
    );
    assert_eq!(count("SELECT processing_generation FROM relay_inbox"), 7);
    execute(
        "PRAGMA ignore_check_constraints = ON; UPDATE relay_inbox SET state = 'unknown'; PRAGMA ignore_check_constraints = OFF;",
    );
    assert!(no_secret.prepare_relay(&peer, frame).await.is_err());
}
