use async_trait::async_trait;
use iota_auth::{AuthenticatedSession, SessionCapability, SessionIdentity};
#[cfg(test)]
use iota_identity::PrincipalHandle;
use iota_identity::{
    AuthorityId, IdentityError, IdentityResolver, IotaNodeId, LocalUserStore, PrincipalHome,
    PrincipalId, RelayRouterId, ResolvedPrincipal,
};
use iota_logger::log;
use iota_storage::util::{chat_files, chats_util, outgoing_relay, relay_queue, relay_replay};
use iota_util::mtp_compat::OptionalDataValueExt;
use iota_util::route_target::RouteTarget;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::Keyring;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::connection_handler::{PeerRouter, RouteDestination, RouteOutcome};
use crate::message_common::typed_container;
use crate::message_handlers;
use crate::relay::{
    RelayValidationError, forward_verified_relay, open_verified_relay_content,
    verify_relay_metadata,
};

static NEXT_CLIENT_EVENT_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressSource {
    Omikron { connection_id: String },
    DirectPeer { node_id: IotaNodeId },
    RelayRouter { router_id: RelayRouterId },
    HostedClient { session: AuthenticatedSession },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayServiceError {
    Rejected(String),
    Internal(String),
}

#[derive(Clone, Debug)]
pub struct VerifiedRelayEnvelope {
    pub signer: ResolvedPrincipal,
    pub recipient: ResolvedPrincipal,
    pub message_id: String,
    pub created_at: u64,
    compatibility: RelayCompatibilityData,
}

#[derive(Clone, Debug)]
struct RelayCompatibilityData {
    legacy: Option<LegacyRelayCompatibility>,
    federated: Option<FederatedRelayCompatibility>,
}

#[derive(Clone, Debug)]
struct LegacyRelayCompatibility {
    verified: crate::relay::VerifiedRelay,
    frame: CommunicationValue,
    keyring: Arc<Keyring>,
    local_iota_id: u64,
}

#[derive(Clone, Debug)]
struct FederatedRelayCompatibility {
    frame: CommunicationValue,
    content: CommunicationValue,
}

pub fn route_destination(home: &PrincipalHome) -> Option<RouteDestination> {
    match home {
        PrincipalHome::Iota(node) => Some(RouteDestination::Iota(node.clone())),
        PrincipalHome::LegacyOmegaIota { omega, iota_id } => {
            Some(RouteDestination::LegacyOmegaIota {
                omega: omega.clone(),
                iota_id: *iota_id,
            })
        }
        PrincipalHome::Omega(_) | PrincipalHome::Unknown => None,
    }
}

#[derive(Clone, Debug)]
pub struct ClientDelivery {
    pub recipient: iota_identity::PrincipalHandle,
    pub frame: CommunicationValue,
}

#[derive(Clone, Debug)]
pub enum RelayOutcome {
    Accepted {
        ingress_response: CommunicationValue,
        local_deliveries: Vec<ClientDelivery>,
    },
    Rejected {
        response: CommunicationValue,
    },
    NoRoute {
        response: CommunicationValue,
    },
    RetryLater {
        response: CommunicationValue,
    },
    Ignored,
}

impl RelayOutcome {
    pub fn into_parts(self) -> (Option<CommunicationValue>, Vec<ClientDelivery>) {
        match self {
            Self::Accepted {
                ingress_response,
                local_deliveries,
            } => (Some(ingress_response), local_deliveries),
            Self::Rejected { response }
            | Self::NoRoute { response }
            | Self::RetryLater { response } => (Some(response), Vec::new()),
            Self::Ignored => (None, Vec::new()),
        }
    }
}

#[async_trait]
pub trait RelayNodeIdentity: Send + Sync {
    async fn keyring(&self) -> Option<Arc<Keyring>>;
    fn node_id(&self) -> Option<IotaNodeId>;
}

#[async_trait]
pub trait LegacyRelayIdentity: RelayNodeIdentity {
    fn legacy_iota_id(&self) -> Option<u64>;
}

pub struct LegacyRelayDecoder {
    identities: Arc<dyn IdentityResolver>,
    node_identity: Arc<dyn LegacyRelayIdentity>,
    authority: AuthorityId,
}

impl LegacyRelayDecoder {
    pub fn new(
        identities: Arc<dyn IdentityResolver>,
        node_identity: Arc<dyn LegacyRelayIdentity>,
        authority: AuthorityId,
    ) -> Self {
        Self {
            identities,
            node_identity,
            authority,
        }
    }

    async fn resolve(&self, user_id: u64) -> Result<ResolvedPrincipal, RelayValidationError> {
        self.identities
            .resolve_principal(&PrincipalId {
                authority: self.authority.clone(),
                user_id,
            })
            .await
            .map_err(|error| RelayValidationError::KeyLookup(error.to_string()))
    }

    pub async fn decode(
        self: &Arc<Self>,
        frame: CommunicationValue,
    ) -> Result<VerifiedRelayEnvelope, RelayValidationError> {
        let local_iota_id = self.node_identity.legacy_iota_id().ok_or_else(|| {
            RelayValidationError::KeyLookup("legacy Iota ID is unavailable".into())
        })?;
        let keyring =
            self.node_identity.keyring().await.ok_or_else(|| {
                RelayValidationError::KeyLookup("Iota keyring is unavailable".into())
            })?;
        let decoder = self.clone();
        let verified = verify_relay_metadata(&frame, local_iota_id, &keyring, move |signer_id| {
            let decoder = decoder.clone();
            async move {
                decoder
                    .resolve(signer_id)
                    .await
                    .map(|principal| principal.public_keys)
            }
        })
        .await?;
        let signer = self.resolve(verified.context.signer_id).await?;
        let recipient = self.resolve(verified.context.final_recipient_id).await?;
        Ok(VerifiedRelayEnvelope {
            signer,
            recipient,
            message_id: verified.context.message_id.clone(),
            created_at: verified.context.created_at,
            compatibility: RelayCompatibilityData {
                legacy: Some(LegacyRelayCompatibility {
                    verified,
                    frame,
                    keyring,
                    local_iota_id,
                }),
                federated: None,
            },
        })
    }
}

pub struct RelayService {
    local_users: Arc<dyn LocalUserStore>,
    router: Arc<dyn PeerRouter>,
    legacy_decoder: Option<Arc<LegacyRelayDecoder>>,
    federated_identities: Option<Arc<dyn IdentityResolver>>,
    federated_node_identity: Option<Arc<dyn RelayNodeIdentity>>,
}

pub struct PendingRelayDispatcher {
    router: Arc<dyn PeerRouter>,
}

impl PendingRelayDispatcher {
    pub fn new(router: Arc<dyn PeerRouter>) -> Self {
        Self { router }
    }

    pub async fn dispatch_ready(&self, limit: i64) -> Result<usize, RelayServiceError> {
        let records = relay_queue::list_active(limit)
            .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
        let mut delivered = 0;
        for record in records {
            let version =
                mtp::type_map::Version::parse(&record.type_map_version).ok_or_else(|| {
                    RelayServiceError::Internal(format!(
                        "pending relay {} has invalid type-map version",
                        record.id
                    ))
                })?;
            let type_map = mtp::codec::TypeMap::new(version);
            let frame =
                CommunicationValue::from_bytes_with(&record.frame, &type_map).map_err(|_| {
                    RelayServiceError::Internal(format!(
                        "pending relay {} contains an invalid frame",
                        record.id
                    ))
                })?;
            let destination = match &record.target {
                relay_queue::RelayTarget::Iota(node) => RouteDestination::Iota(node.clone()),
                relay_queue::RelayTarget::LegacyOmegaIota { omega, iota_id } => {
                    RouteDestination::LegacyOmegaIota {
                        omega: omega.clone(),
                        iota_id: *iota_id,
                    }
                }
                relay_queue::RelayTarget::User(_) => continue,
            };
            let frame = match &record.target {
                relay_queue::RelayTarget::LegacyOmegaIota { iota_id, .. } => {
                    forward_verified_relay(&frame, RouteTarget::Iota(*iota_id))
                        .map_err(|error| RelayServiceError::Internal(error.to_string()))?
                }
                relay_queue::RelayTarget::Iota(_) => frame,
                relay_queue::RelayTarget::User(_) => continue,
            };
            match self.router.route(&destination, frame).await {
                Ok(RouteOutcome::Accepted {
                    relay_message_id,
                    destination_accepted_at,
                }) if record.relay_message_id.as_deref() == Some(&relay_message_id) => {
                    let signer = record.signer_principal.ok_or_else(|| {
                        RelayServiceError::Internal(format!(
                            "pending relay {} has no signer principal",
                            record.id
                        ))
                    })?;
                    iota_storage::util::downstream_relay::acknowledge_iota_delivery(
                        record.frame_id,
                        signer,
                        record.relay_signer_id,
                        &relay_message_id,
                        destination_accepted_at,
                    )
                    .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
                    delivered += 1;
                }
                Ok(RouteOutcome::Rejected { .. }) => {
                    if let (Some(signer), Some(message_id)) =
                        (record.signer_principal, record.relay_message_id.as_deref())
                    {
                        iota_storage::util::downstream_relay::reject_iota_delivery(
                            record.frame_id,
                            signer,
                            record.relay_signer_id,
                            message_id,
                            "destination_rejected",
                        )
                        .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
                    }
                }
                Ok(RouteOutcome::Accepted { .. }) => {
                    relay_queue::quarantine_for_frame(
                        record.frame_id,
                        "destination returned a different RelayMessageId",
                    )
                    .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
                }
                Ok(RouteOutcome::Retryable { reason }) => {
                    relay_queue::record_retry(
                        record.id,
                        crate::message_common::now_millis_i64(),
                        &reason,
                    )
                    .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
                }
                Err(error) => {
                    relay_queue::record_retry(
                        record.id,
                        crate::message_common::now_millis_i64(),
                        &error.to_string(),
                    )
                    .map_err(|error| RelayServiceError::Internal(error.to_string()))?;
                }
            }
        }
        Ok(delivered)
    }
}

impl RelayService {
    pub fn new(
        local_users: Arc<dyn LocalUserStore>,
        router: Arc<dyn PeerRouter>,
        legacy_decoder: Option<Arc<LegacyRelayDecoder>>,
    ) -> Self {
        Self {
            local_users,
            router,
            legacy_decoder,
            federated_identities: None,
            federated_node_identity: None,
        }
    }

    pub fn with_federation(
        mut self,
        identities: Arc<dyn IdentityResolver>,
        node_identity: Arc<dyn RelayNodeIdentity>,
    ) -> Self {
        self.federated_identities = Some(identities);
        self.federated_node_identity = Some(node_identity);
        self
    }

    fn is_hosted_principal(&self, principal: &ResolvedPrincipal) -> Result<bool, IdentityError> {
        self.local_users
            .local_user_for_principal(principal.handle)
            .map(|local_user| local_user.is_some())
    }

    async fn await_relay_response(
        &self,
        destination: &RouteDestination,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        match self
            .router
            .route(destination, frame.clone())
            .await
            .map_err(|error| error.to_string())?
        {
            RouteOutcome::Accepted {
                relay_message_id,
                destination_accepted_at,
            } => Ok(CommunicationValue::new(CommunicationType::Success)
                .add_typed_default(DataType::RelayMessageId, DataValue::Str(relay_message_id))
                .add_typed_default(
                    DataType::RelayAcceptedAt,
                    DataValue::SignedNumber(destination_accepted_at.into()),
                )),
            RouteOutcome::Rejected { response_type } => Ok(CommunicationValue::new(response_type)),
            RouteOutcome::Retryable { reason } => Err(reason),
        }
    }

    fn relay_response(frame_id: Option<u32>, response_type: CommunicationType) -> RelayOutcome {
        let Some(frame_id) = frame_id else {
            return RelayOutcome::Ignored;
        };
        let response = CommunicationValue::new(response_type).with_id(frame_id);
        match response_type {
            CommunicationType::Success => RelayOutcome::Accepted {
                ingress_response: response,
                local_deliveries: Vec::new(),
            },
            CommunicationType::ErrorNoIota => RelayOutcome::NoRoute { response },
            CommunicationType::ErrorInternal => RelayOutcome::RetryLater { response },
            _ => RelayOutcome::Rejected { response },
        }
    }

    fn relay_success(
        frame_id: Option<u32>,
        iota_id: u64,
        relay_message_id: &str,
        accepted_at: i64,
        include_origin_timestamp: bool,
        local_deliveries: Vec<ClientDelivery>,
    ) -> RelayOutcome {
        let Some(frame_id) = frame_id else {
            return RelayOutcome::Ignored;
        };
        let response = CommunicationValue::new(CommunicationType::Success)
            .with_id(frame_id)
            .add_typed_default(DataType::IotaId, DataValue::UnsignedNumber(iota_id.into()))
            .add_typed_default(
                DataType::RelayMessageId,
                DataValue::Str(relay_message_id.to_string()),
            )
            .add_typed_default(
                DataType::RelayAcceptedAt,
                DataValue::SignedNumber(accepted_at.into()),
            );
        let response = if include_origin_timestamp {
            response
                .add_typed_default(
                    DataType::OriginIotaReceivedAt,
                    DataValue::SignedNumber(accepted_at.into()),
                )
                .add_typed_default(
                    DataType::DestinationIotaReceivedAt,
                    DataValue::SignedNumber(accepted_at.into()),
                )
        } else {
            response
        };
        RelayOutcome::Accepted {
            ingress_response: response,
            local_deliveries,
        }
    }

    async fn process_relay_frame(
        self: Arc<Self>,
        normalized: VerifiedRelayEnvelope,
    ) -> RelayOutcome {
        if normalized.compatibility.federated.is_some() {
            return self.process_federated_relay(normalized).await;
        }
        let Some(legacy) = normalized.compatibility.legacy else {
            return RelayOutcome::Rejected {
                response: CommunicationValue::new(CommunicationType::ErrorInvalidData),
            };
        };
        let frame = legacy.frame;
        let Some(incoming_frame_id) = frame.id() else {
            log!("Rejecting Relay without a message id");
            return RelayOutcome::Ignored;
        };
        let local_iota_id = legacy.local_iota_id;
        let keyring = legacy.keyring;
        let verified = legacy.verified;
        let signer_principal = normalized.signer;
        let recipient_principal = normalized.recipient;
        let accepted_at = crate::message_common::now_millis_i64();
        let mut source_mutation = None;
        let signer_id = match i64::try_from(verified.context.signer_id) {
            Ok(id) => id,
            Err(_) => {
                return Self::relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInvalidData,
                );
            }
        };
        let recipient_id = match i64::try_from(verified.context.final_recipient_id) {
            Ok(id) => id,
            Err(_) => {
                return Self::relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInvalidData,
                );
            }
        };
        let signer_is_local = match self.is_hosted_principal(&signer_principal) {
            Ok(is_local) => is_local,
            Err(error) => {
                log!(
                    "Relay locality lookup failed for signer {}: {}",
                    signer_id,
                    error
                );
                return Self::relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInternal,
                );
            }
        };
        let recipient_is_local = match self.is_hosted_principal(&recipient_principal) {
            Ok(is_local) => is_local,
            Err(error) => {
                log!(
                    "Relay locality lookup failed for recipient {}: {}",
                    recipient_id,
                    error
                );
                return Self::relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInternal,
                );
            }
        };
        if !signer_is_local && !recipient_is_local {
            log!(
                "Rejecting Relay with no local origin or destination: signer {}, recipient {}",
                verified.context.signer_id,
                verified.context.final_recipient_id,
            );
            return Self::relay_response(
                Some(incoming_frame_id),
                CommunicationType::ErrorInvalidData,
            );
        }

        /* Evaluate recipient policy before reserving relay replay state or
         * persisting the frame, so blocked traffic leaves no durable trace. */
        if recipient_block_policy_applies(recipient_is_local, recipient_id, signer_id) {
            match iota_storage::util::blocked_users::is_principal_blocked(
                recipient_id,
                signer_principal.handle,
            ) {
                Ok(true) => {
                    log!(
                        "Rejecting Relay from blocked signer {} to recipient {}",
                        signer_id,
                        recipient_id
                    );
                    return Self::relay_response(
                        Some(incoming_frame_id),
                        CommunicationType::ErrorNotAuthenticated,
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    log!(
                        "Relay block policy lookup failed for recipient {}: {}",
                        recipient_id,
                        error
                    );
                    return Self::relay_response(
                        Some(incoming_frame_id),
                        CommunicationType::ErrorInternal,
                    );
                }
            }
        }

        /* An origin Iota is authoritative for receipt disclosure. Inspect
         * local-origin relay content before reserving or queuing the frame. */
        if signer_is_local {
            let content = match open_verified_relay_content(&verified, &[&keyring]) {
                Ok(content) => content,
                Err(error) => {
                    log!("Relay origin content verification failed: {}", error);
                    return Self::relay_response(
                        Some(incoming_frame_id),
                        CommunicationType::ErrorInvalidData,
                    );
                }
            };
            if let Err(error) = message_handlers::validate_outgoing_receipt_policy(
                signer_id,
                &verified.context,
                &content,
            ) {
                log!("Rejecting local receipt relay: {}", error);
                return Self::relay_response(
                    Some(incoming_frame_id),
                    CommunicationType::ErrorInvalidData,
                );
            }
        }

        let frame_bytes = match frame.clone().without_id().to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                log!(
                    "Relay could not be serialized for durable acceptance: {}",
                    error
                );
                return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
            }
        };
        let type_map_version = verified.context.type_map.version.to_string();
        let frame_id = incoming_frame_id;
        let reservation = match relay_replay::reserve(relay_replay::RelayReservationRequest {
            signer_principal: signer_principal.handle,
            signer_id: verified.context.signer_id,
            message_id: &verified.context.message_id,
            created_at: verified.context.created_at,
            accepted_at,
            destination_id: verified.context.final_recipient_id,
            frame: &frame_bytes,
            frame_id,
            type_map_version: &type_map_version,
        }) {
            Ok(value) => value,
            Err(error) => {
                log!("Relay durable acceptance failed: {}", error);
                return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
            }
        };
        let already_applied = match reservation {
            relay_replay::RelayReservation::New => false,
            relay_replay::RelayReservation::Existing {
                frame_matches: false,
                ..
            } => {
                log!(
                    "Rejecting Relay identity collision for signer {} and message {}",
                    verified.context.signer_id,
                    verified.context.message_id
                );
                return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
            }
            relay_replay::RelayReservation::Existing { ref state, .. } if state == "delivered" => {
                return Self::relay_response(frame.id(), CommunicationType::Success);
            }
            relay_replay::RelayReservation::Existing { ref state, .. }
                if state == "applied" || state == "queued" =>
            {
                true
            }
            relay_replay::RelayReservation::Existing { ref state, .. } if state == "rejected" => {
                return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
            }
            relay_replay::RelayReservation::Existing { .. } => false,
        };

        /* A shared Iota owns both independent replicas before delivering to its
         * local recipient. The destination path below writes the recipient copy. */
        if signer_is_local && recipient_is_local && !already_applied {
            let content = match open_verified_relay_content(&verified, &[&keyring]) {
                Ok(value) => value,
                Err(error) => {
                    log!(
                        "Relay shared-Iota origin content verification failed: {}",
                        error
                    );
                    let _ = relay_replay::mark_rejected(
                        signer_principal.handle,
                        &verified.context.message_id,
                    );
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
                }
            };
            let owner = match i64::try_from(verified.context.signer_id) {
                Ok(value) => value,
                Err(_) => {
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
                }
            };
            let application = match message_handlers::apply_verified_relay_content(
                &verified.context,
                &content,
                signer_principal.handle,
                recipient_principal.handle,
                accepted_at,
                owner,
                true,
            ) {
                Ok(application) => application,
                Err(error) => {
                    log!("Relay shared-Iota origin application failed: {}", error);
                    let _ = relay_replay::mark_rejected(
                        signer_principal.handle,
                        &verified.context.message_id,
                    );
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
                }
            };
            source_mutation = application.mutation;
            if let Err(error) = chat_files::record_destination_iota_received(
                owner,
                signer_principal.handle,
                &verified.context.message_id,
                accepted_at,
            ) {
                log!(
                    "Relay shared-Iota destination timestamp storage failed: {}",
                    error
                );
                return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
            }
        }

        if signer_is_local && !recipient_is_local {
            /* Chat-secret versions are immutable. Apply them locally only after
             * the peer has accepted the same relay, so a peer conflict cannot
             * leave a newly generated origin version behind. */
            let defer_chat_secret_commit = frame.is_type(CommunicationType::SetChatSecret);
            if !already_applied && !defer_chat_secret_commit {
                let content = match open_verified_relay_content(&verified, &[&keyring]) {
                    Ok(value) => value,
                    Err(error) => {
                        log!("Relay origin content verification failed: {}", error);
                        let _ = relay_replay::mark_rejected(
                            signer_principal.handle,
                            &verified.context.message_id,
                        );
                        return Self::relay_response(
                            frame.id(),
                            CommunicationType::ErrorInvalidData,
                        );
                    }
                };
                let application = match message_handlers::apply_verified_relay_content(
                    &verified.context,
                    &content,
                    signer_principal.handle,
                    recipient_principal.handle,
                    accepted_at,
                    signer_id,
                    true,
                ) {
                    Ok(application) => application,
                    Err(error) => {
                        log!("Relay origin application failed: {}", error);
                        let _ = relay_replay::mark_rejected(
                            signer_principal.handle,
                            &verified.context.message_id,
                        );
                        return Self::relay_response(
                            frame.id(),
                            CommunicationType::ErrorInvalidData,
                        );
                    }
                };
                source_mutation = application.mutation;
            }
            let Some(route) = route_destination(&recipient_principal.home) else {
                log!("Relay recipient has no Iota route");
                record_origin_delivery_failure(
                    verified.context.signer_id,
                    signer_principal.handle,
                    &verified.context.message_id,
                    "destination_iota_not_found",
                );
                return Self::relay_response(frame.id(), CommunicationType::ErrorNoIota);
            };
            let forwarded = match &route {
                RouteDestination::LegacyOmegaIota { iota_id, .. } => {
                    forward_verified_relay(&frame, RouteTarget::Iota(*iota_id))
                }
                RouteDestination::Iota(_) => Ok(frame.clone()),
            };
            let forwarded = match forwarded {
                Ok(value) => value,
                Err(error) => {
                    log!("Relay origin forwarding validation failed: {}", error);
                    record_origin_delivery_failure(
                        verified.context.signer_id,
                        signer_principal.handle,
                        &verified.context.message_id,
                        "forwarding_validation_failed",
                    );
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
                }
            };
            let bytes = match forwarded.to_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    log!("Relay origin retry could not be serialized: {}", error);
                    record_origin_delivery_failure(
                        verified.context.signer_id,
                        signer_principal.handle,
                        &verified.context.message_id,
                        "serialization_failed",
                    );
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
                }
            };
            let relay_identity = match (
                i64::try_from(verified.context.signer_id),
                i64::try_from(verified.context.final_recipient_id),
            ) {
                (Ok(signer_id), Ok(destination_user_id)) => relay_queue::RelayIdentity {
                    signer: signer_principal.handle,
                    recipient: recipient_principal.handle,
                    message_id: verified.context.message_id.clone(),
                    legacy_signer_id: Some(signer_id),
                    legacy_recipient_id: Some(destination_user_id),
                },
                _ => {
                    log!("Relay identity exceeds the storage range");
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
                }
            };
            if let Err(error) =
                outgoing_relay::commit_outgoing_relay(outgoing_relay::OutgoingRelay {
                    target: match &route {
                        RouteDestination::LegacyOmegaIota { omega, iota_id } => {
                            relay_queue::RelayTarget::LegacyOmegaIota {
                                omega: omega.clone(),
                                iota_id: *iota_id,
                            }
                        }
                        RouteDestination::Iota(node) => {
                            relay_queue::RelayTarget::Iota(node.clone())
                        }
                    },
                    identity: &relay_identity,
                    frame: &bytes,
                    created_at: crate::message_common::now_millis_i64(),
                    frame_id,
                    type_map_version: &type_map_version,
                })
            {
                log!("Relay origin retry queue failed: {}", error);
                record_origin_delivery_failure(
                    verified.context.signer_id,
                    signer_principal.handle,
                    &verified.context.message_id,
                    "queue_failed",
                );
                return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
            }
            match self.await_relay_response(&route, &forwarded).await {
                Ok(response) if response.is_type(CommunicationType::Success) => {
                    let returned_id = response.get_data(DataType::RelayMessageId).as_str();
                    let destination_accepted_at = response
                        .get_data(DataType::RelayAcceptedAt)
                        .as_number()
                        .and_then(|value| i64::try_from(value).ok());
                    if returned_id != Some(verified.context.message_id.as_str()) {
                        log!("Relay acknowledgement returned a different RelayMessageId");
                        return Self::relay_response(
                            frame.id(),
                            CommunicationType::ErrorInvalidData,
                        );
                    }
                    let Some(destination_accepted_at) = destination_accepted_at else {
                        log!("Relay acknowledgement is missing RelayAcceptedAt");
                        return Self::relay_response(
                            frame.id(),
                            CommunicationType::ErrorInvalidData,
                        );
                    };
                    let Ok(signer_id) = i64::try_from(verified.context.signer_id) else {
                        return Self::relay_response(
                            frame.id(),
                            CommunicationType::ErrorInvalidData,
                        );
                    };
                    if defer_chat_secret_commit && !already_applied {
                        let content = match open_verified_relay_content(&verified, &[&keyring]) {
                            Ok(value) => value,
                            Err(error) => {
                                log!("Relay origin content verification failed: {}", error);
                                return Self::relay_response(
                                    frame.id(),
                                    CommunicationType::ErrorInvalidData,
                                );
                            }
                        };
                        let Ok(origin_id) = i64::try_from(verified.context.signer_id) else {
                            return Self::relay_response(
                                frame.id(),
                                CommunicationType::ErrorInvalidData,
                            );
                        };
                        if let Err(error) = message_handlers::apply_verified_relay_content(
                            &verified.context,
                            &content,
                            signer_principal.handle,
                            recipient_principal.handle,
                            accepted_at,
                            origin_id,
                            true,
                        ) {
                            log!("Relay origin chat-secret application failed: {}", error);
                            return Self::relay_response(
                                frame.id(),
                                CommunicationType::ErrorInternal,
                            );
                        }
                    }
                    if let Err(error) =
                        iota_storage::util::downstream_relay::acknowledge_iota_delivery(
                            frame_id,
                            signer_principal.handle,
                            Some(signer_id),
                            &verified.context.message_id,
                            destination_accepted_at,
                        )
                    {
                        log!(
                            "Relay destination acknowledgement storage failed: {}",
                            error
                        );
                        return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
                    }
                    let response = response
                        .add_typed_default(
                            DataType::OriginIotaReceivedAt,
                            DataValue::SignedNumber(accepted_at.into()),
                        )
                        .add_typed_default(
                            DataType::DestinationIotaReceivedAt,
                            DataValue::SignedNumber(destination_accepted_at.into()),
                        )
                        .with_id(frame_id);
                    return RelayOutcome::Accepted {
                        ingress_response: response,
                        local_deliveries: source_mutation
                            .as_ref()
                            .map(|mutation| {
                                vec![mutation_delivery(
                                    mutation,
                                    verified.context.signer_id,
                                    verified.context.signer_id,
                                    verified.context.final_recipient_id,
                                    signer_principal.handle,
                                )]
                            })
                            .unwrap_or_default(),
                    };
                }
                Ok(response) => {
                    log!("Relay origin route returned {}", response.get_type());
                    if response.is_type(CommunicationType::ErrorInternal)
                        && !defer_chat_secret_commit
                    {
                        record_origin_delivery_failure(
                            verified.context.signer_id,
                            signer_principal.handle,
                            &verified.context.message_id,
                            "destination_internal_error",
                        );
                        return Self::relay_success(
                            frame.id(),
                            local_iota_id,
                            &verified.context.message_id,
                            accepted_at,
                            true,
                            source_mutation
                                .as_ref()
                                .map(|mutation| {
                                    vec![mutation_delivery(
                                        mutation,
                                        verified.context.signer_id,
                                        verified.context.signer_id,
                                        verified.context.final_recipient_id,
                                        signer_principal.handle,
                                    )]
                                })
                                .unwrap_or_default(),
                        );
                    } else if let Ok(signer_id) = i64::try_from(verified.context.signer_id) {
                        if let Err(error) =
                            iota_storage::util::downstream_relay::reject_iota_delivery(
                                frame_id,
                                signer_principal.handle,
                                Some(signer_id),
                                &verified.context.message_id,
                                "destination_rejected",
                            )
                        {
                            log!("Relay rejection cleanup failed: {}", error);
                        }
                        record_origin_delivery_failure(
                            verified.context.signer_id,
                            signer_principal.handle,
                            &verified.context.message_id,
                            "destination_rejected",
                        );
                    }
                    return Self::relay_response(
                        frame.id(),
                        response
                            .get_comm_type_enum()
                            .unwrap_or(CommunicationType::ErrorInternal),
                    );
                }
                Err(error) => {
                    log!("Relay origin forwarding failed: {}", error);
                    record_origin_delivery_failure(
                        verified.context.signer_id,
                        signer_principal.handle,
                        &verified.context.message_id,
                        "destination_unreachable",
                    );
                    if defer_chat_secret_commit {
                        if let Ok(signer_id) = i64::try_from(verified.context.signer_id)
                            && let Err(queue_error) =
                                iota_storage::util::downstream_relay::reject_iota_delivery(
                                    frame_id,
                                    signer_principal.handle,
                                    Some(signer_id),
                                    &verified.context.message_id,
                                    "destination_unreachable",
                                )
                        {
                            log!("Chat-secret relay retry cleanup failed: {}", queue_error);
                        }
                        return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
                    }
                    return Self::relay_success(
                        frame.id(),
                        local_iota_id,
                        &verified.context.message_id,
                        accepted_at,
                        true,
                        source_mutation
                            .as_ref()
                            .map(|mutation| {
                                vec![mutation_delivery(
                                    mutation,
                                    verified.context.signer_id,
                                    verified.context.signer_id,
                                    verified.context.final_recipient_id,
                                    signer_principal.handle,
                                )]
                            })
                            .unwrap_or_default(),
                    );
                }
            }
        }

        let destination = verified.context.final_recipient_id;
        let forwarded = match forward_verified_relay(&frame, RouteTarget::User(destination)) {
            Ok(value) => value,
            Err(error) => {
                log!("Relay forwarding validation failed: {}", error);
                return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
            }
        };
        let bytes = match forwarded.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                log!(
                    "Relay could not be serialized for client delivery: {}",
                    error
                );
                return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
            }
        };
        let relay_identity = match (
            i64::try_from(verified.context.signer_id),
            i64::try_from(verified.context.final_recipient_id),
        ) {
            (Ok(signer_id), Ok(destination_user_id)) => relay_queue::RelayIdentity {
                signer: signer_principal.handle,
                recipient: recipient_principal.handle,
                message_id: verified.context.message_id.clone(),
                legacy_signer_id: Some(signer_id),
                legacy_recipient_id: Some(destination_user_id),
            },
            _ => {
                log!("Relay identity exceeds the storage range");
                return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
            }
        };
        if let Err(error) = relay_queue::enqueue(
            relay_queue::RelayTarget::User(destination),
            &relay_identity,
            &bytes,
            crate::message_common::now_millis_i64(),
            frame_id,
            &type_map_version,
        ) {
            log!("Relay could not be queued for client delivery: {}", error);
            return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
        }

        let mut client_event = None;
        if !already_applied {
            let content = match open_verified_relay_content(&verified, &[&keyring]) {
                Ok(value) => value,
                Err(error) => {
                    log!("Relay content verification failed: {}", error);
                    if let Err(queue_error) =
                        relay_queue::remove_for_frame(RouteTarget::User(destination), frame_id)
                    {
                        log!(
                            "Relay invalid-content queue cleanup failed: {}",
                            queue_error
                        );
                    }
                    let _ = relay_replay::mark_rejected(
                        signer_principal.handle,
                        &verified.context.message_id,
                    );
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
                }
            };
            let application = match message_handlers::apply_verified_relay_content(
                &verified.context,
                &content,
                signer_principal.handle,
                recipient_principal.handle,
                accepted_at,
                match i64::try_from(destination) {
                    Ok(value) => value,
                    Err(_) => {
                        log!("Relay destination ID exceeds storage range");
                        return Self::relay_response(
                            frame.id(),
                            CommunicationType::ErrorInvalidData,
                        );
                    }
                },
                false,
            ) {
                Ok(application) => application,
                Err(error) => {
                    log!("Relay application dispatch failed: {}", error);
                    if let Err(queue_error) =
                        relay_queue::remove_for_frame(RouteTarget::User(destination), frame_id)
                    {
                        log!("Relay application queue cleanup failed: {}", queue_error);
                    }
                    let _ = relay_replay::mark_rejected(
                        signer_principal.handle,
                        &verified.context.message_id,
                    );
                    return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
                }
            };
            client_event = application
                .mutation
                .as_ref()
                .map(|mutation| {
                    client_event_from_mutation(
                        mutation,
                        verified.context.signer_id,
                        destination,
                        verified.context.signer_id,
                    )
                })
                .or_else(|| {
                    client_event_from_relay(
                        content.message_type,
                        &content.content,
                        verified.context.signer_id,
                        destination,
                        &verified.context.message_id,
                        accepted_at,
                    )
                });
            if let Err(error) =
                relay_replay::mark_applied(signer_principal.handle, &verified.context.message_id)
            {
                log!("Relay application state update failed: {}", error);
                return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
            }
        }

        if signer_is_local && recipient_is_local {
            let Ok(owner) = i64::try_from(verified.context.signer_id) else {
                return Self::relay_response(frame.id(), CommunicationType::ErrorInvalidData);
            };
            if let Err(error) = outgoing_relay::apply_outgoing_history_policy(
                owner,
                signer_principal.handle,
                &verified.context.message_id,
            ) {
                log!("Shared-Iota outgoing history policy failed: {}", error);
                return Self::relay_response(frame.id(), CommunicationType::ErrorInternal);
            }
        }

        if let Err(error) =
            relay_replay::mark_queued(signer_principal.handle, &verified.context.message_id)
        {
            log!("Relay queue state update failed: {}", error);
        }
        let mut local_deliveries = Vec::new();
        if let Some(mutation) = source_mutation.as_ref() {
            local_deliveries.push(mutation_delivery(
                mutation,
                verified.context.signer_id,
                verified.context.signer_id,
                verified.context.final_recipient_id,
                signer_principal.handle,
            ));
        }
        if let Some(frame) = client_event {
            local_deliveries.push(ClientDelivery {
                recipient: recipient_principal.handle,
                frame,
            });
        }
        Self::relay_success(
            frame.id(),
            local_iota_id,
            &verified.context.message_id,
            accepted_at,
            signer_is_local,
            local_deliveries,
        )
    }

    async fn process_federated_relay(
        self: Arc<Self>,
        normalized: VerifiedRelayEnvelope,
    ) -> RelayOutcome {
        let Some(federated) = normalized.compatibility.federated else {
            return RelayOutcome::Rejected {
                response: CommunicationValue::new(CommunicationType::ErrorInvalidData),
            };
        };
        let Some(frame_id) = federated.frame.id() else {
            return RelayOutcome::Ignored;
        };
        let signer_local = match self
            .local_users
            .local_user_for_principal(normalized.signer.handle)
        {
            Ok(user) => user,
            Err(error) => {
                log!("Relay V2 signer locality lookup failed: {error}");
                return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
            }
        };
        let recipient_local = match self
            .local_users
            .local_user_for_principal(normalized.recipient.handle)
        {
            Ok(user) => user,
            Err(error) => {
                log!("Relay V2 recipient locality lookup failed: {error}");
                return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
            }
        };
        if signer_local.is_none() && recipient_local.is_none() {
            return Self::relay_response(Some(frame_id), CommunicationType::ErrorInvalidData);
        }
        let accepted_at = crate::message_common::now_millis_i64();
        if let Some(recipient) = recipient_local {
            match iota_storage::util::blocked_users::is_principal_blocked(
                recipient.0,
                normalized.signer.handle,
            ) {
                Ok(true) => {
                    return Self::relay_response(
                        Some(frame_id),
                        CommunicationType::ErrorNotAuthenticated,
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    log!("Relay V2 block policy lookup failed: {error}");
                    return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
                }
            }
        }
        let Some(type_map) = federated.content.type_map().cloned() else {
            return Self::relay_response(Some(frame_id), CommunicationType::ErrorInvalidData);
        };
        let Some(message_type) = federated.content.get_comm_type_enum() else {
            return Self::relay_response(Some(frame_id), CommunicationType::ErrorInvalidData);
        };
        let context = crate::relay::VerifiedRelayContext {
            signer_id: normalized.signer.principal.user_id,
            final_recipient_id: normalized.recipient.principal.user_id,
            message_id: normalized.message_id.clone(),
            created_at: normalized.created_at,
            type_map: type_map.clone(),
        };
        let content = mtp::codec::VerifiedRelayContent {
            signer_id: context.signer_id,
            final_recipient_id: context.final_recipient_id,
            message_type,
            content: federated.content.payload().clone(),
        };
        let application = message_handlers::RelayApplicationContext {
            signer: normalized.signer.handle,
            recipient: normalized.recipient.handle,
            signer_principal: normalized.signer.principal.clone(),
            recipient_principal: normalized.recipient.principal.clone(),
            hosted_sender: signer_local,
            hosted_recipient: recipient_local,
            legacy: None,
        };
        let frame_bytes = match federated.frame.clone().without_id().to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                log!("Relay V2 durable encoding failed: {error}");
                return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
            }
        };
        let reservation = match relay_replay::reserve(relay_replay::RelayReservationRequest {
            signer_principal: normalized.signer.handle,
            signer_id: normalized.signer.principal.user_id,
            message_id: &normalized.message_id,
            created_at: normalized.created_at,
            accepted_at,
            destination_id: normalized.recipient.principal.user_id,
            frame: &frame_bytes,
            frame_id,
            type_map_version: &type_map.version.to_string(),
        }) {
            Ok(reservation) => reservation,
            Err(error) => {
                log!("Relay V2 durable acceptance failed: {error}");
                return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
            }
        };
        match &reservation {
            relay_replay::RelayReservation::Existing {
                frame_matches: false,
                ..
            } => {
                return Self::relay_response(Some(frame_id), CommunicationType::ErrorInvalidData);
            }
            relay_replay::RelayReservation::Existing { state, .. } if state == "delivered" => {
                return federated_success(
                    frame_id,
                    &normalized.message_id,
                    accepted_at,
                    Vec::new(),
                );
            }
            relay_replay::RelayReservation::Existing { state, .. } if state == "rejected" => {
                return Self::relay_response(Some(frame_id), CommunicationType::ErrorInvalidData);
            }
            _ => {}
        }
        let already_applied = matches!(
            reservation,
            relay_replay::RelayReservation::Existing { ref state, .. }
                if state == "applied" || state == "queued"
        );

        if let Some(recipient) = recipient_local {
            let mut source_mutation = None;
            let mut destination_mutation = None;
            if !already_applied {
                if let Some(sender) = signer_local {
                    let source_application = message_handlers::apply_relay_application_content(
                        &message_handlers::RelayApplicationContext {
                            hosted_sender: Some(sender),
                            hosted_recipient: None,
                            ..application.clone()
                        },
                        &context,
                        &content,
                        accepted_at,
                    );
                    match source_application {
                        Ok(application) => source_mutation = application.mutation,
                        Err(error) => {
                            log!("Relay V2 shared-Iota origin application failed: {error}");
                            let _ = relay_replay::mark_rejected(
                                normalized.signer.handle,
                                &normalized.message_id,
                            );
                            return Self::relay_response(
                                Some(frame_id),
                                CommunicationType::ErrorInvalidData,
                            );
                        }
                    }
                }
                let destination_application = message_handlers::apply_relay_application_content(
                    &message_handlers::RelayApplicationContext {
                        hosted_sender: None,
                        hosted_recipient: Some(recipient),
                        ..application.clone()
                    },
                    &context,
                    &content,
                    accepted_at,
                );
                match destination_application {
                    Ok(application) => destination_mutation = application.mutation,
                    Err(error) => {
                        log!("Relay V2 destination application failed: {error}");
                        let _ = relay_replay::mark_rejected(
                            normalized.signer.handle,
                            &normalized.message_id,
                        );
                        return Self::relay_response(
                            Some(frame_id),
                            CommunicationType::ErrorInvalidData,
                        );
                    }
                }
            }
            let relay_identity = relay_queue::RelayIdentity {
                signer: normalized.signer.handle,
                recipient: normalized.recipient.handle,
                message_id: normalized.message_id.clone(),
                legacy_signer_id: i64::try_from(normalized.signer.principal.user_id).ok(),
                legacy_recipient_id: Some(recipient.0),
            };
            if let Err(error) = relay_queue::enqueue(
                relay_queue::RelayTarget::User(recipient.0 as u64),
                &relay_identity,
                &frame_bytes,
                accepted_at,
                frame_id,
                &type_map.version.to_string(),
            ) {
                log!("Relay V2 local delivery queue failed: {error}");
                return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
            }
            let _ = relay_replay::mark_queued(normalized.signer.handle, &normalized.message_id);
            let destination_event = destination_mutation
                .as_ref()
                .map(|mutation| {
                    client_event_from_mutation(
                        mutation,
                        normalized.signer.principal.user_id,
                        normalized.recipient.principal.user_id,
                        normalized.signer.principal.user_id,
                    )
                })
                .or_else(|| {
                    client_event_from_relay(
                        message_type,
                        &content.content,
                        normalized.signer.principal.user_id,
                        normalized.recipient.principal.user_id,
                        &normalized.message_id,
                        accepted_at,
                    )
                });
            let mut local_deliveries = Vec::new();
            if let Some(mutation) = source_mutation.as_ref() {
                local_deliveries.push(mutation_delivery(
                    mutation,
                    normalized.signer.principal.user_id,
                    normalized.signer.principal.user_id,
                    normalized.recipient.principal.user_id,
                    normalized.signer.handle,
                ));
            }
            if let Some(frame) = destination_event {
                local_deliveries.push(ClientDelivery {
                    recipient: normalized.recipient.handle,
                    frame,
                });
            }
            return federated_success(
                frame_id,
                &normalized.message_id,
                accepted_at,
                local_deliveries,
            );
        }

        let Some(signer) = signer_local else {
            return Self::relay_response(Some(frame_id), CommunicationType::ErrorInvalidData);
        };
        let source_mutation = if already_applied {
            None
        } else {
            match message_handlers::apply_relay_application_content(
                &application,
                &context,
                &content,
                accepted_at,
            ) {
                Ok(application) => application.mutation,
                Err(error) => {
                    log!("Relay V2 origin application failed: {error}");
                    return Self::relay_response(
                        Some(frame_id),
                        CommunicationType::ErrorInvalidData,
                    );
                }
            }
        };
        let source_deliveries = || {
            source_mutation
                .as_ref()
                .map(|mutation| {
                    vec![mutation_delivery(
                        mutation,
                        normalized.signer.principal.user_id,
                        normalized.signer.principal.user_id,
                        normalized.recipient.principal.user_id,
                        normalized.signer.handle,
                    )]
                })
                .unwrap_or_default()
        };
        let Some(route) = route_destination(&normalized.recipient.home) else {
            return Self::relay_response(Some(frame_id), CommunicationType::ErrorNoIota);
        };
        let relay_identity = relay_queue::RelayIdentity {
            signer: normalized.signer.handle,
            recipient: normalized.recipient.handle,
            message_id: normalized.message_id.clone(),
            legacy_signer_id: Some(signer.0),
            legacy_recipient_id: i64::try_from(normalized.recipient.principal.user_id).ok(),
        };
        if let Err(error) = outgoing_relay::commit_outgoing_relay(outgoing_relay::OutgoingRelay {
            target: match &route {
                RouteDestination::Iota(node) => relay_queue::RelayTarget::Iota(node.clone()),
                RouteDestination::LegacyOmegaIota { omega, iota_id } => {
                    relay_queue::RelayTarget::LegacyOmegaIota {
                        omega: omega.clone(),
                        iota_id: *iota_id,
                    }
                }
            },
            identity: &relay_identity,
            frame: &frame_bytes,
            created_at: accepted_at,
            frame_id,
            type_map_version: &type_map.version.to_string(),
        }) {
            log!("Relay V2 retry queue failed: {error}");
            return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
        }
        match self.router.route(&route, federated.frame).await {
            Ok(RouteOutcome::Accepted {
                relay_message_id,
                destination_accepted_at,
            }) if relay_message_id == normalized.message_id => {
                if let Err(error) = iota_storage::util::downstream_relay::acknowledge_iota_delivery(
                    frame_id,
                    normalized.signer.handle,
                    Some(signer.0),
                    &relay_message_id,
                    destination_accepted_at,
                ) {
                    log!("Relay V2 acknowledgement storage failed: {error}");
                    return Self::relay_response(Some(frame_id), CommunicationType::ErrorInternal);
                }
                federated_success(
                    frame_id,
                    &relay_message_id,
                    destination_accepted_at,
                    source_deliveries(),
                )
            }
            Ok(RouteOutcome::Accepted { .. }) => {
                let _ = iota_storage::util::relay_queue::quarantine_for_frame(
                    frame_id,
                    "destination returned a different RelayMessageId",
                );
                Self::relay_response(Some(frame_id), CommunicationType::ErrorInvalidData)
            }
            Ok(RouteOutcome::Rejected { response_type }) => {
                Self::relay_response(Some(frame_id), response_type)
            }
            Ok(RouteOutcome::Retryable { .. }) | Err(_) => federated_success(
                frame_id,
                &normalized.message_id,
                accepted_at,
                source_deliveries(),
            ),
        }
    }

    pub async fn accept_relay(
        self: &Arc<Self>,
        source: IngressSource,
        frame: CommunicationValue,
    ) -> Result<RelayOutcome, RelayServiceError> {
        if frame.get_data(DataType::VersionNumber).as_number() == Some(2) {
            let identities = self.federated_identities.as_ref().ok_or_else(|| {
                RelayServiceError::Internal("federated identity resolver is unavailable".into())
            })?;
            let node = self
                .federated_node_identity
                .as_ref()
                .and_then(|identity| identity.node_id())
                .ok_or_else(|| {
                    RelayServiceError::Internal("local Iota node identity is unavailable".into())
                })?;
            let expected_destination = match &source {
                IngressSource::HostedClient { .. } => None,
                _ => Some(&node),
            };
            let verified = crate::federated_relay::decode_and_verify_for_ingress(
                frame,
                identities.as_ref(),
                expected_destination,
            )
            .await
            .map_err(|error| RelayServiceError::Rejected(error.to_string()))?;
            return self
                .accept_verified_relay(
                    source,
                    VerifiedRelayEnvelope {
                        signer: verified.signer,
                        recipient: verified.recipient,
                        message_id: verified.message_id,
                        created_at: verified.created_at,
                        compatibility: RelayCompatibilityData {
                            legacy: None,
                            federated: Some(FederatedRelayCompatibility {
                                frame: verified.frame,
                                content: verified.content,
                            }),
                        },
                    },
                )
                .await;
        }
        if matches!(
            source,
            IngressSource::DirectPeer { .. } | IngressSource::RelayRouter { .. }
        ) {
            return Err(RelayServiceError::Rejected(
                "legacy relay wire format is not valid for peer ingress".into(),
            ));
        }
        let frame_id = frame.id();
        let decoder = self.legacy_decoder.as_ref().ok_or_else(|| {
            RelayServiceError::Internal("legacy relay decoder is unavailable".into())
        })?;
        let normalized = match decoder.decode(frame).await {
            Ok(normalized) => normalized,
            Err(error) => {
                log!("Relay metadata verification failed: {error}");
                return Ok(Self::relay_response(
                    frame_id,
                    CommunicationType::ErrorInvalidData,
                ));
            }
        };
        self.accept_verified_relay(source, normalized).await
    }

    pub async fn accept_verified_relay(
        self: &Arc<Self>,
        source: IngressSource,
        normalized: VerifiedRelayEnvelope,
    ) -> Result<RelayOutcome, RelayServiceError> {
        match source {
            IngressSource::Omikron { connection_id } if !connection_id.is_empty() => {}
            IngressSource::DirectPeer { node_id }
                if matches!(
                    &normalized.signer.home,
                    PrincipalHome::Iota(home) if home == &node_id
                ) => {}
            IngressSource::DirectPeer { .. } => {
                return Err(RelayServiceError::Rejected(
                    "authenticated peer is not the signer home Iota".into(),
                ));
            }
            IngressSource::RelayRouter { .. } => {}
            IngressSource::HostedClient { session } => {
                if !matches!(session.identity, SessionIdentity::Hosted { .. })
                    || !session.allows(&SessionCapability::RelayOrigination)
                    || session.principal() != normalized.signer.handle
                {
                    return Err(RelayServiceError::Rejected(
                        "hosted client session cannot originate this relay".into(),
                    ));
                }
            }
            IngressSource::Omikron { .. } => {
                return Err(RelayServiceError::Rejected(
                    "Omikron ingress has no authenticated connection ID".into(),
                ));
            }
        }
        Ok(self.clone().process_relay_frame(normalized).await)
    }
}

fn federated_success(
    frame_id: u32,
    message_id: &str,
    accepted_at: i64,
    local_deliveries: Vec<ClientDelivery>,
) -> RelayOutcome {
    RelayOutcome::Accepted {
        ingress_response: CommunicationValue::new(CommunicationType::Success)
            .with_id(frame_id)
            .add_typed_default(
                DataType::RelayMessageId,
                DataValue::Str(message_id.to_string()),
            )
            .add_typed_default(
                DataType::RelayAcceptedAt,
                DataValue::SignedNumber(accepted_at.into()),
            ),
        local_deliveries,
    }
}

fn next_client_event_id() -> u32 {
    NEXT_CLIENT_EVENT_ID.fetch_add(1, Ordering::Relaxed).max(1)
}

fn record_origin_delivery_failure(
    signer_id: u64,
    signer_principal: iota_identity::PrincipalHandle,
    relay_message_id: &str,
    failure: &str,
) {
    let Ok(storage_owner) = i64::try_from(signer_id) else {
        return;
    };
    if let Err(error) = chat_files::record_delivery_failure(
        storage_owner,
        signer_principal,
        relay_message_id,
        failure,
        crate::message_common::now_millis_i64(),
    ) {
        log!("Relay delivery failure storage failed: {error}");
    }
}

fn client_event_from_mutation(
    mutation: &message_handlers::AppliedMessageMutation,
    actor_id: u64,
    account_id: u64,
    chat_partner_id: u64,
) -> CommunicationValue {
    let event = match mutation {
        message_handlers::AppliedMessageMutation::State { send_time, state } => {
            CommunicationValue::new(CommunicationType::MessageState)
                .add_typed_default(
                    DataType::SendTime,
                    DataValue::SignedNumber((*send_time).into()),
                )
                .add_typed_default(
                    DataType::MessageState,
                    DataValue::Str(state.as_str().to_string()),
                )
        }
        message_handlers::AppliedMessageMutation::Edit {
            send_time,
            content,
            version,
        } => CommunicationValue::new(CommunicationType::MessageEditLive)
            .add_typed_default(DataType::Content, DataValue::Str(content.clone()))
            .add_typed_default(
                DataType::SendTime,
                DataValue::SignedNumber((*send_time).into()),
            )
            .add_typed_default(
                DataType::VersionNumber,
                DataValue::SignedNumber((*version).into()),
            ),
        message_handlers::AppliedMessageMutation::Reaction {
            send_time,
            reaction,
            accepted,
        } => CommunicationValue::new(CommunicationType::MessageReactionLive)
            .add_typed_default(DataType::Reaction, DataValue::Str(reaction.clone()))
            .add_typed_default(
                DataType::SendTime,
                DataValue::SignedNumber((*send_time).into()),
            )
            .add_typed_default(
                DataType::SenderId,
                DataValue::UnsignedNumber(actor_id.into()),
            )
            .add_typed_default(DataType::Accepted, DataValue::Bool(*accepted)),
        message_handlers::AppliedMessageMutation::Delete { send_time } => {
            CommunicationValue::new(CommunicationType::MessageDeleteLive).add_typed_default(
                DataType::SendTime,
                DataValue::SignedNumber((*send_time).into()),
            )
        }
    };

    event
        .with_id(next_client_event_id())
        .with_sender(actor_id)
        .with_receiver(account_id)
        .add_typed_default(
            DataType::ChatPartnerId,
            DataValue::UnsignedNumber(chat_partner_id.into()),
        )
}

fn mutation_delivery(
    mutation: &message_handlers::AppliedMessageMutation,
    actor_id: u64,
    account_id: u64,
    chat_partner_id: u64,
    recipient: iota_identity::PrincipalHandle,
) -> ClientDelivery {
    ClientDelivery {
        recipient,
        frame: client_event_from_mutation(mutation, actor_id, account_id, chat_partner_id),
    }
}

fn client_event_from_relay(
    message_type: CommunicationType,
    payload: &DataValue,
    signer_id: u64,
    recipient_id: u64,
    relay_message_id: &str,
    accepted_at: i64,
) -> Option<CommunicationValue> {
    let sender = DataValue::UnsignedNumber(u128::from(signer_id));
    let receiver = recipient_id;
    let event_id = next_client_event_id();

    match message_type {
        CommunicationType::MessageSend => {
            let frame = CommunicationValue::new(CommunicationType::MessageSend)
                .with_payload(payload.clone());
            let content = frame.get_data(DataType::Content)?.clone();
            let send_time = frame.get_data(DataType::SendTime)?.clone();
            let version = frame.get_data(DataType::VersionNumber)?.clone();
            let mut message = vec![
                (DataType::Content, content),
                (DataType::SendTime, send_time),
                (DataType::VersionNumber, version),
                (
                    DataType::RelayMessageId,
                    DataValue::Str(relay_message_id.to_string()),
                ),
                (DataType::MessageState, DataValue::Str("sent".to_string())),
            ];
            if let Some(reply_id) = frame.get_data(DataType::ReplyId) {
                message.push((DataType::ReplyId, reply_id.clone()));
            }
            let mut event = CommunicationValue::new(CommunicationType::MessageLive)
                .with_id(event_id)
                .with_sender(signer_id)
                .with_receiver(receiver)
                .add_typed_default(DataType::SenderId, sender)
                .add_typed_default(DataType::Message, typed_container(message))
                .add_typed_default(
                    DataType::LastMessageAt,
                    DataValue::SignedNumber(accepted_at.into()),
                );
            if let (Ok(owner), Ok(partner)) =
                (i64::try_from(recipient_id), i64::try_from(signer_id))
                && let Ok(Some(contact)) = chats_util::get_user(owner, partner)
            {
                event = event.add_typed_default(
                    DataType::Notifications,
                    DataValue::SignedNumber(contact.notifications.into()),
                );
                if let Some(last_message_at) = contact.last_message_at {
                    event = event.add_typed_default(
                        DataType::LastMessageAt,
                        DataValue::SignedNumber(last_message_at.into()),
                    );
                }
            }
            Some(event)
        }
        CommunicationType::SetChatSecret => {
            let frame = CommunicationValue::new(CommunicationType::SetChatSecret)
                .with_payload(payload.clone());
            let chat_id = frame.get_data(DataType::ChatId)?.clone();
            let secret_id = frame.get_data(DataType::SecretId)?.clone();
            let version = frame.get_data(DataType::VersionNumber)?.clone();
            Some(
                CommunicationValue::new(CommunicationType::ChatSecretForward)
                    .with_id(event_id)
                    .with_sender(signer_id)
                    .with_receiver(receiver)
                    .add_typed_default(DataType::ChatId, chat_id)
                    .add_typed_default(
                        DataType::SenderUserId,
                        DataValue::Str(signer_id.to_string()),
                    )
                    .add_typed_default(
                        DataType::RecipientUserId,
                        DataValue::Str(recipient_id.to_string()),
                    )
                    .add_typed_default(DataType::SecretId, secret_id)
                    .add_typed_default(DataType::VersionNumber, version)
                    .add_typed_default(DataType::Payload, DataValue::Str("available".to_string())),
            )
        }
        CommunicationType::AddConversation if recipient_id < signer_id => {
            let chat_id = format!("{recipient_id}:{signer_id}");
            Some(
                CommunicationValue::new(CommunicationType::ChatSecretForward)
                    .with_id(event_id)
                    .with_sender(signer_id)
                    .with_receiver(receiver)
                    .add_typed_default(DataType::ChatId, DataValue::Str(chat_id.clone()))
                    .add_typed_default(
                        DataType::SenderUserId,
                        DataValue::Str(signer_id.to_string()),
                    )
                    .add_typed_default(
                        DataType::RecipientUserId,
                        DataValue::Str(recipient_id.to_string()),
                    )
                    .add_typed_default(
                        DataType::SecretId,
                        DataValue::Str(format!("chat:{chat_id}:main")),
                    )
                    .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(1))
                    .add_typed_default(DataType::Payload, DataValue::Str("init".to_string())),
            )
        }
        _ => None,
    }
}

/*
 * Owns relay policy and storage semantics. Transport adapters supply identity
 * material and deliver the returned RelayOutcome on their own connection.
 */

fn recipient_block_policy_applies(
    recipient_is_local: bool,
    recipient_id: i64,
    signer_id: i64,
) -> bool {
    recipient_is_local && recipient_id != signer_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_handler::{RouteError, RouteOutcome};
    use iota_identity::{LocalUserDescriptor, LocalUserId, ResolutionContext, UserAddress};

    struct UnusedDependencies;

    #[async_trait]
    impl IdentityResolver for UnusedDependencies {
        async fn resolve_address(
            &self,
            _: &UserAddress,
            _: &ResolutionContext,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            Err(IdentityError::NotFound)
        }

        async fn resolve_principal(
            &self,
            _: &PrincipalId,
        ) -> Result<ResolvedPrincipal, IdentityError> {
            Err(IdentityError::NotFound)
        }

        async fn signing_keys(
            &self,
            _: &PrincipalId,
            _: &ResolutionContext,
        ) -> Result<Vec<iota_identity::PublicKeyBundle>, IdentityError> {
            Err(IdentityError::NotFound)
        }
    }

    impl LocalUserStore for UnusedDependencies {
        fn get_local_user(
            &self,
            _: LocalUserId,
        ) -> Result<Option<LocalUserDescriptor>, IdentityError> {
            Ok(None)
        }

        fn get_local_user_by_username(
            &self,
            _: &str,
        ) -> Result<Option<LocalUserDescriptor>, IdentityError> {
            Ok(None)
        }

        fn is_hosted_here(&self, _: LocalUserId) -> Result<bool, IdentityError> {
            Ok(false)
        }

        fn local_user_for_principal(
            &self,
            _: PrincipalHandle,
        ) -> Result<Option<LocalUserId>, IdentityError> {
            Ok(None)
        }

        fn principal_for_local_user(
            &self,
            _: LocalUserId,
        ) -> Result<Option<PrincipalHandle>, IdentityError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl PeerRouter for UnusedDependencies {
        async fn route(
            &self,
            destination: &RouteDestination,
            _: CommunicationValue,
        ) -> Result<RouteOutcome, RouteError> {
            match destination {
                RouteDestination::Iota(node) => Err(RouteError::NoRoute(node.clone())),
                RouteDestination::LegacyOmegaIota { .. } => Ok(RouteOutcome::Retryable {
                    reason: "unused".into(),
                }),
            }
        }
    }

    #[async_trait]
    impl RelayNodeIdentity for UnusedDependencies {
        async fn keyring(&self) -> Option<Arc<Keyring>> {
            None
        }

        fn node_id(&self) -> Option<IotaNodeId> {
            None
        }
    }

    fn service() -> Arc<RelayService> {
        let dependencies = Arc::new(UnusedDependencies);
        Arc::new(RelayService::new(
            dependencies.clone(),
            dependencies.clone(),
            None,
        ))
    }

    #[tokio::test]
    async fn peer_ingress_rejects_legacy_wire_frames() {
        let node = iota_identity::LocalNodeIdentity::from_keyring(Keyring::generate())
            .expect("generated identity is valid")
            .node_id()
            .clone();
        let outcome = service()
            .accept_relay(
                IngressSource::DirectPeer { node_id: node },
                CommunicationValue::new(CommunicationType::Relay),
            )
            .await;
        assert!(matches!(outcome, Err(RelayServiceError::Rejected(_))));
    }

    #[test]
    fn normalized_legacy_identity_scopes_numeric_ids_to_authority() {
        let first = PrincipalId {
            authority: AuthorityId::new("omega:a").expect("static authority is valid"),
            user_id: 7,
        };
        let second = PrincipalId {
            authority: AuthorityId::new("iota:b").expect("static authority is valid"),
            user_id: 7,
        };
        assert_ne!(first, second);
    }

    #[test]
    fn principal_home_selects_direct_or_legacy_route() {
        let node = iota_identity::LocalNodeIdentity::from_keyring(Keyring::generate())
            .expect("generated identity is valid")
            .node_id()
            .clone();
        assert_eq!(
            route_destination(&PrincipalHome::Iota(node.clone())),
            Some(RouteDestination::Iota(node))
        );
        assert!(route_destination(&PrincipalHome::Unknown).is_none());
    }

    #[test]
    fn recipient_block_policy_skips_self_delivery() {
        assert!(!recipient_block_policy_applies(true, 42, 42));
        assert!(recipient_block_policy_applies(true, 42, 43));
        assert!(!recipient_block_policy_applies(false, 42, 43));
    }

    #[test]
    fn mutation_events_use_receiving_account_chat_partner() {
        let event = client_event_from_mutation(
            &message_handlers::AppliedMessageMutation::Reaction {
                send_time: 12,
                reaction: "thumbsup".into(),
                accepted: true,
            },
            7,
            8,
            9,
        );

        assert!(event.is_type(CommunicationType::MessageReactionLive));
        assert_eq!(event.receiver(), Some(8));
        assert_eq!(event.sender(), Some(7));
        assert_eq!(event.get_data(DataType::ChatPartnerId).as_number(), Some(9));
        assert_eq!(event.get_data(DataType::SenderId).as_number(), Some(7));
    }
}
