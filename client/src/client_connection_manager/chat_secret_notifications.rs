use super::*;
use iota_storage::util::chat_secret_recovery::{self as recovery, SecretAvailable};
use std::sync::atomic::{AtomicU64, Ordering};

static PREPARATION_FAILURES: AtomicU64 = AtomicU64::new(0);
static RECOVERY_ENQUEUE_FAILURES: AtomicU64 = AtomicU64::new(0);

impl ClientConnectionManager {
    /// Outbox events are retained and paged independently by each admitted session.
    /// A fresh connection starts at zero, including events already dispatched to
    /// another device. No Client acknowledgement is required for these hints.
    pub(super) async fn deliver_chat_secret_notifications(
        &self,
        session: &AuthenticatedSession,
        active: &HostedConnection,
        shutdown: &CancellationToken,
    ) {
        let Some(lease) = session.hosted_lease.as_ref() else {
            return;
        };
        let mut changes = recovery::subscribe_changes();
        let mut retry = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut cursor = 0;
        let mut failures = 0u32;
        loop {
            if failures >= 12 {
                iota_logger::log!(
                    "ChatSecret notification retry budget exhausted; cooling down: preparation_failures={} enqueue_failures={}",
                    PREPARATION_FAILURES.load(Ordering::Relaxed),
                    RECOVERY_ENQUEUE_FAILURES.load(Ordering::Relaxed)
                );
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {},
                }
                failures = 0;
            }
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                _ = active.secret_ready.notified() => {},
                _ = changes.changed() => {},
                _ = retry.tick() => {},
            }
            if !self.session_is_registered(session)
                || iota_storage::hosted_auth::verify(lease).is_err()
            {
                return;
            }
            if !active.state_applied.load(Ordering::Acquire) {
                continue;
            }
            let events =
                match recovery::events_for_owner_after(lease.identity.local_user, cursor, 100) {
                    Ok(events) => events,
                    Err(error) => {
                        let count = PREPARATION_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                        iota_logger::log!(
                            "Cannot read ChatSecret notification outbox: failures={} error={}",
                            count,
                            error
                        );
                        failures += 1;
                        continue;
                    }
                };
            let mut full_page = events.len() == 100;
            for event in events {
                let frame = match secret_available_frame(&event) {
                    Ok(frame) => frame,
                    Err(HintError::EnvelopeUnavailable) => {
                        let count = PREPARATION_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                        match iota_connection::chat_secret_recovery::enqueue_recovery(
                            &event.principal,
                            &event.peer,
                            Some(event.version),
                        ) {
                            Ok(_) => {
                                iota_logger::log!(
                                    "ChatSecret notification recovery queued: event={} preparation_failures={}",
                                    event.id,
                                    count
                                );
                                cursor = event.id;
                                failures = 0;
                                continue;
                            }
                            Err(error) => {
                                let count =
                                    RECOVERY_ENQUEUE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                                iota_logger::log!(
                                    "ChatSecret notification recovery enqueue failed: event={} failures={} error={}",
                                    event.id,
                                    count,
                                    error
                                );
                            }
                        }
                        failures += 1;
                        full_page = false;
                        break;
                    }
                    Err(HintError::StorageUnavailable) => {
                        let count = PREPARATION_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                        iota_logger::log!(
                            "ChatSecret notification storage unavailable: event={} preparation_failures={}",
                            event.id,
                            count
                        );
                        failures += 1;
                        full_page = false;
                        break;
                    }
                };
                if let Some(frame) = frame {
                    // Recheck after the database reads and immediately before send.
                    if !self.session_is_registered(session)
                        || iota_storage::hosted_auth::verify(lease).is_err()
                    {
                        return;
                    }
                    let sent = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => return,
                        result = tokio::time::timeout(std::time::Duration::from_secs(5), active.sender.send(&frame)) => matches!(result, Ok(Ok(()))),
                    };
                    if !sent {
                        return;
                    }
                    // This is local dispatch bookkeeping, not a Client receipt.
                    if let Err(error) = recovery::acknowledge_notification(event.owner, event.id) {
                        iota_logger::log!(
                            "Cannot mark ChatSecret notification dispatched: {}",
                            error
                        );
                    }
                }
                cursor = event.id;
                failures = 0;
            }
            if full_page {
                active.secret_ready.notify_one();
            }
        }
    }
}

enum HintError {
    StorageUnavailable,
    EnvelopeUnavailable,
}

fn secret_available_frame(
    event: &SecretAvailable,
) -> Result<Option<CommunicationValue>, HintError> {
    let owner_key =
        recovery::principal_key(&event.principal).map_err(|_| HintError::StorageUnavailable)?;
    let request = CommunicationValue::new(CommunicationType::GetChatSecret)
        .with_sender(u64::try_from(event.owner.0).map_err(|_| HintError::StorageUnavailable)?)
        .add_typed_default(DataType::UserId, DataValue::Str(owner_key.clone()))
        .add_typed_default(DataType::ChatId, DataValue::Str(event.chat_id.clone()))
        .add_typed_default(DataType::SecretId, DataValue::Str(event.secret_id.clone()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(event.version.into()),
        );
    let (owner, peer, _) = match message_handlers::validated_chat_secret_read_target(&request) {
        Ok(target) => target,
        Err(response) if response.is_type(CommunicationType::ErrorInternal) => {
            return Err(HintError::StorageUnavailable);
        }
        Err(response) if response.is_type(CommunicationType::ErrorInvalidData) => return Ok(None),
        Err(_) => return Err(HintError::StorageUnavailable),
    };
    if owner != event.principal || peer != event.peer {
        return Ok(None);
    }
    // The hint exposes availability only after the accepted-row/evidence gate.
    match message_handlers::read_chat_secret(&request) {
        Ok(_) => {}
        Err(message_handlers::ChatSecretReadError::Unavailable(_)) => {
            return Err(HintError::EnvelopeUnavailable);
        }
        Err(message_handlers::ChatSecretReadError::Storage(error)) => {
            iota_logger::log!(
                "ChatSecret notification read failed: event={} error={}",
                event.id,
                error
            );
            return Err(HintError::StorageUnavailable);
        }
        Err(_) => return Err(HintError::StorageUnavailable),
    }
    Ok(Some(
        CommunicationValue::new_with_type_map(
            CommunicationType::ChatSecretForward,
            request.type_map().ok_or(HintError::StorageUnavailable)?,
        )
        .with_receiver(u64::try_from(event.owner.0).map_err(|_| HintError::StorageUnavailable)?)
        .add_typed_default(DataType::Principal, DataValue::Str(owner_key))
        .add_typed_default(
            DataType::UserAddress,
            DataValue::Str(
                recovery::principal_key(&peer).map_err(|_| HintError::StorageUnavailable)?,
            ),
        )
        .add_typed_default(
            DataType::ChatId,
            DataValue::Str(event.namespace.chat_id.clone()),
        )
        .add_typed_default(
            DataType::SecretId,
            DataValue::Str(event.namespace.secret_id.clone()),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(event.version.into()),
        )
        .add_typed_default(DataType::Payload, DataValue::Str("available".into())),
    ))
}
