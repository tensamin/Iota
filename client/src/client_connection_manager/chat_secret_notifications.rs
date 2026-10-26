use super::*;
use iota_storage::util::chat_secret_recovery::{self as recovery, SecretAvailable};
use std::sync::atomic::Ordering;

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
        loop {
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
                        iota_logger::log!("Cannot read ChatSecret notification outbox: {}", error);
                        continue;
                    }
                };
            let mut full_page = events.len() == 100;
            for event in events {
                let frame = match secret_available_frame(&event) {
                    Ok(frame) => frame,
                    Err(error) => {
                        iota_logger::log!("Cannot prepare ChatSecret notification: {}", error);
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
            }
            if full_page {
                active.secret_ready.notify_one();
            }
        }
    }
}

fn secret_available_frame(
    event: &SecretAvailable,
) -> Result<Option<CommunicationValue>, &'static str> {
    // The unchanged Client addresses peers numerically. Do not publish an
    // ambiguous numeric peer, even when its canonical envelope is available.
    let first = event.principal.user_id.min(event.peer.user_id);
    let second = event.principal.user_id.max(event.peer.user_id);
    let chat = format!("{first}:{second}");
    let request = CommunicationValue::new(CommunicationType::GetChatSecret)
        .with_sender(u64::try_from(event.owner.0).map_err(|_| "invalid storage owner")?)
        .add_typed_default(
            DataType::UserId,
            DataValue::Str(event.principal.user_id.to_string()),
        )
        .add_typed_default(DataType::ChatId, DataValue::Str(chat.clone()))
        .add_typed_default(
            DataType::SecretId,
            DataValue::Str(format!("chat:{chat}:main")),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::SignedNumber(event.version.into()),
        );
    let (owner, peer, _) = match message_handlers::validated_chat_secret_read_target(&request) {
        Ok(target) => target,
        Err(response) if response.is_type(CommunicationType::ErrorInternal) => {
            return Err("identity storage unavailable");
        }
        Err(_) => return Ok(None),
    };
    if owner != event.principal || peer != event.peer {
        return Ok(None);
    }
    // Read through the accepted-row/evidence gate using its original namespace.
    let request = request
        .with_data(
            DataType::UserId,
            DataValue::Str(serde_json::to_string(&owner).map_err(|_| "invalid owner principal")?),
        )
        .with_data(DataType::ChatId, DataValue::Str(event.chat_id.clone()))
        .with_data(DataType::SecretId, DataValue::Str(event.secret_id.clone()));
    if !message_handlers::handle_get_chat_secret(&request)
        .is_type(CommunicationType::ChatSecretResponse)
    {
        return Err("accepted envelope unavailable");
    }
    Ok(Some(
        CommunicationValue::new(CommunicationType::ChatSecretForward)
            .with_sender(peer.user_id)
            .with_receiver(owner.user_id)
            .add_typed_default(
                DataType::SenderUserId,
                DataValue::UnsignedNumber(peer.user_id.into()),
            )
            .add_typed_default(
                DataType::RecipientUserId,
                DataValue::UnsignedNumber(owner.user_id.into()),
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
