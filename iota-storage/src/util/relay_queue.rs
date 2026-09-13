use crate::storage_error::StorageError;
use crate::util::db;
use iota_identity::{AuthorityId, IotaNodeId, PrincipalHandle};
use iota_util::route_target::RouteTarget;
use rusqlite::{OptionalExtension, Transaction, params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRelay {
    pub id: i64,
    pub target: RelayTarget,
    pub frame: Vec<u8>,
    pub created_at: i64,
    pub frame_id: u32,
    pub type_map_version: String,
    pub relay_signer_id: Option<i64>,
    pub relay_destination_user_id: Option<i64>,
    pub signer_principal: Option<PrincipalHandle>,
    pub destination_principal: Option<PrincipalHandle>,
    pub relay_message_id: Option<String>,
    pub delivery_state: PendingRelayDeliveryState,
    pub last_error: Option<String>,
    pub attempt_count: i64,
    pub last_attempt_at: Option<i64>,
    pub next_attempt_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayTarget {
    User(u64),
    Iota(IotaNodeId),
    LegacyOmegaIota { omega: AuthorityId, iota_id: u64 },
}

impl RelayTarget {
    pub fn legacy_wire_target(&self) -> Option<RouteTarget> {
        match self {
            Self::User(user_id) => Some(RouteTarget::User(*user_id)),
            Self::LegacyOmegaIota { iota_id, .. } => Some(RouteTarget::Iota(*iota_id)),
            Self::Iota(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingRelayDeliveryState {
    Ready,
    WaitingClient,
    Quarantined,
}

impl PendingRelayDeliveryState {
    fn from_db(value: String) -> Result<Self, rusqlite::Error> {
        match value.as_str() {
            "ready" => Ok(Self::Ready),
            "waiting_client" => Ok(Self::WaitingClient),
            "quarantined" => Ok(Self::Quarantined),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayIdentity {
    pub signer: PrincipalHandle,
    pub recipient: PrincipalHandle,
    pub message_id: String,
    pub legacy_signer_id: Option<i64>,
    pub legacy_recipient_id: Option<i64>,
}

pub fn enqueue(
    target: RelayTarget,
    relay: &RelayIdentity,
    frame: &[u8],
    created_at: i64,
    frame_id: u32,
    type_map_version: &str,
) -> Result<(), StorageError> {
    if let RelayTarget::User(destination) = target {
        let destination = i64::try_from(destination)
            .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
        if Some(destination) != relay.legacy_recipient_id {
            return Err(StorageError::Other(
                "user relay target does not match final recipient".into(),
            ));
        }
    }
    db::with_immediate_transaction(|tx| {
        enqueue_in_tx(
            tx,
            target,
            relay,
            frame,
            created_at,
            frame_id,
            type_map_version,
        )
    })
}

pub fn enqueue_in_tx(
    tx: &Transaction<'_>,
    target: RelayTarget,
    relay: &RelayIdentity,
    frame: &[u8],
    created_at: i64,
    frame_id: u32,
    type_map_version: &str,
) -> Result<(), StorageError> {
    let (destination_id, target_kind, destination_node_id, destination_authority_id) = match &target
    {
        RelayTarget::User(user_id) => (
            i64::try_from(*user_id).map_err(|_| {
                StorageError::Other("relay destination ID exceeds SQLite range".into())
            })?,
            0_i64,
            None,
            None,
        ),
        RelayTarget::LegacyOmegaIota { omega, iota_id } => (
            i64::try_from(*iota_id).map_err(|_| {
                StorageError::Other("relay destination ID exceeds SQLite range".into())
            })?,
            1_i64,
            None,
            Some(omega.as_str()),
        ),
        RelayTarget::Iota(node) => (0, 2_i64, Some(node.as_str()), None),
    };
    tx.execute(
            "INSERT OR IGNORE INTO pending_relays (destination_id, target_kind, relay_signer_id, relay_destination_user_id, relay_message_id, frame, created_at, frame_id, type_map_version, signer_principal, destination_principal, destination_node_id, destination_authority_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                destination_id,
                target_kind,
                relay.legacy_signer_id,
                relay.legacy_recipient_id,
                relay.message_id,
                frame,
                created_at,
                i64::from(frame_id),
                type_map_version,
                relay.signer.0,
                relay.recipient.0,
                destination_node_id,
                destination_authority_id,
            ],
    )?;
    Ok(())
}

pub fn list(limit: i64) -> Result<Vec<PendingRelay>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare(
            "SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at FROM pending_relays ORDER BY id LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit.clamp(1, 500)], |row| {
            let destination_id = row.get::<_, i64>(1)?;
            let target_kind = row.get::<_, i64>(2)?;
            let destination_id = u64::try_from(destination_id).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    "negative relay destination ID".into(),
                )
            })?;
            let target = match target_kind {
                0 => RelayTarget::User(destination_id),
                1 => RelayTarget::LegacyOmegaIota {
                    omega: AuthorityId::new(row.get::<_, String>(15)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            15,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    iota_id: destination_id,
                },
                2 => RelayTarget::Iota(IotaNodeId::new(row.get::<_, String>(14)?).map_err(
                    |error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            14,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    },
                )?),
                _ => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Integer,
                        "invalid relay target kind".into(),
                    ));
                }
            };
            Ok(PendingRelay {
                id: row.get(0)?,
                target,
                frame: row.get(3)?,
                created_at: row.get(4)?,
                frame_id: u32::try_from(row.get::<_, i64>(5)?).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Integer,
                        "negative relay frame ID".into(),
                    )
                })?,
                type_map_version: row.get(6)?,
                relay_signer_id: row.get(7)?,
                relay_destination_user_id: row.get(8)?,
                signer_principal: row.get::<_, Option<i64>>(13)?.map(PrincipalHandle),
                destination_principal: row
                    .get::<_, Option<i64>>(12)?
                    .map(iota_identity::PrincipalHandle),
                relay_message_id: row.get(9)?,
                delivery_state: PendingRelayDeliveryState::from_db(row.get(10)?)?,
                last_error: row.get(11)?,
                attempt_count: row.get(16)?,
                last_attempt_at: row.get(17)?,
                next_attempt_at: row.get(18)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
}

/* Select only relays whose target and signer remain locally managed. This is
 * the delivery-authority check after user release, independent of row state. */
pub fn list_active(limit: i64) -> Result<Vec<PendingRelay>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare(
            "SELECT p.id, p.destination_id, p.target_kind, p.frame, p.created_at, p.frame_id, p.type_map_version, p.relay_signer_id, p.relay_destination_user_id, p.relay_message_id, p.delivery_state, p.last_error, p.destination_principal, p.signer_principal, p.destination_node_id, p.destination_authority_id, p.attempt_count, p.last_attempt_at, p.next_attempt_at FROM pending_relays p WHERE p.delivery_state = 'ready' AND p.next_attempt_at <= ?1 AND ((p.target_kind = 0 AND EXISTS (SELECT 1 FROM users u WHERE u.user_id = p.destination_id)) OR (p.target_kind IN (1, 2) AND p.signer_principal IS NOT NULL)) ORDER BY p.id LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![now_millis(), limit.clamp(1, 500)],
            pending_relay_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
}

pub fn list_without_relay_identity() -> Result<Vec<PendingRelay>, StorageError> {
    list_without_relay_identity_after(0, i64::MAX)
}

pub fn list_without_relay_identity_after(
    after_id: i64,
    limit: i64,
) -> Result<Vec<PendingRelay>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare("SELECT id, destination_id, target_kind, frame, created_at, frame_id, type_map_version, relay_signer_id, relay_destination_user_id, relay_message_id, delivery_state, last_error, destination_principal, signer_principal, destination_node_id, destination_authority_id, attempt_count, last_attempt_at, next_attempt_at FROM pending_relays WHERE id > ?1 AND (signer_principal IS NULL OR destination_principal IS NULL OR relay_message_id IS NULL) ORDER BY id LIMIT ?2")?;
        let rows = statement.query_map(
            params![after_id, limit.clamp(1, 500)],
            pending_relay_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
}

fn pending_relay_from_row(row: &rusqlite::Row<'_>) -> Result<PendingRelay, rusqlite::Error> {
    let destination_id = u64::try_from(row.get::<_, i64>(1)?)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 0))?;
    let target = match row.get::<_, i64>(2)? {
        0 => RelayTarget::User(destination_id),
        1 => RelayTarget::LegacyOmegaIota {
            omega: AuthorityId::new(row.get::<_, String>(15)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            iota_id: destination_id,
        },
        2 => RelayTarget::Iota(
            IotaNodeId::new(row.get::<_, String>(14)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        _ => return Err(rusqlite::Error::IntegralValueOutOfRange(2, 0)),
    };
    Ok(PendingRelay {
        id: row.get(0)?,
        target,
        frame: row.get(3)?,
        created_at: row.get(4)?,
        frame_id: u32::try_from(row.get::<_, i64>(5)?)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, 0))?,
        type_map_version: row.get(6)?,
        relay_signer_id: row.get(7)?,
        relay_destination_user_id: row.get(8)?,
        signer_principal: row.get::<_, Option<i64>>(13)?.map(PrincipalHandle),
        destination_principal: row
            .get::<_, Option<i64>>(12)?
            .map(iota_identity::PrincipalHandle),
        relay_message_id: row.get(9)?,
        delivery_state: PendingRelayDeliveryState::from_db(row.get(10)?)?,
        last_error: row.get(11)?,
        attempt_count: row.get(16)?,
        last_attempt_at: row.get(17)?,
        next_attempt_at: row.get(18)?,
    })
}

pub fn record_retry(id: i64, now: i64, error: &str) -> Result<(), StorageError> {
    db::with_db(|connection| {
        let attempts = connection.query_row(
            "SELECT attempt_count FROM pending_relays WHERE id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )?;
        let exponent = u32::try_from(attempts.clamp(0, 6)).unwrap_or(6);
        let delay = 5_000_i64.saturating_mul(1_i64 << exponent).min(300_000);
        connection.execute(
            "UPDATE pending_relays SET attempt_count = attempt_count + 1, last_attempt_at = ?2, next_attempt_at = ?3, last_error = ?4 WHERE id = ?1",
            params![id, now, now.saturating_add(delay), error],
        )?;
        Ok(())
    })
}

pub fn quarantine_for_frame(frame_id: u32, error: &str) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute(
            "UPDATE pending_relays SET delivery_state = 'quarantined', last_error = ?2 WHERE frame_id = ?1",
            params![i64::from(frame_id), error],
        )?;
        Ok(())
    })
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

pub fn mark_client_offline(destination_user_id: i64, frame_id: u32) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute("UPDATE pending_relays SET delivery_state = 'waiting_client', last_error = 'client_offline' WHERE target_kind = 0 AND destination_id = ?1 AND frame_id = ?2", params![destination_user_id, i64::from(frame_id)])?;
        Ok(())
    })
}

pub fn pause_client_deliveries(destination_user_id: i64) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE pending_relays SET delivery_state = 'waiting_client', last_error = 'awaiting_state_ack' WHERE target_kind = 0 AND destination_id = ?1 AND delivery_state = 'ready'",
            [destination_user_id],
        )?;
        Ok(())
    })
}

pub fn resume_client_deliveries(destination_user_id: i64) -> Result<usize, StorageError> {
    db::with_db(|connection| {
        Ok(connection.execute("UPDATE pending_relays SET delivery_state = 'ready', last_error = NULL WHERE target_kind = 0 AND destination_id = ?1 AND delivery_state = 'waiting_client'", [destination_user_id])?)
    })
}

pub fn resume_managed_client_deliveries() -> Result<usize, StorageError> {
    db::with_db(|connection| {
        Ok(connection.execute("UPDATE pending_relays SET delivery_state = 'ready', last_error = NULL WHERE target_kind = 0 AND delivery_state = 'waiting_client' AND EXISTS (SELECT 1 FROM users u WHERE u.user_id = pending_relays.destination_id)", [])?)
    })
}

pub fn quarantine_target_mismatch(id: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute("UPDATE pending_relays SET delivery_state = 'quarantined', last_error = 'target_recipient_mismatch' WHERE id = ?1", [id])?;
        Ok(())
    })
}

pub fn set_relay_identity(id: i64, relay: &RelayIdentity) -> Result<(), StorageError> {
    db::with_db(|connection| {
        let target_kind = connection.query_row(
            "SELECT target_kind FROM pending_relays WHERE id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )?;
        if target_kind == 0 {
            let destination_id = connection.query_row(
                "SELECT destination_id FROM pending_relays WHERE id = ?1",
                [id],
                |row| row.get::<_, i64>(0),
            )?;
            if Some(destination_id) != relay.legacy_recipient_id {
                connection.execute(
                    "UPDATE pending_relays SET delivery_state = 'quarantined', last_error = 'target_recipient_mismatch' WHERE id = ?1",
                    [id],
                )?;
                return Ok(());
            }
        }
        connection.execute("UPDATE pending_relays SET relay_signer_id = ?2, relay_destination_user_id = ?3, relay_message_id = ?4, signer_principal = ?5, destination_principal = ?6 WHERE id = ?1", params![id, relay.legacy_signer_id, relay.legacy_recipient_id, relay.message_id, relay.signer.0, relay.recipient.0])?;
        Ok(())
    })
}

pub fn has_unclassified_relays() -> Result<bool, StorageError> {
    db::with_db(|connection| {
        connection
            .query_row("SELECT EXISTS(SELECT 1 FROM pending_relays WHERE signer_principal IS NULL OR destination_principal IS NULL OR relay_message_id IS NULL)", [], |row| row.get(0))
            .map_err(Into::into)
    })
}

pub fn find_user_delivery_in_tx(
    tx: &Transaction<'_>,
    destination_id: i64,
    frame_id: u32,
) -> Result<Option<(i64, RelayIdentity)>, StorageError> {
    tx.query_row(
        "SELECT id, relay_signer_id, relay_destination_user_id, relay_message_id, signer_principal, destination_principal FROM pending_relays WHERE destination_id = ?1 AND target_kind = 0 AND frame_id = ?2",
        params![destination_id, i64::from(frame_id)],
        |row| {
            let signer_id = row.get::<_, Option<i64>>(1)?;
            let destination_user_id = row.get::<_, Option<i64>>(2)?;
            let message_id = row.get::<_, Option<String>>(3)?;
            match (signer_id, destination_user_id, message_id) {
                (Some(signer_id), Some(destination_user_id), Some(message_id)) => {
                    let signer = row.get::<_, Option<i64>>(4)?.ok_or(rusqlite::Error::InvalidQuery)?;
                    let recipient = row.get::<_, Option<i64>>(5)?.ok_or(rusqlite::Error::InvalidQuery)?;
                    Ok((row.get(0)?, RelayIdentity {
                        signer: PrincipalHandle(signer),
                        recipient: PrincipalHandle(recipient),
                        message_id,
                        legacy_signer_id: Some(signer_id),
                        legacy_recipient_id: Some(destination_user_id),
                    }))
                }
                _ => Err(rusqlite::Error::InvalidQuery),
            }
        },
    ).optional().map_err(|error| match error {
        rusqlite::Error::InvalidQuery => StorageError::PendingRelayOwnershipUnknown,
        error => StorageError::Db(error),
    })
}

pub fn acknowledge_in_tx(tx: &Transaction<'_>, id: i64) -> Result<(), StorageError> {
    tx.execute("DELETE FROM pending_relays WHERE id = ?1", [id])?;
    Ok(())
}

pub fn reject_outgoing_relay(
    destination_iota: u64,
    frame_id: u32,
    signer_principal: PrincipalHandle,
    relay_message_id: &str,
) -> Result<(), StorageError> {
    let destination_iota = i64::try_from(destination_iota)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_immediate_transaction(|tx| {
        tx.execute("DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = 1 AND frame_id = ?2", params![destination_iota, i64::from(frame_id)])?;
        tx.execute("UPDATE relay_inbox SET state = 'rejected', rejected_at = COALESCE(rejected_at, ?3) WHERE signer_principal = ?1 AND message_id = ?2", params![signer_principal.0, relay_message_id, crate::util::sync::now_millis()])?;
        Ok(())
    })
}

pub fn acknowledge(destination_id: u64, frame_id: u32) -> Result<bool, StorageError> {
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_db(|connection| {
        let changed = connection.execute(
            "DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = 0 AND frame_id = ?2",
            params![destination_id, i64::from(frame_id)],
        )?;
        Ok(changed == 1)
    })
}

pub fn acknowledge_iota(destination_id: u64, frame_id: u32) -> Result<bool, StorageError> {
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    db::with_db(|connection| {
        let changed = connection.execute(
            "DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = 1 AND frame_id = ?2",
            params![destination_id, i64::from(frame_id)],
        )?;
        Ok(changed == 1)
    })
}

pub fn remove_for_frame(target: RouteTarget, frame_id: u32) -> Result<bool, StorageError> {
    let destination_id = i64::try_from(target.id())
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;
    let target_kind = match target {
        RouteTarget::User(_) => 0_i64,
        RouteTarget::Iota(_) => 1_i64,
    };
    db::with_db(|connection| {
        let changed = connection.execute(
            "DELETE FROM pending_relays WHERE destination_id = ?1 AND target_kind = ?2 AND frame_id = ?3",
            params![destination_id, target_kind, i64::from(frame_id)],
        )?;
        Ok(changed == 1)
    })
}

pub fn delete(id: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute("DELETE FROM pending_relays WHERE id = ?1", params![id])?;
        Ok(())
    })
}
