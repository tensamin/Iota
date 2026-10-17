use crate::storage_error::StorageError;
use crate::util::db;
use rusqlite::params;

pub const RELAY_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_RELAY_FUTURE_SKEW_MILLIS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    Received,
    Processing,
    Applied,
    Queued,
    Delivered,
    Rejected,
}

impl TryFrom<&str> for RelayState {
    type Error = StorageError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "received" => Ok(Self::Received),
            "processing" => Ok(Self::Processing),
            "applied" => Ok(Self::Applied),
            "queued" => Ok(Self::Queued),
            "delivered" => Ok(Self::Delivered),
            "rejected" => Ok(Self::Rejected),
            value => Err(StorageError::UnknownRelayState(value.to_owned())),
        }
    }
}

impl RelayState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Processing => "processing",
            Self::Applied => "applied",
            Self::Queued => "queued",
            Self::Delivered => "delivered",
            Self::Rejected => "rejected",
        }
    }
}

/// Issued locally by storage. Every application write must verify this claim
/// in the same immediate transaction as its mutation and completion record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingClaim {
    pub signer: iota_identity::PrincipalHandle,
    pub message_id: String,
    pub generation: i64,
    pub owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireResult {
    Claimed(ProcessingClaim),
    Busy,
    Applied,
    Queued,
    Delivered,
    Rejected,
    Collision,
}

pub(crate) fn migrate(connection: &rusqlite::Connection) -> Result<(), StorageError> {
    let tx = connection.unchecked_transaction()?;
    // Some migration tests start with a partial historical schema.
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'relay_inbox')",
        [],
        |row| row.get(0),
    )?;
    if exists {
        tx.execute_batch(
            "CREATE TABLE relay_inbox_v52 (
                signer_principal INTEGER NOT NULL REFERENCES principals(principal_pk),
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                destination_id INTEGER NOT NULL,
                frame BLOB NOT NULL,
                type_map_version TEXT NOT NULL,
                frame_id INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('received', 'processing', 'applied', 'queued', 'delivered', 'rejected')),
                accepted_at INTEGER,
                applied_at INTEGER,
                queued_at INTEGER,
                downstream_acked_at INTEGER,
                rejected_at INTEGER,
                processing_generation INTEGER NOT NULL DEFAULT 0 CHECK (processing_generation >= 0),
                processing_owner TEXT,
                processing_deadline INTEGER,
                CHECK ((state = 'processing' AND processing_owner IS NOT NULL AND processing_deadline IS NOT NULL)
                    OR (state <> 'processing' AND processing_owner IS NULL AND processing_deadline IS NULL)),
                PRIMARY KEY (signer_principal, message_id)
            );
            INSERT INTO relay_inbox_v52 (
                signer_principal, signer_id, message_id, created_at, destination_id,
                frame, type_map_version, frame_id, state, accepted_at, applied_at,
                queued_at, downstream_acked_at, rejected_at
            ) SELECT signer_principal, signer_id, message_id, created_at, destination_id,
                frame, type_map_version, frame_id, state, accepted_at, applied_at,
                queued_at, downstream_acked_at, rejected_at FROM relay_inbox;
            DROP TABLE relay_inbox;
            ALTER TABLE relay_inbox_v52 RENAME TO relay_inbox;
            CREATE INDEX idx_relay_inbox_state ON relay_inbox (state, created_at);
            CREATE INDEX idx_relay_inbox_processing ON relay_inbox (processing_deadline)
                WHERE state = 'processing';",
        )?;
    }
    tx.pragma_update(None, "user_version", 52)?;
    tx.commit()?;
    Ok(())
}

pub fn acquire(
    request: RelayReservationRequest<'_>,
    deadline: i64,
) -> Result<AcquireResult, StorageError> {
    db::with_immediate_transaction(|tx| acquire_in_tx(tx, request, deadline))
}

pub fn acquire_hosted_relay(
    lease: &iota_identity::HostedAuthorizationLease,
    request: RelayReservationRequest<'_>,
    deadline: i64,
) -> Result<AcquireResult, StorageError> {
    db::with_immediate_transaction(|tx| acquire_hosted_relay_in_tx(tx, lease, request, deadline))
}

pub fn acquire_hosted_relay_in_tx(
    tx: &rusqlite::Transaction<'_>,
    lease: &iota_identity::HostedAuthorizationLease,
    request: RelayReservationRequest<'_>,
    deadline: i64,
) -> Result<AcquireResult, StorageError> {
    crate::hosted_auth::verify_in_tx(tx, lease)?;
    if request.signer_principal != lease.identity.principal {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    acquire_in_tx(tx, request, deadline)
}

pub fn acquire_in_tx(
    tx: &rusqlite::Transaction<'_>,
    request: RelayReservationRequest<'_>,
    deadline: i64,
) -> Result<AcquireResult, StorageError> {
    let signer = request.signer_principal;
    let message_id = request.message_id.to_owned();
    match reserve_in_tx(tx, request)? {
        RelayReservation::Existing {
            frame_matches: false,
            ..
        } => return Ok(AcquireResult::Collision),
        RelayReservation::Existing { state, .. } => match state {
            RelayState::Received => {}
            RelayState::Processing => return Ok(AcquireResult::Busy),
            RelayState::Applied => return Ok(AcquireResult::Applied),
            RelayState::Queued => return Ok(AcquireResult::Queued),
            RelayState::Delivered => return Ok(AcquireResult::Delivered),
            RelayState::Rejected => return Ok(AcquireResult::Rejected),
        },
        RelayReservation::New => {}
    }
    super::relay_work::fault_point("after_inbox_reservation", &message_id);
    let generation: i64 = tx.query_row(
        "SELECT processing_generation FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2",
        params![signer.0, message_id],
        |row| row.get(0),
    )?;
    let next_generation = generation
        .checked_add(1)
        .ok_or(StorageError::RelayGenerationExhausted)?;
    let owner: String = tx.query_row("SELECT lower(hex(randomblob(32)))", [], |row| row.get(0))?;
    let changed = tx.execute(
        "UPDATE relay_inbox SET state = 'processing', processing_generation = ?3,
            processing_owner = ?4, processing_deadline = ?5
         WHERE signer_principal = ?1 AND message_id = ?2 AND state = 'received'
            AND processing_generation = ?6",
        params![
            signer.0,
            message_id,
            next_generation,
            owner,
            deadline,
            generation
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::StaleRelayClaim);
    }
    Ok(AcquireResult::Claimed(ProcessingClaim {
        signer,
        message_id,
        generation: next_generation,
        owner,
    }))
}

pub fn verify_claim_in_tx(
    tx: &rusqlite::Transaction<'_>,
    claim: &ProcessingClaim,
) -> Result<(), StorageError> {
    let owned: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_inbox WHERE signer_principal = ?1
            AND message_id = ?2 AND state = 'processing'
            AND processing_generation = ?3 AND processing_owner = ?4)",
        params![
            claim.signer.0,
            claim.message_id,
            claim.generation,
            claim.owner
        ],
        |row| row.get(0),
    )?;
    if !owned {
        return Err(StorageError::StaleRelayClaim);
    }
    Ok(())
}

/// Call after applying the operation in this transaction, never after a
/// separately committed application write. Expiry does not authorize takeover.
pub fn complete_application_in_tx(
    tx: &rusqlite::Transaction<'_>,
    claim: &ProcessingClaim,
) -> Result<(), StorageError> {
    let changed = tx.execute(
        "UPDATE relay_inbox SET state = 'applied', applied_at = COALESCE(applied_at, ?5),
            processing_owner = NULL, processing_deadline = NULL
         WHERE signer_principal = ?1 AND message_id = ?2 AND state = 'processing'
            AND processing_generation = ?3 AND processing_owner = ?4",
        params![
            claim.signer.0,
            claim.message_id,
            claim.generation,
            claim.owner,
            crate::util::sync::now_millis()
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::StaleRelayClaim);
    }
    super::relay_work::fault_point("after_application_completion", &claim.message_id);
    Ok(())
}

pub fn reject_unapplied_in_tx(
    tx: &rusqlite::Transaction<'_>,
    claim: &ProcessingClaim,
) -> Result<(), StorageError> {
    let changed = tx.execute(
        "UPDATE relay_inbox SET state = 'rejected', rejected_at = COALESCE(rejected_at, ?5),
            processing_owner = NULL, processing_deadline = NULL
         WHERE signer_principal = ?1 AND message_id = ?2 AND state = 'processing'
            AND applied_at IS NULL AND processing_generation = ?3 AND processing_owner = ?4",
        params![
            claim.signer.0,
            claim.message_id,
            claim.generation,
            claim.owner,
            crate::util::sync::now_millis()
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::StaleRelayClaim);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReservation {
    New,
    Existing {
        state: RelayState,
        frame_matches: bool,
    },
}

pub struct RelayReservationRequest<'a> {
    pub signer_principal: iota_identity::PrincipalHandle,
    pub signer_id: u64,
    pub message_id: &'a str,
    pub created_at: u64,
    pub accepted_at: i64,
    pub destination_id: u64,
    pub frame: &'a [u8],
    pub frame_id: u32,
    pub type_map_version: &'a str,
}

pub fn reserve_in_tx(
    connection: &rusqlite::Transaction<'_>,
    request: RelayReservationRequest<'_>,
) -> Result<RelayReservation, StorageError> {
    let RelayReservationRequest {
        signer_principal,
        signer_id,
        message_id,
        created_at,
        accepted_at,
        destination_id,
        frame,
        frame_id,
        type_map_version,
    } = request;
    let signer_id = i64::try_from(signer_id)
        .map_err(|_| StorageError::Other("relay signer ID exceeds SQLite range".into()))?;
    let created_at = i64::try_from(created_at)
        .map_err(|_| StorageError::Other("relay creation time exceeds SQLite range".into()))?;
    let destination_id = i64::try_from(destination_id)
        .map_err(|_| StorageError::Other("relay destination ID exceeds SQLite range".into()))?;

    let inserted = connection.execute(
            "INSERT OR IGNORE INTO relay_inbox (signer_principal, signer_id, message_id, created_at, accepted_at, destination_id, frame, frame_id, type_map_version, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'received')",
            params![
                signer_principal.0,
                signer_id,
                message_id,
                created_at,
                accepted_at,
                destination_id,
                frame,
                i64::from(frame_id),
                type_map_version
            ],
        )?;
    if inserted == 1 {
        return Ok(RelayReservation::New);
    }

    let (state, existing_destination_id, existing_frame, existing_type_map_version, existing_created_at):
            (String, i64, Vec<u8>, String, i64) = connection.query_row(
            "SELECT state, destination_id, frame, type_map_version, created_at FROM relay_inbox WHERE signer_principal = ?1 AND message_id = ?2",
            params![signer_principal.0, message_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    Ok(RelayReservation::Existing {
        state: RelayState::try_from(state.as_str())?,
        frame_matches: existing_destination_id == destination_id
            && existing_frame == frame
            && existing_type_map_version == type_map_version
            && existing_created_at == created_at,
    })
}

pub fn mark_delivered_in_tx(
    tx: &rusqlite::Transaction<'_>,
    signer: iota_identity::PrincipalHandle,
    message_id: &str,
) -> Result<(), StorageError> {
    let changed = tx.execute(
        "UPDATE relay_inbox SET state = 'delivered', downstream_acked_at = COALESCE(downstream_acked_at, ?3)
         WHERE signer_principal = ?1 AND message_id = ?2 AND state IN ('applied', 'queued')",
        params![signer.0, message_id, crate::util::sync::now_millis()],
    )?;
    if changed != 1 {
        return Err(StorageError::InvalidRelayTransition);
    }
    Ok(())
}

pub fn mark_queued(
    signer_principal: iota_identity::PrincipalHandle,
    message_id: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| mark_queued_in_tx(tx, signer_principal, message_id))
}

pub fn mark_queued_in_tx(
    tx: &rusqlite::Transaction<'_>,
    signer_principal: iota_identity::PrincipalHandle,
    message_id: &str,
) -> Result<(), StorageError> {
    let changed = tx.execute(
        "UPDATE relay_inbox SET state = 'queued', queued_at = COALESCE(queued_at, ?3)
          WHERE signer_principal = ?1 AND message_id = ?2 AND state = 'applied'",
        params![
            signer_principal.0,
            message_id,
            crate::util::sync::now_millis()
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::InvalidRelayTransition);
    }
    Ok(())
}

pub fn mark_downstream_acked(
    signer_principal: iota_identity::PrincipalHandle,
    message_id: &str,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| mark_delivered_in_tx(tx, signer_principal, message_id))
}

pub fn prune_completed(before_terminal_at: i64) -> Result<(), StorageError> {
    db::with_db(|connection| {
        connection.execute(
            "DELETE FROM relay_inbox WHERE COALESCE(downstream_acked_at, rejected_at) < ?1 AND state IN ('delivered', 'rejected')",
            params![before_terminal_at],
        )?;
        connection.execute(
            "DELETE FROM relay_replay WHERE NOT EXISTS (SELECT 1 FROM relay_inbox WHERE relay_inbox.signer_principal = relay_replay.signer_principal AND relay_inbox.message_id = relay_replay.message_id)",
            [],
        )?;
        Ok(())
    })
}

pub fn accept(
    signer_principal: iota_identity::PrincipalHandle,
    signer_id: u64,
    message_id: &str,
    created_at: u64,
) -> Result<bool, StorageError> {
    let signer_id = i64::try_from(signer_id)
        .map_err(|_| StorageError::Other("relay signer ID exceeds SQLite range".into()))?;
    let created_at = i64::try_from(created_at)
        .map_err(|_| StorageError::Other("relay creation time exceeds SQLite range".into()))?;

    db::with_db(|connection| {
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_principal, signer_id, message_id, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![signer_principal.0, signer_id, message_id, created_at],
        )?;
        Ok(inserted == 1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};

    fn initialize(connection: &Connection) -> Result<(), StorageError> {
        connection.execute_batch(
            "CREATE TABLE principals (principal_pk INTEGER PRIMARY KEY);
             INSERT INTO principals VALUES (70), (71);
             CREATE TABLE relay_inbox (
                signer_principal INTEGER NOT NULL, signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL, created_at INTEGER NOT NULL,
                destination_id INTEGER NOT NULL, frame BLOB NOT NULL,
                type_map_version TEXT NOT NULL, frame_id INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('received', 'applied', 'queued', 'delivered', 'rejected')),
                accepted_at INTEGER, applied_at INTEGER, queued_at INTEGER,
                downstream_acked_at INTEGER, rejected_at INTEGER,
                PRIMARY KEY (signer_principal, message_id)
             );",
        )?;
        migrate(connection)
    }

    fn request(frame: &[u8]) -> RelayReservationRequest<'_> {
        RelayReservationRequest {
            signer_principal: iota_identity::PrincipalHandle(70),
            signer_id: 7,
            message_id: "message",
            created_at: 10,
            accepted_at: 20,
            destination_id: 8,
            frame,
            frame_id: 42,
            type_map_version: "1.0",
        }
    }

    #[test]
    fn concurrent_acquisition_issues_one_claim() -> Result<(), StorageError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("relay.sqlite3");
        initialize(&Connection::open(&path)?)?;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || -> Result<AcquireResult, StorageError> {
                    let mut connection = Connection::open(path)?;
                    connection.busy_timeout(std::time::Duration::from_secs(5))?;
                    barrier.wait();
                    let tx = connection
                        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                    let result = acquire_in_tx(&tx, request(b"frame"), 100)?;
                    tx.commit()?;
                    Ok(result)
                })
            })
            .collect();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, AcquireResult::Claimed(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == AcquireResult::Busy)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn stale_claim_cannot_commit_a_mutation() -> Result<(), StorageError> {
        let mut connection = Connection::open_in_memory()?;
        initialize(&connection)?;
        connection.execute_batch("CREATE TABLE effects (id INTEGER PRIMARY KEY);")?;
        let tx = connection.transaction()?;
        let AcquireResult::Claimed(claim) = acquire_in_tx(&tx, request(b"frame"), 100)? else {
            panic!("first worker did not acquire claim");
        };
        tx.commit()?;
        // Model a recovery generation at the storage boundary. Production
        // recovery must not enable takeover until all mutations use this fence.
        connection.execute("UPDATE relay_inbox SET processing_generation = processing_generation + 1, processing_owner = 'recovery'", [])?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        assert!(matches!(
            verify_claim_in_tx(&tx, &claim),
            Err(StorageError::StaleRelayClaim)
        ));
        assert!(matches!(
            complete_application_in_tx(&tx, &claim),
            Err(StorageError::StaleRelayClaim)
        ));
        assert!(matches!(
            reject_unapplied_in_tx(&tx, &claim),
            Err(StorageError::StaleRelayClaim)
        ));
        tx.rollback()?;
        assert_eq!(
            connection.query_row("SELECT count(*) FROM effects", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        let current = ProcessingClaim {
            generation: claim.generation + 1,
            owner: "recovery".into(),
            ..claim
        };
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        verify_claim_in_tx(&tx, &current)?;
        tx.execute("INSERT INTO effects VALUES (1)", [])?;
        complete_application_in_tx(&tx, &current)?;
        tx.commit()?;
        let tx = connection.transaction()?;
        assert_eq!(
            acquire_in_tx(&tx, request(b"frame"), 200)?,
            AcquireResult::Applied
        );
        assert!(matches!(
            reject_unapplied_in_tx(&tx, &current),
            Err(StorageError::StaleRelayClaim)
        ));
        assert_eq!(
            tx.query_row("SELECT count(*) FROM effects", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        Ok(())
    }

    #[test]
    fn expired_claim_stays_busy_and_collisions_do_not_change_it() -> Result<(), StorageError> {
        let mut connection = Connection::open_in_memory()?;
        initialize(&connection)?;
        let tx = connection.transaction()?;
        let AcquireResult::Claimed(claim) = acquire_in_tx(&tx, request(b"frame"), 1)? else {
            panic!("missing claim");
        };
        assert_eq!(
            acquire_in_tx(&tx, request(b"frame"), i64::MAX)?,
            AcquireResult::Busy
        );
        assert_eq!(
            acquire_in_tx(&tx, request(b"different"), i64::MAX)?,
            AcquireResult::Collision
        );
        verify_claim_in_tx(&tx, &claim)?;
        Ok(())
    }

    #[test]
    fn failed_completion_rolls_back_the_application_effect() -> Result<(), StorageError> {
        let mut connection = Connection::open_in_memory()?;
        initialize(&connection)?;
        connection.execute_batch("CREATE TABLE effects (id INTEGER PRIMARY KEY);")?;
        let tx = connection.transaction()?;
        let AcquireResult::Claimed(mut claim) = acquire_in_tx(&tx, request(b"frame"), 100)? else {
            panic!("missing claim");
        };
        tx.commit()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        verify_claim_in_tx(&tx, &claim)?;
        tx.execute("INSERT INTO effects VALUES (1)", [])?;
        claim.owner = "obsolete".into();
        assert!(matches!(
            complete_application_in_tx(&tx, &claim),
            Err(StorageError::StaleRelayClaim)
        ));
        tx.rollback()?;
        assert_eq!(
            connection.query_row("SELECT count(*) FROM effects", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        Ok(())
    }

    #[test]
    fn rejection_and_delivery_are_terminal() -> Result<(), StorageError> {
        for rejected in [false, true] {
            let mut connection = Connection::open_in_memory()?;
            initialize(&connection)?;
            let tx = connection.transaction()?;
            let AcquireResult::Claimed(claim) = acquire_in_tx(&tx, request(b"frame"), 100)? else {
                panic!("missing claim");
            };
            if rejected {
                reject_unapplied_in_tx(&tx, &claim)?;
            } else {
                complete_application_in_tx(&tx, &claim)?;
                mark_queued_in_tx(&tx, claim.signer, &claim.message_id)?;
                mark_delivered_in_tx(&tx, claim.signer, &claim.message_id)?;
            }
            assert!(matches!(
                complete_application_in_tx(&tx, &claim),
                Err(StorageError::StaleRelayClaim)
            ));
            assert!(matches!(
                mark_queued_in_tx(&tx, claim.signer, &claim.message_id),
                Err(StorageError::InvalidRelayTransition)
            ));
            assert!(matches!(
                mark_delivered_in_tx(&tx, claim.signer, &claim.message_id),
                Err(StorageError::InvalidRelayTransition)
            ));
            assert_eq!(
                acquire_in_tx(&tx, request(b"frame"), 200)?,
                if rejected {
                    AcquireResult::Rejected
                } else {
                    AcquireResult::Delivered
                }
            );
        }
        assert!(matches!(
            RelayState::try_from("unknown"),
            Err(StorageError::UnknownRelayState(_))
        ));
        Ok(())
    }

    #[test]
    fn replay_identity_uses_principal_and_message_id() -> Result<(), rusqlite::Error> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE relay_replay (signer_principal INTEGER NOT NULL, signer_id INTEGER NOT NULL, message_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (signer_principal, message_id));",
        )?;

        let first = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_principal, signer_id, message_id, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![70_i64, 7_i64, "message", 1_i64],
        )?;
        let duplicate = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_principal, signer_id, message_id, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![70_i64, 7_i64, "message", 2_i64],
        )?;
        let other_authority_same_numeric_signer = connection.execute(
            "INSERT OR IGNORE INTO relay_replay (signer_principal, signer_id, message_id, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![71_i64, 7_i64, "message", 2_i64],
        )?;

        assert_eq!(
            (first, duplicate, other_authority_same_numeric_signer),
            (1, 0, 1)
        );
        Ok(())
    }
}
