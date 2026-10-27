//! Unaccepted first-epoch work. No proposal is an escrow or readable owner envelope.
use super::*;
use iota_identity::ResolvedPrincipal;

#[derive(Clone, Debug)]
pub struct Proposal {
    pub signer: PrincipalId,
    pub message_id: String,
    pub digest: Vec<u8>,
    pub prepared: Vec<u8>,
    pub state: String,
    pub generation: i64,
    pub claim_owner: Option<String>,
    pub last_error: Option<String>,
    pub type_map_version: String,
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<Proposal> {
    let signer: String = row.get(0)?;
    Ok(Proposal {
        signer: serde_json::from_str(&signer).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        message_id: row.get(1)?,
        digest: row.get(2)?,
        prepared: row.get(3)?,
        state: row.get(4)?,
        generation: row.get(5)?,
        claim_owner: row.get(6)?,
        last_error: row.get(7)?,
        type_map_version: row.get(8)?,
    })
}

const COLUMNS: &str = "signer_principal,message_id,operation_digest,verified_prepared_operation,state,attempt_generation,claim_owner,last_error,original_type_map_version";

pub fn get_on(
    connection: &Connection,
    signer: &PrincipalId,
    message_id: &str,
) -> Result<Option<Proposal>, StorageError> {
    Ok(connection.query_row(&format!("SELECT {COLUMNS} FROM initial_secret_proposals WHERE signer_principal=?1 AND message_id=?2"),
        params![principal_key(signer)?, message_id], decode).optional()?)
}

pub fn persist_in_tx(
    tx: &Transaction<'_>,
    escrow: &Escrow,
    prepared: &[u8],
    first: &ResolvedPrincipal,
    second: &ResolvedPrincipal,
) -> Result<Proposal, StorageError> {
    escrow.validate()?;
    if escrow.version != 1
        || first.principal != escrow.first
        || second.principal != escrow.second
        || prepared.is_empty()
        || prepared.len() > 64 * 1024 * 1024
        || escrow.original_frame.len() > 16 * 1024 * 1024
    {
        return Err(invalid());
    }
    check_fences(
        tx,
        &principal_key(&escrow.first)?,
        &principal_key(&escrow.second)?,
    )?;
    if let Some(existing) = get_on(tx, &escrow.signer, &escrow.message_id)? {
        // prepared contains an ingress timestamp and ephemeral session lease.
        // The signed operation digest, not a new preparation, identifies retries.
        if existing.digest != escrow.operation_digest
            || existing.type_map_version != escrow.original_type_map_version
        {
            return Err(StorageError::PendingRelayConflict);
        }
        return Ok(existing);
    }
    match initialization_state_on(
        tx,
        &escrow.first,
        &escrow.second,
        Some(&escrow.operation_digest),
    )? {
        InitializationState::Empty | InitializationState::ExactPendingProposal => {}
        _ => return Err(StorageError::ChatSecretConflict),
    }
    let home = |principal: &ResolvedPrincipal| match &principal.home {
        iota_identity::PrincipalHome::Iota(node) => Ok(format!("iota:{}", node.as_str())),
        _ => Err(StorageError::MessageUnauthorized),
    };
    let unresolved: i64 = tx.query_row("SELECT count(*) FROM initial_secret_proposals WHERE state IN ('awaiting_peer_proof','verifying')", [], |row| row.get(0))?;
    if unresolved >= 1024 {
        return Err(StorageError::Other(
            "initial secret proposal capacity reached".into(),
        ));
    }
    let now = sync::now_millis();
    tx.execute("INSERT INTO initial_secret_proposals(signer_principal,message_id,first_principal,second_principal,version,operation_digest,verified_prepared_operation,original_type_map_version,first_revision,second_revision,first_home,second_home,state,next_at,created_at) VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10,?11,'awaiting_peer_proof',?12,?12)",
        params![principal_key(&escrow.signer)?,escrow.message_id,principal_key(&escrow.first)?,principal_key(&escrow.second)?,escrow.operation_digest,prepared,escrow.original_type_map_version,first.descriptor_revision,second.descriptor_revision,home(first)?,home(second)?,now])?;
    get_on(tx, &escrow.signer, &escrow.message_id)?.ok_or(StorageError::MissingRelayDependency)
}

pub fn due(limit: usize) -> Result<Vec<Proposal>, StorageError> {
    db::with_db(|connection| {
        let mut statement = connection.prepare(&format!("SELECT {COLUMNS} FROM initial_secret_proposals WHERE (state='awaiting_peer_proof' AND next_at<=?1) OR (state='verifying' AND claim_deadline<=?1) ORDER BY next_at LIMIT ?2"))?;
        Ok(statement
            .query_map(
                params![sync::now_millis(), limit.clamp(1, 32) as i64],
                decode,
            )?
            .collect::<Result<Vec<_>, _>>()?)
    })
}

pub fn claim(observed: &Proposal) -> Result<Option<Proposal>, StorageError> {
    db::with_immediate_transaction(|tx| {
        let now = sync::now_millis();
        let owner = uuid::Uuid::new_v4().to_string();
        let changed = tx.execute("UPDATE initial_secret_proposals SET state='verifying',attempt_generation=attempt_generation+1,claim_owner=?4,claim_deadline=?5 WHERE signer_principal=?1 AND message_id=?2 AND attempt_generation=?3 AND attempt_generation<9223372036854775807 AND ((state='awaiting_peer_proof' AND next_at<=?6) OR (state='verifying' AND claim_deadline<=?6))",
            params![principal_key(&observed.signer)?,observed.message_id,observed.generation,owner,now.saturating_add(30_000),now])?;
        if changed == 0 {
            return Ok(None);
        }
        get_on(tx, &observed.signer, &observed.message_id)
    })
}

pub fn verify_claim_in_tx(tx: &Transaction<'_>, proposal: &Proposal) -> Result<(), StorageError> {
    let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM initial_secret_proposals WHERE signer_principal=?1 AND message_id=?2 AND operation_digest=?3 AND verified_prepared_operation=?4 AND state='verifying' AND attempt_generation=?5 AND claim_owner=?6 AND claim_deadline>?7)",
        params![principal_key(&proposal.signer)?,proposal.message_id,proposal.digest,proposal.prepared,proposal.generation,proposal.claim_owner,sync::now_millis()], |row| row.get(0))?;
    if valid {
        Ok(())
    } else {
        Err(StorageError::StaleRelayClaim)
    }
}

pub fn verify_identity_in_tx(
    tx: &Transaction<'_>,
    proposal: &Proposal,
) -> Result<(), StorageError> {
    verify_claim_in_tx(tx, proposal)?;
    let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM initial_secret_proposals q JOIN principals a ON a.authority_id=json_extract(q.first_principal,'$.authority') AND a.remote_user_id=json_extract(q.first_principal,'$.user_id') JOIN principals b ON b.authority_id=json_extract(q.second_principal,'$.authority') AND b.remote_user_id=json_extract(q.second_principal,'$.user_id') WHERE q.signer_principal=?1 AND q.message_id=?2 AND a.descriptor_revision=q.first_revision AND b.descriptor_revision=q.second_revision AND a.home=q.first_home AND b.home=q.second_home AND a.retired_at IS NULL AND b.retired_at IS NULL AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences WHERE principal IN(q.first_principal,q.second_principal)))",
        params![principal_key(&proposal.signer)?,proposal.message_id], |row| row.get(0))?;
    if valid {
        Ok(())
    } else {
        Err(StorageError::MessageUnauthorized)
    }
}

pub fn finish_in_tx(
    tx: &Transaction<'_>,
    proposal: &Proposal,
    state: &str,
    error: Option<&str>,
) -> Result<(), StorageError> {
    verify_claim_in_tx(tx, proposal)?;
    let delay = 1_000i64.saturating_mul(1i64 << proposal.generation.clamp(0, 6));
    tx.execute("UPDATE initial_secret_proposals SET state=?3,last_error=?4,next_at=?5,claim_owner=NULL,claim_deadline=NULL WHERE signer_principal=?1 AND message_id=?2",
        params![principal_key(&proposal.signer)?,proposal.message_id,state,error,sync::now_millis().saturating_add(delay)])?;
    Ok(())
}
