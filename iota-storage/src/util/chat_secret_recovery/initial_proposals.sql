CREATE TABLE IF NOT EXISTS initial_secret_proposals (
    signer_principal TEXT NOT NULL,
    message_id TEXT NOT NULL CHECK(length(message_id) BETWEEN 1 AND 256),
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version=1),
    operation_digest BLOB NOT NULL UNIQUE CHECK(length(operation_digest)=32),
    verified_prepared_operation BLOB NOT NULL CHECK(length(verified_prepared_operation) BETWEEN 1 AND 67108864),
    original_type_map_version TEXT NOT NULL,
    first_revision INTEGER NOT NULL,
    second_revision INTEGER NOT NULL,
    first_home TEXT NOT NULL,
    second_home TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('awaiting_peer_proof','verifying','committed','rejected')),
    attempt_generation INTEGER NOT NULL DEFAULT 0 CHECK(attempt_generation>=0),
    claim_owner TEXT,
    claim_deadline INTEGER,
    next_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_error TEXT,
    PRIMARY KEY(signer_principal,message_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS initial_secret_proposals_pair ON initial_secret_proposals(first_principal,second_principal,version)
    WHERE state IN ('awaiting_peer_proof','verifying');
CREATE INDEX IF NOT EXISTS initial_secret_proposals_due ON initial_secret_proposals(state,next_at);
CREATE TRIGGER IF NOT EXISTS initial_secret_proposals_immutable BEFORE UPDATE ON initial_secret_proposals
WHEN NEW.signer_principal!=OLD.signer_principal OR NEW.message_id!=OLD.message_id
    OR NEW.first_principal!=OLD.first_principal OR NEW.second_principal!=OLD.second_principal
    OR NEW.version!=OLD.version OR NEW.operation_digest!=OLD.operation_digest
    OR NEW.verified_prepared_operation!=OLD.verified_prepared_operation
    OR NEW.original_type_map_version!=OLD.original_type_map_version
    OR NEW.first_revision!=OLD.first_revision OR NEW.second_revision!=OLD.second_revision
    OR NEW.first_home!=OLD.first_home OR NEW.second_home!=OLD.second_home
    OR NEW.created_at!=OLD.created_at OR OLD.state IN ('committed','rejected')
BEGIN SELECT RAISE(ABORT,'initial secret proposal is immutable'); END;
CREATE TRIGGER IF NOT EXISTS initial_secret_proposals_erasure AFTER INSERT ON chat_secret_erasure_fences
BEGIN DELETE FROM initial_secret_proposals WHERE first_principal=NEW.principal OR second_principal=NEW.principal; END;
