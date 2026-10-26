CREATE TABLE IF NOT EXISTS chat_secret_escrows (
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    evidence BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','committed')),
    signer TEXT NOT NULL,
    message_id TEXT NOT NULL,
    PRIMARY KEY(first_principal,second_principal,version)
);
CREATE TABLE IF NOT EXISTS chat_secret_epochs (
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest)=32),
    state TEXT NOT NULL CHECK(state IN ('pending','committed')),
    PRIMARY KEY(first_principal,second_principal,version)
);
CREATE TRIGGER IF NOT EXISTS chat_secret_epochs_immutable BEFORE UPDATE ON chat_secret_epochs
WHEN NEW.first_principal != OLD.first_principal OR NEW.second_principal != OLD.second_principal
 OR NEW.version != OLD.version OR NEW.evidence_digest != OLD.evidence_digest OR OLD.state='committed'
BEGIN SELECT RAISE(ABORT, 'chat secret epoch is immutable'); END;
CREATE TRIGGER IF NOT EXISTS chat_secret_escrows_immutable BEFORE UPDATE ON chat_secret_escrows
WHEN NEW.first_principal != OLD.first_principal OR NEW.second_principal != OLD.second_principal
 OR NEW.version != OLD.version OR NEW.evidence != OLD.evidence OR NEW.signer != OLD.signer
 OR NEW.message_id != OLD.message_id OR OLD.state = 'committed'
BEGIN SELECT RAISE(ABORT, 'chat secret evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS chat_secret_escrows_accepted_delete BEFORE DELETE ON chat_secret_escrows
WHEN OLD.state='committed' AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences WHERE principal IN (OLD.first_principal,OLD.second_principal))
BEGIN SELECT RAISE(ABORT, 'accepted chat secret evidence requires an erasure fence'); END;
CREATE TRIGGER IF NOT EXISTS chat_secret_epochs_accepted_delete BEFORE DELETE ON chat_secret_epochs
WHEN OLD.state='committed' AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences WHERE principal IN (OLD.first_principal,OLD.second_principal))
BEGIN SELECT RAISE(ABORT, 'accepted chat secret epochs require an erasure fence'); END;
CREATE UNIQUE INDEX IF NOT EXISTS chat_secret_escrows_operation ON chat_secret_escrows(signer,message_id);
CREATE TABLE IF NOT EXISTS chat_secret_erasure_fences (
    principal TEXT PRIMARY KEY NOT NULL,
    erased_at INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS chat_secret_erasure_fences_update BEFORE UPDATE ON chat_secret_erasure_fences
BEGIN SELECT RAISE(ABORT, 'chat secret erasure is permanent'); END;
CREATE TRIGGER IF NOT EXISTS chat_secret_erasure_fences_delete BEFORE DELETE ON chat_secret_erasure_fences
BEGIN SELECT RAISE(ABORT, 'chat secret erasure is permanent'); END;
CREATE TABLE IF NOT EXISTS chat_secret_rejected_proposals (
    signer TEXT NOT NULL,
    message_id TEXT NOT NULL,
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    operation_digest BLOB NOT NULL CHECK(length(operation_digest)=32),
    rejected_at INTEGER NOT NULL,
    PRIMARY KEY(signer,message_id)
);
CREATE TABLE IF NOT EXISTS chat_secret_recovery_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    storage_owner INTEGER NOT NULL,
    owner_principal TEXT NOT NULL,
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 0),
    nonce BLOB NOT NULL UNIQUE CHECK(length(nonce) = 32),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_at INTEGER NOT NULL,
    last_error TEXT,
    done_at INTEGER,
    UNIQUE(storage_owner,owner_principal,first_principal,second_principal,version)
);
CREATE TABLE IF NOT EXISTS chat_secret_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    storage_owner INTEGER NOT NULL,
    owner_principal TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    secret_id TEXT NOT NULL,
    peer_principal TEXT NOT NULL,
    wrapping_chat_id TEXT NOT NULL,
    wrapping_secret_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    dispatched_at INTEGER,
    UNIQUE(storage_owner,owner_principal,chat_id,version)
);
CREATE INDEX IF NOT EXISTS chat_secret_outbox_owner_cursor ON chat_secret_outbox(storage_owner,owner_principal,id);
CREATE INDEX IF NOT EXISTS chat_secret_recovery_jobs_due ON chat_secret_recovery_jobs(done_at,next_at,id);
CREATE TABLE IF NOT EXISTS chat_secret_changes (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    sequence INTEGER NOT NULL
);
INSERT OR IGNORE INTO chat_secret_changes VALUES(1,0);
CREATE TRIGGER IF NOT EXISTS chat_secret_outbox_insert AFTER INSERT ON chat_secret_outbox
BEGIN UPDATE chat_secret_changes SET sequence=sequence+1 WHERE singleton=1; END;
