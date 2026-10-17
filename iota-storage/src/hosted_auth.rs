use crate::{storage_error::StorageError, util::db};
use iota_identity::{
    HostedAuthorizationLease, LocalUserId, PrincipalHandle, ValidatedHostedIdentity,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

static CHANGES: once_cell::sync::Lazy<tokio::sync::watch::Sender<u64>> =
    once_cell::sync::Lazy::new(|| tokio::sync::watch::channel(0).0);
static REVOKED_CONNECTIONS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = once_cell::sync::Lazy::new(Default::default);

pub fn changes() -> tokio::sync::watch::Receiver<u64> {
    CHANGES.subscribe()
}

pub(crate) fn notify_change() {
    CHANGES.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedAuthState {
    pub local_user: LocalUserId,
    pub generation: i64,
    pub enabled: bool,
}

/// Triggers cover external database writers as well as application lifecycle calls.
pub(crate) fn migrate(connection: &Connection) -> Result<(), StorageError> {
    let tx = connection.unchecked_transaction()?;
    let exists = |table: &str| {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get::<_, bool>(0),
        )
    };
    tx.execute_batch(
        "CREATE TABLE hosted_auth_state (
            local_user_id INTEGER PRIMARY KEY,
            generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation > 0),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
        );
        CREATE TABLE hosted_connection_authorizations (
            connection_id TEXT PRIMARY KEY,
            server_instance TEXT NOT NULL,
            local_user_id INTEGER NOT NULL,
            principal_handle INTEGER NOT NULL,
            auth_generation INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
        );
        CREATE INDEX hosted_authorizations_owner
        ON hosted_connection_authorizations(local_user_id, revoked);
        CREATE TABLE hosted_auth_changes (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), sequence INTEGER NOT NULL);
        INSERT INTO hosted_auth_changes VALUES (1, 0);
        CREATE TRIGGER hosted_auth_monotonic BEFORE UPDATE ON hosted_auth_state
        BEGIN
            SELECT CASE WHEN OLD.generation = 9223372036854775807
                THEN RAISE(ABORT, 'hosted auth generation exhausted') END;
            SELECT CASE WHEN NEW.generation <= OLD.generation
                THEN RAISE(ABORT, 'hosted auth generation must increase') END;
        END;
        CREATE TRIGGER hosted_auth_tombstone BEFORE DELETE ON hosted_auth_state
        BEGIN SELECT RAISE(ABORT, 'hosted auth tombstones must survive deletion'); END;
        CREATE TRIGGER hosted_auth_invalidate AFTER UPDATE ON hosted_auth_state
        BEGIN UPDATE hosted_connection_authorizations SET revoked = 1
              WHERE local_user_id = NEW.local_user_id;
              UPDATE hosted_auth_changes SET sequence = sequence + 1 WHERE singleton = 1; END;
        ",
    )?;
    let has_users = exists("users")?;
    if has_users {
        if exists("user_residency")? {
            tx.execute_batch("INSERT INTO hosted_auth_state SELECT u.user_id, 1, CASE WHEN r.lifecycle_state = 'released' THEN 0 ELSE 1 END FROM users u LEFT JOIN user_residency r ON r.user_id = u.user_id;")?;
        } else {
            tx.execute_batch("INSERT INTO hosted_auth_state SELECT user_id, 1, 0 FROM users;")?;
        }
        tx.execute_batch(
            "CREATE TRIGGER hosted_auth_create AFTER INSERT ON users
             BEGIN
                 INSERT INTO hosted_auth_state VALUES (NEW.user_id, 1, 1)
                 ON CONFLICT(local_user_id) DO UPDATE SET generation = generation + 1, enabled = 1;
             END;",
        )?;
    }
    if exists("user_residency")? {
        tx.execute_batch(
            "INSERT OR IGNORE INTO hosted_auth_state SELECT user_id, 1, 0 FROM user_residency;",
        )?;
    }
    // SQLite rejects overflow through the integer CHECK, rolling back the account mutation.
    for (name, event, condition, user, enabled) in [
        (
            "key",
            "AFTER UPDATE OF public_key ON users",
            "NEW.public_key != OLD.public_key",
            "NEW.user_id",
            "enabled",
        ),
        ("delete", "BEFORE DELETE ON users", "1", "OLD.user_id", "0"),
        (
            "residency",
            "AFTER UPDATE OF lifecycle_state ON user_residency",
            "NEW.lifecycle_state != OLD.lifecycle_state",
            "NEW.user_id",
            "CASE WHEN NEW.lifecycle_state = 'managed' THEN 1 ELSE 0 END",
        ),
        (
            "binding",
            "AFTER UPDATE ON hosted_principals",
            "NEW.principal_handle != OLD.principal_handle OR NEW.local_user_id != OLD.local_user_id",
            "OLD.local_user_id",
            "enabled",
        ),
        (
            "moved_binding",
            "AFTER UPDATE ON hosted_principals",
            "NEW.local_user_id != OLD.local_user_id",
            "NEW.local_user_id",
            "enabled",
        ),
        (
            "released_residency",
            "AFTER INSERT ON user_residency",
            "NEW.lifecycle_state = 'released'",
            "NEW.user_id",
            "0",
        ),
        (
            "unbind",
            "BEFORE DELETE ON hosted_principals",
            "1",
            "OLD.local_user_id",
            "0",
        ),
        (
            "bind",
            "AFTER INSERT ON hosted_principals",
            "1",
            "NEW.local_user_id",
            "enabled",
        ),
    ] {
        if !exists(event.split_whitespace().last().expect("trigger table"))? {
            continue;
        }
        tx.execute_batch(&format!(
            "CREATE TRIGGER hosted_auth_{name} {event} WHEN {condition} BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = {user})
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = {enabled}
                WHERE local_user_id = {user};
            END;"
        ))?;
    }
    if exists("principals")? && exists("hosted_principals")? {
        tx.execute_batch(
        "CREATE TRIGGER hosted_auth_principal_delete BEFORE DELETE ON principals BEGIN
            UPDATE hosted_auth_state SET generation = generation + 1, enabled = 0
            WHERE local_user_id IN (SELECT local_user_id FROM hosted_principals WHERE principal_handle = OLD.principal_pk);
        END;
        CREATE TRIGGER hosted_auth_authority AFTER UPDATE OF authority_kind, authority_id, remote_user_id, home, retired_at ON principals
        WHEN NEW.authority_kind IS NOT OLD.authority_kind OR NEW.authority_id IS NOT OLD.authority_id
          OR NEW.remote_user_id IS NOT OLD.remote_user_id OR NEW.home IS NOT OLD.home
          OR NEW.retired_at IS NOT OLD.retired_at
        BEGIN
            UPDATE hosted_auth_state SET generation = generation + 1,
                enabled = CASE WHEN NEW.retired_at IS NULL THEN enabled ELSE 0 END
            WHERE local_user_id IN (SELECT local_user_id FROM hosted_principals WHERE principal_handle = OLD.principal_pk);
        END;
        ",
    )?;
    }
    tx.pragma_update(None, "user_version", 51)?;
    tx.commit()?;
    Ok(())
}

pub fn current(user: LocalUserId) -> Result<HostedAuthState, StorageError> {
    db::with_db(|connection| current_in_db(connection, user))
}

fn current_in_db(
    connection: &Connection,
    user: LocalUserId,
) -> Result<HostedAuthState, StorageError> {
    connection
        .query_row(
            "SELECT generation, enabled FROM hosted_auth_state WHERE local_user_id = ?1",
            [user.0],
            |row| {
                Ok(HostedAuthState {
                    local_user: user,
                    generation: row.get(0)?,
                    enabled: row.get(1)?,
                })
            },
        )
        .optional()?
        .ok_or(StorageError::HostedAuthorizationDenied)
}

pub fn revoke_in_tx(
    tx: &Transaction<'_>,
    user: LocalUserId,
) -> Result<HostedAuthState, StorageError> {
    let state = current_in_db(tx, user)?;
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(StorageError::HostedGenerationExhausted)?;
    if tx.execute("UPDATE hosted_auth_state SET generation = ?2, enabled = 0 WHERE local_user_id = ?1 AND generation = ?3",
        params![user.0, generation, state.generation])? != 1 {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    current_in_db(tx, user)
}

pub fn revoke(user: LocalUserId) -> Result<HostedAuthState, StorageError> {
    db::with_immediate_transaction(|tx| revoke_in_tx(tx, user))
}

/// One SQL statement supplies the account key, principal, residency and generation snapshot.
pub fn resolve(user: LocalUserId) -> Result<(ValidatedHostedIdentity, String), StorageError> {
    db::with_db(|connection| {
        connection
            .query_row(
                "SELECT h.principal_handle, a.generation, u.public_key FROM users u
             JOIN hosted_auth_state a ON a.local_user_id = u.user_id
             JOIN hosted_principals h ON h.local_user_id = u.user_id
             JOIN principals p ON p.principal_pk = h.principal_handle
             LEFT JOIN user_residency r ON r.user_id = u.user_id
             WHERE u.user_id = ?1 AND a.enabled = 1 AND p.retired_at IS NULL
               AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed')",
                [user.0],
                |row| {
                    Ok((
                        ValidatedHostedIdentity {
                            local_user: user,
                            principal: PrincipalHandle(row.get(0)?),
                            auth_generation: row.get(1)?,
                        },
                        row.get(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::HostedAuthorizationDenied)
    })
}

pub fn register(lease: &HostedAuthorizationLease) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| register_in_tx(tx, lease))
}

fn register_in_tx(
    tx: &Transaction<'_>,
    lease: &HostedAuthorizationLease,
) -> Result<(), StorageError> {
    let identity = lease.identity;
    let inserted = tx.execute(
        "INSERT INTO hosted_connection_authorizations
             (connection_id, server_instance, local_user_id, principal_handle, auth_generation)
             SELECT ?1, ?2, a.local_user_id, h.principal_handle, a.generation
             FROM hosted_auth_state a JOIN users u ON u.user_id = a.local_user_id
             JOIN hosted_principals h ON h.local_user_id = a.local_user_id
             JOIN principals p ON p.principal_pk = h.principal_handle
             LEFT JOIN user_residency r ON r.user_id = u.user_id
             WHERE a.local_user_id = ?3 AND h.principal_handle = ?4
               AND a.generation = ?5 AND a.enabled = 1 AND p.retired_at IS NULL
               AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed')",
        params![
            lease.connection_id,
            lease.server_instance,
            identity.local_user.0,
            identity.principal.0,
            identity.auth_generation
        ],
    )?;
    if inserted != 1 {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    Ok(())
}

pub fn verify_in_tx(
    tx: &Transaction<'_>,
    lease: &HostedAuthorizationLease,
) -> Result<(), StorageError> {
    verify_in_db(tx, lease)
}

fn verify_in_db(
    connection: &Connection,
    lease: &HostedAuthorizationLease,
) -> Result<(), StorageError> {
    if REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .contains(&lease.connection_id)
    {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    let identity = lease.identity;
    let valid: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM hosted_connection_authorizations s
         JOIN hosted_auth_state a ON a.local_user_id = s.local_user_id
         JOIN hosted_principals h ON h.local_user_id = s.local_user_id
         JOIN users u ON u.user_id = s.local_user_id
         JOIN principals p ON p.principal_pk = h.principal_handle
         JOIN hosted_server_instances owner ON owner.server_instance = s.server_instance
         LEFT JOIN user_residency r ON r.user_id = u.user_id
         WHERE s.connection_id = ?1 AND s.server_instance = ?2
           AND s.local_user_id = ?3 AND s.principal_handle = ?4 AND s.auth_generation = ?5
            AND owner.expires_at > unixepoch() AND s.revoked = 0 AND a.enabled = 1 AND a.generation = s.auth_generation
           AND h.principal_handle = s.principal_handle AND p.retired_at IS NULL
           AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed'))",
        params![
            lease.connection_id,
            lease.server_instance,
            identity.local_user.0,
            identity.principal.0,
            identity.auth_generation
        ],
        |row| row.get(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(StorageError::HostedAuthorizationDenied)
    }
}

pub fn verify(lease: &HostedAuthorizationLease) -> Result<(), StorageError> {
    db::with_db(|connection| verify_in_db(connection, lease))
}

/// Call from the schema migration after version 54. The caller owns user_version.
pub fn migrate_server_instances(connection: &Connection) -> Result<(), StorageError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'hosted_server_instances')",
        [], |row| row.get(0),
    )?;
    if exists {
        return Ok(());
    }
    let tx = connection.unchecked_transaction()?;
    let has_revoked: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('hosted_connection_authorizations') WHERE name = 'revoked')",
        [], |row| row.get(0),
    )?;
    if !has_revoked {
        tx.execute_batch("ALTER TABLE hosted_connection_authorizations ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1));")?;
    }
    tx.execute_batch(
        "CREATE TABLE hosted_server_instances (
            server_instance TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );
        UPDATE hosted_connection_authorizations SET revoked = 1;
        DROP TRIGGER IF EXISTS hosted_auth_invalidate;
        CREATE TRIGGER hosted_auth_invalidate AFTER UPDATE ON hosted_auth_state
        BEGIN UPDATE hosted_connection_authorizations SET revoked = 1
              WHERE local_user_id = NEW.local_user_id;
              UPDATE hosted_auth_changes SET sequence = sequence + 1 WHERE singleton = 1; END;
        CREATE TRIGGER hosted_server_expiry BEFORE INSERT ON hosted_connection_authorizations
        WHEN NOT EXISTS (SELECT 1 FROM hosted_server_instances
            WHERE server_instance = NEW.server_instance AND expires_at > unixepoch())
        BEGIN SELECT RAISE(ABORT, 'hosted server lease expired'); END;",
    )?;
    tx.commit()?;
    Ok(())
}

/// A stopped owner cannot renew an expired lease or revive its authorizations.
pub fn maintain_server(instance: &str, start: bool) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| maintain_server_in_tx(tx, instance, start))
}

fn maintain_server_in_tx(
    tx: &Transaction<'_>,
    instance: &str,
    start: bool,
) -> Result<(), StorageError> {
    if start {
        tx.execute(
            "INSERT OR IGNORE INTO hosted_server_instances VALUES (?1, unixepoch() + 60)",
            [instance],
        )?;
    }
    if tx.execute("UPDATE hosted_server_instances SET expires_at = unixepoch() + 60 WHERE server_instance = ?1 AND expires_at > unixepoch()", [instance])? != 1 {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    tx.execute("UPDATE hosted_connection_authorizations SET revoked = 1 WHERE revoked = 0 AND NOT EXISTS (SELECT 1 FROM hosted_server_instances owner WHERE owner.server_instance = hosted_connection_authorizations.server_instance AND owner.expires_at > unixepoch())", [])?;
    Ok(())
}

/// One statement verifies the complete active set, including exact lease bindings.
pub fn verify_batch(leases: &[HostedAuthorizationLease]) -> Result<Vec<String>, StorageError> {
    db::with_db(|connection| verify_batch_in_db(connection, leases))
}

fn verify_batch_in_db(
    connection: &Connection,
    leases: &[HostedAuthorizationLease],
) -> Result<Vec<String>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT s.connection_id, s.server_instance, s.local_user_id, s.principal_handle, s.auth_generation
         FROM hosted_connection_authorizations s
         JOIN hosted_server_instances owner ON owner.server_instance = s.server_instance
         JOIN hosted_auth_state a ON a.local_user_id = s.local_user_id
         JOIN hosted_principals h ON h.local_user_id = s.local_user_id
         JOIN users u ON u.user_id = s.local_user_id
         JOIN principals p ON p.principal_pk = h.principal_handle
         LEFT JOIN user_residency r ON r.user_id = u.user_id
         WHERE owner.expires_at > unixepoch() AND s.revoked = 0 AND a.enabled = 1
           AND a.generation = s.auth_generation AND h.principal_handle = s.principal_handle
           AND p.retired_at IS NULL AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed')",
    )?;
    let valid = statement
        .query_map([], |row| {
            Ok(HostedAuthorizationLease {
                connection_id: row.get(0)?,
                server_instance: row.get(1)?,
                identity: ValidatedHostedIdentity {
                    local_user: LocalUserId(row.get(2)?),
                    principal: PrincipalHandle(row.get(3)?),
                    auth_generation: row.get(4)?,
                },
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let valid = valid
        .into_iter()
        .map(|lease| (lease.connection_id.clone(), lease))
        .collect::<std::collections::HashMap<_, _>>();
    let revoked = REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned");
    Ok(leases
        .iter()
        .filter(|lease| {
            revoked.contains(&lease.connection_id) || valid.get(&lease.connection_id) != Some(lease)
        })
        .map(|lease| lease.connection_id.clone())
        .collect())
}

pub fn remove(connection_id: &str) -> Result<(), StorageError> {
    REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .insert(connection_id.to_owned());
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE hosted_connection_authorizations SET revoked = 1 WHERE connection_id = ?1",
            [connection_id],
        )?;
        Ok(())
    })?;
    REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .remove(connection_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(connection: &Connection) {
        connection.execute_batch(
            "CREATE TABLE users (user_id INTEGER PRIMARY KEY, public_key TEXT, display_name TEXT);
             CREATE TABLE user_residency (user_id INTEGER PRIMARY KEY, lifecycle_state TEXT);
             CREATE TABLE principals (principal_pk INTEGER PRIMARY KEY, authority_kind TEXT,
                authority_id TEXT, remote_user_id INTEGER, home TEXT, retired_at INTEGER);
             CREATE TABLE hosted_principals (local_user_id INTEGER PRIMARY KEY, principal_handle INTEGER);
             INSERT INTO users VALUES (7, 'key', 'Alice');
             INSERT INTO user_residency VALUES (7, 'managed');
             INSERT INTO principals VALUES (9, 'iota', 'local', 7, 'local', NULL);
             INSERT INTO principals VALUES (10, 'iota', 'other', 8, 'other', NULL);
             INSERT INTO hosted_principals VALUES (7, 9);
             CREATE TABLE relay_inbox (signer_principal INTEGER, signer_id INTEGER, message_id TEXT,
                created_at INTEGER, accepted_at INTEGER, destination_id INTEGER, frame BLOB,
                frame_id INTEGER, type_map_version TEXT, state TEXT,
                PRIMARY KEY (signer_principal, message_id));"
        ).unwrap();
        migrate(connection).unwrap();
        migrate_server_instances(connection).unwrap();
        connection
            .execute(
                "INSERT INTO hosted_server_instances VALUES ('instance', unixepoch() + 60)",
                [],
            )
            .unwrap();
    }

    fn lease(connection: &mut Connection) -> HostedAuthorizationLease {
        let lease = HostedAuthorizationLease {
            connection_id: "connection".into(),
            server_instance: "instance".into(),
            identity: ValidatedHostedIdentity {
                local_user: LocalUserId(7),
                principal: PrincipalHandle(9),
                auth_generation: 1,
            },
        };
        let tx = connection.transaction().unwrap();
        register_in_tx(&tx, &lease).unwrap();
        tx.commit().unwrap();
        lease
    }

    #[test]
    fn legacy_authorizations_gain_revoked_state_and_migration_is_idempotent() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE hosted_connection_authorizations (connection_id TEXT PRIMARY KEY, server_instance TEXT, local_user_id INTEGER, principal_handle INTEGER, auth_generation INTEGER);
            CREATE TABLE hosted_auth_state (local_user_id INTEGER, generation INTEGER);
            CREATE TABLE hosted_auth_changes (singleton INTEGER, sequence INTEGER);
            INSERT INTO hosted_auth_state VALUES (7, 1);
            INSERT INTO hosted_auth_changes VALUES (1, 0);
            INSERT INTO hosted_connection_authorizations VALUES ('old', 'old-owner', 7, 9, 1);
            CREATE TRIGGER hosted_auth_invalidate AFTER UPDATE ON hosted_auth_state BEGIN DELETE FROM hosted_connection_authorizations WHERE local_user_id = NEW.local_user_id; END;").unwrap();
        migrate_server_instances(&connection).unwrap();
        let revoked = |id: &str| {
            connection
                .query_row(
                    "SELECT revoked FROM hosted_connection_authorizations WHERE connection_id = ?1",
                    [id],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        };
        assert!(revoked("old"));
        connection
            .execute_batch(
                "INSERT INTO hosted_server_instances VALUES ('live', unixepoch() + 60);
            INSERT INTO hosted_connection_authorizations VALUES ('new', 'live', 7, 9, 1, 0);",
            )
            .unwrap();
        migrate_server_instances(&connection).unwrap();
        assert!(!revoked("new"));
        connection
            .execute("UPDATE hosted_auth_state SET generation = 2", [])
            .unwrap();
        assert!(revoked("new"));
    }

    #[test]
    fn reconciliation_preserves_live_other_owners_and_fences_expired_owners() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let live = lease(&mut connection);
        let mut other = live.clone();
        other.connection_id = "other-connection".into();
        other.server_instance = "other-instance".into();
        let tx = connection.transaction().unwrap();
        maintain_server_in_tx(&tx, "other-instance", true).unwrap();
        register_in_tx(&tx, &other).unwrap();
        tx.commit().unwrap();
        assert!(
            verify_batch_in_db(&connection, &[live.clone(), other.clone()])
                .unwrap()
                .is_empty()
        );
        connection.execute("UPDATE hosted_server_instances SET expires_at = 0 WHERE server_instance = 'instance'", []).unwrap();
        assert_eq!(
            verify_batch_in_db(&connection, &[live.clone(), other.clone()]).unwrap(),
            vec![live.connection_id.clone()]
        );
        let tx = connection.transaction().unwrap();
        assert!(maintain_server_in_tx(&tx, "instance", false).is_err());
        maintain_server_in_tx(&tx, "other-instance", false).unwrap();
        tx.commit().unwrap();
        assert!(verify_in_db(&connection, &live).is_err());
        verify_in_db(&connection, &other).unwrap();
        let revoked: bool = connection.query_row("SELECT revoked FROM hosted_connection_authorizations WHERE connection_id = 'connection'", [], |row| row.get(0)).unwrap();
        assert!(revoked);
    }

    #[test]
    fn batch_checks_exact_generation_and_durable_connection_revocation() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let live = lease(&mut connection);
        let mut stale = live.clone();
        stale.identity.auth_generation += 1;
        assert_eq!(
            verify_batch_in_db(&connection, &[stale]).unwrap(),
            vec![live.connection_id.clone()]
        );
        connection
            .execute(
                "UPDATE hosted_connection_authorizations SET revoked = 1",
                [],
            )
            .unwrap();
        assert!(verify_in_db(&connection, &live).is_err());
        assert_eq!(
            verify_batch_in_db(&connection, std::slice::from_ref(&live)).unwrap(),
            vec![live.connection_id]
        );
    }

    #[test]
    fn authority_changes_revoke_clones_but_profile_changes_do_not() {
        for mutation in [
            "UPDATE users SET public_key = 'rotated' WHERE user_id = 7",
            "UPDATE user_residency SET lifecycle_state = 'released' WHERE user_id = 7",
            "UPDATE hosted_principals SET principal_handle = 10 WHERE local_user_id = 7",
            "DELETE FROM hosted_principals WHERE local_user_id = 7",
            "UPDATE principals SET home = 'new-home' WHERE principal_pk = 9",
            "DELETE FROM users WHERE user_id = 7",
        ] {
            let mut connection = Connection::open_in_memory().unwrap();
            setup(&connection);
            let lease = lease(&mut connection);
            connection
                .execute(
                    "UPDATE users SET display_name = 'New name' WHERE user_id = 7",
                    [],
                )
                .unwrap();
            verify_in_db(&connection, &lease).unwrap();
            connection.execute(mutation, []).unwrap();
            assert!(matches!(
                verify_in_db(&connection, &lease),
                Err(StorageError::HostedAuthorizationDenied)
            ));
            assert!(
                current_in_db(&connection, LocalUserId(7))
                    .unwrap()
                    .generation
                    > 1
            );
        }
    }

    #[test]
    fn stale_admission_and_generation_reuse_are_rejected() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let stale = lease(&mut connection);
        connection
            .execute("DELETE FROM users WHERE user_id = 7", [])
            .unwrap();
        connection
            .execute("INSERT INTO users VALUES (7, 'key', 'Alice')", [])
            .unwrap();
        let tx = connection.transaction().unwrap();
        let mut pending = stale.clone();
        pending.connection_id = "pending".into();
        assert!(matches!(
            register_in_tx(&tx, &pending),
            Err(StorageError::HostedAuthorizationDenied)
        ));
        assert!(verify_in_tx(&tx, &stale).is_err());
    }

    #[test]
    fn exhausted_generation_rolls_back_key_rotation() {
        let connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        connection
            .execute(
                "UPDATE hosted_auth_state SET generation = ?1 WHERE local_user_id = 7",
                [i64::MAX],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE users SET public_key = 'rotated' WHERE user_id = 7",
                    []
                )
                .is_err()
        );
        let key: String = connection
            .query_row(
                "SELECT public_key FROM users WHERE user_id = 7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(key, "key");
    }

    #[test]
    fn external_revocation_and_acceptance_have_database_ordering() {
        use std::sync::{Arc, Barrier};
        for acceptance_first in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("authority.sqlite3");
            let mut connection = Connection::open(&path).unwrap();
            setup(&connection);
            let lease = lease(&mut connection);
            let ready = Arc::new(Barrier::new(2));
            let committed = Arc::new(Barrier::new(2));
            let writer = std::thread::spawn({
                let ready = ready.clone();
                let committed = committed.clone();
                move || {
                    let mut external = Connection::open(path).unwrap();
                    external
                        .busy_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    ready.wait();
                    let tx = external
                        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                        .unwrap();
                    revoke_in_tx(&tx, LocalUserId(7)).unwrap();
                    tx.commit().unwrap();
                    committed.wait();
                }
            });
            if !acceptance_first {
                ready.wait();
                committed.wait();
            }
            let tx = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            if acceptance_first {
                ready.wait();
            }
            let authorized = verify_in_tx(&tx, &lease);
            if authorized.is_ok() {
                crate::util::relay_replay::reserve_in_tx(
                    &tx,
                    crate::util::relay_replay::RelayReservationRequest {
                        signer_principal: PrincipalHandle(9),
                        signer_id: 7,
                        message_id: "operation",
                        created_at: 1,
                        accepted_at: 2,
                        destination_id: 8,
                        frame: b"exact verified operation",
                        frame_id: 1,
                        type_map_version: "1.0",
                    },
                )
                .unwrap();
            }
            assert_eq!(authorized.is_ok(), acceptance_first);
            tx.commit().unwrap();
            if acceptance_first {
                committed.wait();
            }
            writer.join().unwrap();
            assert!(verify_in_db(&connection, &lease).is_err());
            let count: i64 = connection
                .query_row("SELECT COUNT(*) FROM relay_inbox", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, i64::from(acceptance_first));
        }
    }
}
