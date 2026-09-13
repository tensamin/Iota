use crate::storage_error::StorageError;
use crate::users::contact::Contact;
use crate::util::db;
use crate::util::sync::{self, EntityType, Operation};
use rusqlite::{OptionalExtension, params};

pub(crate) fn upsert_contact(
    tx: &rusqlite::Transaction<'_>,
    storage_owner: i64,
    contact: &Contact,
) -> Result<(), StorageError> {
    let principal = match contact.principal {
        Some(principal) => principal,
        None => iota_identity::PrincipalHandle(tx.query_row(
            r#"
            SELECT p.principal_pk
            FROM principals p
            WHERE p.authority_id = COALESCE(
                      (SELECT omega_authority_id FROM identity_configuration WHERE singleton = 1),
                      'omega:central'
                  )
              AND p.remote_user_id = ?1
            "#,
            [contact.user_id],
            |row| row.get(0),
        )?),
    };
    tx.execute(
        r#"
        INSERT INTO contacts (
            storage_owner, user_id, principal_handle, user_name, created_at, last_message_at,
            notifications, notifications_read_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(storage_owner, principal_handle) DO UPDATE SET
            user_id = excluded.user_id,
            user_name = COALESCE(excluded.user_name, contacts.user_name),
            created_at = MIN(contacts.created_at, excluded.created_at),
            last_message_at = CASE
                WHEN excluded.last_message_at IS NULL THEN contacts.last_message_at
                WHEN contacts.last_message_at IS NULL THEN excluded.last_message_at
                ELSE MAX(contacts.last_message_at, excluded.last_message_at)
            END
        "#,
        params![
            storage_owner,
            contact.user_id,
            principal.0,
            contact.user_name,
            contact.created_at,
            contact.last_message_at,
            contact.notifications,
            contact.notifications_read_at,
        ],
    )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Contact,
        principal.0,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn has_principal(
    storage_owner: i64,
    principal: iota_identity::PrincipalHandle,
) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM contacts WHERE storage_owner = ?1 AND principal_handle = ?2)",
            params![storage_owner, principal.0],
            |row| row.get(0),
        )?)
    })
}

pub fn has_user(storage_owner: i64, user_id: i64) -> Result<bool, StorageError> {
    get_user(storage_owner, user_id).map(|contact| contact.is_some())
}

pub fn mod_user(storage_owner: i64, contact: &Contact) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| upsert_contact(tx, storage_owner, contact))
}

pub fn get_users_by_principals(
    storage_owner: i64,
    principals: &[iota_identity::PrincipalHandle],
) -> Result<Vec<Contact>, StorageError> {
    if principals.is_empty() {
        return Ok(Vec::new());
    }
    let wanted: std::collections::HashSet<iota_identity::PrincipalHandle> =
        principals.iter().copied().collect();
    Ok(get_users(storage_owner)?
        .into_iter()
        .filter(|contact| {
            contact
                .principal
                .is_some_and(|principal| wanted.contains(&principal))
        })
        .collect())
}

pub fn get_user(storage_owner: i64, user_id: i64) -> Result<Option<Contact>, StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare(
            r#"
            SELECT user_id, principal_handle, user_name, created_at, last_message_at,
                   notifications, notifications_read_at
            FROM contacts
            WHERE storage_owner = ?1 AND user_id = ?2
            LIMIT 2
            "#,
        )?;
        let contacts = statement
            .query_map(params![storage_owner, user_id], |r| {
                Ok(Contact {
                    user_id: r.get(0)?,
                    principal: r
                        .get::<_, Option<i64>>(1)?
                        .map(iota_identity::PrincipalHandle),
                    user_name: r.get(2)?,
                    created_at: r.get(3)?,
                    last_message_at: r.get(4)?,
                    notifications: r.get(5)?,
                    notifications_read_at: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        match contacts.as_slice() {
            [contact] => Ok(Some(contact.clone())),
            _ => Ok(None),
        }
    })
}

pub fn get_user_by_principal(
    storage_owner: i64,
    principal: iota_identity::PrincipalHandle,
) -> Result<Option<Contact>, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            r#"
            SELECT user_id, principal_handle, user_name, created_at, last_message_at,
                   notifications, notifications_read_at
            FROM contacts
            WHERE storage_owner = ?1 AND principal_handle = ?2
            "#,
            params![storage_owner, principal.0],
            |row| {
                Ok(Contact {
                    user_id: row.get(0)?,
                    principal: Some(iota_identity::PrincipalHandle(row.get(1)?)),
                    user_name: row.get(2)?,
                    created_at: row.get(3)?,
                    last_message_at: row.get(4)?,
                    notifications: row.get(5)?,
                    notifications_read_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    })
}

pub fn get_users(storage_owner: i64) -> Result<Vec<Contact>, StorageError> {
    db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT user_id, principal_handle, user_name, created_at, last_message_at,
                   notifications, notifications_read_at
            FROM contacts
            WHERE storage_owner = ?1
            ORDER BY
                CASE WHEN last_message_at IS NULL THEN 1 ELSE 0 END,
                last_message_at DESC,
                user_id ASC
            "#,
        )?;

        let rows = stmt.query_map(params![storage_owner], |r| {
            Ok(Contact {
                user_id: r.get(0)?,
                principal: r
                    .get::<_, Option<i64>>(1)?
                    .map(iota_identity::PrincipalHandle),
                user_name: r.get(2)?,
                created_at: r.get(3)?,
                last_message_at: r.get(4)?,
                notifications: r.get(5)?,
                notifications_read_at: r.get(6)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
}

pub fn read_notifications(
    storage_owner: i64,
    principal: iota_identity::PrincipalHandle,
    through: i64,
) -> Result<Option<Contact>, StorageError> {
    db::with_immediate_transaction(|tx| {
        let Some(current_read_at) = tx
            .query_row(
                "SELECT notifications_read_at FROM contacts WHERE storage_owner = ?1 AND principal_handle = ?2",
                params![storage_owner, principal.0],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(None);
        };
        let read_at = current_read_at.max(through);
        let notifications = tx.query_row(
            r#"
            SELECT COUNT(*)
            FROM messages
            WHERE storage_owner = ?1
              AND external_principal = ?2
              AND sent_by_self = 0
              AND deleted_by_external = 0
              AND history_deleted = 0
              AND COALESCE(destination_iota_received_at, stored_at, authored_at, message_time) > ?3
            "#,
            params![storage_owner, principal.0, read_at],
            |row| row.get::<_, i64>(0),
        )?;
        tx.execute(
            "UPDATE contacts SET notifications = ?3, notifications_read_at = ?4 WHERE storage_owner = ?1 AND principal_handle = ?2",
            params![storage_owner, principal.0, notifications, read_at],
        )?;
        sync::record_event(
            tx,
            storage_owner,
            EntityType::Contact,
            principal.0,
            Operation::Upsert,
        )?;

        Ok(Some(tx.query_row(
            r#"
            SELECT user_id, principal_handle, user_name, created_at, last_message_at,
                   notifications, notifications_read_at
            FROM contacts
            WHERE storage_owner = ?1 AND principal_handle = ?2
            "#,
            params![storage_owner, principal.0],
            |row| {
                Ok(Contact {
                    user_id: row.get(0)?,
                    principal: row
                        .get::<_, Option<i64>>(1)?
                        .map(iota_identity::PrincipalHandle),
                    user_name: row.get(2)?,
                    created_at: row.get(3)?,
                    last_message_at: row.get(4)?,
                    notifications: row.get(5)?,
                    notifications_read_at: row.get(6)?,
                })
            },
        )?))
    })
}
