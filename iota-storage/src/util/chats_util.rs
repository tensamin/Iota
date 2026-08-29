use crate::storage_error::StorageError;
use crate::users::contact::Contact;
use crate::util::db;
use crate::util::sync::{self, EntityType, Operation};
use rusqlite::params;

pub fn has_user(storage_owner: i64, user_id: i64) -> Result<bool, StorageError> {
    db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM contacts WHERE storage_owner = ?1 AND user_id = ?2)",
            params![storage_owner, user_id],
            |row| row.get(0),
        )?)
    })
}

pub fn mod_user(storage_owner: i64, contact: &Contact) {
    if let Err(e) = db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            r#"
            INSERT INTO contacts (storage_owner, user_id, user_name, last_message_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(storage_owner, user_id) DO UPDATE SET
                user_name = excluded.user_name,
                last_message_at = excluded.last_message_at
            "#,
            params![
                storage_owner,
                contact.user_id,
                contact.user_name.clone(),
                contact.last_message_at,
            ],
        )?;
        sync::record_event(
            &tx,
            storage_owner,
            EntityType::Contact,
            contact.user_id,
            Operation::Upsert,
        )?;
        tx.commit()?;
        Ok(())
    }) {
        eprintln!("Failed to mod_user: {}", e);
    }
}

pub fn get_users_by_ids(storage_owner: i64, ids: &[i64]) -> Vec<Contact> {
    if ids.is_empty() {
        return Vec::new();
    }
    let wanted: std::collections::HashSet<i64> = ids.iter().copied().collect();
    get_users(storage_owner)
        .into_iter()
        .filter(|contact| wanted.contains(&contact.user_id))
        .collect()
}

pub fn get_user(storage_owner: i64, user_id: i64) -> Option<Contact> {
    match db::with_db(|conn| {
        match conn.query_row(
            r#"
            SELECT user_id, user_name, last_message_at
            FROM contacts
            WHERE storage_owner = ?1 AND user_id = ?2
            LIMIT 1
            "#,
            params![storage_owner, user_id],
            |r| {
                Ok(Contact {
                    user_id: r.get(0)?,
                    user_name: r.get(1)?,
                    last_message_at: r.get(2)?,
                })
            },
        ) {
            Ok(c) => Ok(Some(c)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }) {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error querying user in get_user: {}", e);
            None
        }
    }
}

pub fn get_users(storage_owner: i64) -> Vec<Contact> {
    match db::with_db(|conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT user_id, user_name, last_message_at
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
                user_name: r.get(1)?,
                last_message_at: r.get(2)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            match row {
                Ok(contact) => out.push(contact),
                Err(e) => eprintln!("Failed to read contact row: {}", e),
            }
        }
        Ok(out)
    }) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to query contacts in get_users: {}", e);
            Vec::new()
        }
    }
}
