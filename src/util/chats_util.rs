use crate::users::contact::Contact;
use crate::util::db;
use rusqlite::params;
use std::sync::{Arc, LazyLock, Mutex};

/// Shared DB connection for contacts/messages (created by db helper).
static MESSAGES_DB: LazyLock<Arc<Mutex<rusqlite::Connection>>> = LazyLock::new(|| {
    db::create_general_messages_db().expect("Failed to create or initialize general messages DB")
});

/// Insert or update a contact for the given storage owner.
pub fn mod_user(storage_owner: i64, contact: &Contact) {
    if let Err(e) = db::with_conn(&MESSAGES_DB, |conn| {
        conn.execute(
            r#"
            INSERT INTO contacts (
                storage_owner,
                user_id,
                user_name,
                last_message_at
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(storage_owner, user_id) DO UPDATE SET
                user_name = excluded.user_name,
                last_message_at = excluded.last_message_at
            "#,
            params![
                storage_owner,
                contact.user_id,
                contact.user_name.clone(),
                contact.last_message_at
            ],
        )?;
        Ok(())
    }) {
        eprintln!("Failed to mod_user: {}", e);
    }
}

/// Retrieve a single contact for storage_owner/user_id.
pub fn get_user(storage_owner: i64, user_id: i64) -> Option<Contact> {
    let res: Result<Option<Contact>, String> = db::with_conn(&MESSAGES_DB, |conn| {
        match conn.query_row(
            r#"
            SELECT user_id, user_name, last_message_at
            FROM contacts
            WHERE storage_owner = ?1 AND user_id = ?2
            LIMIT 1
            "#,
            params![storage_owner, user_id],
            |r| {
                let user_id: i64 = r.get(0)?;
                let user_name: Option<String> = r.get(1)?;
                let last_message_at: Option<i64> = r.get(2)?;
                Ok(Contact {
                    user_id,
                    user_name,
                    last_message_at,
                })
            },
        ) {
            Ok(c) => Ok(Some(c)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    });

    match res {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error querying user in get_user: {}", e);
            None
        }
    }
}

/// Retrieve all contacts for a storage owner, ordered by last_message_at desc / user_id asc.
pub fn get_users(storage_owner: i64) -> Vec<Contact> {
    let contacts_out = Vec::new();

    let res: Result<Vec<Contact>, String> = db::with_conn(&MESSAGES_DB, |conn| {
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
            let user_id: i64 = r.get(0)?;
            let user_name: Option<String> = r.get(1)?;
            let last_message_at: Option<i64> = r.get(2)?;
            Ok(Contact {
                user_id,
                user_name,
                last_message_at,
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
    });

    match res {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to query contacts in get_users: {}", e);
            contacts_out
        }
    }
}
