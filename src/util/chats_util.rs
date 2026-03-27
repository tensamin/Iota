use crate::users::contact::Contact;
use crate::util::file_util::get_directory;
use rusqlite::{Connection, params};
use std::sync::{LazyLock, Mutex};

static DB_CONN: LazyLock<Mutex<Connection>> = LazyLock::new(|| {
    let conn = Connection::open(format!("{}/messages.sqlite3", get_directory()))
        .expect("Failed to open DB");
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            storage_owner INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            user_name TEXT,
            last_message_at INTEGER,
            UNIQUE(storage_owner, user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_contacts_owner
            ON contacts (storage_owner, last_message_at DESC, user_id ASC);
        "#,
    )
    .expect("Failed to initialize DB");
    Mutex::new(conn)
});

pub fn mod_user(storage_owner: i64, contact: &Contact) {
    let conn = DB_CONN.lock().unwrap();

    let _ = conn.execute(
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
    );
}

pub fn get_user(storage_owner: i64, user_id: i64) -> Option<Contact> {
    let conn = DB_CONN.lock().unwrap();

    let row = conn.query_row(
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
    );

    match row {
        Ok(contact) => Some(contact),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => {
            eprintln!("Error querying user in get_user: {}", e);
            None
        }
    }
}

pub fn get_users(storage_owner: i64) -> Vec<Contact> {
    let mut contacts_out = Vec::new();

    let conn = DB_CONN.lock().unwrap();

    let mut stmt = match conn.prepare(
        r#"
        SELECT user_id, user_name, last_message_at
        FROM contacts
        WHERE storage_owner = ?1
        ORDER BY
            CASE WHEN last_message_at IS NULL THEN 1 ELSE 0 END,
            last_message_at DESC,
            user_id ASC
        "#,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to prepare statement in get_users: {}", e);
            return contacts_out;
        }
    };

    let rows = match stmt.query_map(params![storage_owner], |r| {
        let user_id: i64 = r.get(0)?;
        let user_name: Option<String> = r.get(1)?;
        let last_message_at: Option<i64> = r.get(2)?;
        Ok(Contact {
            user_id,
            user_name,
            last_message_at,
        })
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to query map in get_users: {}", e);
            return contacts_out;
        }
    };

    for row in rows {
        if let Ok(contact) = row {
            contacts_out.push(contact);
        }
    }

    contacts_out
}
