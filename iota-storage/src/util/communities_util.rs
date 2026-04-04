use crate::util::db;
use json::Array;
use rusqlite::params;
use std::sync::{Arc, LazyLock, Mutex};

static MESSAGES_DB: LazyLock<Arc<Mutex<rusqlite::Connection>>> = LazyLock::new(|| {
    db::create_general_messages_db().expect("Failed to create or initialize general messages DB")
});

pub struct CommunitiesUtil;

impl CommunitiesUtil {
    pub fn add_community(storage_owner: i64, address: String, title: String, position: String) {
        if let Err(e) = db::with_conn(&MESSAGES_DB, |conn| {
            conn.execute(
                r#"
                INSERT INTO communities (
                    storage_owner,
                    address,
                    title,
                    position
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(storage_owner, address) DO UPDATE SET
                    title = excluded.title,
                    position = excluded.position
                "#,
                params![storage_owner, address, title, position],
            )?;
            Ok(())
        }) {
            eprintln!("Failed to add_community: {}", e);
        }
    }

    pub fn remove_community(storage_owner: i64, community_address: String) {
        if let Err(e) = db::with_conn(&MESSAGES_DB, |conn| {
            conn.execute(
                "DELETE FROM communities WHERE storage_owner = ?1 AND address = ?2",
                params![storage_owner, community_address],
            )?;
            Ok(())
        }) {
            eprintln!("Failed to remove_community: {}", e);
        }
    }

    pub fn get_communities(storage_owner: i64) -> Array {
        let communities_out = Array::new();

        let res: Result<Array, String> = db::with_conn(&MESSAGES_DB, |conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT address, title, position
                FROM communities
                WHERE storage_owner = ?1
                "#,
            )?;

            let rows = stmt.query_map(params![storage_owner], |r| {
                let address: String = r.get(0)?;
                let title: String = r.get(1)?;
                let position: String = r.get(2)?;
                Ok((address, title, position))
            })?;

            let mut out = Array::new();
            for row in rows {
                match row {
                    Ok((address, title, position)) => {
                        let mut community = json::JsonValue::new_object();
                        community["title"] = json::JsonValue::String(title);
                        community["address"] = json::JsonValue::String(address);
                        community["position"] = json::JsonValue::String(position);
                        out.push(community);
                    }
                    Err(e) => eprintln!("Failed to read community row: {}", e),
                }
            }
            Ok(out)
        });

        match res {
            Ok(arr) => arr,
            Err(e) => {
                eprintln!("Failed to query communities in get_communities: {}", e);
                communities_out
            }
        }
    }
}
