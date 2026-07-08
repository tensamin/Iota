use crate::util::db;
use rusqlite::params;

#[derive(Debug, Clone)]
pub struct StoredCommunity {
    pub address: String,
    pub title: String,
    pub position: String,
}

pub struct CommunitiesUtil;

impl CommunitiesUtil {
    pub fn add_community(storage_owner: i64, address: String, title: String, position: String) {
        if let Err(e) = db::with_db(|conn| {
            conn.execute(
                r#"
                INSERT INTO communities (storage_owner, address, title, position)
                VALUES (?1, ?2, ?3, ?4)
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
        if let Err(e) = db::with_db(|conn| {
            conn.execute(
                "DELETE FROM communities WHERE storage_owner = ?1 AND address = ?2",
                params![storage_owner, community_address],
            )?;
            Ok(())
        }) {
            eprintln!("Failed to remove_community: {}", e);
        }
    }

    pub fn get_communities(storage_owner: i64) -> Vec<StoredCommunity> {
        match db::with_db(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT address, title, position
                FROM communities
                WHERE storage_owner = ?1
                "#,
            )?;

            let rows = stmt.query_map(params![storage_owner], |r| {
                Ok(StoredCommunity {
                    address: r.get(0)?,
                    title: r.get(1)?,
                    position: r.get(2)?,
                })
            })?;

            let mut out = Vec::new();
            for row in rows {
                match row {
                    Ok(community) => out.push(community),
                    Err(e) => eprintln!("Failed to read community row: {}", e),
                }
            }
            Ok(out)
        }) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to query communities in get_communities: {}", e);
                Vec::new()
            }
        }
    }
}
