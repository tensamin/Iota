use crate::storage_error::StorageError;
use crate::util::db;
use crate::util::synced_settings::{self, SettingScope};
use rusqlite::params;

#[derive(Debug, Clone)]
pub struct StoredCommunity {
    pub address: String,
    pub title: String,
    pub position: String,
}

pub struct CommunitiesUtil;

impl CommunitiesUtil {
    pub fn has_community(storage_owner: i64, address: &str) -> Result<bool, StorageError> {
        db::with_db(|conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM communities WHERE storage_owner = ?1 AND address = ?2)",
                params![storage_owner, address],
                |row| row.get(0),
            )?)
        })
    }

    pub fn add_community(
        storage_owner: i64,
        address: String,
        title: String,
        position: String,
    ) -> Result<(), StorageError> {
        db::with_db(|conn| {
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
        })
    }

    pub fn remove_community(
        storage_owner: i64,
        community_address: String,
    ) -> Result<(), StorageError> {
        db::with_immediate_transaction(|tx| {
            tx.execute(
                "DELETE FROM communities WHERE storage_owner = ?1 AND address = ?2",
                params![storage_owner, community_address],
            )?;
            synced_settings::delete_scope_in_tx(
                tx,
                storage_owner,
                SettingScope::Community,
                &community_address,
            )
        })
    }

    pub fn get_communities(storage_owner: i64) -> Result<Vec<StoredCommunity>, StorageError> {
        db::with_db(|conn| {
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

            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }
}
