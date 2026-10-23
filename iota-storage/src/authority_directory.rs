use iota_identity::{AuthorityDirectory, AuthorityId, AuthorityLocator, IdentityError, IotaNodeId};
use rusqlite::{OptionalExtension, params};

use crate::{storage_error::StorageError, util::db};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS federation_authorities (
    authority_id TEXT NOT NULL,
    locator TEXT NOT NULL UNIQUE,
    node_id TEXT NOT NULL,
    discovered_at INTEGER NOT NULL,
    verified_at INTEGER NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('https_domain','explicit_pin','manual')),
    is_preferred INTEGER NOT NULL DEFAULT 0 CHECK(is_preferred IN (0,1)),
    PRIMARY KEY(authority_id, locator)
);
CREATE INDEX IF NOT EXISTS idx_federation_authority_lookup
ON federation_authorities(authority_id, is_preferred DESC, verified_at DESC);";

#[derive(Default)]
pub struct SqliteAuthorityDirectory;

impl AuthorityDirectory for SqliteAuthorityDirectory {
    fn record_verified_iota(
        &self,
        locator: &AuthorityLocator,
        authority: &AuthorityId,
        node: &IotaNodeId,
        verified_at: i64,
    ) -> Result<(), IdentityError> {
        if *authority != AuthorityId::for_iota(node) {
            return Err(IdentityError::KeyPinMismatch);
        }
        db::with_immediate_transaction(|tx| {
            let pin: Option<String> = tx.query_row(
                "SELECT node_id FROM node_endpoint_pins WHERE endpoint = ?1",
                [locator.as_str()], |r| r.get(0),
            ).optional()?;
            let current: Option<(String, String)> = tx.query_row(
                "SELECT authority_id, node_id FROM federation_authorities WHERE locator = ?1",
                [locator.as_str()], |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional()?;
            if pin.as_deref().is_some_and(|pin| pin != node.as_str())
                || current.is_some_and(|(a, n)| a != authority.as_str() || n != node.as_str())
            {
                return Err(StorageError::Other("authority locator conflicts with established pin".into()));
            }
            let verified: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM node_directory WHERE node_id = ?1 AND last_resolved_at >= ?2)",
                params![node.as_str(), verified_at], |r| r.get(0),
            )?;
            if !verified {
                return Err(StorageError::Other("authority requires a verified node descriptor".into()));
            }
            tx.execute("INSERT OR IGNORE INTO node_endpoint_pins(endpoint,node_id,pinned_at) VALUES(?1,?2,?3)",
                params![locator.as_str(), node.as_str(), verified_at])?;
            tx.execute("INSERT INTO federation_authorities(authority_id,locator,node_id,discovered_at,verified_at,source)
                VALUES(?1,?2,?3,?4,?4,?5)
                ON CONFLICT(authority_id,locator) DO UPDATE SET verified_at = MAX(verified_at, excluded.verified_at)",
                params![authority.as_str(),locator.as_str(),node.as_str(),verified_at,
                    if locator.is_ip_literal() { "explicit_pin" } else { "https_domain" }])?;
            Ok(())
        }).map_err(|e| IdentityError::Storage(e.to_string()))
    }

    fn locators_for(
        &self,
        authority: &AuthorityId,
    ) -> Result<Vec<AuthorityLocator>, IdentityError> {
        db::with_db(|db| {
            let mut stmt = db.prepare("SELECT locator FROM federation_authorities WHERE authority_id = ?1 ORDER BY is_preferred DESC, verified_at DESC, locator")?;
            Ok(stmt.query_map([authority.as_str()], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?)
        }).map_err(|e| IdentityError::Storage(e.to_string()))?
            .into_iter().map(AuthorityLocator::new).collect()
    }
}
