use async_trait::async_trait;
use iota_identity::{
    AuthorityLocator, IdentityError, IotaNodeId, LocalNodeIdentity, NodeDescriptor,
    NodeIdentityResolver, PublicKeyBundle, ResolvedNodeIdentity, SignedNodeDescriptor,
    VerifiedNodeDescriptor,
};
use iota_util::crypto_helper::{public_key_bundle_from_base64, public_key_bundle_to_base64};
use rusqlite::{OptionalExtension, params};

use crate::util::db;

const DESCRIPTOR_LIFETIME_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
const DESCRIPTOR_RENEWAL_MILLIS: i64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Default)]
pub struct SqliteNodeDirectory;

impl SqliteNodeDirectory {
    pub fn key_for_authentication_hint(
        &self,
        hint: u64,
    ) -> Result<Option<PublicKeyBundle>, IdentityError> {
        db::with_db(|connection| {
            let now = now_millis();
            let mut statement = connection.prepare(
                "SELECT n.node_id, k.public_key FROM node_directory n JOIN node_keys k ON k.node_id = n.node_id AND k.source_revision = n.descriptor_revision WHERE n.authentication_hint = ?1 AND (n.descriptor_valid_until IS NULL OR n.descriptor_valid_until > ?2) AND k.valid_from <= ?2 AND (k.valid_until IS NULL OR k.valid_until > ?2)",
            )?;
            let matches = statement
                .query_map(params![hint as i64, now], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            if matches.len() > 1 {
                let nodes = matches.iter().map(|(node, _)| node.as_str()).collect::<Vec<_>>();
                iota_logger::log!("Ambiguous peer authentication hint {}: {:?}", hint, nodes);
                return Err(crate::storage_error::StorageError::Other("ambiguous peer authentication hint".into()));
            }
            Ok(matches.into_iter().next().map(|(_, key)| key))
        })
        .map_err(storage_error)?
        .map(|key| {
            public_key_bundle_from_base64(&key).ok_or_else(|| {
                IdentityError::InvalidDescriptor("stored node key is invalid".into())
            })
        })
        .transpose()
    }

    pub fn ensure_local_descriptor(
        &self,
        identity: &LocalNodeIdentity,
        direct_endpoints: Vec<AuthorityLocator>,
        relay_hints: Vec<AuthorityLocator>,
        now: i64,
    ) -> Result<SignedNodeDescriptor, IdentityError> {
        let current = self.load(identity.node_id())?;
        let fields_match = current.as_ref().is_some_and(|current| {
            current.direct_endpoints == direct_endpoints && current.relay_hints == relay_hints
        });
        let renew = current
            .as_ref()
            .and_then(|current| current.valid_until)
            .is_none_or(|valid_until| valid_until <= now + DESCRIPTOR_RENEWAL_MILLIS);
        let revision = current.as_ref().map_or(0, |current| {
            if fields_match && !renew {
                current.descriptor_revision
            } else {
                current.descriptor_revision.saturating_add(1)
            }
        });
        let valid_until = if fields_match && !renew {
            current.and_then(|current| current.valid_until)
        } else {
            Some(now.saturating_add(DESCRIPTOR_LIFETIME_MILLIS))
        };
        let descriptor = NodeDescriptor {
            node: identity.node_id().clone(),
            public_keys: identity.public_keys(),
            direct_endpoints,
            relay_hints,
            revision,
            valid_until,
        };
        let signed = SignedNodeDescriptor::sign(descriptor, identity)?;
        let verified = signed
            .clone()
            .verify(current_revision(&self.load(identity.node_id())?), now)?;
        self.upsert(&verified)?;
        Ok(signed)
    }

    pub fn upsert(&self, verified: &VerifiedNodeDescriptor) -> Result<(), IdentityError> {
        let descriptor = verified.descriptor();
        let direct_endpoints = serde_json::to_string(&descriptor.direct_endpoints)
            .map_err(|error| IdentityError::Storage(error.to_string()))?;
        let relay_hints = serde_json::to_string(&descriptor.relay_hints)
            .map_err(|error| IdentityError::Storage(error.to_string()))?;
        let public_key = public_key_bundle_to_base64(&descriptor.public_keys);
        if public_key.is_empty() {
            return Err(IdentityError::InvalidDescriptor(
                "node public key could not be encoded".into(),
            ));
        }
        db::with_immediate_transaction(|transaction| {
            Self::upsert_in_tx(
                transaction,
                verified,
                &direct_endpoints,
                &relay_hints,
                &public_key,
            )
        })
        .map_err(storage_error)
    }

    pub(crate) fn upsert_in_tx(
        transaction: &rusqlite::Transaction<'_>,
        verified: &VerifiedNodeDescriptor,
        direct_endpoints: &str,
        relay_hints: &str,
        public_key: &str,
    ) -> Result<(), crate::storage_error::StorageError> {
        let descriptor = verified.descriptor();
        let current = transaction
                .query_row(
                    "SELECT n.descriptor_revision, n.last_resolved_at, n.descriptor_valid_until, n.direct_endpoints, n.relay_hints, (SELECT public_key FROM node_keys WHERE node_id = n.node_id AND source_revision = n.descriptor_revision LIMIT 1) FROM node_directory n WHERE n.node_id = ?1",
                    [descriptor.node.as_str()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<String>>(5)?)),
                )
                .optional()?;
        if let Some((
            revision,
            resolved_at,
            valid_until,
            current_endpoints,
            current_relays,
            current_key,
        )) = current
        {
            if revision > descriptor.revision
                || (revision == descriptor.revision && resolved_at > verified.resolved_at())
            {
                return Err(crate::storage_error::StorageError::Other(
                    "stale node descriptor update was rejected".into(),
                ));
            }
            if revision == descriptor.revision
                && (valid_until != descriptor.valid_until
                    || current_endpoints != direct_endpoints
                    || current_relays != relay_hints
                    || current_key.as_deref() != Some(public_key))
            {
                return Err(crate::storage_error::StorageError::Other(
                    "conflicting node descriptor revision was rejected".into(),
                ));
            }
        }
        transaction.execute(
            r#"INSERT INTO node_directory (
                       node_id, descriptor_revision, descriptor_valid_until,
                       direct_endpoints, relay_hints, last_resolved_at, authentication_hint
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                   ON CONFLICT(node_id) DO UPDATE SET
                       descriptor_revision = excluded.descriptor_revision,
                       descriptor_valid_until = excluded.descriptor_valid_until,
                       direct_endpoints = excluded.direct_endpoints,
                       relay_hints = excluded.relay_hints,
                       last_resolved_at = excluded.last_resolved_at,
                       authentication_hint = excluded.authentication_hint"#,
            params![
                descriptor.node.as_str(),
                descriptor.revision,
                descriptor.valid_until,
                direct_endpoints,
                relay_hints,
                verified.resolved_at(),
                descriptor.node.mtp_authentication_hint() as i64,
            ],
        )?;
        transaction.execute(
                "UPDATE node_keys SET valid_until = MIN(COALESCE(valid_until, ?2), ?2) WHERE node_id = ?1",
                params![descriptor.node.as_str(), verified.resolved_at()],
            )?;
        transaction.execute(
            r#"INSERT INTO node_keys (
                       node_id, public_key, valid_from, valid_until, source_revision
                   ) VALUES (?1, ?2, ?3, ?4, ?5)
                   ON CONFLICT(node_id, public_key) DO UPDATE SET
                       valid_until = excluded.valid_until,
                       source_revision = excluded.source_revision"#,
            params![
                descriptor.node.as_str(),
                public_key,
                verified.resolved_at(),
                descriptor.valid_until,
                descriptor.revision,
            ],
        )?;
        Ok(())
    }

    pub fn pin_endpoint_record(
        &self,
        endpoint: &AuthorityLocator,
        node: &IotaNodeId,
        now: i64,
    ) -> Result<(), IdentityError> {
        db::with_immediate_transaction(|connection| {
            let current = connection
                .query_row(
                    "SELECT node_id FROM node_endpoint_pins WHERE endpoint = ?1",
                    [endpoint.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if current.as_deref().is_some_and(|current| current != node.as_str()) {
                return Err(crate::storage_error::StorageError::Other(
                    "endpoint node identity changed from its TOFU pin".into(),
                ));
            }
            connection.execute(
                "INSERT OR IGNORE INTO node_endpoint_pins (endpoint, node_id, pinned_at) VALUES (?1, ?2, ?3)",
                params![endpoint.as_str(), node.as_str(), now],
            )?;
            Ok(())
        })
        .map_err(storage_error)
    }

    pub fn pinned_node_record(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<IotaNodeId>, IdentityError> {
        db::with_db(|connection| {
            connection
                .query_row(
                    "SELECT node_id FROM node_endpoint_pins WHERE endpoint = ?1",
                    [endpoint.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(Into::into)
        })
        .map_err(storage_error)?
        .map(IotaNodeId::new)
        .transpose()
    }

    pub fn pin_endpoint_certificate_record(
        &self,
        endpoint: &AuthorityLocator,
        certificate: &[u8],
    ) -> Result<(), IdentityError> {
        if certificate.is_empty() {
            return Err(IdentityError::InvalidDescriptor(
                "endpoint TLS certificate is empty".into(),
            ));
        }
        db::with_db(|connection| {
            let current = connection
                .query_row(
                    "SELECT tls_certificate FROM node_endpoint_pins WHERE endpoint = ?1",
                    [endpoint.as_str()],
                    |row| row.get::<_, Option<Vec<u8>>>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    crate::storage_error::StorageError::Other(
                        "endpoint must be pinned before its TLS certificate".into(),
                    )
                })?;
            if current
                .as_deref()
                .is_some_and(|current| current != certificate)
            {
                return Err(crate::storage_error::StorageError::Other(
                    "endpoint TLS certificate changed from its TOFU pin".into(),
                ));
            }
            connection.execute(
                "UPDATE node_endpoint_pins SET tls_certificate = COALESCE(tls_certificate, ?2) WHERE endpoint = ?1",
                params![endpoint.as_str(), certificate],
            )?;
            Ok(())
        })
        .map_err(storage_error)
    }

    pub fn pinned_endpoint_certificate_record(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<Vec<u8>>, IdentityError> {
        db::with_db(|connection| {
            connection
                .query_row(
                    "SELECT tls_certificate FROM node_endpoint_pins WHERE endpoint = ?1",
                    [endpoint.as_str()],
                    |row| row.get::<_, Option<Vec<u8>>>(0),
                )
                .optional()
                .map(|certificate| certificate.flatten())
                .map_err(Into::into)
        })
        .map_err(storage_error)
    }

    pub fn record_successful_endpoint(
        &self,
        node: &IotaNodeId,
        endpoint: &AuthorityLocator,
    ) -> Result<(), IdentityError> {
        db::with_db(|connection| {
            connection.execute(
                "UPDATE node_directory SET last_successful_endpoint = ?2 WHERE node_id = ?1",
                params![node.as_str(), endpoint.as_str()],
            )?;
            Ok(())
        })
        .map_err(storage_error)
    }

    fn load(&self, node: &IotaNodeId) -> Result<Option<ResolvedNodeIdentity>, IdentityError> {
        db::with_db(|connection| {
            let row = connection
                .query_row(
                    "SELECT descriptor_revision, descriptor_valid_until, direct_endpoints, relay_hints, last_successful_endpoint, last_resolved_at FROM node_directory WHERE node_id = ?1",
                    [node.as_str()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, i64>(5)?)),
                )
                .optional()?;
            let Some((descriptor_revision, valid_until, direct_endpoints, relay_hints, last_successful_endpoint, resolved_at)) = row else {
                return Ok(None);
            };
            let mut statement = connection.prepare(
                "SELECT public_key FROM node_keys WHERE node_id = ?1 AND valid_from <= ?2 AND (valid_until IS NULL OR valid_until > ?2) ORDER BY source_revision DESC",
            )?;
            let encoded = statement
                .query_map(params![node.as_str(), now_millis()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some((descriptor_revision, valid_until, direct_endpoints, relay_hints, last_successful_endpoint, resolved_at, encoded)))
        })
        .map_err(storage_error)?
        .map(|(descriptor_revision, valid_until, direct_endpoints, relay_hints, last_successful_endpoint, resolved_at, encoded)| {
            Ok(ResolvedNodeIdentity {
                node: node.clone(),
                public_keys: encoded
                    .into_iter()
                    .map(|key| public_key_bundle_from_base64(&key).ok_or_else(|| IdentityError::InvalidDescriptor("stored node key is invalid".into())))
                    .collect::<Result<Vec<PublicKeyBundle>, _>>()?,
                descriptor_revision,
                valid_until,
                direct_endpoints: serde_json::from_str(&direct_endpoints).map_err(|error| IdentityError::Storage(error.to_string()))?,
                relay_hints: serde_json::from_str(&relay_hints).map_err(|error| IdentityError::Storage(error.to_string()))?,
                last_successful_endpoint: last_successful_endpoint.map(AuthorityLocator::new).transpose()?,
                resolved_at,
            })
        })
        .transpose()
    }
}

#[async_trait]
impl NodeIdentityResolver for SqliteNodeDirectory {
    async fn resolve_node(&self, node: &IotaNodeId) -> Result<ResolvedNodeIdentity, IdentityError> {
        let node = node.clone();
        let resolved = crate::blocking::identity_lookup(move || SqliteNodeDirectory.load(&node))
            .await?
            .ok_or(IdentityError::NotFound)?;
        if resolved
            .valid_until
            .is_some_and(|valid_until| valid_until <= now_millis())
        {
            return Err(IdentityError::Unavailable(
                "cached node descriptor is expired".into(),
            ));
        }
        Ok(resolved)
    }
}

impl iota_identity::NodeDirectory for SqliteNodeDirectory {
    fn peer_admission(
        &self,
        node: &IotaNodeId,
        key: &PublicKeyBundle,
        now: i64,
    ) -> Result<Option<iota_identity::peer_introduction::PeerTrust>, IdentityError> {
        crate::peer_admission::trust_for_peer(node, key, now).map(Some)
    }

    fn promote_peer(
        &self,
        trust: &iota_identity::peer_introduction::PeerTrust,
        key: &PublicKeyBundle,
        now: i64,
    ) -> Result<Option<iota_identity::peer_introduction::PeerTrust>, IdentityError> {
        crate::peer_admission::promote(trust, key, now).map(Some)
    }

    fn revoke_peer_admission(&self, node: &IotaNodeId) -> Result<(), IdentityError> {
        crate::peer_admission::revoke(node)
    }

    fn upsert_node_descriptor(
        &self,
        descriptor: &VerifiedNodeDescriptor,
    ) -> Result<(), IdentityError> {
        self.upsert(descriptor)
    }

    fn pin_endpoint(
        &self,
        endpoint: &AuthorityLocator,
        node: &IotaNodeId,
        now: i64,
    ) -> Result<(), IdentityError> {
        self.pin_endpoint_record(endpoint, node, now)
    }

    fn pinned_node(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<IotaNodeId>, IdentityError> {
        self.pinned_node_record(endpoint)
    }

    fn pin_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
        certificate: &[u8],
    ) -> Result<(), IdentityError> {
        self.pin_endpoint_certificate_record(endpoint, certificate)
    }

    fn pinned_endpoint_certificate(
        &self,
        endpoint: &AuthorityLocator,
    ) -> Result<Option<Vec<u8>>, IdentityError> {
        self.pinned_endpoint_certificate_record(endpoint)
    }

    fn record_successful_endpoint(
        &self,
        node: &IotaNodeId,
        endpoint: &AuthorityLocator,
    ) -> Result<(), IdentityError> {
        SqliteNodeDirectory::record_successful_endpoint(self, node, endpoint)
    }
}

fn current_revision(node: &Option<ResolvedNodeIdentity>) -> Option<i64> {
    node.as_ref().map(|node| node.descriptor_revision)
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn storage_error(error: impl std::fmt::Display) -> IdentityError {
    IdentityError::Storage(error.to_string())
}
