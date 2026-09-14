use crate::storage_error::StorageError;
use crate::util::db;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
pub const AUTHORIZATION_CODE_LIFETIME_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "identity.read")]
    IdentityRead,
    #[serde(rename = "contacts.read")]
    ContactsRead,
    #[serde(rename = "metadata.read")]
    MetadataRead,
    #[serde(rename = "metadata.write")]
    MetadataWrite,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentityRead => "identity.read",
            Self::ContactsRead => "contacts.read",
            Self::MetadataRead => "metadata.read",
            Self::MetadataWrite => "metadata.write",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "identity.read" => Some(Self::IdentityRead),
            "contacts.read" => Some(Self::ContactsRead),
            "metadata.read" => Some(Self::MetadataRead),
            "metadata.write" => Some(Self::MetadataWrite),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerApp {
    pub app_id: String,
    pub owner_user_id: i64,
    pub domain: String,
    pub public_key: String,
    pub owner_certificate: String,
    pub connection_mode: String,
    pub endpoint_url: String,
    pub omikron_public_key: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub local_user_id: i64,
    pub app_id: String,
    pub app_name: String,
    pub domain: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub app_public_key: String,
    pub manifest_hash: String,
    pub insecure: bool,
    pub updated_at: i64,
    pub metadata: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthorizationGrant<'a> {
    pub local_user_id: i64,
    pub app_id: &'a str,
    pub app_name: &'a str,
    pub domain: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a [String],
    pub app_public_key: &'a str,
    pub manifest_hash: &'a str,
    pub pkce_challenge: &'a str,
    pub authorization_request: &'a str,
    pub locator: &'a str,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub token: String,
    pub local_user_id: i64,
    pub app_id: String,
    pub scopes: Vec<String>,
    pub locator: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TAuthStorageError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("unknown TAuth scope: {0}")]
    UnknownScope(String),
    #[error("authorization code is invalid, expired, or already used")]
    InvalidCode,
    #[error("PKCE verifier does not match authorization request")]
    InvalidPkce,
    #[error("TAuth grant is insecure")]
    InsecureGrant,
    #[error("TAuth session is invalid")]
    InvalidSession,
    #[error("TAuth scope is required: {0}")]
    ScopeDenied(&'static str),
    #[error("metadata is not valid JSON")]
    InvalidJson,
    #[error("metadata exceeds 16 MiB")]
    MetadataTooLarge,
}

pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn normalize_scopes(scopes: &[String]) -> Result<Vec<String>, TAuthStorageError> {
    let mut normalized = BTreeSet::new();
    for scope in scopes {
        let parsed =
            Scope::parse(scope).ok_or_else(|| TAuthStorageError::UnknownScope(scope.clone()))?;
        normalized.insert(parsed.as_str().to_owned());
    }
    Ok(normalized.into_iter().collect())
}

pub fn grant_covers(grant: &Grant, scopes: &[String]) -> Result<bool, TAuthStorageError> {
    let requested = normalize_scopes(scopes)?;
    Ok(!grant.insecure && requested.iter().all(|scope| grant.scopes.contains(scope)))
}

pub fn register_owner_app(app: &OwnerApp) -> Result<(), TAuthStorageError> {
    db::with_db(|conn| {
        conn.execute(
            r#"INSERT INTO tauth_owner_apps (
                app_id, owner_user_id, domain, public_key, owner_certificate,
                connection_mode, endpoint_url, omikron_public_key, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            params![
                app.app_id,
                app.owner_user_id,
                app.domain,
                app.public_key,
                app.owner_certificate,
                app.connection_mode,
                app.endpoint_url,
                app.omikron_public_key,
                app.created_at,
            ],
        )?;
        Ok(())
    })?;
    Ok(())
}

pub fn list_owner_apps() -> Result<Vec<OwnerApp>, TAuthStorageError> {
    Ok(db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT app_id, owner_user_id, domain, public_key, owner_certificate, connection_mode, endpoint_url, omikron_public_key, created_at FROM tauth_owner_apps ORDER BY domain, app_id",
        )?;
        let rows = statement.query_map([], owner_app_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })?)
}

pub fn get_owner_app(app_id: &str) -> Result<Option<OwnerApp>, TAuthStorageError> {
    Ok(db::with_db(|conn| {
        conn.query_row(
            "SELECT app_id, owner_user_id, domain, public_key, owner_certificate, connection_mode, endpoint_url, omikron_public_key, created_at FROM tauth_owner_apps WHERE app_id = ?1",
            params![app_id],
            owner_app_from_row,
        )
        .optional()
        .map_err(Into::into)
    })?)
}

pub fn delete_owner_app(app_id: &str) -> Result<bool, TAuthStorageError> {
    Ok(db::with_immediate_transaction(|tx| {
        let removed = tx.execute(
            "DELETE FROM tauth_owner_apps WHERE app_id = ?1",
            params![app_id],
        )?;
        Ok(removed > 0)
    })?)
}

pub fn get_grant(local_user_id: i64, app_id: &str) -> Result<Option<Grant>, TAuthStorageError> {
    Ok(db::with_db(|conn| {
        conn.query_row(
            "SELECT g.local_user_id, g.app_id, g.app_name, g.domain, g.redirect_uri, g.scopes, g.app_public_key, g.manifest_hash, g.security_state, g.updated_at, m.json FROM tauth_grants g LEFT JOIN tauth_metadata m ON m.local_user_id = g.local_user_id AND m.app_id = g.app_id WHERE g.local_user_id = ?1 AND g.app_id = ?2",
            params![local_user_id, app_id],
            grant_from_row,
        )
        .optional()
        .map_err(Into::into)
    })?)
}

pub fn list_grants(local_user_id: i64) -> Result<Vec<Grant>, TAuthStorageError> {
    Ok(db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT g.local_user_id, g.app_id, g.app_name, g.domain, g.redirect_uri, g.scopes, g.app_public_key, g.manifest_hash, g.security_state, g.updated_at, m.json FROM tauth_grants g LEFT JOIN tauth_metadata m ON m.local_user_id = g.local_user_id AND m.app_id = g.app_id WHERE g.local_user_id = ?1 ORDER BY g.app_name, g.domain",
        )?;
        let rows = statement.query_map(params![local_user_id], grant_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })?)
}

pub fn issue_code(grant: AuthorizationGrant<'_>) -> Result<String, TAuthStorageError> {
    normalize_scopes(grant.scopes)?;
    let code = random_token();
    let code_hash = hash(&code);
    let now = now_seconds();
    db::with_immediate_transaction(|tx| issue_code_in(tx, grant, &code_hash, now))?;
    Ok(code)
}

fn issue_code_in(
    tx: &rusqlite::Transaction<'_>,
    grant: AuthorizationGrant<'_>,
    code_hash: &[u8; 32],
    now: i64,
) -> Result<(), StorageError> {
    let requested_scopes =
        normalize_scopes(grant.scopes).map_err(|error| StorageError::Other(error.to_string()))?;
    let requested_scopes_json =
        serde_json::to_string(&requested_scopes).expect("string list serializes");
    let mut granted_scopes = tx
        .query_row(
            "SELECT scopes FROM tauth_grants WHERE local_user_id = ?1 AND app_id = ?2",
            params![grant.local_user_id, grant.app_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|scopes| serde_json::from_str::<BTreeSet<String>>(&scopes))
        .transpose()
        .map_err(|error| StorageError::Other(error.to_string()))?
        .unwrap_or_default();
    granted_scopes.extend(requested_scopes);
    let granted_scopes_json =
        serde_json::to_string(&granted_scopes).expect("string set serializes");
    tx.execute(
        "DELETE FROM tauth_codes WHERE expires_at <= ?1",
        params![now],
    )?;
    tx.execute(
        r#"INSERT INTO tauth_grants (
                local_user_id, app_id, app_name, domain, redirect_uri, scopes,
                app_public_key, manifest_hash, security_state, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'secure', ?9)
            ON CONFLICT(local_user_id, app_id) DO UPDATE SET
                app_name = excluded.app_name,
                domain = excluded.domain,
                redirect_uri = excluded.redirect_uri,
                scopes = excluded.scopes,
                app_public_key = excluded.app_public_key,
                manifest_hash = excluded.manifest_hash,
                security_state = 'secure',
                updated_at = excluded.updated_at"#,
        params![
            grant.local_user_id,
            grant.app_id,
            grant.app_name,
            grant.domain,
            grant.redirect_uri,
            granted_scopes_json,
            grant.app_public_key,
            grant.manifest_hash,
            now,
        ],
    )?;
    tx.execute(
            "INSERT INTO tauth_codes (code_hash, local_user_id, app_id, redirect_uri, scopes, pkce_challenge, authorization_request, locator, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![code_hash.as_slice(), grant.local_user_id, grant.app_id, grant.redirect_uri, requested_scopes_json, grant.pkce_challenge, grant.authorization_request, grant.locator, now + AUTHORIZATION_CODE_LIFETIME_SECONDS],
    )?;
    Ok(())
}

pub fn authorization_request_for_code(code: &str) -> Result<Option<String>, TAuthStorageError> {
    let code_hash = hash(code);
    Ok(db::with_db(|conn| {
        conn.query_row(
            "SELECT authorization_request FROM tauth_codes WHERE code_hash = ?1 AND expires_at > ?2",
            params![code_hash.as_slice(), now_seconds()],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    })?)
}

pub fn exchange_code(
    code: &str,
    app_id: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Session, TAuthStorageError> {
    let code_hash = hash(code);
    let now = now_seconds();
    let token = random_token();
    let token_hash = hash(&token);
    let session = db::with_immediate_transaction(|tx| {
        exchange_code_in(
            tx,
            &code_hash,
            app_id,
            redirect_uri,
            verifier,
            &token_hash,
            now,
        )
    });
    let (local_user_id, app_id, scopes_json, locator) = session.map_err(map_exchange_error)?;
    Ok(Session {
        token,
        local_user_id,
        app_id,
        scopes: serde_json::from_str(&scopes_json)
            .map_err(|_| TAuthStorageError::InvalidSession)?,
        locator,
    })
}

fn exchange_code_in(
    tx: &rusqlite::Transaction<'_>,
    code_hash: &[u8; 32],
    app_id: &str,
    redirect_uri: &str,
    verifier: &str,
    token_hash: &[u8; 32],
    now: i64,
) -> Result<(i64, String, String, String), StorageError> {
    let row = tx
            .query_row(
                "SELECT local_user_id, app_id, redirect_uri, scopes, pkce_challenge, locator, expires_at FROM tauth_codes WHERE code_hash = ?1",
                params![code_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;
    tx.execute(
        "DELETE FROM tauth_codes WHERE code_hash = ?1",
        params![code_hash.as_slice()],
    )?;
    let Some((
        local_user_id,
        stored_app_id,
        stored_redirect,
        scopes_json,
        challenge,
        locator,
        expires_at,
    )) = row
    else {
        return Err(StorageError::Other("invalid authorization code".into()));
    };
    if expires_at <= now || stored_app_id != app_id || stored_redirect != redirect_uri {
        return Err(StorageError::Other("invalid authorization code".into()));
    }
    if pkce_challenge(verifier) != challenge {
        return Err(StorageError::Other("invalid PKCE verifier".into()));
    }
    let secure: bool = tx.query_row(
            "SELECT security_state = 'secure' FROM tauth_grants WHERE local_user_id = ?1 AND app_id = ?2",
            params![local_user_id, app_id],
            |row| row.get(0),
        )?;
    if !secure {
        return Err(StorageError::Other("insecure TAuth grant".into()));
    }
    tx.execute(
            "INSERT INTO tauth_sessions (token_hash, local_user_id, app_id, scopes, locator, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![token_hash.as_slice(), local_user_id, app_id, scopes_json, locator, now],
        )?;
    Ok((local_user_id, stored_app_id, scopes_json, locator))
}

fn map_exchange_error(error: StorageError) -> TAuthStorageError {
    match error {
        StorageError::Other(message) if message == "invalid PKCE verifier" => {
            TAuthStorageError::InvalidPkce
        }
        StorageError::Other(message) if message == "insecure TAuth grant" => {
            TAuthStorageError::InsecureGrant
        }
        StorageError::Other(message) if message == "invalid authorization code" => {
            TAuthStorageError::InvalidCode
        }
        other => TAuthStorageError::Storage(other),
    }
}

pub fn authorize_session(token: &str, required: Scope) -> Result<Session, TAuthStorageError> {
    let token_hash = hash(token);
    let session = db::with_db(|conn| authorize_session_in(conn, &token_hash))?
        .ok_or(TAuthStorageError::InvalidSession)?;
    let scopes: Vec<String> =
        serde_json::from_str(&session.2).map_err(|_| TAuthStorageError::InvalidSession)?;
    if !session_has_scope(&scopes, required) {
        return Err(TAuthStorageError::ScopeDenied(required.as_str()));
    }
    Ok(Session {
        token: token.to_owned(),
        local_user_id: session.0,
        app_id: session.1,
        scopes,
        locator: session.3,
    })
}

fn session_has_scope(scopes: &[String], required: Scope) -> bool {
    scopes.iter().any(|scope| scope == required.as_str())
}

fn authorize_session_in(
    conn: &rusqlite::Connection,
    token_hash: &[u8; 32],
) -> Result<Option<(i64, String, String, String)>, StorageError> {
    conn.query_row(
        "SELECT local_user_id, app_id, scopes, locator FROM tauth_sessions WHERE token_hash = ?1",
        params![token_hash.as_slice()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn mark_insecure(app_id: &str, domain: &str) -> Result<usize, TAuthStorageError> {
    Ok(db::with_db(|conn| {
        mark_insecure_in(conn, app_id, domain, now_seconds())
    })?)
}

fn mark_insecure_in(
    conn: &rusqlite::Connection,
    app_id: &str,
    domain: &str,
    now: i64,
) -> Result<usize, StorageError> {
    Ok(conn.execute(
            "UPDATE tauth_grants SET security_state = 'insecure', updated_at = ?3 WHERE app_id = ?1 AND domain = ?2",
            params![app_id, domain, now],
    )?)
}

pub fn get_metadata(token: &str) -> Result<Option<String>, TAuthStorageError> {
    let session = authorize_session(token, Scope::MetadataRead)?;
    Ok(db::with_db(|conn| {
        conn.query_row(
            "SELECT json FROM tauth_metadata WHERE local_user_id = ?1 AND app_id = ?2",
            params![session.local_user_id, session.app_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    })?)
}

pub fn set_metadata(token: &str, json: &str) -> Result<(), TAuthStorageError> {
    let session = authorize_session(token, Scope::MetadataWrite)?;
    validate_json(json)?;
    db::with_db(|conn| {
        conn.execute(
            "INSERT INTO tauth_metadata (local_user_id, app_id, json, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(local_user_id, app_id) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at",
            params![session.local_user_id, session.app_id, json, now_seconds()],
        )?;
        Ok(())
    })?;
    Ok(())
}

pub fn set_metadata_for_user(
    local_user_id: i64,
    app_id: &str,
    json: &str,
) -> Result<(), TAuthStorageError> {
    validate_json(json)?;
    db::with_immediate_transaction(|tx| {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM tauth_grants WHERE local_user_id = ?1 AND app_id = ?2)",
            params![local_user_id, app_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StorageError::Other("TAuth grant does not exist".into()));
        }
        tx.execute(
            "INSERT INTO tauth_metadata (local_user_id, app_id, json, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(local_user_id, app_id) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at",
            params![local_user_id, app_id, json, now_seconds()],
        )?;
        Ok(())
    })?;
    Ok(())
}

pub fn delete_metadata(token: &str) -> Result<(), TAuthStorageError> {
    let session = authorize_session(token, Scope::MetadataWrite)?;
    db::with_db(|conn| {
        conn.execute(
            "DELETE FROM tauth_metadata WHERE local_user_id = ?1 AND app_id = ?2",
            params![session.local_user_id, session.app_id],
        )?;
        Ok(())
    })?;
    Ok(())
}

pub fn disconnect_and_delete(token: &str) -> Result<(), TAuthStorageError> {
    let token_hash = hash(token);
    db::with_immediate_transaction(|tx| {
        let grant = tx
            .query_row(
                "SELECT local_user_id, app_id FROM tauth_sessions WHERE token_hash = ?1",
                params![token_hash.as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((local_user_id, app_id)) = grant else {
            return Err(StorageError::Other("invalid TAuth session".into()));
        };
        revoke_grant_in(tx, local_user_id, &app_id)?;
        Ok(())
    })
    .map_err(|error| match error {
        StorageError::Other(message) if message == "invalid TAuth session" => {
            TAuthStorageError::InvalidSession
        }
        other => TAuthStorageError::Storage(other),
    })
}

pub fn revoke_grant(local_user_id: i64, app_id: &str) -> Result<bool, TAuthStorageError> {
    Ok(db::with_immediate_transaction(|tx| {
        revoke_grant_in(tx, local_user_id, app_id)
    })?)
}

fn revoke_grant_in(
    tx: &rusqlite::Transaction<'_>,
    local_user_id: i64,
    app_id: &str,
) -> Result<bool, StorageError> {
    tx.execute(
        "DELETE FROM tauth_codes WHERE local_user_id = ?1 AND app_id = ?2",
        params![local_user_id, app_id],
    )?;
    tx.execute(
        "DELETE FROM tauth_sessions WHERE local_user_id = ?1 AND app_id = ?2",
        params![local_user_id, app_id],
    )?;
    tx.execute(
        "DELETE FROM tauth_metadata WHERE local_user_id = ?1 AND app_id = ?2",
        params![local_user_id, app_id],
    )?;
    Ok(tx.execute(
        "DELETE FROM tauth_grants WHERE local_user_id = ?1 AND app_id = ?2",
        params![local_user_id, app_id],
    )? > 0)
}

pub fn canonical_contact_ids(local_user_id: i64) -> Result<Vec<String>, TAuthStorageError> {
    Ok(db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT p.authority_id, p.remote_user_id FROM contacts c JOIN principals p ON p.principal_pk = c.principal_handle WHERE c.storage_owner = ?1 ORDER BY p.authority_id, p.remote_user_id",
        )?;
        let rows = statement.query_map(params![local_user_id], |row| {
            Ok(format!(
                "{}#{}",
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })?)
}

pub fn canonical_principal(local_user_id: i64) -> Result<Option<String>, TAuthStorageError> {
    Ok(db::with_db(|conn| {
        conn.query_row(
            "SELECT p.authority_id, p.remote_user_id FROM hosted_principals h JOIN principals p ON p.principal_pk = h.principal_handle WHERE h.local_user_id = ?1",
            params![local_user_id],
            |row| Ok(format!("{}#{}", row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(Into::into)
    })?)
}

pub fn public_profile(principal: &str) -> Result<Option<serde_json::Value>, TAuthStorageError> {
    let Some((authority, user_id)) = principal.rsplit_once('#') else {
        return Ok(None);
    };
    let Ok(user_id) = user_id.parse::<i64>() else {
        return Ok(None);
    };
    if user_id < 0 {
        return Ok(None);
    }
    Ok(db::with_db(|conn| {
        let profile = conn
            .query_row(
                "SELECT principal_pk, username, display_name FROM principals WHERE authority_id = ?1 AND remote_user_id = ?2",
                params![authority, user_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, Option<String>>(2)?)),
            )
            .optional()?;
        let Some((handle, username, display_name)) = profile else {
            return Ok(None);
        };
        let mut statement = conn.prepare("SELECT public_key FROM principal_keys WHERE principal_pk = ?1 ORDER BY valid_from DESC")?;
        let keys = statement
            .query_map(params![handle], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(serde_json::json!({
            "principal": principal,
            "username": username,
            "display_name": display_name,
            "avatar": null,
            "public_keys": keys,
            "home_node": null,
        })))
    })?)
}

pub fn is_local_principal(principal: &str) -> Result<bool, TAuthStorageError> {
    let Some((authority, user_id)) = principal.rsplit_once('#') else {
        return Ok(false);
    };
    let Ok(user_id) = user_id.parse::<i64>() else {
        return Ok(false);
    };
    Ok(db::with_db(|conn| {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosted_principals h JOIN principals p ON p.principal_pk = h.principal_handle WHERE p.authority_id = ?1 AND p.remote_user_id = ?2)",
            params![authority, user_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
    })?)
}

fn validate_json(json: &str) -> Result<(), TAuthStorageError> {
    if json.len() > MAX_METADATA_BYTES {
        return Err(TAuthStorageError::MetadataTooLarge);
    }
    serde_json::from_str::<serde_json::Value>(json).map_err(|_| TAuthStorageError::InvalidJson)?;
    Ok(())
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn owner_app_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OwnerApp> {
    Ok(OwnerApp {
        app_id: row.get(0)?,
        owner_user_id: row.get(1)?,
        domain: row.get(2)?,
        public_key: row.get(3)?,
        owner_certificate: row.get(4)?,
        connection_mode: row.get(5)?,
        endpoint_url: row.get(6)?,
        omikron_public_key: row.get(7)?,
        created_at: row.get(8)?,
    })
}

fn grant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Grant> {
    let scopes_json: String = row.get(5)?;
    let scopes = serde_json::from_str(&scopes_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            scopes_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(Grant {
        local_user_id: row.get(0)?,
        app_id: row.get(1)?,
        app_name: row.get(2)?,
        domain: row.get(3)?,
        redirect_uri: row.get(4)?,
        scopes,
        app_public_key: row.get(6)?,
        manifest_hash: row.get(7)?,
        insecure: row.get::<_, String>(8)? == "insecure",
        updated_at: row.get(9)?,
        metadata: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn test_database() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE tauth_grants (
                    local_user_id INTEGER NOT NULL,
                    app_id TEXT NOT NULL,
                    app_name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    app_public_key TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    security_state TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (local_user_id, app_id)
                );
                CREATE TABLE tauth_codes (
                    code_hash BLOB PRIMARY KEY,
                    local_user_id INTEGER NOT NULL,
                    app_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    pkce_challenge TEXT NOT NULL,
                    authorization_request TEXT NOT NULL,
                    locator TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE tauth_sessions (
                    token_hash BLOB PRIMARY KEY,
                    local_user_id INTEGER NOT NULL,
                    app_id TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    locator TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE tauth_metadata (
                    local_user_id INTEGER NOT NULL,
                    app_id TEXT NOT NULL,
                    json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (local_user_id, app_id)
                );
                "#,
            )
            .unwrap();
        connection
    }

    fn issue_test_code(connection: &mut Connection, code: &str, scopes: &[String], now: i64) {
        let verifier = "verifier";
        let tx = connection.transaction().unwrap();
        issue_code_in(
            &tx,
            AuthorizationGrant {
                local_user_id: 7,
                app_id: "app",
                app_name: "Example",
                domain: "app.example",
                redirect_uri: "https://app.example/callback",
                scopes,
                app_public_key: "key",
                manifest_hash: "hash",
                pkce_challenge: &pkce_challenge(verifier),
                authorization_request: "request",
                locator: "locator",
            },
            &hash(code),
            now,
        )
        .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn metadata_validation_rejects_invalid_and_oversized_json() {
        assert!(matches!(
            validate_json("{"),
            Err(TAuthStorageError::InvalidJson)
        ));
        let oversized = format!("\"{}\"", "x".repeat(MAX_METADATA_BYTES));
        assert!(matches!(
            validate_json(&oversized),
            Err(TAuthStorageError::MetadataTooLarge)
        ));
    }

    #[test]
    fn pkce_uses_s256_base64url() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn codes_bind_redirect_expire_once_and_enforce_scopes() {
        let mut connection = test_database();
        let scopes = vec!["identity.read".to_owned()];
        issue_test_code(&mut connection, "valid-code", &scopes, 1_000);

        let tx = connection.transaction().unwrap();
        assert!(
            exchange_code_in(
                &tx,
                &hash("valid-code"),
                "app",
                "https://evil.example/callback",
                "verifier",
                &hash("token"),
                1_001,
            )
            .is_err()
        );
        drop(tx);

        let tx = connection.transaction().unwrap();
        let session = exchange_code_in(
            &tx,
            &hash("valid-code"),
            "app",
            "https://app.example/callback",
            "verifier",
            &hash("token"),
            1_001,
        )
        .unwrap();
        tx.commit().unwrap();
        let session_scopes: Vec<String> = serde_json::from_str(&session.2).unwrap();
        assert!(session_has_scope(&session_scopes, Scope::IdentityRead));
        assert!(!session_has_scope(&session_scopes, Scope::MetadataRead));

        let tx = connection.transaction().unwrap();
        assert!(
            exchange_code_in(
                &tx,
                &hash("valid-code"),
                "app",
                "https://app.example/callback",
                "verifier",
                &hash("second-token"),
                1_002,
            )
            .is_err()
        );
        drop(tx);

        issue_test_code(&mut connection, "expired-code", &scopes, 2_000);
        let tx = connection.transaction().unwrap();
        assert!(
            exchange_code_in(
                &tx,
                &hash("expired-code"),
                "app",
                "https://app.example/callback",
                "verifier",
                &hash("expired-token"),
                2_061,
            )
            .is_err()
        );
    }

    #[test]
    fn insecure_discovery_blocks_new_sessions_but_revoke_cleans_everything() {
        let mut connection = test_database();
        let scopes = vec!["identity.read".to_owned()];
        issue_test_code(&mut connection, "first-code", &scopes, 1_000);
        let tx = connection.transaction().unwrap();
        exchange_code_in(
            &tx,
            &hash("first-code"),
            "app",
            "https://app.example/callback",
            "verifier",
            &hash("live-token"),
            1_001,
        )
        .unwrap();
        tx.commit().unwrap();
        connection
            .execute(
                "INSERT INTO tauth_metadata VALUES (7, 'app', '{}', 1001)",
                [],
            )
            .unwrap();
        issue_test_code(&mut connection, "pending-code", &scopes, 1_002);
        assert_eq!(
            mark_insecure_in(&connection, "app", "app.example", 1_003).unwrap(),
            1
        );
        assert!(
            authorize_session_in(&connection, &hash("live-token"))
                .unwrap()
                .is_some()
        );

        let tx = connection.transaction().unwrap();
        assert!(
            exchange_code_in(
                &tx,
                &hash("pending-code"),
                "app",
                "https://app.example/callback",
                "verifier",
                &hash("blocked-token"),
                1_004,
            )
            .is_err()
        );
        drop(tx);

        let tx = connection.transaction().unwrap();
        assert!(revoke_grant_in(&tx, 7, "app").unwrap());
        tx.commit().unwrap();
        for table in [
            "tauth_grants",
            "tauth_codes",
            "tauth_sessions",
            "tauth_metadata",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} was not cleaned up");
        }
    }

    #[test]
    fn narrower_session_keeps_broader_persistent_grant() {
        let mut connection = test_database();
        issue_test_code(
            &mut connection,
            "broad-code",
            &["identity.read".to_owned(), "metadata.read".to_owned()],
            1_000,
        );
        issue_test_code(
            &mut connection,
            "narrow-code",
            &["identity.read".to_owned()],
            1_001,
        );
        let grant_scopes: String = connection
            .query_row(
                "SELECT scopes FROM tauth_grants WHERE local_user_id = 7 AND app_id = 'app'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let grant_scopes: BTreeSet<String> = serde_json::from_str(&grant_scopes).unwrap();
        assert_eq!(
            grant_scopes,
            BTreeSet::from(["identity.read".to_owned(), "metadata.read".to_owned()])
        );
        let code_scopes: String = connection
            .query_row(
                "SELECT scopes FROM tauth_codes WHERE code_hash = ?1",
                params![hash("narrow-code").as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&code_scopes).unwrap(),
            vec!["identity.read"]
        );
    }
}
