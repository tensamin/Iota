use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_ipc::{SecretString, TAuthAppSummary, TAuthConnectionInput};
use iota_storage::tauth::{self, OwnerApp};
use iota_util::crypto_helper::{public_key_bundle_from_base64, public_key_bundle_to_base64};
use iota_util::ta::{ConnectionMode, TaCredential};
use mtp::crypto::{Ed25519Signer, Keyring, SignatureScheme};
use serde::Serialize;
use std::collections::BTreeSet;
use url::Url;

#[derive(Serialize)]
struct UnsignedOwnerCertificate<'a> {
    version: u16,
    app_id: &'a str,
    app_public_key: &'a str,
    owner_principal: &'a str,
    owner_public_key: &'a str,
    owner_iota_id: u64,
    issued_at: i64,
}

#[derive(Serialize)]
struct OwnerCertificate<'a> {
    version: u16,
    app_id: &'a str,
    app_public_key: &'a str,
    owner_principal: &'a str,
    owner_public_key: &'a str,
    owner_iota_id: u64,
    issued_at: i64,
    signature: String,
}

#[derive(Serialize)]
struct UnsignedManifest<'a> {
    version: u16,
    app_id: &'a str,
    public_key: &'a str,
    name: &'a str,
    domain: &'a str,
    redirects: &'a [String],
    owner_certificate: &'a str,
}

#[derive(Serialize)]
struct Manifest<'a> {
    version: u16,
    app_id: &'a str,
    public_key: &'a str,
    name: &'a str,
    domain: &'a str,
    redirects: &'a [String],
    owner_certificate: &'a str,
    signature: String,
}

pub struct CreatedApp {
    pub app: TAuthAppSummary,
    pub credential: SecretString,
    pub txt_record: String,
    pub manifest_template: String,
}

pub fn list() -> Result<Vec<TAuthAppSummary>, String> {
    tauth::list_owner_apps()
        .map(|apps| apps.into_iter().map(summary).collect())
        .map_err(|error| error.to_string())
}

pub fn get(app_id: &str) -> Result<Option<TAuthAppSummary>, String> {
    tauth::get_owner_app(app_id)
        .map(|app| app.map(summary))
        .map_err(|error| error.to_string())
}

pub fn export(app_id: &str) -> Result<Option<SecretString>, String> {
    iota_util::file_util::read_tauth_credential(app_id)
        .map(|credential| credential.map(|bytes| SecretString(STANDARD.encode(bytes))))
        .map_err(|error| error.to_string())
}

pub fn delete(app_id: &str) -> Result<bool, String> {
    if tauth::get_owner_app(app_id)
        .map_err(|error| error.to_string())?
        .is_none()
    {
        return Ok(false);
    }
    iota_util::file_util::remove_tauth_credential(app_id).map_err(|error| error.to_string())?;
    tauth::delete_owner_app(app_id).map_err(|error| error.to_string())
}

pub fn create(
    owner_user_id: i64,
    domain: String,
    name: String,
    redirects: Vec<String>,
    connection: TAuthConnectionInput,
) -> Result<CreatedApp, String> {
    let domain = canonical_domain(domain)?;
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err("app name is empty".into());
    }
    let redirects = redirects
        .into_iter()
        .map(|redirect| validate_redirect(&redirect).map(|()| redirect))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    if redirects.is_empty() {
        return Err("at least one redirect is required".into());
    }
    let owner_iota_id = iota_storage::util::config_util::CONFIG
        .load()
        .iota_id
        .ok_or_else(|| "Iota ID is not configured".to_string())?;
    let owner = iota_storage::users::user_manager::get_user(owner_user_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "owner user does not exist".to_string())?;
    let owner_credential =
        iota_util::file_util::read_user_credential_with_legacy(owner_user_id, &owner.username)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "owner user credential is unavailable".to_string())?;
    let owner_credential =
        iota_util::tu::TuCredential::parse(&owner_credential).map_err(|error| error.to_string())?;
    let owner_principal = owner_credential
        .principal()
        .map_err(|error| error.to_string())?;
    let owner_principal = format!(
        "{}#{}",
        owner_principal.authority.as_str(),
        owner_principal.user_id
    );
    let owner_public_key = public_key_bundle_to_base64(&owner_credential.public_key_bundle());

    let keyring = Keyring::generate();
    let app_id = iota_util::ta::app_id(&keyring.public_key_bundle());
    let app_public_key = public_key_bundle_to_base64(&keyring.public_key_bundle());
    let issued_at = tauth::now_seconds();
    let unsigned_certificate = UnsignedOwnerCertificate {
        version: 1,
        app_id: &app_id,
        app_public_key: &app_public_key,
        owner_principal: &owner_principal,
        owner_public_key: &owner_public_key,
        owner_iota_id,
        issued_at,
    };
    let owner_signer = Ed25519Signer::new(&owner_credential.keyring.sig_cl_secret_key)
        .map_err(|error| error.to_string())?;
    let owner_signature = owner_signer
        .sign(&serde_json::to_vec(&unsigned_certificate).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let certificate = OwnerCertificate {
        version: unsigned_certificate.version,
        app_id: unsigned_certificate.app_id,
        app_public_key: unsigned_certificate.app_public_key,
        owner_principal: unsigned_certificate.owner_principal,
        owner_public_key: unsigned_certificate.owner_public_key,
        owner_iota_id: unsigned_certificate.owner_iota_id,
        issued_at: unsigned_certificate.issued_at,
        signature: STANDARD.encode(owner_signature),
    };
    let certificate_bytes = serde_json::to_vec(&certificate).map_err(|error| error.to_string())?;
    let owner_certificate = STANDARD.encode(&certificate_bytes);

    let unsigned_manifest = UnsignedManifest {
        version: 1,
        app_id: &app_id,
        public_key: &app_public_key,
        name: &name,
        domain: &domain,
        redirects: &redirects,
        owner_certificate: &owner_certificate,
    };
    let app_signer =
        Ed25519Signer::new(&keyring.sig_cl_secret_key).map_err(|error| error.to_string())?;
    let manifest_signature = app_signer
        .sign(&serde_json::to_vec(&unsigned_manifest).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let manifest = Manifest {
        version: unsigned_manifest.version,
        app_id: unsigned_manifest.app_id,
        public_key: unsigned_manifest.public_key,
        name: unsigned_manifest.name,
        domain: unsigned_manifest.domain,
        redirects: unsigned_manifest.redirects,
        owner_certificate: unsigned_manifest.owner_certificate,
        signature: STANDARD.encode(manifest_signature),
    };
    let manifest_template =
        serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?;

    let (mode, connection_mode, endpoint_url, omikron_public_key) = match connection {
        TAuthConnectionInput::Hosted { omega_url } => {
            let omega_url = validate_https(&omega_url)?;
            (
                ConnectionMode::Hosted {
                    omega_url: omega_url.clone(),
                    owner_iota_id,
                },
                "hosted".to_owned(),
                omega_url.to_string(),
                None,
            )
        }
        TAuthConnectionInput::ForcedOmikron {
            omikron_url,
            omikron_public_key,
        } => {
            let omikron_url = validate_https(&omikron_url)?;
            let key = public_key_bundle_from_base64(&omikron_public_key)
                .ok_or_else(|| "forced Omikron public key is invalid".to_string())?;
            (
                ConnectionMode::ForcedOmikron {
                    omikron_url: omikron_url.clone(),
                    omikron_public_key: key,
                    owner_iota_id,
                },
                "forced_omikron".to_owned(),
                omikron_url.to_string(),
                Some(omikron_public_key),
            )
        }
    };
    let credential = TaCredential {
        keyring,
        owner_certificate: certificate_bytes,
        mode,
    };
    let credential_bytes = credential.to_bytes().map_err(|error| error.to_string())?;
    let credential_path =
        iota_util::file_util::tauth_credential_path(&app_id).map_err(|error| error.to_string())?;
    credential
        .export(&credential_path)
        .map_err(|error| error.to_string())?;

    let app = OwnerApp {
        app_id: app_id.clone(),
        owner_user_id,
        domain: domain.clone(),
        public_key: app_public_key,
        owner_certificate,
        connection_mode,
        endpoint_url,
        omikron_public_key,
        created_at: issued_at,
    };
    if let Err(error) = tauth::register_owner_app(&app) {
        let _ = iota_util::file_util::remove_tauth_credential(&app_id);
        return Err(error.to_string());
    }
    let manifest_hash = hex::encode(mtp::crypto::sha256(manifest_template.as_bytes()));
    Ok(CreatedApp {
        app: summary(app),
        credential: SecretString(STANDARD.encode(credential_bytes)),
        txt_record: format!("v=TAUTH1;app={app_id};manifest={manifest_hash}"),
        manifest_template,
    })
}

fn summary(app: OwnerApp) -> TAuthAppSummary {
    TAuthAppSummary {
        app_id: app.app_id,
        owner_user_id: app.owner_user_id,
        domain: app.domain,
        public_key: app.public_key,
        connection_mode: app.connection_mode,
        endpoint_url: app.endpoint_url,
        created_at: app.created_at,
    }
}

fn canonical_domain(domain: String) -> Result<String, String> {
    let domain = domain.trim().to_ascii_lowercase();
    if domain.is_empty()
        || domain.contains(['/', ':'])
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("app domain is invalid".into());
    }
    Ok(domain)
}

fn validate_redirect(value: &str) -> Result<(), String> {
    let url = Url::parse(value).map_err(|error| error.to_string())?;
    let loopback = url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url
            .query_pairs()
            .any(|(key, _)| matches!(key.as_ref(), "code" | "state" | "locator" | "error"))
        || (url.scheme() != "https" && !loopback)
    {
        return Err("redirect must be exact HTTPS, or HTTP loopback, without a fragment".into());
    }
    Ok(())
}

fn validate_https(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| error.to_string())?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err("connection URL must use HTTPS".into());
    }
    Ok(url)
}
