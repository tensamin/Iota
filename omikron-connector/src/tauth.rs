use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_storage::tauth::{self, Scope};
use mtp::crypto::{PublicKeyBundle, verify_ed25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAuthorizationRequest {
    pub version: u16,
    pub app_id: String,
    pub domain: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub pkce_challenge: String,
    pub expires_at: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppManifest {
    pub version: u16,
    pub app_id: String,
    pub public_key: String,
    pub name: String,
    pub domain: String,
    pub redirects: Vec<String>,
    pub owner_certificate: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerCertificate {
    pub version: u16,
    pub app_id: String,
    pub app_public_key: String,
    pub owner_principal: String,
    pub owner_public_key: String,
    pub owner_iota_id: u64,
    pub issued_at: i64,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedAuthorization {
    pub request: SignedAuthorizationRequest,
    pub manifest: AppManifest,
    pub manifest_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid signed authorization request: {0}")]
    Request(String),
    #[error("TAuth DNS discovery failed: {0}")]
    Dns(String),
    #[error("TAuth manifest fetch failed: {0}")]
    Http(String),
    #[error("TAuth manifest verification failed: {0}")]
    Manifest(String),
}

#[derive(Serialize)]
struct UnsignedAuthorizationRequest<'a> {
    version: u16,
    app_id: &'a str,
    domain: &'a str,
    redirect_uri: &'a str,
    scopes: &'a [String],
    state: &'a str,
    pkce_challenge: &'a str,
    expires_at: i64,
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
struct UnsignedOwnerCertificate<'a> {
    version: u16,
    app_id: &'a str,
    app_public_key: &'a str,
    owner_principal: &'a str,
    owner_public_key: &'a str,
    owner_iota_id: u64,
    issued_at: i64,
}

pub async fn verify_authorization(
    client: &reqwest::Client,
    request_json: &str,
) -> Result<VerifiedAuthorization, VerificationError> {
    let request: SignedAuthorizationRequest = serde_json::from_str(request_json)
        .map_err(|error| VerificationError::Request(error.to_string()))?;
    validate_request_shape(&request)?;
    let result = verify_discovery(client, &request).await;
    if matches!(
        &result,
        Err(VerificationError::Dns(_)
            | VerificationError::Http(_)
            | VerificationError::Manifest(_))
    ) {
        let _ = tauth::mark_insecure(&request.app_id, &request.domain);
    }
    result
}

async fn verify_discovery(
    client: &reqwest::Client,
    request: &SignedAuthorizationRequest,
) -> Result<VerifiedAuthorization, VerificationError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup = resolver
        .txt_lookup(format!("_tauth.{}", request.domain))
        .await
        .map_err(|error| VerificationError::Dns(error.to_string()))?;
    let txt = lookup
        .iter()
        .map(|record| {
            record
                .txt_data()
                .iter()
                .flat_map(|part| part.iter().copied())
                .collect::<Vec<_>>()
        })
        .find_map(|bytes| {
            String::from_utf8(bytes)
                .ok()
                .filter(|value| value.starts_with("v=TAUTH1;"))
        })
        .ok_or_else(|| VerificationError::Dns("missing v=TAUTH1 TXT value".into()))?;
    let txt_app_id = txt_value(&txt, "app")
        .ok_or_else(|| VerificationError::Dns("TXT app fingerprint is missing".into()))?;
    let txt_manifest_hash = txt_value(&txt, "manifest")
        .ok_or_else(|| VerificationError::Dns("TXT manifest hash is missing".into()))?;
    if txt_app_id != request.app_id || !is_sha256_hex(txt_manifest_hash) {
        return Err(VerificationError::Dns(
            "TXT fingerprint or manifest hash is invalid".into(),
        ));
    }

    let manifest_url = Url::parse(&format!(
        "https://{}/.well-known/tauth.json",
        request.domain
    ))
    .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    let response = client
        .get(manifest_url)
        .send()
        .await
        .map_err(|error| VerificationError::Http(error.to_string()))?
        .error_for_status()
        .map_err(|error| VerificationError::Http(error.to_string()))?;
    let bytes = response
        .bytes()
        .await
        .map_err(|error| VerificationError::Http(error.to_string()))?;
    let manifest_hash = hex::encode(Sha256::digest(&bytes));
    if manifest_hash != txt_manifest_hash.to_ascii_lowercase() {
        return Err(VerificationError::Manifest(
            "manifest hash does not match DNS".into(),
        ));
    }
    let manifest: AppManifest = serde_json::from_slice(&bytes)
        .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    validate_manifest(request, &manifest)?;
    Ok(VerifiedAuthorization {
        request: request.clone(),
        manifest,
        manifest_hash,
    })
}

fn validate_request_shape(request: &SignedAuthorizationRequest) -> Result<(), VerificationError> {
    if request.version != 1 || !is_sha256_hex(&request.app_id) || request.state.is_empty() {
        return Err(VerificationError::Request(
            "version, app ID, or state is invalid".into(),
        ));
    }
    let domain = request.domain.trim().to_ascii_lowercase();
    if domain != request.domain || domain.is_empty() || domain.contains('/') {
        return Err(VerificationError::Request("domain is not canonical".into()));
    }
    validate_redirect(&request.redirect_uri)?;
    tauth::normalize_scopes(&request.scopes)
        .map_err(|error| VerificationError::Request(error.to_string()))?;
    if request.pkce_challenge.len() < 43 || request.pkce_challenge.len() > 128 {
        return Err(VerificationError::Request(
            "PKCE challenge length is invalid".into(),
        ));
    }
    let now = tauth::now_seconds();
    if request.expires_at <= now || request.expires_at > now + 300 {
        return Err(VerificationError::Request(
            "request is expired or too long-lived".into(),
        ));
    }
    Ok(())
}

fn validate_manifest(
    request: &SignedAuthorizationRequest,
    manifest: &AppManifest,
) -> Result<(), VerificationError> {
    if manifest.version != 1
        || manifest.app_id != request.app_id
        || manifest.domain != request.domain
        || manifest.name.trim().is_empty()
        || !manifest
            .redirects
            .iter()
            .any(|redirect| redirect == &request.redirect_uri)
    {
        return Err(VerificationError::Manifest(
            "manifest fields do not match request".into(),
        ));
    }
    for redirect in &manifest.redirects {
        validate_redirect(redirect)?;
    }
    let public_key = PublicKeyBundle::from_base64(&manifest.public_key)
        .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    if iota_util::ta::app_id(&public_key) != request.app_id {
        return Err(VerificationError::Manifest(
            "public key fingerprint does not match app ID".into(),
        ));
    }
    let owner_bytes = STANDARD
        .decode(&manifest.owner_certificate)
        .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    let owner: OwnerCertificate = serde_json::from_slice(&owner_bytes)
        .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    validate_owner_certificate(&owner, manifest)?;
    verify(
        &public_key,
        &serde_json::to_vec(&UnsignedManifest {
            version: manifest.version,
            app_id: &manifest.app_id,
            public_key: &manifest.public_key,
            name: &manifest.name,
            domain: &manifest.domain,
            redirects: &manifest.redirects,
            owner_certificate: &manifest.owner_certificate,
        })
        .expect("manifest fields serialize"),
        &manifest.signature,
        "manifest",
    )?;
    let request_signature = STANDARD
        .decode(&request.signature)
        .map_err(|error| VerificationError::Request(error.to_string()))?;
    verify_ed25519(
        &public_key.sig_cl_public_key,
        &serde_json::to_vec(&UnsignedAuthorizationRequest {
            version: request.version,
            app_id: &request.app_id,
            domain: &request.domain,
            redirect_uri: &request.redirect_uri,
            scopes: &request.scopes,
            state: &request.state,
            pkce_challenge: &request.pkce_challenge,
            expires_at: request.expires_at,
        })
        .expect("authorization fields serialize"),
        &request_signature,
    )
    .map_err(|_| VerificationError::Request("authorization request signature is invalid".into()))
}

fn validate_owner_certificate(
    owner: &OwnerCertificate,
    manifest: &AppManifest,
) -> Result<(), VerificationError> {
    if owner.version != 1
        || owner.owner_iota_id == 0
        || owner.owner_principal.is_empty()
        || owner.app_id != manifest.app_id
        || owner.app_public_key != manifest.public_key
    {
        return Err(VerificationError::Manifest(
            "owner certificate does not bind this app".into(),
        ));
    }
    let owner_key = PublicKeyBundle::from_base64(&owner.owner_public_key)
        .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    verify(
        &owner_key,
        &serde_json::to_vec(&UnsignedOwnerCertificate {
            version: owner.version,
            app_id: &owner.app_id,
            app_public_key: &owner.app_public_key,
            owner_principal: &owner.owner_principal,
            owner_public_key: &owner.owner_public_key,
            owner_iota_id: owner.owner_iota_id,
            issued_at: owner.issued_at,
        })
        .expect("certificate fields serialize"),
        &owner.signature,
        "owner certificate",
    )
}

fn verify(
    key: &PublicKeyBundle,
    message: &[u8],
    encoded_signature: &str,
    label: &str,
) -> Result<(), VerificationError> {
    let signature = STANDARD
        .decode(encoded_signature)
        .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    verify_ed25519(&key.sig_cl_public_key, message, &signature)
        .map_err(|_| VerificationError::Manifest(format!("{label} signature is invalid")))
}

fn validate_redirect(value: &str) -> Result<(), VerificationError> {
    let url = Url::parse(value).map_err(|error| VerificationError::Request(error.to_string()))?;
    let localhost = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && localhost))
        || url.fragment().is_some()
        || url
            .query_pairs()
            .any(|(key, _)| matches!(key.as_ref(), "code" | "state" | "locator" | "error"))
    {
        return Err(VerificationError::Request(
            "redirect URL must be exact HTTPS without a fragment".into(),
        ));
    }
    Ok(())
}

fn txt_value<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    record.split(';').find_map(|field| {
        field
            .split_once('=')
            .filter(|(name, value)| *name == key && !value.is_empty())
            .map(|(_, value)| value)
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn scope_for_command(command: mtp::codec::CommunicationType) -> Option<Scope> {
    use mtp::codec::CommunicationType;
    match command {
        CommunicationType::TAuthUser | CommunicationType::TAuthPublicLookup => {
            Some(Scope::IdentityRead)
        }
        CommunicationType::TAuthContacts => Some(Scope::ContactsRead),
        CommunicationType::TAuthMetadataGet => Some(Scope::MetadataRead),
        CommunicationType::TAuthMetadataSet | CommunicationType::TAuthMetadataDelete => {
            Some(Scope::MetadataWrite)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp::crypto::{Ed25519Signer, Keyring, SignatureScheme};

    fn signed_authorization() -> (SignedAuthorizationRequest, AppManifest) {
        let app_keyring = Keyring::generate();
        let owner_keyring = Keyring::generate();
        let app_public_key = app_keyring.public_key_bundle().try_to_base64().unwrap();
        let owner_public_key = owner_keyring.public_key_bundle().try_to_base64().unwrap();
        let app_id = iota_util::ta::app_id(&app_keyring.public_key_bundle());
        let owner_unsigned = UnsignedOwnerCertificate {
            version: 1,
            app_id: &app_id,
            app_public_key: &app_public_key,
            owner_principal: "iota:owner#7",
            owner_public_key: &owner_public_key,
            owner_iota_id: 7,
            issued_at: tauth::now_seconds(),
        };
        let owner_signer = Ed25519Signer::new(&owner_keyring.sig_cl_secret_key).unwrap();
        let owner = OwnerCertificate {
            version: owner_unsigned.version,
            app_id: owner_unsigned.app_id.to_owned(),
            app_public_key: owner_unsigned.app_public_key.to_owned(),
            owner_principal: owner_unsigned.owner_principal.to_owned(),
            owner_public_key: owner_unsigned.owner_public_key.to_owned(),
            owner_iota_id: owner_unsigned.owner_iota_id,
            issued_at: owner_unsigned.issued_at,
            signature: STANDARD.encode(
                owner_signer
                    .sign(&serde_json::to_vec(&owner_unsigned).unwrap())
                    .unwrap(),
            ),
        };
        let owner_certificate = STANDARD.encode(serde_json::to_vec(&owner).unwrap());
        let redirects = vec!["https://app.example/callback".to_owned()];
        let manifest_unsigned = UnsignedManifest {
            version: 1,
            app_id: &app_id,
            public_key: &app_public_key,
            name: "Example",
            domain: "app.example",
            redirects: &redirects,
            owner_certificate: &owner_certificate,
        };
        let app_signer = Ed25519Signer::new(&app_keyring.sig_cl_secret_key).unwrap();
        let manifest = AppManifest {
            version: manifest_unsigned.version,
            app_id: manifest_unsigned.app_id.to_owned(),
            public_key: manifest_unsigned.public_key.to_owned(),
            name: manifest_unsigned.name.to_owned(),
            domain: manifest_unsigned.domain.to_owned(),
            redirects: manifest_unsigned.redirects.to_vec(),
            owner_certificate: manifest_unsigned.owner_certificate.to_owned(),
            signature: STANDARD.encode(
                app_signer
                    .sign(&serde_json::to_vec(&manifest_unsigned).unwrap())
                    .unwrap(),
            ),
        };
        let scopes = vec!["identity.read".to_owned()];
        let request_unsigned = UnsignedAuthorizationRequest {
            version: 1,
            app_id: &app_id,
            domain: "app.example",
            redirect_uri: &redirects[0],
            scopes: &scopes,
            state: "state",
            pkce_challenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expires_at: tauth::now_seconds() + 60,
        };
        let request = SignedAuthorizationRequest {
            version: request_unsigned.version,
            app_id: request_unsigned.app_id.to_owned(),
            domain: request_unsigned.domain.to_owned(),
            redirect_uri: request_unsigned.redirect_uri.to_owned(),
            scopes: request_unsigned.scopes.to_vec(),
            state: request_unsigned.state.to_owned(),
            pkce_challenge: request_unsigned.pkce_challenge.to_owned(),
            expires_at: request_unsigned.expires_at,
            signature: STANDARD.encode(
                app_signer
                    .sign(&serde_json::to_vec(&request_unsigned).unwrap())
                    .unwrap(),
            ),
        };
        (request, manifest)
    }

    #[test]
    fn signatures_and_exact_redirect_are_bound() {
        let (request, manifest) = signed_authorization();
        validate_request_shape(&request).unwrap();
        validate_manifest(&request, &manifest).unwrap();

        let mut tampered = request.clone();
        tampered.state = "different".into();
        assert!(validate_manifest(&tampered, &manifest).is_err());

        let mut wrong_redirect = request;
        wrong_redirect.redirect_uri = "https://app.example/other".into();
        assert!(validate_manifest(&wrong_redirect, &manifest).is_err());
    }

    #[test]
    fn expired_requests_and_unsafe_redirects_fail_before_discovery() {
        let (mut request, _) = signed_authorization();
        request.expires_at = tauth::now_seconds();
        assert!(validate_request_shape(&request).is_err());
        request.expires_at = tauth::now_seconds() + 60;
        request.redirect_uri = "https://app.example/callback#fragment".into();
        assert!(validate_request_shape(&request).is_err());
    }
}
