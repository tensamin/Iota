use std::env;
use std::time::Duration;

use mtp::crypto::PublicKeyBundle;

const OMEGA_API_BASE_DEFAULT: &str = "https://omega.tensamin.net";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct OmikronEndpoint {
    pub id: i64,
    pub host: String,
    pub port: u16,
    pub public_key: PublicKeyBundle,
}

pub(crate) fn api_base() -> String {
    env::var("OMEGA_API_URL").unwrap_or_else(|_| OMEGA_API_BASE_DEFAULT.to_string())
}

/* The Omega host as stored in `.tu` files: no `https://` scheme, but with port. */
pub fn omega_host() -> String {
    api_base()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string()
}

/* `GET /api/get/omikron` - random connected Omikron. Used on first-ever run;
 * the only discovery endpoint with a liveness guarantee. */
pub async fn discover_random() -> Result<OmikronEndpoint, String> {
    fetch(&format!("{}/api/get/omikron", api_base())).await
}

/* `GET /api/get/omikron/{iota_id}` - this Iota's primary Omikron.
 * No liveness guarantee (may 404 after restart or point at a stale Omikron);
 * fall back to `discover_random`. */
pub async fn discover_primary(iota_id: u64) -> Result<OmikronEndpoint, String> {
    fetch(&format!("{}/api/get/omikron/{}", api_base(), iota_id)).await
}

async fn fetch(url: &str) -> Result<OmikronEndpoint, String> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let body = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Request to {} failed: {}", url, e))?
        .text()
        .await
        .map_err(|e| format!("Failed to read response body from {}: {}", url, e))?;

    let json = json::parse(&body).map_err(|e| format!("Invalid JSON from {}: {}", url, e))?;

    if json["status"].as_str() != Some("success") {
        return Err(format!(
            "Omega returned status {:?} for {}",
            json["status"].as_str(),
            url
        ));
    }

    let id = json["id"]
        .as_i64()
        .ok_or_else(|| format!("Missing/invalid \"id\" in response from {}", url))?;
    let host = json["ip_address"]
        .as_str()
        .ok_or_else(|| format!("Missing/invalid \"ip_address\" in response from {}", url))?
        .to_string();
    let port = json["port"]
        .as_u16()
        .ok_or_else(|| format!("Missing/invalid \"port\" in response from {}", url))?;
    let public_key_b64 = json["public_key"]
        .as_str()
        .ok_or_else(|| format!("Missing/invalid \"public_key\" in response from {}", url))?;
    let public_key = PublicKeyBundle::from_base64(public_key_b64)
        .map_err(|e| format!("Failed to decode public key from {}: {}", url, e))?;

    Ok(OmikronEndpoint {
        id,
        host,
        port,
        public_key,
    })
}
