use iota_identity::{AuthorityLocator, IdentityError};
use std::{net::IpAddr, sync::Arc, time::Duration};

pub const MAX_METADATA_BYTES: usize = 256 * 1024;

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0)
                && !(a == 198 && (18..=19).contains(&b))
                && !ip.is_documentation()
        }
        IpAddr::V6(ip) => {
            // Permit global unicast only. Excludes local, mapped IPv4, transition and multicast ranges.
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
        }
    }
}

struct PublicDns;
impl reqwest::dns::Resolve for PublicDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if addresses.is_empty() || addresses.iter().any(|a| !public_address(a.ip())) {
                return Err(std::io::Error::other(
                    "federation DNS resolved to a non-public address",
                )
                .into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub fn client_builder(allow_lan: bool) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15));
    if allow_lan {
        builder
    } else {
        builder.dns_resolver(Arc::new(PublicDns))
    }
}

pub fn url(
    locator: &AuthorityLocator,
    path: &str,
    allow_lan: bool,
) -> Result<reqwest::Url, IdentityError> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['\\', '?', '#']) {
        return Err(IdentityError::InvalidDescriptor(
            "invalid same-origin federation path".into(),
        ));
    }
    let url = reqwest::Url::parse(&format!("https://{}{path}", locator.as_str()))
        .map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(IdentityError::InvalidDescriptor(
            "federation URL contains credentials".into(),
        ));
    }
    if !allow_lan
        && let Some(host) = url.host_str()
        && let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>()
        && !public_address(ip)
    {
        return Err(IdentityError::InvalidDescriptor(
            "non-public federation destination".into(),
        ));
    }
    Ok(url)
}

pub async fn bounded_json<T: serde::de::DeserializeOwned + Send + 'static>(
    mut response: reqwest::Response,
) -> Result<T, IdentityError> {
    if response.status().is_redirection() {
        return Err(IdentityError::InvalidDescriptor(
            "federation redirects are disabled".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_METADATA_BYTES as u64)
    {
        return Err(IdentityError::InvalidDescriptor(
            "federation response too large".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| IdentityError::Unavailable(e.to_string()))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_METADATA_BYTES {
            return Err(IdentityError::InvalidDescriptor(
                "federation response too large".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    tokio::task::spawn_blocking(move || {
        serde_json::from_slice(&body).map_err(|e| IdentityError::InvalidDescriptor(e.to_string()))
    })
    .await
    .map_err(|e| IdentityError::Unavailable(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connection_dns_and_literal_urls_reject_non_public_targets() {
        use reqwest::dns::Resolve;
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "192.0.2.1",
            "::1",
            "::ffff:127.0.0.1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!public_address(address.parse().unwrap()), "{address}");
        }
        assert!(
            PublicDns
                .resolve("localhost".parse().unwrap())
                .await
                .is_err()
        );
        let loopback = AuthorityLocator::new("127.0.0.1:1984").unwrap();
        assert!(url(&loopback, "/.well-known/tensamin", false).is_err());
        assert!(url(&loopback, "/.well-known/tensamin", true).is_ok());
        let authority = AuthorityLocator::new("example.com").unwrap();
        for path in [
            "http://other.example/",
            "//other.example/",
            "/\\other.example/",
            "/node?redirect=elsewhere",
            "/node#fragment",
        ] {
            assert!(url(&authority, path, false).is_err());
        }
    }
}
