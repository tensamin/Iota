use super::*;

impl Default for HttpFederationIdentityClient {
    fn default() -> Self {
        Self::new(false, false)
    }
}

impl HttpFederationIdentityClient {
    pub fn new(allow_lan: bool, allow_raw_ip: bool) -> Self {
        Self {
            client: iota_util::federation_http::client_builder(allow_lan)
                .build()
                .expect("valid federation HTTP configuration"),
            ip_bootstrap_client: iota_util::federation_http::client_builder(allow_lan)
                .danger_accept_invalid_certs(true)
                .tls_info(true)
                .build()
                .map_err(|error| error.to_string()),
            allow_lan,
            allow_raw_ip,
            requests: tokio::sync::Semaphore::new(16),
        }
    }
}

pub async fn publish_omega_node_descriptor(
    locator: &AuthorityLocator,
    iota_id: u64,
    descriptor: &NodeDescriptorWireV1,
) -> Result<(), IdentityError> {
    let response = reqwest::Client::new()
        .post(format!(
            "https://{}/federation/v1/iotas/{iota_id}/node",
            locator.as_str()
        ))
        .json(descriptor)
        .send()
        .await
        .map_err(|error| IdentityError::Unavailable(error.to_string()))?;
    if !response.status().is_success() {
        return Err(IdentityError::Unavailable(format!(
            "Omega rejected node descriptor publication with HTTP {}",
            response.status()
        )));
    }
    Ok(())
}

#[async_trait]
impl FederationIdentityClient for HttpFederationIdentityClient {
    async fn discover(
        &self,
        locator: &AuthorityLocator,
    ) -> Result<DiscoveredAuthority, IdentityError> {
        let _permit = self
            .requests
            .acquire()
            .await
            .map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        iota_util::federation_http::url(locator, "/.well-known/tensamin", self.allow_lan)?;
        iota_util::authority_discovery::discover_authority(self.client(locator)?, locator).await
    }

    async fn node_descriptor(
        &self,
        locator: &AuthorityLocator,
        path: &str,
    ) -> Result<FetchedNodeDescriptor, IdentityError> {
        let (descriptor, certificate) = self.get_json_with_certificate(locator, path).await?;
        Ok(FetchedNodeDescriptor {
            descriptor,
            tls_certificate: certificate.map(certificate_to_pem).transpose()?,
        })
    }

    async fn principal_descriptor(
        &self,
        locator: &AuthorityLocator,
        selector: &UserSelector,
    ) -> Result<PrincipalDescriptorWireV1, IdentityError> {
        let path = match selector {
            UserSelector::UserId(user) => format!("/federation/v1/users/id/{user}"),
            UserSelector::Username(username) => {
                let mut url = reqwest::Url::parse("https://placeholder.invalid/")
                    .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
                url.path_segments_mut()
                    .map_err(|_| {
                        IdentityError::InvalidIdentifier(
                            "username cannot be encoded in a federation URL".into(),
                        )
                    })?
                    .extend(["federation", "v1", "users", "name", username]);
                url.path().to_owned()
            }
        };
        self.get_json(locator, &path).await
    }
}

impl HttpFederationIdentityClient {
    pub(super) fn client(
        &self,
        locator: &AuthorityLocator,
    ) -> Result<&reqwest::Client, IdentityError> {
        if !locator.is_ip_literal() {
            return Ok(&self.client);
        }
        if !self.allow_raw_ip {
            return Err(IdentityError::InvalidIdentifier(
                "raw-IP federation requires explicit opt-in".into(),
            ));
        }
        self.ip_bootstrap_client.as_ref().map_err(|error| {
            IdentityError::Unavailable(format!("raw-IP bootstrap client is unavailable: {error}"))
        })
    }

    pub(super) async fn get_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        locator: &AuthorityLocator,
        path: &str,
    ) -> Result<T, IdentityError> {
        let _permit = self
            .requests
            .acquire()
            .await
            .map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        let url = iota_util::federation_http::url(locator, path, self.allow_lan)?;
        let response = self
            .client(locator)?
            .get(url.clone())
            .send()
            .await
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request failed for {url}: {error}"))
            })?
            .error_for_status()
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request rejected {url}: {error}"))
            })?;
        iota_util::federation_http::bounded_json(response).await
    }

    pub(super) async fn get_json_with_certificate<
        T: serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        locator: &AuthorityLocator,
        path: &str,
    ) -> Result<(T, Option<Vec<u8>>), IdentityError> {
        let _permit = self
            .requests
            .acquire()
            .await
            .map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        let url = iota_util::federation_http::url(locator, path, self.allow_lan)?;
        let response = self
            .client(locator)?
            .get(url.clone())
            .send()
            .await
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request failed for {url}: {error}"))
            })?
            .error_for_status()
            .map_err(|error| {
                IdentityError::Unavailable(format!("federation request rejected {url}: {error}"))
            })?;
        let certificate = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(reqwest::tls::TlsInfo::peer_certificate)
            .map(Vec::from);
        let descriptor = iota_util::federation_http::bounded_json(response).await?;
        Ok((descriptor, certificate))
    }
}

pub(super) fn certificate_to_pem(certificate: Vec<u8>) -> Result<Vec<u8>, IdentityError> {
    if certificate.is_empty() {
        return Err(IdentityError::InvalidDescriptor(
            "raw-IP bootstrap response contains an empty TLS certificate".into(),
        ));
    }
    let encoded =
        iota_util::crypto_util::export(&certificate, iota_util::crypto_util::DataFormat::Base64)
            .map_err(IdentityError::InvalidDescriptor)?;
    Ok(format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n").into_bytes())
}
