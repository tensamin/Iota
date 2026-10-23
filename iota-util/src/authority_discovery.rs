use iota_identity::{
    AuthorityDiscoveryDocument, AuthorityLocator, DiscoveredAuthority, IdentityError,
};

pub async fn discover_authority(
    client: &reqwest::Client,
    locator: &AuthorityLocator,
) -> Result<DiscoveredAuthority, IdentityError> {
    let url = format!("https://{}/.well-known/tensamin", locator.as_str());
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| {
            IdentityError::Unavailable(format!("authority discovery failed for {url}: {error}"))
        })?
        .error_for_status()
        .map_err(|error| {
            IdentityError::Unavailable(format!("authority discovery rejected {url}: {error}"))
        })?;
    let document: AuthorityDiscoveryDocument =
        crate::federation_http::bounded_json(response).await?;
    document.verify()
}
