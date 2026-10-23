use super::*;

impl HostedAndPeerKeyResolver {
    pub fn new(local_users: Arc<dyn LocalUserStore>) -> Self {
        Self { local_users }
    }
}

#[async_trait]
impl web_server::ClientPublicKeyResolver for HostedAndPeerKeyResolver {
    async fn public_key(&self, client_id: u64) -> Option<PublicKeyBundle> {
        let local_users = self.local_users.clone();
        iota_storage::blocking::identity_lookup(move || {
            if client_id & (1_u64 << 63) != 0 {
                return iota_storage::peer_admission::key_for_peer_authentication_hint(client_id);
            }
            let Ok(local_user) = i64::try_from(client_id) else {
                return Ok(None);
            };
            Ok(local_users
                .get_local_user(LocalUserId(local_user))?
                .and_then(|user| public_key_bundle_from_base64(&user.public_key)))
        })
        .await
        .map_err(|error| {
            iota_logger::log!("Authentication key lookup failed: {}", error);
        })
        .ok()
        .flatten()
    }
}

impl ClientConnectionManager {
    pub(super) async fn resolve_hosted_identity(
        &self,
        id: u64,
        verified_key: &PublicKeyBundle,
    ) -> Result<IotaConnectionIdentity, GatewayError> {
        let verified_key = verified_key.clone();
        iota_storage::blocking::identity_lookup(move || {
            Ok(resolve_hosted_binding(id, &verified_key))
        })
        .await
        .map_err(|_| GatewayError::StorageLookup)?
    }
}

pub(super) fn resolve_hosted_binding(
    id: u64,
    verified_key: &PublicKeyBundle,
) -> Result<IotaConnectionIdentity, GatewayError> {
    let local_user = LocalUserId(
        i64::try_from(id)
            .ok()
            .filter(|id| *id > 0)
            .ok_or(GatewayError::InvalidHostedIdentity)?,
    );
    let (identity, public_key) = iota_storage::hosted_auth::resolve(local_user)
        .map_err(|_| GatewayError::InvalidHostedIdentity)?;
    let stored_key =
        public_key_bundle_from_base64(&public_key).ok_or(GatewayError::InvalidHostedKeyBinding)?;
    if stored_key
        .try_as_bytes()
        .ok()
        .zip(verified_key.try_as_bytes().ok())
        .is_none_or(|(stored, verified)| stored != verified)
    {
        return Err(GatewayError::InvalidHostedKeyBinding);
    }
    Ok(IotaConnectionIdentity::HostedClient {
        local_user,
        principal: identity.principal,
        auth_generation: identity.auth_generation,
    })
}
