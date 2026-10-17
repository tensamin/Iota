use super::*;

impl OmikronConnection {
    pub(super) async fn handle_tauth_authorize(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(user_id) = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok())
        else {
            self.send_tauth_error(cv, "missing authenticated user")
                .await;
            return;
        };
        let Some(request_json) = cv.get_data(DataType::AuthorizationRequest).as_str() else {
            self.send_tauth_error(cv, "missing authorization request")
                .await;
            return;
        };
        let cancellation = self.preparation_cancellation();
        let verification = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = crate::tauth::verify_authorization(&self.http_client, request_json) => result,
        };
        let verified = match verification {
            Ok(verified) => verified,
            Err(error) => {
                self.send_tauth_error(cv, &error.to_string()).await;
                return;
            }
        };
        let existing = iota_storage::tauth::get_grant(user_id, &verified.request.app_id)
            .ok()
            .flatten();
        let reusable = existing.as_ref().is_some_and(|grant| {
            grant.domain == verified.request.domain
                && grant.app_public_key == verified.manifest.public_key
                && iota_storage::tauth::grant_covers(grant, &verified.request.scopes)
                    .unwrap_or(false)
        });
        let approved = cv.get_data(DataType::Enabled) == Some(&DataValue::BoolTrue);
        let locator = match self.signed_tauth_locator(user_id).await {
            Ok(locator) => locator,
            Err(error) => {
                self.send_tauth_error(cv, &error).await;
                return;
            }
        };
        let mut response = CommunicationValue::new(CommunicationType::TAuthAuthorizationResult)
            .with_request_id(cv)
            .with_receiver(user_id as u64)
            .add_typed_default(
                DataType::AppId,
                DataValue::Str(verified.request.app_id.clone()),
            )
            .add_typed_default(
                DataType::AppName,
                DataValue::Str(verified.manifest.name.clone()),
            )
            .add_typed_default(
                DataType::Domain,
                DataValue::Str(verified.request.domain.clone()),
            )
            .add_typed_default(
                DataType::RedirectUri,
                DataValue::Str(verified.request.redirect_uri.clone()),
            )
            .add_typed_default(
                DataType::State,
                DataValue::Str(verified.request.state.clone()),
            )
            .add_typed_default(DataType::Scopes, string_array(&verified.request.scopes))
            .add_typed_default(DataType::Locator, DataValue::Str(locator.clone()));
        if approved || reusable {
            match iota_storage::tauth::issue_code(iota_storage::tauth::AuthorizationGrant {
                local_user_id: user_id,
                app_id: &verified.request.app_id,
                app_name: &verified.manifest.name,
                domain: &verified.request.domain,
                redirect_uri: &verified.request.redirect_uri,
                scopes: &verified.request.scopes,
                app_public_key: &verified.manifest.public_key,
                manifest_hash: &verified.manifest_hash,
                pkce_challenge: &verified.request.pkce_challenge,
                authorization_request: request_json,
                locator: &locator,
            }) {
                Ok(code) => {
                    response = response
                        .add_typed_default(DataType::AuthorizationCode, DataValue::Str(code))
                }
                Err(error) => {
                    self.send_tauth_error(cv, &error.to_string()).await;
                    return;
                }
            }
        }
        let _ = self.send_message(&response).await;
    }

    pub(super) async fn handle_tauth_exchange_code(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(code) = cv.get_data(DataType::AuthorizationCode).as_str() else {
            self.send_tauth_error(cv, "missing authorization code")
                .await;
            return;
        };
        let Some(app_id) = cv.get_data(DataType::AppId).as_str() else {
            self.send_tauth_error(cv, "missing app ID").await;
            return;
        };
        let Some(redirect) = cv.get_data(DataType::RedirectUri).as_str() else {
            self.send_tauth_error(cv, "missing redirect URI").await;
            return;
        };
        let Some(verifier) = cv.get_data(DataType::CodeVerifier).as_str() else {
            self.send_tauth_error(cv, "missing PKCE verifier").await;
            return;
        };
        let request_json = match iota_storage::tauth::authorization_request_for_code(code) {
            Ok(Some(request)) => request,
            _ => {
                self.send_tauth_error(cv, "authorization code is invalid, expired, or used")
                    .await;
                return;
            }
        };
        let cancellation = self.preparation_cancellation();
        let verification = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = crate::tauth::verify_authorization(&self.http_client, &request_json) => result,
        };
        let verified = match verification {
            Ok(verified)
                if verified.request.app_id == app_id
                    && verified.request.redirect_uri == redirect =>
            {
                verified
            }
            Ok(_) => {
                self.send_tauth_error(cv, "authorization code binding mismatch")
                    .await;
                return;
            }
            Err(error) => {
                self.send_tauth_error(cv, &error.to_string()).await;
                return;
            }
        };
        let session = match iota_storage::tauth::exchange_code(code, app_id, redirect, verifier) {
            Ok(session) => session,
            Err(error) => {
                self.send_tauth_error(cv, &error.to_string()).await;
                return;
            }
        };
        let principal = iota_storage::tauth::canonical_principal(session.local_user_id)
            .ok()
            .flatten()
            .unwrap_or_default();
        let response = CommunicationValue::new(CommunicationType::TAuthExchangeCodeResponse)
            .with_request_id(cv)
            .add_typed_default(DataType::SessionToken, DataValue::Str(session.token))
            .add_typed_default(DataType::AppId, DataValue::Str(verified.request.app_id))
            .add_typed_default(DataType::Principal, DataValue::Str(principal))
            .add_typed_default(DataType::Scopes, string_array(&session.scopes))
            .add_typed_default(DataType::Locator, DataValue::Str(session.locator));
        let _ = self.send_message(&response).await;
    }

    pub(super) async fn handle_tauth_user(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(session) = self
            .tauth_session(cv, iota_storage::tauth::Scope::IdentityRead)
            .await
        else {
            return;
        };
        let principal = iota_storage::tauth::canonical_principal(session.local_user_id)
            .ok()
            .flatten()
            .unwrap_or_default();
        match iota_storage::tauth::public_profile(&principal) {
            Ok(Some(mut profile)) => {
                match self.signed_tauth_home_node().await {
                    Ok(descriptor) => profile["home_node"] = descriptor,
                    Err(error) => {
                        self.send_tauth_error(cv, &error).await;
                        return;
                    }
                }
                self.send_tauth_json(cv, CommunicationType::TAuthUser, profile.to_string())
                    .await
            }
            _ => {
                self.send_tauth_error(cv, "user profile is unavailable")
                    .await
            }
        }
    }

    pub(super) async fn handle_tauth_contacts(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(session) = self
            .tauth_session(cv, iota_storage::tauth::Scope::ContactsRead)
            .await
        else {
            return;
        };
        match iota_storage::tauth::canonical_contact_ids(session.local_user_id) {
            Ok(contacts) => {
                self.send_tauth_json(
                    cv,
                    CommunicationType::TAuthContacts,
                    serde_json::to_string(&contacts).unwrap(),
                )
                .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    pub(super) async fn handle_tauth_public_lookup(self: Arc<Self>, cv: &CommunicationValue) {
        if self
            .tauth_session(cv, iota_storage::tauth::Scope::IdentityRead)
            .await
            .is_none()
        {
            return;
        }
        let Some(principal) = cv.get_data(DataType::Principal).as_str() else {
            self.send_tauth_error(cv, "missing principal").await;
            return;
        };
        match iota_storage::tauth::public_profile(principal) {
            Ok(Some(mut profile)) => {
                if iota_storage::tauth::is_local_principal(principal).unwrap_or(false) {
                    match self.signed_tauth_home_node().await {
                        Ok(descriptor) => profile["home_node"] = descriptor,
                        Err(error) => {
                            self.send_tauth_error(cv, &error).await;
                            return;
                        }
                    }
                }
                self.send_tauth_json(
                    cv,
                    CommunicationType::TAuthPublicLookup,
                    profile.to_string(),
                )
                .await
            }
            Ok(None) => self.send_tauth_error(cv, "principal was not found").await,
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    pub(super) async fn handle_tauth_metadata_get(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(token) = cv.get_data(DataType::SessionToken).as_str() else {
            self.send_tauth_error(cv, "missing session token").await;
            return;
        };
        match iota_storage::tauth::get_metadata(token) {
            Ok(value) => {
                let mut response = CommunicationValue::new(CommunicationType::TAuthMetadataGet)
                    .with_request_id(cv);
                if let Some(value) = value {
                    response = response.add_typed_default(DataType::Json, DataValue::Str(value));
                }
                let _ = self.send_message(&response).await;
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    pub(super) async fn handle_tauth_metadata_set(self: Arc<Self>, cv: &CommunicationValue) {
        let token = cv.get_data(DataType::SessionToken).as_str();
        let json = cv.get_data(DataType::Json).as_str();
        match token.zip(json) {
            Some((token, json)) => match iota_storage::tauth::set_metadata(token, json) {
                Ok(()) => {
                    self.send_tauth_empty(cv, CommunicationType::TAuthMetadataSet)
                        .await
                }
                Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
            },
            None => {
                self.send_tauth_error(cv, "missing session token or JSON")
                    .await
            }
        }
    }

    pub(super) async fn handle_tauth_metadata_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(token) = cv.get_data(DataType::SessionToken).as_str() else {
            self.send_tauth_error(cv, "missing session token").await;
            return;
        };
        match iota_storage::tauth::delete_metadata(token) {
            Ok(()) => {
                self.send_tauth_empty(cv, CommunicationType::TAuthMetadataDelete)
                    .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    pub(super) async fn handle_tauth_disconnect_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(token) = cv.get_data(DataType::SessionToken).as_str() else {
            self.send_tauth_error(cv, "missing session token").await;
            return;
        };
        match iota_storage::tauth::disconnect_and_delete(token) {
            Ok(()) => {
                self.send_tauth_empty(cv, CommunicationType::TAuthDisconnectDelete)
                    .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    pub(super) async fn handle_tauth_grant_list(self: Arc<Self>, cv: &CommunicationValue) {
        let Some(user_id) = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok())
        else {
            self.send_tauth_error(cv, "missing authenticated user")
                .await;
            return;
        };
        match iota_storage::tauth::list_grants(user_id) {
            Ok(grants) => {
                self.send_tauth_json(
                    cv,
                    CommunicationType::TAuthGrantResponse,
                    serde_json::to_string(&grants).unwrap(),
                )
                .await
            }
            Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
        }
    }

    pub(super) async fn handle_tauth_grant_revoke(self: Arc<Self>, cv: &CommunicationValue) {
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok());
        let app_id = cv.get_data(DataType::AppId).as_str();
        match user_id.zip(app_id) {
            Some((user_id, app_id)) => match iota_storage::tauth::revoke_grant(user_id, app_id) {
                Ok(_) => {
                    self.send_tauth_empty(cv, CommunicationType::TAuthGrantResponse)
                        .await
                }
                Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
            },
            None => self.send_tauth_error(cv, "missing user or app ID").await,
        }
    }

    pub(super) async fn handle_tauth_grant_metadata_set(self: Arc<Self>, cv: &CommunicationValue) {
        let user_id = cv
            .require_sender()
            .ok()
            .and_then(|value| i64::try_from(value).ok());
        let app_id = cv.get_data(DataType::AppId).as_str();
        let json = cv.get_data(DataType::Json).as_str();
        match user_id.zip(app_id).zip(json) {
            Some(((user_id, app_id), json)) => {
                match iota_storage::tauth::set_metadata_for_user(user_id, app_id, json) {
                    Ok(()) => {
                        self.send_tauth_empty(cv, CommunicationType::TAuthGrantResponse)
                            .await
                    }
                    Err(error) => self.send_tauth_error(cv, &error.to_string()).await,
                }
            }
            None => {
                self.send_tauth_error(cv, "missing user, app ID, or JSON")
                    .await
            }
        }
    }

    pub(super) async fn tauth_session(
        self: &Arc<Self>,
        cv: &CommunicationValue,
        scope: iota_storage::tauth::Scope,
    ) -> Option<iota_storage::tauth::Session> {
        let token = cv.get_data(DataType::SessionToken).as_str();
        match token.map(|token| iota_storage::tauth::authorize_session(token, scope)) {
            Some(Ok(session)) => Some(session),
            Some(Err(error)) => {
                self.clone().send_tauth_error(cv, &error.to_string()).await;
                None
            }
            None => {
                self.clone()
                    .send_tauth_error(cv, "missing session token")
                    .await;
                None
            }
        }
    }

    pub(super) async fn signed_tauth_locator(&self, user_id: i64) -> Result<String, String> {
        let config = CONFIG.load();
        let target_iota_id = config
            .iota_id
            .ok_or_else(|| "Iota ID is unavailable".to_string())?;
        let omikron_id = config
            .omikron_id
            .ok_or_else(|| "Omikron ID is unavailable".to_string())?;
        let host = config
            .omikron_host
            .as_deref()
            .ok_or_else(|| "Omikron host is unavailable".to_string())?;
        let port = config
            .omikron_port
            .ok_or_else(|| "Omikron port is unavailable".to_string())?;
        let omikron_key = mtp::files::load_public_key_bundle(omikron_public_key_path(omikron_id))
            .map_err(|error| error.to_string())?;
        let omikron_public_key = omikron_key
            .try_to_base64()
            .map_err(|error| error.to_string())?;
        let keyring = self
            .keyring
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| "Iota keyring is unavailable".to_string())?;
        let iota_public_key = keyring
            .public_key_bundle()
            .try_to_base64()
            .map_err(|error| error.to_string())?;
        let principal = iota_storage::tauth::canonical_principal(user_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "canonical principal is unavailable".to_string())?;
        let omikron_url = format!("https://{host}:{port}");
        let issued_at = iota_storage::tauth::now_seconds();
        let unsigned = TAuthLocatorUnsigned {
            version: 1,
            principal: &principal,
            omikron_url: &omikron_url,
            omikron_public_key: &omikron_public_key,
            target_iota_id,
            iota_public_key: &iota_public_key,
            issued_at,
        };
        let signer =
            Ed25519Signer::new(&keyring.sig_cl_secret_key).map_err(|error| error.to_string())?;
        let signature = STANDARD.encode(
            signer
                .sign(&serde_json::to_vec(&unsigned).unwrap())
                .map_err(|error| error.to_string())?,
        );
        serde_json::to_string(&TAuthLocator {
            version: 1,
            principal: &principal,
            omikron_url: &omikron_url,
            omikron_public_key: &omikron_public_key,
            target_iota_id,
            iota_public_key: &iota_public_key,
            issued_at,
            signature,
        })
        .map_err(|error| error.to_string())
    }

    pub(super) async fn signed_tauth_home_node(&self) -> Result<serde_json::Value, String> {
        let config = CONFIG.load();
        let host = config
            .omikron_host
            .as_deref()
            .ok_or_else(|| "Omikron host is unavailable".to_string())?;
        let port = config
            .omikron_port
            .ok_or_else(|| "Omikron port is unavailable".to_string())?;
        let relay =
            AuthorityLocator::new(format!("{host}:{port}")).map_err(|error| error.to_string())?;
        let identity = self
            .load_or_migrate_keyring()
            .await
            .map_err(|error| error.to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let descriptor = iota_storage::node_directory::SqliteNodeDirectory
            .ensure_local_descriptor(&identity, Vec::new(), vec![relay], now)
            .map_err(|error| error.to_string())?
            .to_wire_v1()
            .map_err(|error| error.to_string())?;
        serde_json::to_value(descriptor).map_err(|error| error.to_string())
    }

    pub(super) async fn send_tauth_empty(
        self: Arc<Self>,
        cv: &CommunicationValue,
        kind: CommunicationType,
    ) {
        let _ = self
            .send_message(&CommunicationValue::new(kind).with_request_id(cv))
            .await;
    }

    pub(super) async fn send_tauth_json(
        self: Arc<Self>,
        cv: &CommunicationValue,
        kind: CommunicationType,
        json: String,
    ) {
        let response = CommunicationValue::new(kind)
            .with_request_id(cv)
            .add_typed_default(DataType::Json, DataValue::Str(json));
        let _ = self.send_message(&response).await;
    }

    pub(super) async fn send_tauth_error(self: Arc<Self>, cv: &CommunicationValue, message: &str) {
        let response = error_response(cv, CommunicationType::ErrorInvalidData)
            .add_typed_default(DataType::Message, DataValue::Str(message.to_owned()));
        let _ = self.send_message(&response).await;
    }
}
