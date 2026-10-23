use super::*;

pub(super) fn resolve_error(
    cv: &CommunicationValue,
    ty: CommunicationType,
    code: &'static str,
) -> CommunicationValue {
    error_response(cv, ty).add_typed_default(DataType::ErrorType, DataValue::Str(code.into()))
}

pub(super) fn identity_resolve_error(
    cv: &CommunicationValue,
    error: &iota_identity::IdentityError,
) -> CommunicationValue {
    use iota_identity::IdentityError;
    match error {
        IdentityError::InvalidIdentifier(_) | IdentityError::InvalidDescriptor(_) => {
            resolve_error(cv, CommunicationType::ErrorInvalidData, "invalid_address")
        }
        IdentityError::NotFound => {
            resolve_error(cv, CommunicationType::ErrorNotFound, "unknown_user")
        }
        IdentityError::Unavailable(_) => {
            resolve_error(cv, CommunicationType::ErrorNoIota, "authority_unreachable")
        }
        IdentityError::KeyPinMismatch => resolve_error(
            cv,
            CommunicationType::ErrorNotAuthenticated,
            "key_pin_mismatch",
        ),
        IdentityError::Storage(_) => resolve_error(cv, CommunicationType::ErrorInternal, "storage"),
    }
}

/// Resolve a `usernameOrId@otherIotaDomainOrIp` address through the federation
/// identity chain. Network resolution fetches the remote authority's discovery
/// document, node descriptor and principal descriptor, and pins them into the
/// local directory, so the returned principal can be addressed by a signed
/// Federation relay message without Omega or an Omikron.
pub async fn handle_user_resolve(
    cv: &CommunicationValue,
    identities: &dyn iota_identity::IdentityResolver,
) -> CommunicationValue {
    let Some(raw) = cv.get_data(DataType::UserAddress).as_string() else {
        return resolve_error(cv, CommunicationType::ErrorInvalidData, "missing_address");
    };
    let context = iota_identity::ResolutionContext {
        allow_network: true,
        offline_policy: Default::default(),
    };
    let result = if raw.trim_start().starts_with('{') {
        let principal = match serde_json::from_str::<iota_identity::PrincipalId>(&raw) {
            Ok(principal) => principal,
            Err(_) => {
                return resolve_error(cv, CommunicationType::ErrorInvalidData, "invalid_address");
            }
        };
        identities
            .resolve_principal_with_context(&principal, &context)
            .await
    } else {
        let address = match iota_identity::UserAddress::parse(&raw) {
            Ok(address) => address,
            Err(_) => {
                return resolve_error(cv, CommunicationType::ErrorInvalidData, "invalid_address");
            }
        };
        if address.authority.is_none() {
            return resolve_error(cv, CommunicationType::ErrorInvalidData, "missing_authority");
        }
        match identities.resolve_address(&address, &context).await {
            Ok(resolved) => {
                if let Some(pin) = &address.public_key_pin {
                    let pin = match pin.try_as_bytes() {
                        Ok(pin) => pin,
                        Err(_) => {
                            return resolve_error(
                                cv,
                                CommunicationType::ErrorInvalidData,
                                "invalid_address",
                            );
                        }
                    };
                    if !resolved
                        .public_keys
                        .iter()
                        .any(|key| key.try_as_bytes().is_ok_and(|key| key == pin))
                    {
                        return identity_resolve_error(
                            cv,
                            &iota_identity::IdentityError::KeyPinMismatch,
                        );
                    }
                }
                Ok(resolved)
            }
            Err(error) => Err(error),
        }
    };
    let resolved = match result {
        Ok(resolved) => resolved,
        Err(error) => return identity_resolve_error(cv, &error),
    };
    let iota_identity::PrincipalHome::Iota(node) = &resolved.home else {
        return resolve_error(cv, CommunicationType::ErrorInvalidData, "unsupported_home");
    };
    let home = match iota_storage::node_directory::SqliteNodeDirectory
        .resolve_node(node)
        .await
    {
        Ok(home) => home,
        Err(error) => return identity_resolve_error(cv, &error),
    };
    let now = iota_storage::util::sync::now_millis();
    let public_key = match authoritative_node_key(node, &home, now) {
        Ok(key) => key,
        Err(error) => return identity_resolve_error(cv, &error),
    };
    let canonical = match serde_json::to_string(&resolved.principal) {
        Ok(canonical) => canonical,
        Err(error) => return internal_handler_error(cv, "user_resolve.principal", error),
    };
    let keys = resolved
        .public_keys
        .iter()
        .map(|key| key.try_to_base64().map(DataValue::Str))
        .collect::<Result<Vec<_>, _>>();
    let Ok(keys) = keys else {
        return resolve_error(cv, CommunicationType::ErrorInternal, "key_encoding");
    };
    let mut response = CommunicationValue::new(CommunicationType::UserResolved)
        .with_request_id(cv)
        .add_typed_default(DataType::PublicKey, DataValue::Str(public_key))
        .add_typed_default(DataType::Principal, DataValue::Str(canonical.clone()))
        .add_typed_default(DataType::UserAddress, DataValue::Str(canonical))
        .add_typed_default(
            DataType::UserId,
            DataValue::UnsignedNumber(resolved.principal.user_id.into()),
        )
        .add_typed_default(
            DataType::AuthorityId,
            DataValue::Str(resolved.principal.authority.as_str().into()),
        )
        .add_typed_default(DataType::NodeId, DataValue::Str(node.as_str().into()))
        .add_typed_default(DataType::SigningKeys, DataValue::Array(keys));
    if let Some(username) = &resolved.username {
        response = response.add_typed_default(DataType::Username, DataValue::Str(username.clone()));
    }
    response
}

pub(super) fn authoritative_node_key(
    node: &iota_identity::IotaNodeId,
    descriptor: &iota_identity::ResolvedNodeIdentity,
    now: i64,
) -> Result<String, iota_identity::IdentityError> {
    use iota_identity::IdentityError;
    if &descriptor.node != node || descriptor.valid_until.is_some_and(|until| until <= now) {
        return Err(IdentityError::InvalidDescriptor(
            "home node descriptor is stale or mismatched".into(),
        ));
    }
    let key = descriptor
        .public_keys
        .first()
        .filter(|_| descriptor.public_keys.len() == 1)
        .ok_or_else(|| {
            IdentityError::InvalidDescriptor("home node needs one current key".into())
        })?;
    if iota_identity::IotaNodeId::from_public_keys(key)? != *node {
        return Err(IdentityError::KeyPinMismatch);
    }
    key.try_to_base64()
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
}
