use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::{
    LoginFinishError, OpaqueIntegrationError, OpaqueProfileV1, PasswordLoginBindingV1,
    login_context, server_identifier,
};

pub type PasswordServerSetup = ServerSetup<OpaqueProfileV1>;

pub fn generate_server_setup() -> PasswordServerSetup {
    ServerSetup::new(&mut OsRng)
}

pub fn serialize_server_setup(setup: &PasswordServerSetup) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(setup.serialize().to_vec())
}

pub fn deserialize_server_setup(
    bytes: &[u8],
) -> Result<PasswordServerSetup, OpaqueIntegrationError> {
    ServerSetup::deserialize(bytes)
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))
}

pub fn deserialize_server_setup_owned(
    bytes: Vec<u8>,
) -> Result<PasswordServerSetup, OpaqueIntegrationError> {
    let bytes = Zeroizing::new(bytes);
    deserialize_server_setup(&bytes)
}

pub fn registration_start(
    setup: &PasswordServerSetup,
    request: &[u8],
    principal: &[u8],
) -> Result<Vec<u8>, OpaqueIntegrationError> {
    let message = RegistrationRequest::<OpaqueProfileV1>::deserialize(request)
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    let result = ServerRegistration::<OpaqueProfileV1>::start(setup, message, principal)
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    Ok(result.message.serialize().to_vec())
}

pub fn registration_finish(upload: &[u8]) -> Result<Vec<u8>, OpaqueIntegrationError> {
    let message = RegistrationUpload::<OpaqueProfileV1>::deserialize(upload)
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    Ok(ServerRegistration::<OpaqueProfileV1>::finish(message)
        .serialize()
        .to_vec())
}

pub fn validate_login_request(request: &[u8]) -> Result<(), OpaqueIntegrationError> {
    CredentialRequest::<OpaqueProfileV1>::deserialize(request)
        .map(|_| ())
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))
}

/// Secret pending exchange state. Consumed by server_login_finish.
pub struct ServerLoginState {
    // opaque-ke's ServerLogin zeroizes its secret state on drop.
    state: ServerLogin<OpaqueProfileV1>,
    context: Vec<u8>,
}

pub struct LoginStartResult {
    pub response: Vec<u8>,
    pub state: ServerLoginState,
}

pub fn login_start(
    setup: &PasswordServerSetup,
    record: Option<&[u8]>,
    request: &[u8],
    binding: &PasswordLoginBindingV1<'_>,
) -> Result<LoginStartResult, OpaqueIntegrationError> {
    let message = CredentialRequest::<OpaqueProfileV1>::deserialize(request)
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    let registration = record
        .map(ServerRegistration::<OpaqueProfileV1>::deserialize)
        .transpose()
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    let principal = binding.principal.as_bytes();
    let server = server_identifier(binding.iota_id);
    let context = login_context(binding)?;
    let result = ServerLogin::<OpaqueProfileV1>::start(
        &mut OsRng,
        setup,
        registration,
        message,
        principal,
        ServerLoginParameters {
            context: Some(&context),
            identifiers: Identifiers {
                client: Some(principal),
                server: Some(&server),
            },
        },
    )
    .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    Ok(LoginStartResult {
        response: result.message.serialize().to_vec(),
        state: ServerLoginState {
            state: result.state,
            context,
        },
    })
}

pub fn login_finish(
    state: ServerLoginState,
    finalization: &[u8],
    binding: &PasswordLoginBindingV1<'_>,
) -> Result<(), LoginFinishError> {
    // TripleDH verifies its saved transcript, so also enforce the caller's current binding.
    let context = login_context(binding).map_err(|_| LoginFinishError::InvalidMessage)?;
    if context != state.context {
        return Err(LoginFinishError::AuthenticationFailed);
    }
    let message = CredentialFinalization::<OpaqueProfileV1>::deserialize(finalization)
        .map_err(|_| LoginFinishError::InvalidMessage)?;
    let server = server_identifier(binding.iota_id);
    state
        .state
        .finish(
            message,
            ServerLoginParameters {
                context: Some(&context),
                identifiers: Identifiers {
                    client: Some(binding.principal.as_bytes()),
                    server: Some(&server),
                },
            },
        )
        .map_err(|_| LoginFinishError::AuthenticationFailed)?;
    Ok(())
}
