use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::{
    OpaqueIntegrationError, OpaqueProfileV1, PasswordLoginBindingV1, login_context,
    server_identifier,
};

/// Client-only key material. Credential operations borrow it without exporting its bytes.
pub struct OpaqueExportKey(Zeroizing<Vec<u8>>);

impl OpaqueExportKey {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct RegistrationClient {
    state: ClientRegistration<OpaqueProfileV1>,
    password: Zeroizing<Vec<u8>>,
}

pub struct RegistrationStart {
    pub request: Vec<u8>,
    pub state: RegistrationClient,
}

pub struct RegistrationFinish {
    pub upload: Vec<u8>,
    pub export_key: OpaqueExportKey,
}

pub fn registration_start(password: &[u8]) -> Result<RegistrationStart, OpaqueIntegrationError> {
    let result = ClientRegistration::<OpaqueProfileV1>::start(&mut OsRng, password)
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    Ok(RegistrationStart {
        request: result.message.serialize().to_vec(),
        state: RegistrationClient {
            state: result.state,
            password: Zeroizing::new(password.to_vec()),
        },
    })
}

impl RegistrationClient {
    pub fn finish(
        self,
        response: &[u8],
        principal: &str,
        iota_id: i64,
    ) -> Result<RegistrationFinish, OpaqueIntegrationError> {
        let response = RegistrationResponse::<OpaqueProfileV1>::deserialize(response)
            .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
        let server = server_identifier(iota_id);
        let result = self
            .state
            .finish(
                &mut OsRng,
                &self.password,
                response,
                ClientRegistrationFinishParameters::new(
                    Identifiers {
                        client: Some(principal.as_bytes()),
                        server: Some(&server),
                    },
                    None,
                ),
            )
            .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
        Ok(RegistrationFinish {
            upload: result.message.serialize().to_vec(),
            export_key: OpaqueExportKey::new(result.export_key.to_vec()),
        })
    }
}

pub struct LoginClient {
    state: ClientLogin<OpaqueProfileV1>,
    password: Zeroizing<Vec<u8>>,
}

pub struct LoginStart {
    pub request: Vec<u8>,
    pub state: LoginClient,
}

pub struct LoginFinish {
    pub finalization: Vec<u8>,
    pub export_key: OpaqueExportKey,
}

pub fn login_start(password: &[u8]) -> Result<LoginStart, OpaqueIntegrationError> {
    let result = ClientLogin::<OpaqueProfileV1>::start(&mut OsRng, password)
        .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
    Ok(LoginStart {
        request: result.message.serialize().to_vec(),
        state: LoginClient {
            state: result.state,
            password: Zeroizing::new(password.to_vec()),
        },
    })
}

impl LoginClient {
    pub fn finish(
        self,
        response: &[u8],
        binding: &PasswordLoginBindingV1<'_>,
    ) -> Result<LoginFinish, OpaqueIntegrationError> {
        let response = CredentialResponse::<OpaqueProfileV1>::deserialize(response)
            .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
        let server = server_identifier(binding.iota_id);
        let context = login_context(binding)?;
        let result = self
            .state
            .finish(
                &mut OsRng,
                &self.password,
                response,
                ClientLoginFinishParameters::new(
                    Some(&context),
                    Identifiers {
                        client: Some(binding.principal.as_bytes()),
                        server: Some(&server),
                    },
                    None,
                ),
            )
            .map_err(|error| OpaqueIntegrationError::Opaque(error.to_string()))?;
        Ok(LoginFinish {
            finalization: result.message.serialize().to_vec(),
            export_key: OpaqueExportKey::new(result.export_key.to_vec()),
        })
    }
}
