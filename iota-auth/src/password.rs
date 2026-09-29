use generic_array::{ArrayLength, GenericArray};
use mtp::crypto::PublicKeyBundle;
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup, TripleDh,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct OpaqueProfileV1;

impl OpaqueProfileV1 {
    pub const ID: i64 = 1;
    pub const SERVER_ID_DOMAIN: &'static [u8] = b"tensamin:iota-password\0";
    pub const LOGIN_CONTEXT_DOMAIN: &'static [u8] = b"tensamin:password-provisioning\0";

    pub fn server_identifier(iota_id: i64) -> Vec<u8> {
        let mut result = Self::SERVER_ID_DOMAIN.to_vec();
        result.extend_from_slice(&iota_id.to_be_bytes());
        result
    }

    pub fn login_context(
        principal: &str,
        iota_id: i64,
        session_id: uuid::Uuid,
        contact_key: &PublicKeyBundle,
    ) -> Result<Vec<u8>, PasswordAuthError> {
        let mut result = Self::LOGIN_CONTEXT_DOMAIN.to_vec();
        let principal_len =
            u32::try_from(principal.len()).map_err(|_| PasswordAuthError::FieldTooLarge)?;
        result.extend_from_slice(&principal_len.to_be_bytes());
        result.extend_from_slice(principal.as_bytes());
        result.extend_from_slice(&iota_id.to_be_bytes());
        result.extend_from_slice(session_id.as_bytes());
        let key = contact_key
            .try_as_bytes()
            .map_err(|error| PasswordAuthError::ContactKey(error.to_string()))?;
        result.extend_from_slice(&Sha256::digest(key));
        Ok(result)
    }
}

pub const CURRENT_OPAQUE_PROFILE: i64 = OpaqueProfileV1::ID;

/// KSF parameters are persistent semantics of OpaqueProfileV1. Do not change deployed profile-1 credentials.
pub struct PasswordKsfV1(argon2::Argon2<'static>);

impl Default for PasswordKsfV1 {
    fn default() -> Self {
        let params = argon2::Params::new(19 * 1024, 2, 1, None)
            .expect("PasswordKsfV1 parameters must be valid");
        Self(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

impl Ksf for PasswordKsfV1 {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        let mut output = GenericArray::<u8, L>::default();
        self.0
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;
        Ok(output)
    }
}

pub type TensaminOpaque = OpaqueProfileV1;

impl CipherSuite for OpaqueProfileV1 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = PasswordKsfV1;
}

pub type PasswordServerSetup = ServerSetup<TensaminOpaque>;

#[derive(Debug, thiserror::Error)]
pub enum PasswordAuthError {
    #[error("invalid OPAQUE exchange: {0}")]
    Opaque(String),
    #[error("invalid Contact public key: {0}")]
    ContactKey(String),
    #[error("OPAQUE context field is too large")]
    FieldTooLarge,
}

pub fn generate_server_setup() -> PasswordServerSetup {
    ServerSetup::new(&mut OsRng)
}

pub fn serialize_server_setup(setup: &PasswordServerSetup) -> Vec<u8> {
    setup.serialize().to_vec()
}

pub fn deserialize_server_setup(bytes: &[u8]) -> Result<PasswordServerSetup, PasswordAuthError> {
    ServerSetup::deserialize(bytes).map_err(|error| PasswordAuthError::Opaque(error.to_string()))
}

pub fn deserialize_server_setup_owned(
    bytes: Vec<u8>,
) -> Result<PasswordServerSetup, PasswordAuthError> {
    let bytes = Zeroizing::new(bytes);
    deserialize_server_setup(&bytes)
}

pub fn registration_start(
    setup: &PasswordServerSetup,
    request: &[u8],
    identifier: &[u8],
) -> Result<Vec<u8>, PasswordAuthError> {
    let message = RegistrationRequest::<TensaminOpaque>::deserialize(request)
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
    let result = ServerRegistration::<TensaminOpaque>::start(setup, message, identifier)
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
    Ok(result.message.serialize().to_vec())
}

pub fn registration_finish(upload: &[u8]) -> Result<Vec<u8>, PasswordAuthError> {
    let message = RegistrationUpload::<TensaminOpaque>::deserialize(upload)
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
    Ok(ServerRegistration::<TensaminOpaque>::finish(message)
        .serialize()
        .to_vec())
}

pub fn validate_login_request(request: &[u8]) -> Result<(), PasswordAuthError> {
    CredentialRequest::<TensaminOpaque>::deserialize(request)
        .map(|_| ())
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))
}

pub fn server_identifier(iota_id: i64) -> Vec<u8> {
    OpaqueProfileV1::server_identifier(iota_id)
}

pub fn login_context(
    principal: &str,
    iota_id: i64,
    session_id: uuid::Uuid,
    contact_key: &PublicKeyBundle,
) -> Result<Vec<u8>, PasswordAuthError> {
    OpaqueProfileV1::login_context(principal, iota_id, session_id, contact_key)
}

pub struct LoginStartResult {
    pub response: Vec<u8>,
    pub state: SerializedLoginState,
}

pub type SerializedLoginState = Zeroizing<Vec<u8>>;

pub fn login_start(
    setup: &PasswordServerSetup,
    record: Option<&[u8]>,
    request: &[u8],
    principal: &[u8],
    server_id: &[u8],
    context: &[u8],
) -> Result<LoginStartResult, PasswordAuthError> {
    let message = CredentialRequest::<TensaminOpaque>::deserialize(request)
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
    let registration = record
        .map(ServerRegistration::<TensaminOpaque>::deserialize)
        .transpose()
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
    let result = ServerLogin::<TensaminOpaque>::start(
        &mut OsRng,
        setup,
        registration,
        message,
        principal,
        ServerLoginParameters {
            context: Some(context),
            identifiers: Identifiers {
                client: Some(principal),
                server: Some(server_id),
            },
        },
    )
    .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
    Ok(LoginStartResult {
        response: result.message.serialize().to_vec(),
        state: Zeroizing::new(result.state.serialize().to_vec()),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum LoginFinishError {
    #[error("invalid OPAQUE finalization message")]
    InvalidMessage,
    #[error("OPAQUE authentication failed")]
    AuthenticationFailed,
}

pub fn login_finish(
    serialized_state: &[u8],
    finalization: &[u8],
    principal: &[u8],
    server_id: &[u8],
    context: &[u8],
) -> Result<(), LoginFinishError> {
    let state = ServerLogin::<TensaminOpaque>::deserialize(serialized_state)
        .map_err(|_| LoginFinishError::InvalidMessage)?;
    let message = CredentialFinalization::<TensaminOpaque>::deserialize(finalization)
        .map_err(|_| LoginFinishError::InvalidMessage)?;
    state
        .finish(
            message,
            ServerLoginParameters {
                context: Some(context),
                identifiers: Identifiers {
                    client: Some(principal),
                    server: Some(server_id),
                },
            },
        )
        .map_err(|_| LoginFinishError::AuthenticationFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp::crypto::Keyring;
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use uuid::Uuid;

    #[test]
    fn profile_one_persistent_semantics_are_stable() {
        assert_eq!(OpaqueProfileV1::ID, 1);
        assert_eq!(
            OpaqueProfileV1::SERVER_ID_DOMAIN,
            b"tensamin:iota-password\0"
        );
        assert_eq!(
            OpaqueProfileV1::LOGIN_CONTEXT_DOMAIN,
            b"tensamin:password-provisioning\0"
        );
        assert_eq!(
            OpaqueProfileV1::server_identifier(11),
            [
                b"tensamin:iota-password\0".as_slice(),
                &11_i64.to_be_bytes()
            ]
            .concat()
        );
        let input = GenericArray::from([7_u8; 64]);
        let pinned = PasswordKsfV1::default().hash(input.clone()).unwrap();
        let previous = argon2::Argon2::default().hash(input).unwrap();
        assert_eq!(pinned, previous);
    }

    #[test]
    fn malformed_finalization_is_not_an_authentication_failure() {
        assert!(matches!(
            login_finish(b"invalid", b"invalid", b"account", b"server", b"context"),
            Err(LoginFinishError::InvalidMessage)
        ));
    }

    #[test]
    fn login_request_validation_rejects_arbitrary_bytes() {
        assert!(validate_login_request(b"not a KE1").is_err());
        let request = ClientLogin::<TensaminOpaque>::start(&mut OsRng, b"password").unwrap();
        assert!(validate_login_request(&request.message.serialize()).is_ok());
    }

    #[test]
    fn registration_and_login_bind_context_identifiers_and_persisted_setup() {
        let setup = generate_server_setup();
        let restored = deserialize_server_setup(&serialize_server_setup(&setup)).unwrap();
        let principal = b"omega-key:example#7";
        let server = server_identifier(11);
        let identifiers = Identifiers {
            client: Some(principal),
            server: Some(&server),
        };
        let registration =
            ClientRegistration::<TensaminOpaque>::start(&mut OsRng, b"correct horse").unwrap();
        let response =
            registration_start(&restored, &registration.message.serialize(), principal).unwrap();
        let upload = registration
            .state
            .finish(
                &mut OsRng,
                b"correct horse",
                RegistrationResponse::<TensaminOpaque>::deserialize(&response).unwrap(),
                ClientRegistrationFinishParameters::new(identifiers, None),
            )
            .unwrap();
        let record = registration_finish(&upload.message.serialize()).unwrap();
        let key = Keyring::generate().public_key_bundle();
        let session = Uuid::new_v4();
        let context = login_context("omega-key:example#7", 11, session, &key).unwrap();

        let client = ClientLogin::<TensaminOpaque>::start(&mut OsRng, b"correct horse").unwrap();
        let result = login_start(
            &restored,
            Some(&record),
            &client.message.serialize(),
            principal,
            &server,
            &context,
        )
        .unwrap();
        let ke2 = CredentialResponse::<TensaminOpaque>::deserialize(&result.response).unwrap();
        let finish = client
            .state
            .finish(
                &mut OsRng,
                b"correct horse",
                ke2,
                ClientLoginFinishParameters::new(Some(&context), identifiers, None),
            )
            .unwrap();
        assert!(
            login_finish(
                &result.state,
                &finish.message.serialize(),
                principal,
                &server,
                &context
            )
            .is_ok()
        );
        for (binding, changed_context) in [
            (
                "session",
                login_context("omega-key:example#7", 11, Uuid::new_v4(), &key).unwrap(),
            ),
            (
                "contact key",
                login_context(
                    "omega-key:example#7",
                    11,
                    session,
                    &Keyring::generate().public_key_bundle(),
                )
                .unwrap(),
            ),
            (
                "account",
                login_context("omega-key:example#8", 11, session, &key).unwrap(),
            ),
            (
                "Iota",
                login_context("omega-key:example#7", 12, session, &key).unwrap(),
            ),
        ] {
            let client =
                ClientLogin::<TensaminOpaque>::start(&mut OsRng, b"correct horse").unwrap();
            let mismatched = login_start(
                &restored,
                Some(&record),
                &client.message.serialize(),
                principal,
                &server,
                &changed_context,
            )
            .unwrap();
            assert!(
                client
                    .state
                    .finish(
                        &mut OsRng,
                        b"correct horse",
                        CredentialResponse::<TensaminOpaque>::deserialize(&mismatched.response)
                            .unwrap(),
                        ClientLoginFinishParameters::new(Some(&context), identifiers, None),
                    )
                    .is_err(),
                "login accepted a different {binding}"
            );
        }

        let wrong_server = server_identifier(12);
        for (login_principal, login_server, password) in [
            (
                b"omega-key:example#8".as_slice(),
                server.as_slice(),
                b"correct horse".as_slice(),
            ),
            (
                principal.as_slice(),
                wrong_server.as_slice(),
                b"correct horse".as_slice(),
            ),
            (
                principal.as_slice(),
                server.as_slice(),
                b"wrong horse".as_slice(),
            ),
        ] {
            let client = ClientLogin::<TensaminOpaque>::start(&mut OsRng, password).unwrap();
            let result = login_start(
                &restored,
                Some(&record),
                &client.message.serialize(),
                login_principal,
                login_server,
                &context,
            )
            .unwrap();
            assert!(
                client
                    .state
                    .finish(
                        &mut OsRng,
                        password,
                        CredentialResponse::<TensaminOpaque>::deserialize(&result.response)
                            .unwrap(),
                        ClientLoginFinishParameters::new(Some(&context), identifiers, None)
                    )
                    .is_err()
            );
        }

        let client = ClientLogin::<TensaminOpaque>::start(&mut OsRng, b"correct horse").unwrap();
        let dummy = login_start(
            &restored,
            None,
            &client.message.serialize(),
            principal,
            &server,
            &context,
        )
        .unwrap();
        assert!(CredentialResponse::<TensaminOpaque>::deserialize(&dummy.response).is_ok());
        let unrelated = generate_server_setup();
        let client = ClientLogin::<TensaminOpaque>::start(&mut OsRng, b"correct horse").unwrap();
        let response = login_start(
            &unrelated,
            Some(&record),
            &client.message.serialize(),
            principal,
            &server,
            &context,
        )
        .unwrap();
        assert!(
            client
                .state
                .finish(
                    &mut OsRng,
                    b"correct horse",
                    CredentialResponse::<TensaminOpaque>::deserialize(&response.response).unwrap(),
                    ClientLoginFinishParameters::new(Some(&context), identifiers, None)
                )
                .is_err()
        );
    }

    #[test]
    fn login_context_binds_account_iota_session_and_contact_key() {
        let first = Keyring::generate().public_key_bundle();
        let second = Keyring::generate().public_key_bundle();
        let session = Uuid::new_v4();
        let original = login_context("omega-key:example#7", 11, session, &first).unwrap();
        for changed in [
            login_context("omega-key:example#8", 11, session, &first).unwrap(),
            login_context("omega-key:example#7", 12, session, &first).unwrap(),
            login_context("omega-key:example#7", 11, Uuid::new_v4(), &first).unwrap(),
            login_context("omega-key:example#7", 11, session, &second).unwrap(),
        ] {
            assert_ne!(original, changed);
        }
    }
}
