use mtp::crypto::PublicKeyBundle;
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup, TripleDh,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

pub struct TensaminOpaque;

impl CipherSuite for TensaminOpaque {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
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

pub fn server_identifier(iota_id: i64) -> Vec<u8> {
    let mut result = b"tensamin:iota-password:v1\0".to_vec();
    result.extend_from_slice(&iota_id.to_be_bytes());
    result
}

pub fn login_context(
    principal: &str,
    iota_id: i64,
    session_id: uuid::Uuid,
    contact_key: &PublicKeyBundle,
) -> Result<Vec<u8>, PasswordAuthError> {
    let mut result = b"tensamin:password-provisioning:v1\0".to_vec();
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

pub struct LoginStartResult {
    pub response: Vec<u8>,
    pub state: Vec<u8>,
}

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
        state: result.state.serialize().to_vec(),
    })
}

pub fn login_finish(
    serialized_state: &[u8],
    finalization: &[u8],
    principal: &[u8],
    server_id: &[u8],
    context: &[u8],
) -> Result<(), PasswordAuthError> {
    let state = ServerLogin::<TensaminOpaque>::deserialize(serialized_state)
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
    let message = CredentialFinalization::<TensaminOpaque>::deserialize(finalization)
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
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
        .map_err(|error| PasswordAuthError::Opaque(error.to_string()))?;
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
        let context = login_context("omega-key:example#7", 11, Uuid::new_v4(), &key).unwrap();

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
        let client = ClientLogin::<TensaminOpaque>::start(&mut OsRng, b"correct horse").unwrap();
        let mismatched = login_start(
            &restored,
            Some(&record),
            &client.message.serialize(),
            principal,
            &server,
            b"wrong context",
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
                    ClientLoginFinishParameters::new(Some(&context), identifiers, None)
                )
                .is_err()
        );

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
