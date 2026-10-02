mod client;
mod context;
mod error;
mod profile_v1;
mod server;

pub use client::{
    LoginClient, LoginFinish, LoginStart, OpaqueExportKey, RegistrationClient, RegistrationFinish,
    RegistrationStart, login_start as client_login_start,
    registration_start as client_registration_start,
};
pub use context::{PasswordLoginBindingV1, login_context, server_identifier};
pub use error::{LoginFinishError, OpaqueIntegrationError};
pub use profile_v1::{CURRENT_OPAQUE_PROFILE, OpaqueProfileV1, PasswordKsfV1};
pub use server::{
    LoginStartResult as ServerLoginStartResult, PasswordServerSetup, ServerLoginState,
    deserialize_server_setup, deserialize_server_setup_owned, generate_server_setup,
    login_finish as server_login_finish, login_start as server_login_start,
    registration_finish as server_registration_finish,
    registration_start as server_registration_start, serialize_server_setup,
    validate_login_request,
};

#[cfg(test)]
mod tests;
