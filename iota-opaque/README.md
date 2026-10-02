# Iota OPAQUE

Native Rust profile-1 OPAQUE client/server operations and client-only password credential encryption. This workspace crate owns the cryptographic implementation used by `omikron-connector`.

`opaque` provides registration, login, setup serialization, and transcript bindings. `credential` encrypts and decrypts credential bytes with the client's OPAQUE export key. The implementation uses `opaque-ke 4.0.1` and preserves existing profile-1 setup files, registration records, and credential envelopes.

See [profile 1](docs/OPAQUE_PROFILE_V1.md) and [credential envelope 1](docs/CREDENTIAL_ENVELOPE_V1.md) for the persistent byte formats.

## Rust API

```rust
use iota_opaque::{credential, opaque};

let registration = opaque::client_registration_start(password)?;
let response = opaque::server_registration_start(
    &setup, &registration.request, principal.as_bytes(),
)?;
let finished = registration.state.finish(&response, principal, iota_id)?;
let record = opaque::server_registration_finish(&finished.upload)?;
let encrypted = credential::encrypt(&finished.export_key, &credential_binding, &tu_bytes)?;
```

Login uses `client_login_start`, `server_login_start`, the consumed client's `finish`, and `server_login_finish`. Only the client uses `credential::decrypt` with its finish export key.

`credential::validate_envelope` checks the magic, version, and minimum framing length without the export key. It does not authenticate ciphertext. Enrollment uses this check before storing credentials.

The connector returns dummy-record OPAQUE responses for unknown accounts and accounts without compatible password records. Login database work and OPAQUE computation run on blocking threads. `PASSWORD_MAX_BLOCKING_WORKERS` limits concurrency and defaults to the available CPU count, capped by `PASSWORD_MAX_PENDING_EXCHANGES`.

`PASSWORD_MAX_PENDING_EXCHANGES` bounds pending logins and enrollments separately. Enrollment permits stay reserved during preparation and until finish or expiry. `PASSWORD_PENDING_TTL_SECONDS` controls expiry.

## Development

Run from the Iota workspace in `nix develop`:

```sh
cargo fmt -p iota-opaque -p omikron-connector --check
cargo clippy -p iota-opaque --locked --all-targets --all-features -- -D warnings -W unreachable-pub
cargo clippy -p omikron-connector --locked --all-targets --all-features
cargo test -p iota-opaque -p omikron-connector --locked --all-features
```
