# Tensamin OPAQUE profile 1

Profile ID is signed i64 `1`. The implementation is pinned to `opaque-ke 4.0.1`.

The OPRF group is Ristretto255. The authenticated key exchange is TripleDH over Ristretto255 with SHA-512.

The key stretching function is Argon2id, version `0x13`, with `m_cost = 19456` KiB, `t_cost = 2`, `p_cost = 1`. It uses the deployed deterministic 16-byte zero salt. The output length equals the input length. A known-answer vector is in `tests/vectors/profile_v1.json`.

## Identifiers and login context

The server identifier is ASCII `tensamin:iota-password\0` followed by the signed i64 Iota ID in big-endian order. The client identifier and credential identifier are the UTF-8 Omega principal, normally `{omega-authority}#{user_id}`. Callers supply the canonical principal without normalization by this library.

Login context concatenates these bytes:

1. ASCII `tensamin:password-provisioning\0`.
2. Principal UTF-8 byte length as unsigned u32 big-endian.
3. Principal UTF-8 bytes.
4. Signed i64 Iota ID big-endian.
5. The 16 raw provisioning UUID bytes.
6. A 32-byte SHA-256 digest of canonical MTP PublicKeyBundle bytes.

The caller computes the fingerprint. The library has no MTP dependency. Both client and server construct this context from `PasswordLoginBindingV1`. Pending server state also retains the initial context and rejects a changed finish binding.

Any change to these persistent values requires a new profile ID.

## Persistence and secrets

Setup files and registration records use opaque-ke's profile-1 serialization directly, with no new framing. Iota owns setup file location and lifecycle, record persistence, account discovery, throttling, and protected transport. Missing setup with enrolled accounts must remain an Iota error.

Client registration and login states are consumed by finish. Password buffers and native server exchange state are zeroized on drop. OPAQUE export keys remain in `OpaqueExportKey` and credential operations borrow them without exporting their bytes. Servers discard the OPAQUE session key and never receive the export key.

The permanent vectors preserve the deployed server identifier, login context, and KSF bytes. There is no legacy implementation or fallback.
