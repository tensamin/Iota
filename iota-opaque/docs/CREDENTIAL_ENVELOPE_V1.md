# Credential envelope version 1

The plaintext is arbitrary canonical credential bytes. Serialization of `.tu` credentials belongs to the consumer.

## Key derivation

Input secret is the OPAQUE client export key. Use HKDF-SHA-256 with absent salt and 32-byte output. HKDF info concatenates:

1. ASCII `tensamin:opaque-export-key:credential:v1\0`.
2. OPAQUE profile ID `1` as signed i64 big-endian.
3. Credential version `1` as unsigned u16 big-endian.

## Associated data

Concatenate:

1. ASCII `tensamin:opaque-credential-aad:v1\0`.
2. OPAQUE profile ID `1` as signed i64 big-endian.
3. Principal UTF-8 byte length as unsigned u32 big-endian.
4. Principal UTF-8 bytes.
5. Signed i64 Iota ID big-endian.
6. The 32-byte SHA-256 digest of the canonical account public key bundle.

The provisioning session UUID is not credential AAD. Enrollment ciphertext must decrypt in later provisioning sessions.

## Envelope bytes

| Offset | Length | Value |
| --- | --- | --- |
| 0 | 8 | `TSCRED\0\0` |
| 8 | 2 | Version `1`, unsigned big-endian |
| 10 | 24 | Fresh random XChaCha20 nonce |
| 34 | Remaining | XChaCha20-Poly1305 ciphertext followed by its 16-byte tag |

Minimum version-1 envelope length is 50 bytes, including an empty plaintext. The parser rejects wrong magic and incomplete framing, reports unknown versions explicitly, and authenticates before returning plaintext. It never guesses a format or falls back to version 1. The fixed magic and version are enforced by the parser; all identity AAD and nonce bytes affect authentication.

Derived key buffers and decrypted plaintext zeroize on drop. Iota stores and returns only the envelope, never the export key or plaintext.
