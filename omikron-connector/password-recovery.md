# Password readiness, mutation recovery and release

## Health is not a recovery guarantee

`password_health()` reports setup availability separately from the last storage
scan and per-account credential counts. It refreshes the scan when queried.
`credentials = None` means the scan could not complete, not that no accounts
have passwords. Invalid records do not prevent unaffected accounts from using
a valid setup. A setup-binding or database validation failure remains fail-closed.
`SetupMismatch` is distinct from a failed database scan. Its rows are counted as
invalid while `storage_validated` still reports that the database scan completed.

Each stored registration and encrypted backup is checked for supported format,
size, account-key fingerprint and available setup/principal/Iota bindings.
Missing legacy binding metadata is reported as `legacy_unverified`. Bound rows
whose current authority or Iota identity is not yet available are counted as
`identity_unverified`, not validated. These checks cannot decrypt a backup or
prove knowledge of an account's password. `Initialized` requires a successful
scan with no invalid or unverified records, rather than just an available setup.

## Lost mutation acknowledgments

The signed protected message ID identifies an enrollment finish or disable
operation. Iota commits an immutable receipt containing the ID, exact normalized
request digest, account-key and authorization-generation fence, and historical
outcome in the same SQLite transaction as the credential mutation. Changing
transport correlation IDs does not change operation identity.
Pre-upgrade uncertain operations have no such receipt. A digest alone cannot
reconstruct their protected command, so those outcomes remain unresolved.

Omikron's private mutation journal retains the original account-encrypted frame
as proof until reconciliation succeeds. It never retains decrypted OPAQUE state.
After a timeout, an identical unresolved request, or reconnect, Omikron sends a
read-only `PasswordEnrollmentStatus` wrapper containing that original protected
frame and its type-map version. Iota verifies the original account signature,
recipient and current account authorization without consuming replay state.
This path only reads a receipt. It never invokes enrollment finish again.

A committed result is Iota-signed and encrypted to the account. Missing evidence,
changed authorization, invalid proof and unavailable peers leave the operation
unresolved. None authorize a blind mutation retry. A receipt describes the
historical mutation, not the account's current enrollment state. Reassignment,
key rotation and account erasure fence or remove the receipts.

## Credential-release linearization

The final successful `authorize_release()` immediate SQLite transaction is the
release linearization point. It checks the current enabled authorization and
generation, account key, and the complete credential snapshot together. A disable
or key rotation that commits first prevents release of the old snapshot. Both
the OPAQUE proof and the protected response must already be prepared before this
transaction.

A later disablement does not retract a release already granted. In particular,
Omikron may deliver already-granted ciphertext after disablement commits. No
cross-node delivery barrier or remote recall is promised. Guaranteeing no bytes
reach a Client after the commit would require coordination with Omikron's actual
transport delivery, not another SQLite check in Iota. KE3 remains single-use,
including when response delivery fails.
