# Relay recovery and deployment

## Upgrade order

Deploy the type maps, Tau, Iota, Omikron and client from matching dependency
revisions. `RelayReceiptPage` changes the account synchronization contract. A
bounded `AcceptedIds` page is not a complete acceptance history.

Iota applies SQLite migrations transactionally before publishing its storage
pool. The recovery scheduling and dispatch lease migration follows schema 55.
Receipt metadata is backfilled before the application migrates unversioned
prepared operations to the versioned persistence DTO. Keep the legacy persistence
decoder until a deliberate deployment transition verifies that no records need
it. Legacy network relay delivery is not enabled by that decoder.

Schema 56 adds recovery scheduling and dispatch leases. Schema 57 records DTO
migration readiness, 58 quarantines legacy numeric relay targets, and 59 creates
and backfills receipt metadata. Schema 60 records the before and after key epochs
of new message edits.

Back up the database before upgrading. Preserve blocked operation bytes for
diagnosis. Do not mark an unreadable accepted operation delivered or delete it
just to clear a health failure.

## Recovery policy

The application processing generation and owner remain the authority for local
mutation. Recovery scheduling only determines when work may be considered.

The recovery worker isolates blocked records and schedules transient failures
individually. These environment variables configure retries:

| Variable | Default | Meaning |
| --- | --- | --- |
| `IOTA_RECOVERY_MIN_DELAY_MS` | `2000` | Initial per-record retry delay |
| `IOTA_RECOVERY_MAX_DELAY_MS` | `300000` | Maximum per-record retry delay |
| `IOTA_RECOVERY_MAX_ATTEMPTS` | `0` | Retry limit, with zero allowing indefinite bounded retries |

Exhausting the configured retry limit records `retry_exhausted`. Exhausting the
persisted attempt counter records `recovery_attempts_exhausted` without wrapping
the counter or stopping the batch.

An empty eligible batch does not mean the backlog is empty. Inspect blocked and
deferred counts as well as eligible work and its oldest age. Database enumeration
or migration failures affect service health. Individual retryable records do not
prevent unrelated records from progressing.

Investigate the structured error code and application logs before repairing an
operation. Any repair must preserve the canonical relay identity and respect the
current processing generation. A stale worker must not clear a replacement
worker's scheduling decision.

## Outbound delivery

Outbound Iota delivery and client delivery use separate dispatch claims from
application processing claims. Each send acquires a generation-qualified lease.
Acknowledgement, retry and quarantine must match the pending row, dispatch owner
and generation. Acquisition and completion recheck canonical hosted ownership,
managed residency, enabled account authorization and principal retirement. A key
generation change alone does not invalidate accepted work for an enabled account.

Terminal peer responses bind the signer, recipient, destination node and relay
message ID to the signed request. `bind_relay_response_identity` adds that binding
to the response's `SecurePayload`. Router wrappers validate their own correlation
ID before restoring the inner relay's ID for terminal validation.

`IOTA_DISPATCH_TIMEOUT_MS` configures the remote send timeout. It defaults to
30000 milliseconds and accepts 1 through 300000 milliseconds. The remote dispatch
lease includes another 5000 milliseconds. Workers acquire one record per send
and recheck the claim immediately before sending.

A lease does not provide exactly-once network transmission. A destination may
accept an attempt whose response is lost before the sender's lease expires.
Takeover can resend it. Destinations must continue to deduplicate the canonical
signed relay identity.

Do not use transport frame IDs as durable queue identifiers. They are scoped to
request correlation and may repeat across connections or unrelated relays.

## Receipt retention

Acceptance receipts are indexed by storage owner and database sequence. Each
synchronization window captures an upper sequence boundary. Later acceptance
belongs to a later window. Client progress is durable, and an incomplete window
does not prove that a pending operation was unaccepted.

Receipts are retained until account erasure. There is no age-based pruning.
Adding pruning requires a durable reconciliation watermark or another explicit
retention contract that accounts for offline clients.

An unreadable historical receipt source leaves a durable backfill-block marker.
Iota preserves the original operation bytes and can still process unrelated relay
work. Receipt synchronization fails for the affected owner until the source is
repaired. If corrupt bytes hide the owner, the receipt subsystem fails closed for
all owners. Do not delete the marker without restoring complete receipt coverage.

## Edit key epochs

`VersionNumber` identifies the encryption key for an edit's replacement
ciphertext. Any positive version available in the owner's canonical chat-secret
namespace is permitted, including a historical version. A missing version leaves
the accepted operation retryable instead of partially updating either local copy.

The relay transaction updates content, `key_version`, edit history and sync events
together. New history rows retain both ciphertext key epochs. Existing history
rows have null epoch fields because the old schema did not record them. Migration
does not guess those lost versions.

## Release verification

Run these commands from the Iota checkout in its Nix development shell, with
published dependencies and the committed lockfile:

```sh
nix develop --command cargo fmt --all -- --check
nix develop --command cargo check --locked --workspace --all-targets
nix develop --command cargo test --locked --workspace --all-targets --all-features
nix develop --command cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Validate Tau independently before pinning its revision in Iota, Omikron and the
client. Refresh Cargo lockfiles and Nix dependency hashes, then build without
Cargo patches or local dependency overrides. A successful local patched build
does not establish that a release can be reproduced from its pins.

The all-feature run includes the relay fault-injection tests. Those tests verify
that an unexpired dispatch lease remains owned across a crash and that recovery
can take over after expiry.
