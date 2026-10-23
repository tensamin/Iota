# Backend federation

Standalone federation uses HTTPS identity discovery and authenticated MTP. Omega
and Omikron are not involved. The top-level Tensamin client application has not
been migrated to this wire format.

## Configuration

Federation is opt-in. `web.federation_mode` defaults to `private`, which does not
publish identity discovery or activate incoming federation roles. Select
`federated_direct` for public inbound MTP, or `federated_relay` for an outgoing
connection to configured routers. Both public modes require HTTPS discovery and
an authority locator. Relay mode must not advertise a public direct endpoint.

```yaml
web:
  federation_mode: federated_direct
  mode: network
  bind: 0.0.0.0
  port: 1984
  certificate: /etc/tensamin/tls/fullchain.pem
  key: /etc/tensamin/tls/privkey.pem
  required: true
  authority_locator: example.com
  direct_endpoints:
    - iota.example.com:1984
  relay_hints: []
relay_routers: []
```

For `bob@example.com`, `example.com` must serve `/.well-known/tensamin` and the
`/federation/v1/node` and `/federation/v1/users/...` routes. A TLS-authenticated
reverse proxy can serve those routes from the Iota on port 1984. Publishing an MTP
endpoint on another hostname does not delegate identity discovery to that host.

The signed node descriptor is authoritative for endpoints. Discovery publishes
the same endpoint lists. Endpoint and descriptor changes currently require a
daemon restart. Startup renews descriptors approaching expiry. Do not leave a
daemon running beyond its published descriptor's validity window without renewal.

For a relay-only home node, set `federation_mode: federated_relay`, leave
`direct_endpoints` empty and configure `relay_routers` with the router's endpoint,
public key and certificate file. HTTPS discovery must still be reachable through
the authority's proxy. There is no implicit registrar or discovery delegation.

Public discovery rejects non-public connection targets. Trusted LAN deployments
can explicitly set `web.allow_lan_federation: true`. Raw-IP discovery additionally
requires `web.allow_raw_ip_federation: true`. Its certificate and node pinning are
TOFU, not independently verified domain ownership. Public hostname discovery uses
normal certificate verification. Redirects and proxy environment variables are
disabled for federation metadata. Response bodies, deadlines and parallel fetches
are bounded.

## Introduction and trust

The public bootstrap routes are `POST /federation/peer/challenge` and
`POST /federation/peer/introduce`. The challenge does not create an MTP key entry.
The dual-signature proof binds the descriptor digest, nonce, expiry and both node
IDs. SQLite atomically consumes the proof's nonce and records a provisional lease.
Replaying a proof fails. A new challenge for an existing live lease cannot extend
that lease.

Defaults under `web.peer_introduction` are:

| Setting | Default |
| --- | --- |
| `max_request_bytes` | 65536 |
| `max_concurrent_requests` | 8 |
| `request_timeout_ms` | 15000 |
| `challenge_lifetime_ms` | 60000 |
| `admission_lifetime_ms` | 300000 |
| `max_pending_challenges` | 1024 |
| `max_challenges_per_origin` | 8 per minute |
| `max_admissions` | 1024 |

The HTTP limiter counts challenge and proof requests, including invalid requests.
Persistent challenges also enforce per-origin and global quotas across restart.
The admission cap includes established entries. Operators should revoke abusive
peers rather than silently deleting their pins or revocation records.

MTP looks up established and provisional keys in one SQLite snapshot. Ambiguous
64-bit authentication hints fail closed. The backend gateway verifies the full
node ID, role description, hint and transport-authenticated key. Only then does
it promote the lease and record the signed descriptor in one transaction.
Established descriptor renewal requires a fresh possession proof and respects
monotonic revisions. Neither introduction nor discovery changes user contacts.
`PeerTrust` distinguishes provisional leases from established descriptor revisions.
Validation does not promote a lease. The client-facing gateway first binds the
authenticated key, full node ID, hint and requested role, then promotes that exact
lease. Its Tau identity carries established trust before session activation.
Expired or replaced leases cannot publish a route, even if the same node already
has an independently discovered directory entry. SQLite's node directory always
enforces this policy, including when no outgoing introducer is configured.
Federation relays still pass through principal resolution, home-node checks,
blocklists, processing claims and the existing application transaction.

An initiator's claimed authority locator is stored with the challenge. The
responder verifies possession before fetching that locator independently over
HTTPS. Successful verification records the persistent authority-to-locator
mapping. A node with no verifiable authority can authenticate its node key, but
that proof does not authorize arbitrary canonical user principals.

Outgoing dials are task-owned single flights. Cancelling a waiter does not cancel
the shared attempt. Attempts have a total budget, bounded concurrency and a retry
delay. Successful introductions are cached for their admission lifetime; network
failures do not cause repeated introduction or automatic key replacement.

## Optional router mailbox

To operate a router, set `web.serve_relay_router: true` on a federated Iota. For
durable forwarding, also set `web.relay_mailbox: {}`. An omitted mailbox keeps
online-only forwarding. Router access requires its separate authenticated
`iota-router` role and an established or introduced node key.
Router access is separately controlled by `web.relay_router_allowed_nodes`, a list
of canonical node IDs. It defaults to empty. To serve every successfully introduced
peer under the configured quotas, explicitly set `web.relay_router_public: true`.

The mailbox uses the existing router request/response protocol. It stores the
immutable encrypted envelope before forwarding and leases pending entries to
the authenticated destination's live connection. Its envelope ID binds signer,
recipient, destination and message ID. Reusing that identity with different bytes
fails. The router checks that the signed destination matches the requested route
and that the authenticated sender owns the signer's Iota authority.

Defaults under `web.relay_mailbox` are a 4 MiB frame cap, 10000 entries, 100 per
sender, 1000 per destination, 256 MiB of queued payloads and a 24-hour TTL.
Expired entries are removed during store and fetch. Failed entries are delayed
so they cannot monopolize delivery. SQLite leases fence stale workers.

Storage returns a retryable result to the sender. It never synthesizes destination
acceptance. After the destination commits its inbox operation and responds on its
authenticated connection, the router retains the correlated acceptance and
discards the queued ciphertext. The sender's existing durable queue obtains that
acceptance on retry. Acceptance records expire at the original mailbox TTL.
Destination deduplication handles redelivery after a lost response or crash.

## Key continuity and revocation

Node keys are self-certifying. A new key means a new node and authority ID.
`iota_identity::node_transition::NodeTransition` supports dual-signed transitions
with a bounded validity period and an exact previous descriptor revision.
`iota_storage::node_transition::record` records the verified transition against
the established revision, rejects divergent successors and revokes the old node.
It does not rename principals, change domain pins or rewrite encrypted secrets.
Applications adopting the replacement must resolve and explicitly approve its
new canonical principals separately.

`iota_storage::peer_admission::revoke` persists a tombstone.
`PeerManager::revoke_peer` also removes and closes its selected route immediately.
Active transports recheck trust periodically and before relay application;
revoked peers cannot regain access through another introduction. No network
protocol removes a revocation or replaces a pin automatically.
Local revocation notifications also interrupt transports blocked in identity
discovery. Descriptor deadlines close expired sessions without waiting for the
periodic external-writer check. These checks never promote a provisional peer.

If the previous key is lost, the transition cannot be signed. Recovery requires
an operator to verify ownership out of band and explicitly establish a new
authority with new principal IDs. Existing contacts must approve that identity.
Keep the old pins and revocation records as evidence; do not SQL-replace IDs or
secret namespaces.

## Operator diagnostics

The existing authenticated daemon component/health IPC reports a JSON diagnostic
message on the web component. It includes node descriptor validity, the local
HTTPS discovery/TLS probe, connected-router state, the last peer authentication
error, pending remote relay count and oldest retry time.

`discovery_reachable` and `advertised_mtp_reachable` remain unknown with
`external_probe_status: not_configured`. The local HTTPS probe does not prove
external reachability. Verify DNS, TLS proxying, TCP/UDP access and MTP from an
external host before advertising a direct endpoint. No user or peer diagnostics
are exposed through an unauthenticated public status route.

## Wire and development databases

Federation uses one unversioned `RelayWire` JSON object in MTP SecurePayload.
Unknown JSON fields and extra outer metadata, including legacy VersionNumber,
are rejected. Signing and derived-message-ID domains are independently separated
with NUL terminators. Chat IDs use `principal:` with the original sorted-pair
serialization. Application message/secret generations and MTP type-map versions
remain intact.

Identity descriptor wire versions, `/federation/v1/...` routes, `iota:v1:` node IDs
and credential text formats remain unchanged. They are separate from this relay
migration. Frozen legacy client fixtures are rejection tests; they were not
rewritten to masquerade as new signatures.

SQLite migrations 61 through 64 append authority locators, admission state,
mailbox state and transition proofs. Existing accepted relay transactions and
recovery work keep their current schema. For pre-release installations with old
relay frames or chat namespaces, back up and rebuild the development database.
There is no in-place rewrite of signed or encrypted data.

## Validation

The Iota workspace patches both Tau packages to the sibling `../tau` checkout.
Validate the local graph with `cargo tree -i tau-relay-protocol`. Publication still
requires coordinated Tau revision and Nix hash updates.

From `iota/`:

```sh
nix develop --override-input type-maps path:./mtp-type-maps --command cargo fmt --all --check
nix develop --override-input type-maps path:./mtp-type-maps --command cargo test --workspace --all-targets
nix develop --override-input type-maps path:./mtp-type-maps --command cargo clippy --workspace --all-targets -- -D warnings
```

Tau's relay crate is an independent workspace. From `tau/relay-protocol/`, run its
native tests with `MTP_TYPE_MAPS="$PWD/tests/type-maps.yaml"`. Its tests deliberately
use two distinct application maps to verify that decoding never falls back to the
latest map. The production Iota map is not a substitute for that test registry.

`iota-daemon/tests/clean_federation.rs` starts two actual daemon processes with
separate databases and keys, deterministic local TLS and no remote key seeding.
It checks address resolution, first-contact introduction, authenticated transport,
secret and message delivery, canonical refresh after restart and duplicate
application. Storage tests cover atomic nonce races, lease expiry, hint ambiguity,
pin conflicts, mailbox leases and identity transitions. Router tests exercise
online forwarding and durable offline delivery separately.
`client/tests/peer_admission.rs` exercises the backend gateway over real MTP. It
checks role isolation, expiry between handshake and activation, stale admission
after renewal, and revocation while a relay is blocked in discovery.
