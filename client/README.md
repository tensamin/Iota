# Inbound connection admission

Decentralized startup installs `ConnectionGateway` with Tau's authenticated role
rules. The gateway accepts `client` and `iota-peer:<node-id>`. It normalizes the
peer policy description while retaining the declared canonical node identity.
Neither the description nor the numeric MTP hint proves application authority.

Hosted admission rechecks the current account key, local hosting relationship,
and principal record. Tau's connection UUID correlates the application session
and active sender. `HostedSessionRegistrar` is currently infallible. Its insertion
and sender publication run synchronously after Tau activation.

Peer admission derives the full node identity from the verified key and checks
the declaration and numeric hint. `PeerManager::validate_peer` performs the trusted
directory lookup and produces the private-construction `ValidatedPeer` handoff.
Peers use `DirectPeerRouter`, with generation-checked removal, rather than the
hosted-user session registry. Outbound connection establishment remains in
`PeerManager`.

The webserver supervises accepted handlers and retains their limits until cleanup
finishes. Shutdown interrupts idle receive loops through the handler's cancellation
token. Handlers finish accepted application operations before removing their
registry entries. Cancelling a future would not roll back committed state.
Scoped guards remove connection-local registrations if a handler future is dropped.
The daemon drains webserver handlers and supervised outbound peers before its
generic task shutdown deadline. Shutdown joins remain owned by their supervisors
when a waiter is cancelled.

Authentication storage runs on a shared blocking executor with eight permits.
Cancelled lookup waiters do not release a permit until the SQLite closure finishes.
Peer authentication hints use an indexed column in the canonical directory.
Ambiguous active hints fail closed. Descriptor updates update that column in the
same transaction as keys; expiry and deletion apply directly to each lookup.

Relay identity preparation has a 15 second deadline before relay mutation.
Remote delivery has a 30 second deadline after durable retry publication. Response
delivery has a 5 second deadline and cannot roll back an accepted relay. The
webserver's `shutdown_budget_secs` defaults to 60. A budget overrun reports
`ShutdownReport::Incomplete`, preserves task ownership of permits, and causes
the daemon to exit with failure. It does not claim local cleanup succeeded.
Unfinished synchronous storage operations remain a process-termination limitation.
SQLite rolls back open transactions on process termination; committed relay retry
entries remain available for recovery. Operators must investigate incomplete
shutdown reports before treating the node as cleanly stopped.

## Trust lifetime

Hosted keys, hosting assignments and principal records are rechecked before
requests, after cancellable Relay V2 proof preparation, and every five seconds
while idle. Failed lookup or changed binding removes that connection's UUID
capabilities and closes its transport. Account management can call `revoke_session`
for one connection or `revoke_principal` after an account-wide authoritative change.
Already committed operations finish without rollback; revoked sessions cannot
start another mutation. Idle revocation detection includes storage lookup latency,
which has a separate 15 second deadline.

Peer trust is checked before publication, before outbound routing, after Relay V2
preparation, and every five seconds while idle. Removal, expiry, trusted-key
replacement or lookup failure stops new peer work and closes invalid connections.
`revoke_peer` removes the selected route immediately after an authoritative
directory revocation. Superseded transports still use live directory checks.
Endpoint changes apply to subsequent outbound dials and do not revoke an otherwise
trusted existing key. Generation checks keep stale cleanup from removing replacements.

Outbound transports have registration guards from handshake completion through
handler exit. `PeerManager` tracks their tasks, closes transports on shutdown,
clears inbound response waiters, and drains committed operations under the daemon's
configured budget. Network replies and live delivery remain cancellable after commit.

Centralized startup retains its existing hosted-client handler. Both startup paths
keep MTP forced authentication and host-side numeric namespace accounting.
The centralized compatibility handler shares hosted key binding and scoped
publication cleanup. `PeerManager`'s compatibility handler validates the expected
peer description and full transport binding in `accept_validated`; decentralized
startup must install `ConnectionGateway` instead.

## Local Tau development

Tau and Iota share the canonical MTP Git URL and pinned revision. Normal builds
use the published Tau revision in `Cargo.toml`. From the workspace root:

```sh
cargo --config "patch.'https://git.methanium.net/tensamin/tau'.tau.path='../tau'" check -p client
```

Run a normal build afterwards to restore the published dependency in `Cargo.lock`.
