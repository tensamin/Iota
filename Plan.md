# Iota Decentralization Implementation Guide

## Scope

The implementation should proceed in three stages:

1. Separate Iota responsibilities so decentralized routing, foreign users, and Communities can use common identity, authentication, session, storage, and routing services.
2. Implement decentralized operation without requiring an Omega or Omikron.
3. Compose centralized and decentralized providers into hybrid mode.

This guide does not include:

* UI changes.
* Add Conversation UI changes.
* Browser bootstrap changes.
* Static webclient hosting on the Iota.
* Reimplementation of Communities themselves.

The networking endpoint required for a client to connect directly to an Iota is in scope because decentralized mode requires it. Serving the webclient assets from that endpoint is not.

The old `iota/communities` crate should be treated as a prototype, not as the implementation base. It is excluded from the workspace and its authentication and storage model do not fit the new architecture.

Look at MTP when deciding protocol / connection details.

---

# Stage 1: Separate the Iota architecture

## Goal

After Stage 1, the Iota should still operate in centralized mode, but core Iota logic should no longer depend directly on `OmikronConnection`.

The architectural target is:

```text
                         +--------------------+
                         |   Daemon / IPC     |
                         +----------+---------+
                                    |
                  +-----------------+-----------------+
                  |                                   |
          +-------v--------+                  +-------v--------+
          | AccountService |                  | SessionManager |
          +-------+--------+                  +-------+--------+
                  |                                   |
          +-------v--------+                  +-------v--------+
          | IdentityService|<---------------->| AuthService    |
          +-------+--------+                  +----------------+
                  |
        +---------+----------+
        |                    |
+-------v-------+    +-------v-------+
| Local users   |    | Foreign users |
| and accounts  |    | and principals|
+---------------+    +---------------+

                  +-------------------+
                  |   RelayService    |
                  +---------+---------+
                            |
                  +---------v---------+
                  |    PeerRouter     |
                  +---------+---------+
                            |
         +------------------+------------------+
         |                                     |
 +-------v---------+                    +------v------+
 | Omikron adapter |                    | future peer |
 | centralized     |                    | transports  |
 +-----------------+                    +-------------+
```

`OmikronConnection` becomes one provider attached to these abstractions. It stops implementing identity resolution, account lifecycle, relay processing, routing, and client delivery itself.

## 1. Introduce canonical identity types

The current system treats numeric `user_id` values as globally meaningful because Omega allocates them.

That assumption must stop at the domain layer.

Create a small identity module or crate, preferably `iota-identity`, containing types with no network or database dependencies.

Suggested concepts:

```rust
pub struct IotaNodeId(/* hash/fingerprint of Iota public identity */);

pub struct AuthorityId(/* stable cryptographic authority identity */);

pub enum AuthorityKind {
    Iota,
    Omega,
}

pub struct PrincipalId {
    pub authority: AuthorityId,
    pub user_id: u64,
}

pub enum UserSelector {
    UserId(u64),
    Username(String),
}

pub struct UserAddress {
    pub selector: UserSelector,
    pub public_key_pin: Option<PublicKeyBundle>,
    pub authority: Option<AuthorityLocator>,
}
```

A username is an alias used for lookup. It must not become the network identity.

A public key supplied through an address is a verification pin. It must not replace the authority and user ID pair as the canonical identity because keys need to be rotatable.

For example:

```text
alice@example.org
```

might resolve to:

```text
AuthorityId = Iota abc123...
UserId      = 51
Username    = alice
Key         = K1
```

The canonical identity is:

```text
abc123... / 51
```

If `alice` later changes display name or rotates keys, existing chats and community memberships still reference the same principal.

### Numeric IDs must become local identifiers

Keep the existing local `UserProfile.user_id`.

It remains useful as the local account identifier.

Do not use it as a network-wide user identity after this boundary.

Code should make the distinction visible:

```rust
pub struct LocalUserId(pub i64);
pub struct PrincipalHandle(pub i64);
```

Using separate Rust types is preferable to aliases because accidentally passing a local user ID into a federated lookup should become a compile-time error where practical.

## 2. Add a principal directory separate from hosted users

Do not place users from another Iota or Omega into the existing `users` table.

Current code uses:

```rust
user_manager::get_user(id).is_some()
```

as a locality test in relay handling.

If foreign users are inserted into that table, the Iota will incorrectly conclude that they are hosted locally.

Create a separate principal directory.

A useful model is:

```text
principals
----------
principal_pk
authority_kind
authority_id
remote_user_id
username
display_name
current_public_key
descriptor_revision
descriptor_valid_until
last_resolved_at

UNIQUE(authority_id, remote_user_id)
```

Key history should be stored separately if rotation is supported:

```text
principal_keys
--------------
principal_pk
public_key
valid_from
valid_until
source_revision
```

Aliases can also be separate:

```text
principal_aliases
-----------------
principal_pk
authority_locator
username
```

`principal_pk` is an Iota-local database handle. It exists so existing tables do not have to carry large cryptographic authority identifiers everywhere.

Then expose distinct storage services:

```rust
trait LocalUserStore {
    fn get_local_user(...);
    fn get_local_user_by_username(...);
    fn is_hosted_here(...);
}

trait PrincipalStore {
    fn get_principal(...);
    fn get_by_canonical_id(...);
    fn upsert_remote_descriptor(...);
    fn signing_keys(...);
}
```

A locally hosted account should also have a corresponding principal record.

That produces one identity namespace for chats, relays, Communities, ACLs, and foreign connections without pretending every principal is hosted locally.

## 3. Migrate references to remote users toward `PrincipalHandle`

Several current tables use numeric remote user IDs directly.

The main examples include:

* `contacts.user_id`
* `messages.external_user`
* relay replay state
* relay inbox state
* queued relay identity
* blocked users
* receipt policy
* chat secrets and other per-peer state

Do not attempt a complete database rewrite in one commit.

Introduce repository APIs that accept `PrincipalHandle`, then migrate consumers behind those APIs.

For centralized users already stored by numeric Omega user ID, Stage 1 migration can create principal records representing:

```text
(current Omega authority, existing numeric user ID)
```

This preserves existing behavior while removing the assumption that the number alone identifies the user.

`storage_owner` can remain a local user ID because only a locally hosted account owns local account storage.

The important separation is:

```text
storage_owner -> LocalUserId
external_user -> PrincipalHandle
```

## 4. Build `IdentityService`

Move all user identity lookup behind one service.

Suggested interface:

```rust
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    async fn resolve_address(
        &self,
        address: &UserAddress,
        context: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError>;

    async fn resolve_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<ResolvedPrincipal, IdentityError>;

    async fn signing_keys(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError>;
}
```

`ResolvedPrincipal` should contain at least:

```rust
pub struct ResolvedPrincipal {
    pub principal: PrincipalId,
    pub handle: PrincipalHandle,
    pub username: Option<String>,
    pub public_keys: Vec<PublicKeyBundle>,
    pub home: PrincipalHome,
}
```

During Stage 1, implement:

```text
LocalIdentityResolver
OmegaIdentityResolver
```

`OmegaIdentityResolver` wraps the behavior currently embedded in:

```text
OmikronConnection::resolve_relay_signing_keys
OmikronConnection::hosting_iota_for_user
GetUserData
```

The rest of the Iota must stop issuing `GetUserData` itself.

## 5. Separate account lifecycle from Omega

The daemon command router currently calls:

```text
omikron_connector::user_ops::create_user
omikron_connector::user_ops::attach_user_from_tu
omikron_connector::user_ops::inspect_tu_credential
omikron_connector::user_ops::get_remote_user_assignment
```

directly.

Replace that dependency with an account service.

For example:

```rust
#[async_trait]
pub trait AccountAuthority: Send + Sync {
    async fn create_user(&self, request: CreateUserRequest)
        -> Result<LocalAccount, AccountError>;

    async fn inspect_credential(&self, credential: &[u8])
        -> Result<CredentialPreview, AccountError>;

    async fn attach_user(&self, credential: &[u8])
        -> Result<LocalAccount, AccountError>;

    async fn reconcile_user(&self, user: LocalUserId)
        -> Result<ReconcileResult, AccountError>;

    async fn release_user(&self, user: LocalUserId)
        -> Result<(), AccountError>;
}
```

Stage 1 provides:

```text
OmegaAccountAuthority
```

which internally calls the current `omikron_connector::user_ops`.

Stage 2 will add:

```text
LocalIotaAccountAuthority
```

The IPC command router should depend only on `AccountAuthority`.

This removes a large amount of mode-specific logic from `iota-daemon-lib/src/command_router.rs`.

## 6. Extract relay processing from `OmikronConnection`

This is the most important Stage 1 refactor.

`OmikronConnection::handle_relay()` currently performs several unrelated responsibilities:

* relay metadata verification
* signer lookup
* local/remote user classification
* replay reservation
* policy validation
* content opening
* message application
* outgoing history updates
* relay queue insertion
* forwarding
* local client event generation
* success/error responses

Move these into a transport-independent `RelayService`.

Conceptually:

```rust
pub struct RelayService {
    identities: Arc<dyn IdentityResolver>,
    local_users: Arc<dyn LocalUserStore>,
    principals: Arc<dyn PrincipalStore>,
    router: Arc<dyn PeerRouter>,
    sessions: Arc<SessionManager>,
    storage: Arc<RelayStorage>,
    iota_identity: Arc<IotaIdentity>,
}
```

Ingress becomes:

```rust
relay_service
    .accept_relay(IngressSource::Omikron(...), frame)
    .await;
```

Later:

```rust
relay_service
    .accept_relay(IngressSource::Peer(...), frame)
    .await;
```

and:

```rust
relay_service
    .accept_relay(IngressSource::HostedClient(...), frame)
    .await;
```

The handler should not care how the relay reached the Iota.

### Preserve the existing relay machinery

Do not rewrite the following unless the identity migration requires it:

* durable pending relay queue
* relay inbox
* replay lifecycle
* delivery acknowledgements
* sealed relay verification
* message application
* outgoing message history policy

The current implementation already has the difficult storage and retry behavior.

The purpose of Stage 1 is to move it behind a reusable service.

## 7. Separate relay transport from relay semantics

`ConnectionHandler` already describes itself as supporting Omikron, direct, and future modes, but its current return-position `impl Future` API is inconvenient for heterogeneous dynamically selected connections.

Change it to an object-safe asynchronous interface.

For example:

```rust
#[async_trait]
pub trait ConnectionHandler: Send + Sync {
    async fn send_message(
        &self,
        value: &CommunicationValue,
    ) -> Result<(), ConnectionError>;

    async fn await_response(
        &self,
        value: &CommunicationValue,
        timeout: Option<Duration>,
    ) -> Result<CommunicationValue, ConnectionError>;

    async fn is_connected(&self) -> bool;

    async fn is_identified(&self) -> bool;

    async fn stop(&self);
}
```

Then introduce the higher-level routing interface separately:

```rust
#[async_trait]
pub trait PeerRouter: Send + Sync {
    async fn send_to_iota(
        &self,
        destination: &IotaNodeId,
        frame: CommunicationValue,
    ) -> Result<DeliveryReceipt, RouteError>;
}
```

`ConnectionHandler` represents one connection.

`PeerRouter` answers the question:

```text
How do I reach this Iota?
```

Do not combine those two responsibilities.

## 8. Replace mandatory Omikron in `DaemonServices`

Current:

```rust
pub struct DaemonServices {
    pub omikron: Arc<dyn OmikronClient>,
    ...
}
```

Target:

```rust
pub struct DaemonServices {
    pub accounts: Arc<dyn AccountAuthority>,
    pub identities: Arc<dyn IdentityResolver>,
    pub principals: Arc<dyn PrincipalStore>,
    pub local_users: Arc<dyn LocalUserStore>,
    pub relay: Arc<RelayService>,
    pub router: Arc<dyn PeerRouter>,
    pub sessions: Arc<SessionManager>,
    pub auth: Arc<AuthService>,

    pub centralized: Option<Arc<CentralizedServices>>,
}
```

`OmikronClient` can remain available inside the centralized adapter for Omega-specific administration.

Core handlers should not receive it.

Daemon startup must also stop treating construction of an Omikron connection as a prerequisite for normal Iota construction.

During Stage 1, centralized mode still creates it, but service composition should look like:

```text
construct storage
construct identity services
construct auth
construct session manager
construct Omikron adapter
construct centralized peer router
construct relay service
construct account service
start daemon
```

instead of:

```text
connect Omikron
build everything around Omikron
```

## 9. Build one session model for hosted and foreign clients

Communities require users from other authorities to connect directly to an Iota without becoming hosted accounts on that Iota.

Create a general session manager rather than another community-specific connection implementation.

Suggested distinction:

```rust
pub enum SessionIdentity {
    Hosted {
        local_user: LocalUserId,
        principal: PrincipalHandle,
    },
    Foreign {
        principal: PrincipalHandle,
    },
}
```

A connection then has:

```rust
pub struct AuthenticatedSession {
    pub connection_id: Uuid,
    pub identity: SessionIdentity,
    pub capabilities: SessionCapabilities,
}
```

Capabilities should determine what the connection can do.

A hosted client could receive capabilities such as:

```text
AccountData
Messaging
Settings
LocalStorage
Communities
```

A foreign client connected to a Community Iota might receive only:

```text
Community(<community-id>)
```

The foreign session must not gain access to:

* local account state
* local user settings
* hosted user message history
* local user management
* other Communities
* arbitrary relay origination unless explicitly allowed

This makes Communities an authorization problem rather than a parallel networking stack.

## 10. Repurpose `iota-auth`

`iota-auth` currently appears detached from the working architecture.

Use it for reusable principal authentication.

It should support:

```text
HostedAccountAuthenticator
ForeignPrincipalAuthenticator
IotaPeerAuthenticator
```

### Foreign principal authentication

A foreign user should be able to connect to the Iota hosting a Community without becoming a user hosted by that Iota.

The flow should be:

```text
client -> identify as PrincipalId or UserAddress
Iota   -> load cached principal or resolve authority
Iota   -> obtain trusted public key history
Iota   -> issue challenge
client -> prove possession of matching private key
Iota   -> create Foreign session
```

The existing MTP authentication facilities can be used where appropriate.

Do not make Communities implement another hand-written WebSocket challenge protocol like the old excluded prototype.

### Authentication without contacting the home authority every time

The foreign user's home Iota or Omega should not have to be online for every Community connection.

On initial resolution, store an authority-authenticated user descriptor and key material locally.

Subsequent authentication can use the cached trusted key while that descriptor remains valid under its authority rules.

If there is no trusted cached descriptor and the authority cannot be reached, authentication must fail closed.

This gives Communities the required property:

```text
Foreign user connects directly to Community Iota
        |
        +-> Community Iota verifies their existing identity
        |
        +-> user is not hosted on Community Iota
```

## 11. Prepare Communities around principals

Do not implement Community behavior yet.

Only establish interfaces Communities will later consume.

Community membership should eventually reference:

```text
PrincipalHandle
```

not:

```text
UserProfile
LocalUserId
raw username
```

Community ACL logic should be able to ask:

```rust
session.principal()
community_membership.has_permission(principal, permission)
```

A Community handler should not need to know:

* which Omega the user belongs to
* which Iota hosts the user
* whether the current connection came through centralized or decentralized networking
* how the user's public key was resolved

That information belongs below the Community layer.

## 12. Stage 1 acceptance criteria

Stage 1 is complete when all of the following hold:

* [x] Existing centralized users continue to work.
* [x] Existing Omikron relay traffic enters `RelayService`.
* [x] `RelayService` does not depend on `OmikronConnection`.
* [x] User creation from the daemon goes through `AccountAuthority`.
* [x] Core identity lookup goes through `IdentityResolver`.
* [x] Remote users are represented independently from hosted users.
* [x] A foreign principal can be authenticated without being inserted into the hosted `users` table.
* [x] Session authorization distinguishes hosted and foreign clients.
* [x] Two users with the same numeric user ID under different authorities are different principals.
* [x] Daemon service construction no longer exposes Omikron as the primary general-purpose service.
* [x] The future Communities implementation can identify an authenticated remote participant using only a `PrincipalHandle`.

At the end of Stage 1, behavior should still be centralized. The architecture should no longer be centralized.

---

# Stage 2: Implement decentralized mode

## Goal

A deployment consisting of:

```text
Client A
Iota A

Client B
Iota B
```

must be able to create local accounts, authenticate clients, resolve remote users, and exchange messages without either Iota belonging to an Omega or connecting to an Omikron.

If direct Iota-to-Iota connectivity is impossible, an independent relay/router may be used.

That relay is infrastructure, not an Omega or Omikron.

## 1. Give every Iota a standalone cryptographic identity

The existing Omega-assigned `iota_id` cannot be the decentralized node identity.

Create:

```rust
pub struct IotaNodeId(...);
```

derived from the persistent Iota public identity.

The exact representation should be stable across restarts and independent from IP address, hostname, Omega membership, or Omikron assignment.

An Iota can then simultaneously have:

```text
IotaNodeId
legacy Omega Iota ID
network endpoints
relay endpoints
```

Only `IotaNodeId` is fundamental.

The Omega-assigned ID becomes centralized compatibility metadata.

Rotating the node keyring changes `IotaNodeId`. The decentralized protocol must
treat this as creating a new Iota identity, not as rotating operational keys
under an existing node identity.

Implementation status:

* [x] Persist the Iota keyring through `LocalNodeIdentity`, outside the Omikron connector.
* [x] Derive a versioned `IotaNodeId` from the canonical public key bundle.
* [x] Derive the decentralized `AuthorityId` from `IotaNodeId`.
* [x] Reject arbitrary unversioned `IotaNodeId` strings.
* [x] Load `LocalNodeIdentity` during standalone daemon startup.

## 2. Define decentralized user identity

A locally created decentralized user becomes:

```text
PrincipalId {
    authority: this Iota's AuthorityId,
    user_id: locally allocated ID
}
```

Two Iotas can both contain local user `42` without collision:

```text
Iota A / 42
Iota B / 42
```

The user's public key is attached to the principal descriptor.

It is not necessary for local numeric IDs themselves to be globally unique.

### Finish application storage migration

Before decentralized relays enter normal chat storage, contacts and messages
must use canonical principals as their authoritative external identity.

Migrate contact uniqueness from:

```text
(storage_owner, user_id)
```

to:

```text
(storage_owner, principal_handle)
```

Migrate message, receipt, reaction, block, chat-secret, notification, and sync
lookups toward `PrincipalHandle` or `PrincipalId`. Keep remote numeric user IDs
only as legacy protocol metadata.

The existing client may continue to use an Iota-local stable contact or chat ID.
The backend maps that local ID to `PrincipalHandle`; it must not expose a remote
authority's numeric user ID as the cross-authority identity.

Implementation status:

* [x] Store contacts uniquely by `PrincipalHandle`.
* [x] Treat `messages.external_principal` as authoritative.
* [x] Migrate the remaining persisted peer-identity lookups.
* [x] Verify that two authorities can each provide numeric user ID `7` to one local user.

## 3. Implement the address parser

Support a generic form:

```text
<selector>[::<public-key>][@<authority>]
```

Implementation status:

* [x] Parse username and numeric selectors with optional key pins and authorities.
* [x] Normalize domain names, IP literals, ports, and bracketed IPv6 authorities.
* [x] Reject empty fields, malformed key pins, and extra authority delimiters.
* [x] Discover authority identity and service type through `/.well-known/tensamin`.

Examples:

```text
alice
51

alice@192.0.2.20
51@iota.example.org

alice::KEY@iota.example.org
51::KEY@omega.example.org

alice@omega.example.org
```

The selector is:

```text
username
or
numeric user ID
```

The optional public key is a pin.

The optional authority selects the resolver.

### No `@`

If no `@` is supplied, use the account's default authority.

For a decentralized account:

```text
own Iota
```

For a centralized account:

```text
own Omega
```

Hybrid behavior is handled in Stage 3.

### Literal IP

Treat a literal IP authority as an Iota endpoint.

The connection must still authenticate the remote Iota key and obtain its `IotaNodeId`.

### Domain

A domain needs service discovery because:

```text
alice@example.org
```

does not itself reveal whether `example.org` is an Iota or Omega.

Define a small discovery document, for example:

```text
/.well-known/tensamin
```

An Iota response should expose:

```text
service type
protocol versions
IotaNodeId
public key
direct endpoints
relay hints
```

An Omega response should identify itself as an Omega and expose its public authority identity and supported lookup protocols.

The authority type is discovered, not guessed from the username syntax.

### Public-key pin

For:

```text
51::KEY@omega.example.org
```

resolution should:

```text
query authority
resolve user 51
obtain trusted key
compare against KEY
reject on mismatch
```

The supplied key must not silently override authority data.

## 4. Define signed user descriptors

Remote user resolution needs a transferable authenticated record.

For example:

```rust
pub struct UserDescriptor {
    pub principal: PrincipalId,
    pub username: String,
    pub display_name: Option<String>,
    pub public_keys: Vec<PublicKeyBundle>,
    pub home_iota: IotaNodeId,
    pub revision: u64,
    pub valid_until: Option<Timestamp>,
    pub authority_signature: Signature,
}
```

For an Iota-native user, the hosting Iota signs the descriptor.

For an Omega-native user, the Omega signs the descriptor and identifies the user's hosting Iota.

The local Iota verifies the descriptor before inserting it into `PrincipalStore`.

Keep the untrusted signed wire type separate from the verified descriptor stored
by `PrincipalStore`. Network code must not construct the trusted storage type
without signature, authority, revision, and validity checks.

This descriptor becomes the basis for:

* remote key lookup
* foreign Community authentication
* route lookup
* contact information
* key rotation
* cached offline authentication

Key rotation will use a separate authority-signed key-history record. Principal
descriptors contain only keys valid for new signatures at descriptor issue
time. `PrincipalStore` closes prior key validity when it accepts a newer
descriptor, so old keys are not trusted indefinitely. Add the signed history
record before accepting signatures created before the current descriptor.

## 5. Implement direct client-to-Iota sessions

The current `client/src/client_connection.rs` already contains much of the client-side server logic, but it explicitly rejects:

```text
Relay
AccountStateRequest
AccountStateApplied
MessageSend
```

where centralized infrastructure currently owns those paths.

Stage 2 should make these call the common services introduced in Stage 1.

A hosted client connection should become:

```text
MTP transport
    |
    v
hosted-user authentication
    |
    v
SessionManager
    |
    +-> account state
    +-> RelayService
    +-> message handlers
    +-> settings/storage
```

Implement a dedicated network gateway for this purpose.

Do not make static webclient serving part of this work.

The gateway can share MTP infrastructure with existing components, but its responsibility is only:

```text
accept network connection
authenticate
create session
forward messages into Iota services
```

## 6. Implement local account creation

Add:

```text
LocalIotaAccountAuthority
```

User creation becomes:

```text
validate username
allocate local user ID
generate user keyring
persist UserProfile
create local Principal record
persist credential
return account
```

No Omega request occurs.

The account's authority is the local Iota.

### Version `.tu` credentials

Current `.tu` credentials contain Omega-specific assumptions.

Introduce a versioned credential format capable of representing:

```text
credential version
PrincipalId
authority descriptor
user keyring
```

Legacy Omega credentials must remain parseable.

Do not reinterpret existing credentials as decentralized credentials.

A credential needs to state which authority owns the account.

## 7. Implement `other-iota`

`iota/other-iota` currently provides the peer connection and router interfaces,
an in-memory `DirectPeerRouter`, and a `PeerRelayAdapter`. It does not yet create
network connections.

Its responsibility should be Iota peer connectivity, not general message semantics.

Suggested components:

```text
PeerManager
PeerConnection
PeerAuthenticator
PeerDiscovery
PeerConnectionPool
```

The handshake should authenticate the remote Iota using its node key.

A successful peer connection becomes keyed by:

```text
IotaNodeId
```

not hostname or legacy numeric Iota ID.

Before implementing the handshake, define relay provenance rules. A direct peer
that originates a user relay should authenticate as the signer's home Iota.
Infrastructure that forwards opaque frames needs a separate ingress role and
authorization policy.

For example:

```rust
pub enum PeerIngressSource {
    DirectPeer { node_id: IotaNodeId },
    RelayRouter { router_id: RelayRouterId },
}
```

A valid user signature proves authorship. It does not prove that the connected
Iota is authorized to originate that network hop.

### Direct path

The basic path becomes:

```text
Iota A
  |
  | authenticated peer connection
  v
Iota B
```

The receiving peer passes relay frames into:

```text
RelayService
```

It does not contain another copy of relay handling logic.

## 8. Replace numeric decentralized relay identities

The current relay format uses bare numeric:

```text
signer_id
final_recipient_id
Iota route ID
```

That is insufficient once multiple independent authorities exist.

Introduce a federated relay version containing canonical principals.

Conceptually:

```rust
pub struct FederatedRelayIdentity {
    pub signer: PrincipalId,
    pub recipient: PrincipalId,
}
```

The route must identify an Iota using:

```text
IotaNodeId
```

not the existing Omega-assigned numeric Iota ID.

Do not truncate a key fingerprint to fit the existing numeric route field.

Version the protocol instead.

### Compatibility

Keep legacy relay parsing for centralized traffic.

Normalize both forms into an internal representation:

```rust
pub struct VerifiedRelayEnvelope {
    pub signer: ResolvedPrincipal,
    pub recipient: ResolvedPrincipal,
    pub message_id: RelayMessageId,
    pub created_at: Timestamp,
    pub content: VerifiedRelayContent,
    pub compatibility: RelayCompatibilityData,
}
```

The common representation must not require `legacy_iota_id` or read canonical
identity from V1 fields such as `verified.context.signer_id` and
`verified.context.final_recipient_id`. `LegacyRelayDecoder` owns those fields and
places any required numeric data in optional compatibility metadata.

The common service returns domain results rather than encoded V1 frames:

```rust
pub struct RelayOutcome {
    pub ingress_response: RelayResponse,
    pub local_deliveries: Vec<ClientDelivery>,
}
```

The ingress adapter encodes `ingress_response`. A local client-event sink or
adapter sends `local_deliveries`. A peer adapter must not call `into_frames()` and
send local client events back to the remote Iota.

For a legacy relay:

```text
numeric user ID + configured Omega authority
```

becomes a canonical `PrincipalId`.

For a decentralized relay, the canonical identity is already encoded.

From that point onward, storage and application logic should use the normalized representation.

## 9. Migrate replay protection

Current replay protection effectively keys on:

```text
signer_id
message_id
```

This becomes unsafe with independent user namespaces.

Change it to:

```text
PrincipalId
message_id
```

or its stable local `PrincipalHandle`.

The same applies to:

* `relay_inbox`
* `RelayIdentity`
* pending relay ownership
* outgoing relay bookkeeping

This migration is required before two authorities can safely contain the same numeric user ID.

Implementation status:

* [x] Key replay identity by signer principal and message ID.
* [x] Store principal-aware relay identity and decentralized queue destinations.
* [x] Complete the application-storage migration described under decentralized user identity.

## 10. Implement decentralized routing

`PeerRouter` should resolve a destination principal to its home Iota:

```text
PrincipalId
   |
   v
IdentityService
   |
   v
UserDescriptor.home_iota
   |
   v
PeerRouter
```

Then the router selects a transport:

```text
direct connection
or
external relay/router
```

The application layer should not know which was selected.

Move durable retry execution out of `OmikronConnection` into a common
`PendingRelayDispatcher`. It consumes `RelayTarget` and uses `PeerRouter` for
both legacy Omega Iotas and decentralized `IotaNodeId` destinations.

The `RelayTarget::Iota(_)` branch must deliver queued relays and preserve restart
recovery semantics before direct peer messaging is complete.

Implementation status:

* [x] Resolve `PrincipalHome` into centralized or decentralized route destinations.
* [x] Persist `IotaNodeId` and legacy Omega Iota destinations separately.
* [x] Route through the `PeerRouter` abstraction.
* [x] Dispatch pending decentralized relays through `PeerRouter`.

## 11. Add an independent Iota relay/router

Two Iotas behind networks without inbound connectivity cannot guarantee direct communication using only those two machines.

Provide a separate relay service.

Its responsibility should be intentionally narrow:

```text
authenticate Iota nodes
associate IotaNodeId with active connection
accept opaque frame for destination IotaNodeId
forward frame
```

It should not:

* allocate users
* resolve usernames
* host user data
* issue user identities
* decrypt sealed user relays
* become an Omega
* become an Omikron

The topology becomes:

```text
Iota A ---- outbound ----+
                         |
                         v
                    Relay/router
                         |
                         +---- active connection ---- Iota B
```

Both Iotas can establish outbound connections to it.

The existing origin Iota relay queue should remain responsible for durable retries.

The router can remain primarily a live forwarding service.

### Multiple routers

An Iota descriptor can advertise multiple relay hints.

A PeerRouter can attempt:

```text
existing direct connection
known direct endpoint
configured/advised relay
```

without changing the message handler.

Implementation status:

* [x] Authenticate router and Iota connections with pinned public keys.
* [x] Register live Iota connections by `IotaNodeId`.
* [x] Forward opaque Relay V2 frames and return destination acknowledgements.
* [x] Mark destination ingress as `IngressSource::RelayRouter`.
* [x] Provide direct-first routing with relay fallback.
* [x] Add deployment configuration for explicit router endpoint, public-key, and TLS certificate pins, and publish configured endpoints as signed relay hints.

## 12. Support Omega addresses without requiring a local Omega

A decentralized Iota should be able to resolve:

```text
alice@omega.example.org
```

without itself being registered with that Omega.

Add an `OmegaAuthorityResolver`.

Its responsibility is only to query the explicitly addressed Omega.

For example:

```text
local decentralized Iota
        |
        | public identity query
        v
omega.example.org
        |
        v
signed UserDescriptor
```

The remote Omega must expose enough information to obtain:

```text
remote user's canonical Omega principal
remote user's public keys
hosting Iota
hosting Iota decentralized identity/endpoints
```

This does not make Omega mandatory for decentralized mode.

It means an address explicitly naming an Omega depends on that remote authority for initial resolution.

If the descriptor is cached, future identity verification can use the cached material according to its validity rules.

## 13. Fetch and cache remote public user data

Remote user fetching should use `IdentityResolver`, not message handlers.

A lookup can populate:

```text
PrincipalId
username
display name
public key history
home Iota
descriptor revision
descriptor validity
```

Do not cache arbitrary private account data from another Iota.

The distinction should remain:

```text
PrincipalStore = public identity information
LocalUserStore = accounts hosted by this Iota
```

## 14. Foreign client connections

Stage 2 should also complete the foreign-session path prepared for Communities.

Example:

```text
User Alice hosted by Iota A

Alice's client
      |
      | connects directly
      v
Iota B hosting a Community
```

Iota B performs:

```text
parse Alice's principal
load or resolve Alice's trusted descriptor
issue authentication challenge
verify proof using Alice's public key
create Foreign session
```

Alice does not become a hosted user on Iota B.

Iota A does not need to proxy the connection.

If Iota B already has a valid cached descriptor, Iota A does not need to participate in that login.

This provides the identity/session foundation Communities need before Communities themselves are implemented.

## 15. Decentralized startup

The daemon must start normally with:

```text
no omikron_host
no omikron_port
no omikron_id
no Omega-issued iota_id
```

The mandatory identity becomes the local Iota keypair and derived `IotaNodeId`.

Startup should construct:

```text
LocalIotaAccountAuthority
LocalIdentityResolver
RemoteIotaResolver
OmegaAuthorityResolver
DirectPeerTransport
RelayPeerTransport
RelayService
SessionManager
```

The Omikron connector should not be constructed.

## 16. Stage 2 acceptance tests

The following integration tests should exist before calling decentralized mode complete.

### Independent namespaces

Create:

```text
Iota A / user 1
Iota B / user 1
```

Verify that the users remain separate throughout:

```text
contacts
relay verification
messages
blocking
replay protection
foreign sessions
```

### Direct messaging

Run two Iotas without Omega or Omikron.

Create one local user on each.

Resolve the remote address.

Exchange messages over direct Iota-to-Iota transport.

Restart both Iotas and verify stored identity and relay state remain valid.

### Relay messaging

Place the Iotas behind conditions where the test only exposes outbound connectivity through the independent relay service.

Verify the same relay reaches the destination.

No application handler should change between direct and relayed delivery.

### Address resolution

Test:

```text
username@iota-ip
userid@iota-domain
username@iota-domain
userid::public-key@iota-domain
username@omega-domain
userid::public-key@omega-domain
```

Test local inference without `@`.

### Key mismatch

Resolve a valid user while supplying the wrong public-key pin.

The operation must fail.

### Foreign authentication

Cache a foreign user's signed descriptor.

Disconnect the foreign user's authority.

Authenticate the foreign client directly to another Iota.

Verify the session is foreign and cannot access hosted-account functionality.

### Queue recovery

Disconnect the destination Iota.

Send a relay.

Restart the origin Iota.

Reconnect the destination.

Verify the durable relay queue delivers the original relay without generating a second application event.

### No centralized dependencies

Run the Iota with no reachable Omega or Omikron.

Local account creation, local login, remote Iota resolution, peer routing, and messaging must remain functional.

---

# Stage 3: Optional hybrid mode

## Goal

Hybrid mode should not become another set of handlers.

A hybrid Iota should simply construct more providers.

Application code should not need:

```rust
if decentralized {
    ...
} else if centralized {
    ...
} else if hybrid {
    ...
}
```

The mode should affect service composition and route selection, not business logic.

## 1. Composite identity resolution

Build:

```text
CompositeIdentityResolver
```

It dispatches based on the address authority.

Examples:

```text
alice@iota.example
    -> IotaAuthorityResolver

alice@omega.example
    -> OmegaAuthorityResolver

alice
    -> account's configured default authority
```

Do not blindly try Omega and then Iota for the same unresolved address.

The namespace must remain deterministic.

## 2. Store account origin

Every hosted account should know who owns its identity.

For example:

```rust
pub enum AccountOrigin {
    LocalIota {
        authority: AuthorityId,
    },
    Omega {
        authority: AuthorityId,
    },
}
```

This controls account lifecycle operations.

Creating or deleting a locally authoritative user calls:

```text
LocalIotaAccountAuthority
```

An Omega-managed user calls:

```text
OmegaAccountAuthority
```

Messaging code does not need to care.

## 3. Composite routing

Implement route providers:

```text
DirectPeerRoute
RelayPeerRoute
OmikronRoute
```

The router should return a route plan for the destination.

For a decentralized-capable remote Iota:

```text
direct
then independent relay
```

For a legacy centralized destination:

```text
Omikron
```

For an Omega user whose Iota advertises decentralized capability:

```text
direct/relay peer transport
with Omikron available as compatibility fallback
```

The exact preference should live in route policy.

No relay handler should contain transport preference logic.

## 4. Normalize ingress before processing

All ingress paths should produce the same internal object:

```text
Omikron
   |
   +------+
          |
Peer -----+--> normalized verified relay --> RelayService
          |
Client ---+
```

The source transport is metadata used for policy and acknowledgements.

It must not select a separate message implementation.

## 5. Use one replay namespace

A message received through a direct Iota connection and later through Omikron must be recognized as the same logical relay.

Replay identity therefore has to use:

```text
canonical PrincipalId
canonical message ID
```

not transport-specific IDs.

This prevents hybrid mode from applying one message twice after route failover.

## 6. Keep centralized administration isolated

Functions that only make sense for Omega-managed accounts should remain inside the centralized adapter:

```text
Omega invitations
Omikron registration
Iota registration with Omega
Omega assignment reconciliation
Omega-specific credential operations
```

They should not leak back into:

```text
RelayService
IdentityService
SessionManager
Communities
message handlers
```

## 7. Hybrid acceptance criteria

Hybrid mode is complete when:

* One Iota can host both local-Iota-authoritative and Omega-authoritative accounts.
* Both account types use the same local message/session handlers.
* A remote principal resolves to the same canonical identity regardless of transport.
* Direct and Omikron delivery cannot apply the same relay twice.
* Omikron disconnect does not affect decentralized users.
* Direct peer failure does not affect centralized users.
* Communities only see authenticated principals and are independent of the route used to authenticate or contact the user's home network.

---

# Recommended repository boundaries

The current workspace already contains many crates, so avoid splitting every trait into a new crate.

A practical distribution is:

```text
iota-identity
    PrincipalId
    AuthorityId
    UserAddress
    UserDescriptor
    resolver traits
    principal normalization

iota-auth
    hosted authentication
    foreign principal authentication
    peer authentication
    challenge/proof logic

iota-storage
    LocalUserStore
    PrincipalStore
    relay persistence
    account data

iota-connection
    wire-level relay parsing
    relay verification primitives
    normalized connection errors
    transport connection traits

iota-routing
    RelayService
    PeerRouter
    route planning
    relay ingress normalization

client
    authenticated client connection
    session binding
    client message dispatch

other-iota
    PeerManager
    PeerConnection
    peer discovery
    direct peer transport
    external relay transport

omikron-connector
    Omikron transport
    Omega resolver adapter
    Omega account authority
    centralized administration

iota-daemon-lib
    service composition
    IPC
    lifecycle

communities
    future implementation consuming:
        PrincipalId
        SessionManager
        AuthService
        PrincipalStore
        PeerRouter
```

The key rule is that `omikron-connector` should depend inward on common abstractions where necessary. Core identity, relay, session, and Communities code should not depend outward on `omikron-connector`.

---

# Suggested implementation sequence

### Stage 1A: Identity foundation

Implement:

```text
PrincipalId
AuthorityId
UserAddress
PrincipalHandle
PrincipalStore
LocalUserStore wrapper
```

Add tests for identical numeric IDs under different authorities.

Do not change network behavior.

### Stage 1B: Service extraction

Implement:

```text
IdentityResolver
AccountAuthority
PeerRouter
SessionManager
```

Wrap existing centralized behavior.

Change daemon and command-router consumers to use the new interfaces.

### Stage 1C: Relay extraction

Move `handle_relay` logic from `OmikronConnection` into `RelayService`.

Keep Omikron as the only transport initially.

Make the centralized integration tests pass through the new service.

### Stage 1D: Foreign sessions

Implement foreign principal caching and authentication.

Add session capabilities.

Prove that a foreign principal can authenticate without entering `users`.

This completes the architectural work required by future Communities.

The Stage 2 sections describe components. Implement the remaining work in this
dependency order.

### Stage 2A: Principal-native application storage

Make contact uniqueness and message-side identity use `PrincipalHandle`.
Migrate receipts, reactions, blocks, chat secrets, notifications, and sync keys
that still identify a remote user by a bare numeric ID.

### Stage 2B: Protocol-neutral relay domain

Replace `VerifiedNormalizedRelay` with a representation that contains canonical
resolved principals and optional V1 compatibility data. Split ingress responses
from local client deliveries.

### Stage 2C: Federated relay protocol

Add canonical signer and recipient principals plus `IotaNodeId` routing to MTP.
Keep V1 decoding and encoding in transport adapters.

### Stage 2D: Signed descriptors

Define signed node and user descriptor wire types, verification, revision rules,
and cache validity.

### Stage 2E: Authority discovery

Implement raw-IP Iota bootstrap and `/.well-known/tensamin` authority discovery.
Raw-IP bootstrap pins both the authenticated `IotaNodeId` and the observed TLS
certificate. Later direct MTP connections load that certificate pin instead of
using system roots or disabling certificate verification.

### Stage 2F: Local accounts and credentials

Implement `LocalIotaAccountAuthority` and versioned `.tu` credentials. Preserve
the V1 Omega credential parser.

Iota-native `.tu` V2 credentials authenticate accounts already hosted by the
same Iota authority. They do not reconstruct a deleted account. `attach_user()`
must find the matching local account and descriptor state, and it must reject a
credential bound to another `IotaNodeId`. Account backup and deleted-account
restoration require a separate authority-side backup format.

### Stage 2G: Common pending-relay dispatch

Move retry execution out of `OmikronConnection`. Dispatch legacy and
decentralized queue targets through `PeerRouter`, including restart recovery for
`RelayTarget::Iota(_)`.

### Stage 2H: Direct Iota peers

Define peer ingress provenance, then implement mutual node authentication,
listener, dialer, connection pool, duplicate-connection policy, liveness,
reconnection, and `DirectPeerRouter` registration.

### Stage 2I: Federated relay path

Connect two Iotas and exchange one federated relay through `RelayService`. Verify
that the peer receives only the ingress response and the hosted client receives
the local delivery.

### Stage 2J: Direct client gateway

Implement the MTP client gateway and hosted-client relay origination.

### Stage 2K: Standalone daemon composition

Load `LocalNodeIdentity` during daemon startup and compose decentralized
providers without constructing `OmikronConnection`.

### Stage 2L: Independent relay/router

Implement the independent opaque relay/router after direct peer delivery works.

### Stage 2M: Remote Omega resolution

Add direct remote-Omega resolution without requiring a local Omikron connection.

### Stage 2N: Integration suite

Run the Stage 2 acceptance tests. Include two remote authorities that both use
the same numeric user ID, durable queue recovery, key-pin mismatch, cached
foreign authentication, direct delivery, and relay-only delivery.

### Stage 3: Hybrid composition

Add:

```text
CompositeIdentityResolver
CompositeAccountAuthority
HybridPeerRouter
route policy
```

Do not introduce hybrid-specific message handlers.

---

# Architecture required before Communities

Communities should not be started until the following interfaces are stable:

```text
PrincipalId
PrincipalStore
IdentityResolver
AuthService
AuthenticatedSession
SessionCapabilities
IotaNodeId
PeerRouter
```

Once those are available, the Community architecture becomes straightforward:

```text
foreign/local client
        |
        v
AuthService
        |
        v
AuthenticatedSession
        |
        v
Community authorization
        |
        v
Community handlers
```

A Community only needs to answer:

```text
Who is this principal?
Are they a member?
What are they allowed to do?
```

It should not need to answer:

```text
Which Omega owns them?
Which Iota hosts them?
How do I fetch their key?
Did they arrive through Omikron?
Are they a local user?
How do I establish a peer connection?
```

Those questions belong to the infrastructure built in Stages 1 and 2.

The resulting separation also gives decentralized and hybrid mode the same property: identity and application semantics remain stable while the transport and authority providers can change underneath them.
