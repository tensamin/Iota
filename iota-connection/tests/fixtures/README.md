# Client relay interoperability fixtures

These files contain generated test keys only. They are not user credentials.

`relay_browser_v2.json` is captured from actual Chromium executing the client's
`sendFederatedRelay`, including SDK framing, WASM signing and encryption, and
IndexedDB journaling. Its canonical signature bytes are constructed independently
in JavaScript. A test-only Vite transform copies the original SDK application
frame immediately before signing. This preserves its randomly generated frame ID
without replacing the encoder. Directory replies and transport settlement are
simulated.

`relay_desktop_v2.json` is captured from the actual desktop
`federated_relay::sign` function. Its export test includes the production module.
Unused UI conversion and live connection manager entry points panic if reached.
The producer's identity checks, signing, encryption and framing execute unchanged.

The two JSON V2 fixtures are historical formats, not native MTP sealed relays.
The current test explicitly checks their rejection. The verification branch for
new signed federation fixtures checks canonical signature input, application
bytes, recipient encryption and tampering.

The following capture commands require a historical Client revision that still
contains these producers. They do not generate native sealed frames.

Regenerate the historical browser file from that Client root with Chromium
installed and `RELAY_BROWSER_BIN` set, then run:

```sh
RELAY_INTEROP_FIXTURE=/absolute/path/relay_browser_v2.json pnpm exec vitest run packages/mtp/src/relayInterop.test.ts
```

Regenerate the desktop file from the client root with:

```sh
RELAY_INTEROP_FIXTURE=/absolute/path/relay_desktop_v2.json nix develop .#tauri --command cargo test --locked --manifest-path apps/tauri/src-tauri/Cargo.toml --test relay_interop export_actual_desktop_producer_for_iota_ingress -- --exact
```

Run Iota verification from the Iota root with:

```sh
nix develop --command cargo test --locked -p iota-connection --test relay_client_interop
```

`RELAY_BROWSER_INTEROP_FIXTURE` and `RELAY_DESKTOP_INTEROP_FIXTURE` override the
checked-in files for a fresh producer-to-backend run.

## Pinned native sealed relay

`relay_native_client.json` comes from the unchanged `MTPClient.sendSealedRelay`
in the Client's pinned `0.4.0-dev-b678361` package. The capture script rebuilds
that package's bundled Rust sources with the Client's application type map,
using the pinned Vite plugin outside `client/`. It uses the same raw-binding and
type-map aliases that the plugin installs. A default package WASM build has no
application types and cannot encode `SetChatSecret`.

The script also imports the unchanged Client `chatSecret.ts` through TypeScript
transpilation. Both recipient copies must pass `unwrapChatSecret()`. A changed
wrapping namespace must fail. The fixture records package-input, WASM, type-map
and wrapping-source hashes. It contains generated Iota decryption keys only.

Regenerate from the Iota root, with the pinned Client dependencies installed:

```sh
nix develop --no-write-lock-file ../client --command node iota-connection/tests/native_relay_fixture.mjs iota-connection/tests/fixtures/relay_native_client.json
```

`RELAY_CLIENT_WASM_DIR` can select an existing application-map WASM build. The
script verifies its Vite build fingerprint before accepting it. A stale cache
fails rather than silently becoming a new fixture.

The Rust test opens metadata and content using the explicit bounded MTP APIs
with both intended Iota keys, preserves the captured frame and numeric wrapping
namespace, and rejects mismatched identities, keys, destination and tampering.
This is a cryptographic boundary test, not a two-hop transport test. Production
`RelayService`, durable replay, routing and acknowledgement still require native
format integration. The new decoder does not activate that ingress path.
