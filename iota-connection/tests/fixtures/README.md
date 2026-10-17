# Client Relay V2 interoperability fixtures

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

The Iota integration test decodes each original outer MTP frame, compares the
canonical outer signature input, verifies and decrypts through Iota's actual
`decode_and_verify_for_ingress`, and compares the exact original application
bytes. It also rejects the wrong private key, destination, changed message ID and
changed signature. Identity resolution uses generated fixture principals.

Regenerate the browser file from the client root with Chromium installed and
`RELAY_BROWSER_BIN` set, then run:

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
