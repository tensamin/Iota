# Unmanaged signed releases

Publishing belongs to prod-pins. Iota only builds and verifies release inputs.

## Operator commands

Run as root for the unmanaged system installation:

```sh
iota update channel stable
iota update channel canary
iota update check
iota update apply
```

`iota update channel` shows the selected channel. Selection atomically persists
`/etc/iota/update.env` without fetching or applying a release. The standalone
`iota-updater` supports the same commands. Check and apply read this file directly,
including the pinned public key and key ID. Process environment cannot replace
the trust configuration. Channel selection preserves both trust values and all
per-channel anti-replay state.

The manifest URL is
`https://git.methanium.net/tensamin/prod-pins/releases/download/CHANNEL/iota-update-linux-ARCH.json`.
The signature URL appends `.sig`. CHANNEL is `stable` or `canary`, ARCH is
`x86_64` or `aarch64`. Apply can select a previously accepted target when the
active release belongs to the other channel. It still rejects older sequences,
sequence/version reuse and failed activation sequences. Same-channel explicit
rollback remains respected.

The initial ZIP installer remains supported. It preserves existing update.env
and removes a previously provisioned unattended update timer. The update service
is an explicit oneshot apply operation with no timer.

## Release script contracts

```sh
bash scripts/build-update-manifest.sh BINARY_DIRECTORY BASE_VERSION CHANNEL RELEASE_SEQUENCE PUBLISHED_AT EXPIRES_AT linux ARCH BASE_URL OUTPUT.json
iota-release sign OUTPUT.json OUTPUT.json.sig
bash scripts/build-release-bundle.sh BINARY_DIRECTORY PRODUCT_VERSION OUTPUT.json MANIFEST_URL PUBLIC_KEY SIGNATURE_URL CHANNEL SIGNING_KEY_ID OUTPUT.zip
iota-bundle OUTPUT.zip
```

The binary directory contains `iota`, `iota-daemon` and `iota-updater`.
The manifest script emits PRODUCT_VERSION as `BASE_VERSION-CHANNEL-FULL_SOURCE_SHA`.
Read `.product_version` from the generated manifest for the bundle command.
Use an immutable release BASE_URL in prod-pins. Upload the binaries there as
`iota-linux-ARCH`, `iota-daemon-linux-ARCH` and `iota-updater-linux-ARCH`.
The signed artifact paths remain `bin/iota`, `bin/iota-daemon` and
`bin/iota-updater`, with SHA-256 hashes and byte lengths.

Publish the manifest and signature under each mutable `stable` or `canary`
release as `iota-update-linux-ARCH.json` and `iota-update-linux-ARCH.json.sig`.
Sequences must increase per channel. Serialize publication per channel and
reject a lower sequence or reuse with a different product version. Keep
immutable binary assets available for already published manifests.

## Signature and workflow inputs

`IOTA_RELEASE_SIGNING_KEY` is a secret containing a 32-byte Ed25519 seed as
64 hexadecimal characters. `iota-release sign` prints the derived 32-byte
public key as hex. Compare it with the expected pinned public key before
publishing or building installer trust configuration.

The detached signature is 64 Ed25519 bytes encoded as 128 hexadecimal
characters. It signs `serde_json::to_vec` of the typed `ReleaseManifest`, in
the Rust declaration field order, with nested artifacts in their declaration
field order. It does not sign the pretty-printed JSON file bytes. Use the Rust
signer rather than a generic JSON canonicalizer.

The prod-pins workflow needs:

- `IOTA_RELEASE_SIGNING_KEY`, secret signing seed.
- `IOTA_RELEASE_SOURCE_SHA`, full 40-character Iota source commit SHA. Defaults
  to the local repository HEAD, so set it explicitly when building elsewhere.
- `IOTA_RELEASE_SIGNING_KEY_ID`, defaults to `primary`.
- Expected pinned public key, supplied as the bundle PUBLIC_KEY argument.
- Base product version, channel, positive release sequence, RFC 3339 publication
  and expiry timestamps, architecture and immutable artifact BASE_URL.
- A Forgejo API token with release upload access to `tensamin/prod-pins`.

Build the Rust release binaries plus `iota-release` and `iota-bundle`. Shell
scripts require bash, git, coreutils, jq and zip. No Iota publishing workflow
remains; verification runs in `.forgejo/workflows/validate.yml`.
