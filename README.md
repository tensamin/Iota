# IOTA

A lightweight, Rust-based TUI and service orchestrator for Tensamin IOTA.
Iota manages users and stores their messages and communities. It can be run in a centralised, decentralised or hybrid mode.

The Iota is a work in progress.

## Terminal themes

The TUI defaults to the ANSI theme. Select a theme for one invocation with `--theme`:

```text
iota --theme monospace
iota --theme binary status
```

The available names are `monospace`, `binary`, `ansi`, and `surface`. Theme selection uses this precedence: `--theme`, `IOTA_THEME`, then `ui.yaml` in Iota's configuration directory. For example:

```text
IOTA_THEME=surface iota
```

On Linux, the configuration file defaults to `~/.config/iota/ui.yaml` (or `$XDG_CONFIG_HOME/iota/ui.yaml` when set):

```yaml
theme: surface
```

An invalid `ui.yaml` value is reported and Iota falls back to ANSI so the TUI can still start.

## Accepting terms without the TUI

Iota services do not start until the required agreements have been accepted for
the deployment. Use the terminal flow to read each current document and type
the document-specific acceptance phrase:

```text
iota terms accept
```

For a system-managed daemon, accept its deployment-scoped terms as an account
that can write the system Iota state directory (normally via `sudo`):

```text
sudo iota terms accept --system
```

`iota terms status` reports the stored state, and `iota terms show eula`,
`iota terms show tos`, or `iota terms show privacy` displays an individual
document without accepting it.

# Linux daemon installation

The system-managed daemon runs as the dedicated `iota` account and listens on
`/run/iota/iota.sock` through socket activation. The system IPC socket is the
privilege boundary. Operator access is granted through the `iota-operators`
group, and every account admitted through that socket is authorized for the
full operator-console role, including user management, identity rotation,
configuration, and daemon lifecycle commands. After installing, add an
account with:

```text
usermod -aG iota-operators USER
```

The user must start a new login session before supplementary group membership
is visible. Unix per-user deployments must set `IOTA_SOCKET` to an absolute
path; Iota does not derive its IPC socket from `XDG_RUNTIME_DIR`.

## Asset storage limits

`storage_limits` in Iota's configuration controls upload admission. Defaults are 256 MiB per asset, 2 GiB of committed assets plus active upload reservations per user, four active uploads per user, 512 MiB of free filesystem space reserved, four concurrent asset I/O workers, and 4096 blobs per user. Set these fields to match deployment capacity:

```yaml
storage_limits:
  max_asset_bytes: 268435456
  max_user_asset_bytes: 2147483648
  max_active_asset_uploads_per_user: 4
  min_free_asset_storage_bytes: 536870912
  max_asset_io_workers: 4
  max_user_blobs: 4096
```

Replacement uploads temporarily count both old and new assets until commit.

## Relay freshness

Signed relays expire after 30 days less five minutes; replay rows remain for 30 days. `max_relay_future_skew_millis` defaults to 300000, or five minutes, and can be reduced for deployment clock tolerance. Fixed five-minute margin keeps freshness within replay retention even if configuration changes. Timestamps use Unix milliseconds.

Asset and blob list responses contain at most 128 entries. Send the returned positive `Offset` as the next request cursor; `Offset: 0` ends pagination. `web.max_mtp_sessions` defaults to 256 and limits concurrent authenticated MTP sessions. `web.max_mtp_sessions_per_user` defaults to four sessions per hosted user. Legacy web administration requires the non-default `legacy-web-admin` feature.
