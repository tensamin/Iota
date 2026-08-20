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
