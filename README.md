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

# Linux daemon installation

The system-managed daemon runs as the dedicated `iota` account and listens on
`/run/iota/iota.sock` through socket activation. Operator access is granted
through the `iota-operators` group. After installing, add an account with:

```text
usermod -aG iota-operators USER
```

The user must start a new login session before supplementary group membership
is visible. Unix per-user deployments must set `IOTA_SOCKET` to an absolute
path; Iota does not derive its IPC socket from `XDG_RUNTIME_DIR`.
