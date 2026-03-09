# AGENTS.md

## Overview

`secrets-guard` is a Go CLI that intercepts secret file opens and serves data from 1Password through a private FUSE mount.

Core flow:

1. `main.go` parses flags and launches the guard.
2. `guard/guard.go` mounts FUSE, re-execs the target under seccomp user notification, and injects FUSE-backed file descriptors for configured secret paths.
3. `seccomp/` handles syscall notification, path extraction, fd injection, and `/proc` helpers.
4. `fuse/` exposes secret files and enforces access checks for read/write/flush operations.
5. `secretmanager/` talks to 1Password.

## Important Behavior

- Guard mode is intentionally strict by default.
- The first trusted runtime process that successfully opens a guarded secret pins the allowed identity.
- Later access must match that exact runtime `proc.name` and full command line.
- This is meant to allow wrapper scripts like Amp while still denying unrelated child processes.
- `Ctrl-C` and `SIGTERM` should unmount the private FUSE mount before exit.
- Avoid reintroducing `os.Exit` from inside `guard.Run`; it skips deferred cleanup.

## Files To Check First

- `main.go`: CLI entrypoint and exit-code handling.
- `guard/guard.go`: lifecycle, seccomp loop, signal cleanup, runtime identity pinning.
- `fuse/file.go`: guard-mode access enforcement after fd injection.
- `fuse/root.go`: secret inode creation and guard config plumbing.
- `procid/identity.go`: runtime identity inspection and pin/match logic.
- `seccomp/proc.go`: `/proc`-based helpers for path, exe, and TGID resolution.

## Local Commands

Use a writable Go cache in this environment:

```bash
env GOCACHE=/tmp/secrets-fuse-gocache go test ./procid
env GOCACHE=/tmp/secrets-fuse-gocache go test -run '^$' ./...
env GOCACHE=/tmp/secrets-fuse-gocache go build .
```

Notes:

- Full `go test ./...` may fail in sandboxed environments because FUSE tests need `/dev/fuse`.
- If you need the installed binary updated, rebuild to `/usr/local/bin/secrets-guard`.

## Editing Guidance

- Keep security checks duplicated at both layers when needed:
  - seccomp decides whether the secret path open is allowed
  - FUSE re-checks access for later reads/writes on injected fds
- Prefer process-level identity checks via TGID-backed `/proc` inspection.
- Be careful with wrappers and launchers: the initial CLI command may not be the long-lived guarded runtime.
- If you change signal handling, preserve explicit unmount and mount-dir cleanup on interruption.
