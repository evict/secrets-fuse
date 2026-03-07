# secrets-guard - Transparent secret injection via seccomp + FUSE

A process wrapper that transparently intercepts file reads and injects secrets from 1Password. Applications read their normal config paths; secrets-guard intercepts the `openat` syscall, verifies the calling binary's SHA-256 hash, and serves the secret via a private FUSE mount.

**No ptrace. No eBPF. No root required.** Uses `SECCOMP_RET_USER_NOTIF` (kernel ≥5.14) + Landlock-style private FUSE.

## How it works

1. `secrets-guard` mounts a private FUSE filesystem at a random path under `/run/user/UID/`
2. It re-execs itself as a child, installs a seccomp BPF filter intercepting `openat`/`openat2`, then execs the target binary
3. When the target opens a configured secret path, the seccomp notification wakes the parent
4. The parent reads `/proc/PID/exe` (kernel-resolved, unforgeable), hashes it, and checks against trusted hashes
5. If trusted: opens the secret on the private FUSE mount, injects the fd into the child via `SECCOMP_ADDFD_FLAG_SEND`
6. The child's `openat()` returns the FUSE fd transparently — it reads the secret as if it were a normal file
7. The child runs with `PR_SET_DUMPABLE=0`, making `/proc/PID/fd/` root-only

## Prerequisites

### Linux kernel ≥5.14

Required for `SECCOMP_ADDFD_FLAG_SEND`. Check with:

```bash
uname -r
```

### Enable 1Password Desktop Integration

1. Open and unlock the [1Password app](https://1password.com/downloads/)
2. Select your account or collection at the top of the sidebar
3. Navigate to **Settings** > **Developer**
4. Under "Integrate with the 1Password SDKs", select **Integrate with other apps**
5. (Optional) For biometric unlock, go to **Settings** > **Security** and enable biometric unlock

See [1Password SDK documentation](https://developer.1password.com/docs/sdks/desktop-app-integrations/) for more details.

## Installation

```bash
go install github.com/evict/secrets-guard@latest
```

## Configuration

Create a configuration file at `~/.config/secrets-guard.conf` or `config.yaml`:

```yaml
op_account: "my.1password.com"

secrets:
  - path: "~/.config/app/secrets.json"      # path the app tries to open
    reference: "op://VAULT-UUID/ITEM-UUID/FIELD"
    trusted_binaries:                        # SHA-256 hashes of allowed executables
      - "sha256:a1b2c3d4..."                 # /usr/bin/myapp
    max_reads: 0                             # 0 = unlimited
    writable: false
```

### Trusted Binaries

Generate hashes for binaries you want to allow:

```bash
secrets-guard -hash /usr/bin/myapp
# sha256:a1b2c3d4e5f6...
```

If `trusted_binaries` is empty, any binary is allowed (useful for development).

### 1Password Account

Priority: `-account` flag > `OP_ACCOUNT` environment variable > config file `op_account`

### Getting 1Password References

```bash
# Get account URL
op account list

# Get vault UUID
op vault list

# Get item UUID and fields
op item list --vault VAULT-UUID
op item get ITEM-UUID
```

Common fields: `password`, `username`, `credential`, `notesPlain`

## Usage

```bash
# Run an application with secret injection
secrets-guard -- /usr/bin/myapp --flag

# With explicit config
secrets-guard -config /path/to/config.yaml -- myapp

# Override 1Password account
secrets-guard -account my.1password.com -- myapp

# Enable debug logging (FUSE + seccomp)
secrets-guard -debug -- myapp

# Hash a binary for the config file
secrets-guard -hash /usr/bin/myapp
```

### Flags

- `-config`: Path to configuration file (default: `~/.config/secrets-guard.conf` or `config.yaml`)
- `-account`: 1Password account (default: `$OP_ACCOUNT`)
- `-debug`: Enable FUSE and seccomp debug logging
- `-hash`: Print SHA-256 hash of a binary and exit

## Security Model

| Layer | Protection |
|---|---|
| seccomp `USER_NOTIF` | Intercepts `openat`/`openat2`; child suspended until parent responds |
| Binary hash verification | `/proc/PID/exe` is kernel-resolved, cannot be spoofed |
| TOCTOU checks | `notif_id_valid()` called before and after path extraction |
| Private FUSE mount | Random path under `/run/user/UID/` (mode 0700) |
| FUSE guard PID | Only the parent process can open FUSE files |
| `PR_SET_DUMPABLE=0` | `/proc/PID/fd/` inaccessible to non-root |
| `PR_SET_NO_NEW_PRIVS` | Required by seccomp, prevents privilege escalation |
