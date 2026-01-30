# secrets-fuse

A FUSE filesystem that exposes secrets from 1Password as virtual files.

## Prerequisites

### Enable 1Password Desktop Integration

1. Open and unlock the [1Password app](https://1password.com/downloads/)
2. Select your account or collection at the top of the sidebar
3. Navigate to **Settings** > **Developer**
4. Under "Integrate with the 1Password SDKs", select **Integrate with other apps**
5. (Optional) For biometric unlock, go to **Settings** > **Security** and enable **Unlock using Touch ID** (macOS) or **Windows Hello** (Windows)

See [1Password SDK documentation](https://developer.1password.com/docs/sdks/desktop-app-integrations/) for more details.

## Installation

```bash
go install github.com/evict/secrets-fuse@latest
```

## Configuration

Create a configuration file at `~/.config/secret-fuse.conf` or `config.yaml`:

```yaml
op_account: "my.1password.com"  # default 1Password account (optional)

secrets:
  - reference: "op://VAULT-UUID/ITEM-UUID/FIELD"
    filename: "secrets.json"
    max_reads: 1  # 0 = unlimited
    writable: true  # optional: allow writing back to password manager
    allowed_cmds:  # optional: restrict which commands can read this secret
      - "/usr/bin/myapp"
      - "python *"
    symlink_to: "~/.config/app/secrets.json"  # optional: create symlink to secret
    # op_account: "other.1password.com"  # optional: override account for this secret
```

### Writable Secrets

Set `writable: true` to allow writing to the secret file. Changes are written back to the password manager. A backup of the previous value is created automatically (e.g., `field_previous` for fields, `.bak` for document files).

### Symlinks

The `symlink_to` field creates a symlink pointing to the mounted secret file. Supports `~` expansion. The symlink is created on mount and removed on unmount. Only existing symlinks will be replaced; regular files are not overwritten.

### 1Password Account

The `op_account` field specifies which 1Password account to use for desktop app integration. It can be set at the top level as a default, or per-secret to override.

Priority: `OP_ACCOUNT` environment variable > config file `op_account`

### Allowlist Patterns

The `allowed_cmds` field accepts glob patterns matched against the full command line or executable path:

- `/usr/bin/myapp` - exact match
- `python *` - any python command
- `*/node *` - node from any path
- Empty list or omitted = allow all

### Getting 1Password References

1. List your accounts to get the account URL:

```bash
op account list
```

Use the value from the URL column (e.g., `my.1password.com`).

2. List your vaults to get the vault UUID:

```bash
op vault list
```

3. List items in a vault to get the item UUID:

```bash
op item list --vault VAULT-UUID
```

4. Get item details to see available fields:

```bash
op item get ITEM-UUID
```

Common fields: `password`, `username`, `credential`, `notesPlain`

### Example

```bash
# Get account URL
$ op account list
URL                           EMAIL
my.1password.com              user@example.com

# Get vault UUID
$ op vault list
ID                            NAME
abc123...                     Personal

# Get item UUID
$ op item list --vault abc123
ID                            TITLE
def456...                     API Key

# Check available fields
$ op item get def456
...
password: ********
...

# Configure
secrets:
  - reference: "op://abc123/def456/password"
    filename: "api-key.txt"
```

## Usage

```bash
# Mount with default path (/tmp/secrets-mount)
secrets-fuse

# Mount with custom path
secrets-fuse -mount /run/user/$(id -u)/secrets

# Mount with explicit config
secrets-fuse -mount /tmp/secrets -config /path/to/config.yaml

# Enable debug logging
secrets-fuse -debug
```

### Flags

- `-mount`: Mount point for the secrets filesystem (default: `/tmp/secrets-mount`)
- `-config`: Path to configuration file (default: `~/.config/secret-fuse.conf` or `config.yaml`)
- `-max-reads`: Default maximum reads per secret, 0 = unlimited (default: 0)
- `-debug`: Enable FUSE debug logging

## Unmounting

Press `Ctrl+C` to unmount. If the filesystem is busy, close any files or terminals using the mount and try again.