# secrets-fuse

A FUSE filesystem that exposes secrets from 1Password as virtual files.

## Installation

```bash
go install github.com/evict/secrets-fuse@latest
```

## Configuration

Create a configuration file at `~/.config/secret-fuse.conf` or `config.yaml`:

```yaml
secrets:
  - reference: "op://VAULT-UUID/ITEM-UUID/FIELD"
    filename: "secrets.json"
    max_reads: 1  # 0 = unlimited
```

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
# Mount with default config (~/.config/secret-fuse.conf or ./config.yaml)
secrets-fuse -mount ~/mnt/secrets

# Mount with explicit config
secrets-fuse -mount ~/mnt/secrets -config /path/to/config.yaml

# Enable debug logging
secrets-fuse -mount ~/mnt/secrets -debug
```

### Flags

- `-mount`: Mount point for the secrets filesystem (default: `~/mnt/secrets`)
- `-config`: Path to configuration file (default: `~/.config/secret-fuse.conf` or `config.yaml`)
- `-max-reads`: Default maximum reads per secret, 0 = unlimited (default: 0)
- `-debug`: Enable FUSE debug logging

## Unmounting

Press `Ctrl+C` to unmount. If the filesystem is busy, close any files or terminals using the mount and try again.
