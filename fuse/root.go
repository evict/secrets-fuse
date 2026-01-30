package fuse

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/evict/secrets-fuse/secretmanager"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type SecretConfig struct {
	Reference string
	Filename  string // optional custom filename
	MaxReads  int32  // 0 = unlimited
}

type SecretRoot struct {
	fs.Inode
	manager  secretmanager.SecretManager
	secrets  []SecretConfig
	maxReads int32 // default max reads for all secrets
}

func NewSecretRoot(manager secretmanager.SecretManager, secrets []SecretConfig, defaultMaxReads int32) *SecretRoot {
	return &SecretRoot{
		manager:  manager,
		secrets:  secrets,
		maxReads: defaultMaxReads,
	}
}

func (r *SecretRoot) OnAdd(ctx context.Context) {
	for _, secret := range r.secrets {
		filename := secret.Filename
		if filename == "" {
			filename = referenceToFilename(secret.Reference)
		}

		maxReads := secret.MaxReads
		if maxReads == 0 {
			maxReads = r.maxReads
		}

		child := r.NewInode(ctx, NewSecretFile(r.manager, secret.Reference, maxReads),
			fs.StableAttr{Mode: fuse.S_IFREG})
		r.AddChild(filename, child, true)
	}
}

// referenceToFilename converts "op://Vault/Item/Field" to "Vault_Item_Field"
func referenceToFilename(ref string) string {
	// Remove protocol prefix
	ref = strings.TrimPrefix(ref, "op://")
	// Replace path separators with underscores
	ref = strings.ReplaceAll(ref, "/", "_")
	// Clean up the path
	return filepath.Clean(ref)
}
