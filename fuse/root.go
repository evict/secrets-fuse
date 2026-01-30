package fuse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evict/secrets-fuse/secretmanager"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type SecretConfig struct {
	Reference   string
	Filename    string   // optional custom filename
	MaxReads    int32    // 0 = unlimited
	AllowedCmds []string // glob patterns for allowed command lines
	SymlinkTo   string   // optional path to create a symlink to the secret
}

func (s *SecretConfig) CreateSymlink(mountPoint string) (string, error) {
	if s.SymlinkTo == "" {
		return "", nil
	}

	filename := s.Filename
	if filename == "" {
		filename = filepath.Base(s.Reference)
	}

	target := filepath.Join(mountPoint, filename)
	linkPath := s.SymlinkTo

	if len(linkPath) > 0 && linkPath[0] == '~' {
		if home, err := os.UserHomeDir(); err == nil {
			linkPath = filepath.Join(home, linkPath[1:])
		}
	}

	if info, err := os.Lstat(linkPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			os.Remove(linkPath)
		} else {
			return "", fmt.Errorf("path %s exists and is not a symlink", linkPath)
		}
	}

	if err := os.Symlink(target, linkPath); err != nil {
		return "", fmt.Errorf("creating symlink %s -> %s: %w", linkPath, target, err)
	}
	return linkPath, nil
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

		child := r.NewInode(ctx, NewSecretFile(r.manager, secret.Reference, maxReads, secret.AllowedCmds),
			fs.StableAttr{Mode: fuse.S_IFREG})
		r.AddChild(filename, child, true)
	}
}

// referenceToFilename converts "op://Vault/Item/Field" to "Vault_Item_Field"
func referenceToFilename(ref string) string {
	ref = strings.TrimPrefix(ref, "op://")
	ref = strings.ReplaceAll(ref, "/", "_")

	return filepath.Clean(ref)
}