package fuse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

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
	Writable    bool     // allow writing back to password manager
	OPAccount   string   // optional: override 1Password account for this secret
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

// EphemeralDir is an in-memory directory that supports creating files/subdirs
type EphemeralDir struct {
	fs.Inode
}

func (d *EphemeralDir) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	child := d.NewInode(ctx, &EphemeralDir{}, fs.StableAttr{Mode: fuse.S_IFDIR})
	return child, 0
}

func (d *EphemeralDir) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	child := d.NewInode(ctx, &EphemeralFile{}, fs.StableAttr{Mode: fuse.S_IFREG})
	return child, nil, fuse.FOPEN_DIRECT_IO, 0
}

func (d *EphemeralDir) Unlink(ctx context.Context, name string) syscall.Errno {
	return 0
}

func (d *EphemeralDir) Rmdir(ctx context.Context, name string) syscall.Errno {
	return 0
}

func (d *EphemeralDir) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	return 0
}

func (d *EphemeralDir) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	srcChild := d.GetChild(name)
	if srcChild == nil {
		return syscall.ENOENT
	}

	var content []byte
	if ef, ok := srcChild.Operations().(*EphemeralFile); ok {
		content = ef.content
	} else {
		return syscall.ENOTSUP
	}

	// Destination is SecretRoot with a SecretFile
	if destRoot, ok := newParent.(*SecretRoot); ok {
		destChild := destRoot.GetChild(newName)
		if destChild != nil {
			if sf, ok := destChild.Operations().(*SecretFile); ok {
				sf.mu.Lock()
				sf.content = content
				sf.dirty = true
				sf.mu.Unlock()
				if err := sf.Flush(ctx, nil); err != 0 {
					return err
				}
				d.RmChild(name)
				return 0
			}
		}
	}

	return syscall.ENOTSUP
}

// EphemeralFile is a temporary in-memory file
type EphemeralFile struct {
	fs.Inode
	content []byte
}

func (f *EphemeralFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	return nil, fuse.FOPEN_DIRECT_IO, 0
}

func (f *EphemeralFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if int(off) >= len(f.content) {
		return fuse.ReadResultData(nil), 0
	}
	end := min(int(off)+len(dest), len(f.content))
	return fuse.ReadResultData(f.content[off:end]), 0
}

func (f *EphemeralFile) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	end := int(off) + len(data)
	if end > len(f.content) {
		newContent := make([]byte, end)
		copy(newContent, f.content)
		f.content = newContent
	}
	copy(f.content[off:], data)
	return uint32(len(data)), 0
}

func (f *EphemeralFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Size = uint64(len(f.content))
	out.Mode = 0600
	return 0
}

func (f *EphemeralFile) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if sz, ok := in.GetSize(); ok {
		if sz < uint64(len(f.content)) {
			f.content = f.content[:sz]
		} else if sz > uint64(len(f.content)) {
			newContent := make([]byte, sz)
			copy(newContent, f.content)
			f.content = newContent
		}
	}
	out.Size = uint64(len(f.content))
	out.Mode = 0600
	return 0
}

func (f *EphemeralFile) Flush(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	return 0
}

func (f *EphemeralFile) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	return 0
}

func NewSecretRoot(manager secretmanager.SecretManager, secrets []SecretConfig, defaultMaxReads int32) *SecretRoot {
	return &SecretRoot{
		manager:  manager,
		secrets:  secrets,
		maxReads: defaultMaxReads,
	}
}

func (r *SecretRoot) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	child := r.NewInode(ctx, &EphemeralDir{}, fs.StableAttr{Mode: fuse.S_IFDIR})
	return child, 0
}

func (r *SecretRoot) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	// First check if child exists in the tree
	if child := r.GetChild(name); child != nil {
		return child, 0
	}

	// Check if this is a configured secret that needs to be recreated
	for _, secret := range r.secrets {
		filename := secret.Filename
		if filename == "" {
			filename = referenceToFilename(secret.Reference)
		}
		if filename == name {
			// Recreate the SecretFile inode
			maxReads := secret.MaxReads
			if maxReads == 0 {
				maxReads = r.maxReads
			}
			sf := NewSecretFile(r.manager, secret.Reference, maxReads, secret.AllowedCmds, secret.Writable)
			child := r.NewInode(ctx, sf, fs.StableAttr{Mode: fuse.S_IFREG})
			r.AddChild(name, child, true)
			return child, 0
		}
	}

	return nil, syscall.ENOENT
}

func (r *SecretRoot) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	return 0
}

func (r *SecretRoot) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	srcChild := r.GetChild(name)
	if srcChild == nil {
		return syscall.ENOENT
	}

	// Read content from source (ephemeral file from temp dir)
	var content []byte
	if ef, ok := srcChild.Operations().(*EphemeralFile); ok {
		content = ef.content
	} else {
		return syscall.ENOTSUP
	}

	// Find destination - check if it's a SecretFile
	if destRoot, ok := newParent.(*SecretRoot); ok {
		destChild := destRoot.GetChild(newName)
		if destChild != nil {
			if sf, ok := destChild.Operations().(*SecretFile); ok {
				sf.mu.Lock()
				sf.content = content
				sf.dirty = true
				sf.mu.Unlock()
				if err := sf.Flush(ctx, nil); err != 0 {
					return err
				}
				r.RmChild(name)
				return 0
			}
		}
	}

	return syscall.ENOTSUP
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

		child := r.NewInode(ctx, NewSecretFile(r.manager, secret.Reference, maxReads, secret.AllowedCmds, secret.Writable),
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