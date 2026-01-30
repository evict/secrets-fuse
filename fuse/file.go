package fuse

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/evict/secrets-fuse/secretmanager"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type SecretFile struct {
	fs.Inode
	manager   secretmanager.SecretManager
	reference string

	mu        sync.Mutex
	content   []byte
	readCount atomic.Int32
	maxReads  int32
}

func NewSecretFile(manager secretmanager.SecretManager, reference string, maxReads int32) *SecretFile {
	return &SecretFile{
		manager:   manager,
		reference: reference,
		maxReads:  maxReads,
	}
}

func (f *SecretFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check read limit
	if f.maxReads > 0 {
		current := f.readCount.Load()
		if current >= f.maxReads {
			log.Printf("Secret %s: read limit (%d) exhausted", f.reference, f.maxReads)
			return nil, 0, syscall.EACCES
		}
	}

	// Fetch fresh from secret manager
	val, err := f.manager.Resolve(ctx, f.reference)
	if err != nil {
		log.Printf("Failed to resolve %s: %v", f.reference, err)
		return nil, 0, syscall.ENOENT
	}

	f.content = []byte(val)
	f.readCount.Add(1)

	if f.maxReads > 0 {
		log.Printf("Secret %s: read %d/%d", f.reference, f.readCount.Load(), f.maxReads)
	}

	return nil, fuse.FOPEN_DIRECT_IO, 0
}

func (f *SecretFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if int(off) >= len(f.content) {
		return fuse.ReadResultData(nil), 0
	}

	end := min(int(off)+len(dest), len(f.content))

	return fuse.ReadResultData(f.content[off:end]), 0
}

func (f *SecretFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()

	out.Size = uint64(len(f.content))
	out.Mode = 0400 // r-------- (read-only)
	out.Mtime = uint64(time.Now().Unix())
	return 0
}
