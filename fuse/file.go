package fuse

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
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
	manager     secretmanager.SecretManager
	reference   string
	allowedCmds []string

	mu        sync.Mutex
	content   []byte
	readCount atomic.Int32
	maxReads  int32
}

func NewSecretFile(manager secretmanager.SecretManager, reference string, maxReads int32, allowedCmds []string) *SecretFile {
	return &SecretFile{
		manager:     manager,
		reference:   reference,
		maxReads:    maxReads,
		allowedCmds: allowedCmds,
	}
}

func (f *SecretFile) isAllowed(cmdline string) bool {
	if len(f.allowedCmds) == 0 {
		return true // no allowlist = allow all
	}
	for _, pattern := range f.allowedCmds {
		if matched, _ := filepath.Match(pattern, cmdline); matched {
			return true
		}
		// Also try matching just the first arg (executable name)
		if matched, _ := filepath.Match(pattern, firstArg(cmdline)); matched {
			return true
		}
	}
	return false
}

func firstArg(cmdline string) string {
	for i, c := range cmdline {
		if c == ' ' {
			return cmdline[:i]
		}
	}
	return cmdline
}

func (f *SecretFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Get caller info for logging and allowlist
	caller, _ := fuse.FromContext(ctx)
	callerInfo := "unknown"
	cmdline := ""
	if caller != nil {
		cmdline = getCmdline(caller.Pid)
		callerInfo = fmt.Sprintf("uid=%d gid=%d pid=%d cmd=%q", caller.Uid, caller.Gid, caller.Pid, cmdline)
	}

	if !f.isAllowed(cmdline) {
		log.Printf("Secret %s: access denied (not in allowlist) [%s]", f.reference, callerInfo)
		return nil, 0, syscall.EACCES
	}

	if f.maxReads > 0 {
		current := f.readCount.Load()
		if current >= f.maxReads {
			log.Printf("Secret %s: read limit (%d) exhausted [%s]", f.reference, f.maxReads, callerInfo)
			return nil, 0, syscall.EACCES
		}
	}

	val, err := f.manager.Resolve(ctx, f.reference)
	if err != nil {
		log.Printf("Failed to resolve %s: %v [%s]", f.reference, err, callerInfo)
		return nil, 0, syscall.ENOENT
	}

	f.content = []byte(val)
	f.readCount.Add(1)

	if f.maxReads > 0 {
		log.Printf("Secret %s: access granted (read %d/%d) [%s]", f.reference, f.readCount.Load(), f.maxReads, callerInfo)
	} else {
		log.Printf("Secret %s: access granted [%s]", f.reference, callerInfo)
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
