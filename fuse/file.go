package fuse

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	writable    bool
	guardPID    uint32 // if set, only this PID may access (guard mode)

	mu        sync.Mutex
	content   []byte
	readCount atomic.Int32
	maxReads  int32

	dirty       bool
	writeSize   uint64
	guardOpened bool // set when opened by the guard; skips PID checks on Write/Flush
}

func NewSecretFile(manager secretmanager.SecretManager, reference string, maxReads int32, allowedCmds []string, writable bool, guardPID uint32) *SecretFile {
	return &SecretFile{
		manager:     manager,
		reference:   reference,
		maxReads:    maxReads,
		allowedCmds: allowedCmds,
		writable:    writable,
		guardPID:    guardPID,
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

func (f *SecretFile) checkAccess(caller *fuse.Caller, op string) (cmdline string, callerInfo string, errno syscall.Errno) {
	if caller == nil {
		return "", "unknown", 0
	}

	// Guard mode: only the guard process may open FUSE files directly.
	// The guard handles trust verification via seccomp before opening.
	// After Open, the fd is injected into the child via SECCOMP_ADDFD,
	// so subsequent Write/Flush calls come from the child's PID.
	// guardOpened tracks that the guard already authorized this fd.
	if f.guardPID != 0 {
		if f.guardOpened {
			return "", fmt.Sprintf("tid=%d (guard-authorized)", caller.Pid), 0
		}
		// Not yet opened — only the guard PID may call Open.
		// FUSE caller.Pid is a TID; resolve to TGID for comparison.
		callerTGID, err := tgidOfTid(caller.Pid)
		if err != nil || callerTGID != f.guardPID {
			log.Printf("Secret %s: %s denied (tid %d tgid %d is not guard pid %d)", f.reference, op, caller.Pid, callerTGID, f.guardPID)
			return "", fmt.Sprintf("tid=%d", caller.Pid), syscall.EACCES
		}
		return "", fmt.Sprintf("tid=%d tgid=%d (guard)", caller.Pid, callerTGID), 0
	}

	cmdline = getCmdline(caller.Pid)
	callerInfo = fmt.Sprintf("uid=%d gid=%d pid=%d cmd=%q", caller.Uid, caller.Gid, caller.Pid, cmdline)

	if !validateCmdlineExe(caller.Pid) {
		log.Printf("Secret %s: %s denied (cmdline/exe mismatch - possible spoofing) [%s]", f.reference, op, callerInfo)
		return cmdline, callerInfo, syscall.EACCES
	}

	if !f.isAllowed(cmdline) {
		log.Printf("Secret %s: %s denied (not in allowlist) [%s]", f.reference, op, callerInfo)
		return cmdline, callerInfo, syscall.EACCES
	}

	return cmdline, callerInfo, 0
}

// tgidOfTid reads the TGID (process ID) for a given TID (thread ID)
// from /proc/<tid>/status.
func tgidOfTid(tid uint32) (uint32, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "Tgid:") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				v, err := strconv.ParseUint(fields[1], 10, 32)
				return uint32(v), err
			}
		}
	}
	return 0, fmt.Errorf("no Tgid in /proc/%d/status", tid)
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

	caller, _ := fuse.FromContext(ctx)
	_, callerInfo, errno := f.checkAccess(caller, "access")
	if errno != 0 {
		return nil, 0, errno
	}

	isWrite := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0
	isTrunc := flags&syscall.O_TRUNC != 0

	if isWrite && !f.writable {
		log.Printf("Secret %s: write denied (not writable) [%s]", f.reference, callerInfo)
		return nil, 0, syscall.EACCES
	}

	if f.maxReads > 0 && !isWrite {
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

	if isTrunc {
		f.content = []byte{}
		f.dirty = true
	} else {
		f.content = []byte(val)
	}

	if f.guardPID != 0 {
		f.guardOpened = true
	}

	if !isWrite {
		f.readCount.Add(1)
	}

	if f.maxReads > 0 && !isWrite {
		log.Printf("Secret %s: access granted (read %d/%d) [%s]", f.reference, f.readCount.Load(), f.maxReads, callerInfo)
	} else if isWrite {
		log.Printf("Secret %s: opened for writing [%s]", f.reference, callerInfo)
	} else {
		log.Printf("Secret %s: access granted [%s]", f.reference, callerInfo)
	}

	return nil, fuse.FOPEN_DIRECT_IO, 0
}

func (f *SecretFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Re-fetch if content was invalidated (after a write)
	if f.content == nil {
		val, err := f.manager.Resolve(ctx, f.reference)
		if err != nil {
			log.Printf("Secret %s: failed to re-read: %v", f.reference, err)
			return nil, syscall.EIO
		}
		f.content = []byte(val)
		log.Printf("Secret %s: re-fetched %d bytes", f.reference, len(f.content))
	}

	if int(off) >= len(f.content) {
		return fuse.ReadResultData(nil), 0
	}

	end := min(int(off)+len(dest), len(f.content))

	return fuse.ReadResultData(f.content[off:end]), 0
}

func (f *SecretFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()

	size := max(f.writeSize, uint64(len(f.content)))
	out.Size = size
	out.Mode = 0400 // r--------
	if f.writable {
		out.Mode = 0600 // rw-------
	}
	out.Mtime = uint64(time.Now().Unix()) // #nosec G115 -- Unix time is positive
	return 0
}

func (f *SecretFile) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	caller, _ := fuse.FromContext(ctx)
	_, callerInfo, errno := f.checkAccess(caller, "write")
	if errno != 0 {
		return 0, errno
	}

	if !f.writable {
		log.Printf("Secret %s: write denied (not writable) [%s]", f.reference, callerInfo)
		return 0, syscall.EACCES
	}

	end := int(off) + len(data)
	if end > len(f.content) {
		newContent := make([]byte, end)
		copy(newContent, f.content)
		f.content = newContent
	}
	copy(f.content[off:], data)
	f.dirty = true

	log.Printf("Secret %s: wrote %d bytes at offset %d [%s]", f.reference, len(data), off, callerInfo)
	return uint32(len(data)), 0 // #nosec G115 -- data len fits in uint32
}

func (f *SecretFile) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()

	if sz, ok := in.GetSize(); ok {
		f.writeSize = sz
		if sz < uint64(len(f.content)) {
			f.content = f.content[:sz]
		} else if sz > uint64(len(f.content)) {
			newContent := make([]byte, sz)
			copy(newContent, f.content)
			f.content = newContent
		}
		f.dirty = true
	}

	size := max(f.writeSize, uint64(len(f.content)))
	out.Size = size
	out.Mode = 0600
	out.Mtime = uint64(time.Now().Unix()) // #nosec G115 -- Unix time is positive
	return 0
}

func (f *SecretFile) Flush(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Reset guard authorization so the next Open requires going through
	// the seccomp guard again.
	f.guardOpened = false

	if !f.dirty {
		return 0
	}

	caller, _ := fuse.FromContext(ctx)
	callerInfo := "unknown"
	if caller != nil {
		cmdline := getCmdline(caller.Pid)
		callerInfo = fmt.Sprintf("uid=%d gid=%d pid=%d cmd=%q", caller.Uid, caller.Gid, caller.Pid, cmdline)
	}

	err := f.manager.Write(ctx, f.reference, string(f.content))
	if err != nil {
		log.Printf("Secret %s: failed to write back: %v [%s]", f.reference, err, callerInfo)
		return syscall.EIO
	}

	f.dirty = false
	flushedBytes := len(f.content)
	f.content = nil // Clear so next Read re-fetches

	log.Printf("Secret %s: flushed %d bytes to password manager [%s]", f.reference, flushedBytes, callerInfo)
	return 0
}

func (f *SecretFile) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	return f.Flush(ctx, fh)
}
