package seccomp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ReadPathFromPid reads a null-terminated path string from the target
// thread's memory at the given address using process_vm_readv.
// Note: seccomp_notif.pid is a TID (thread ID), and process_vm_readv
// accepts any TID in the thread group.
func ReadPathFromPid(pid uint32, addr uint64) (string, error) {
	buf := make([]byte, 4096)

	localIov := []unix.Iovec{{
		Base: &buf[0],
		Len:  uint64(len(buf)),
	}}
	remoteIov := []unix.RemoteIovec{{
		Base: uintptr(addr),
		Len:  len(buf),
	}}

	n, err := unix.ProcessVMReadv(int(pid), localIov, remoteIov, 0)
	if err != nil {
		return "", fmt.Errorf("process_vm_readv pid %d at 0x%x: %w", pid, addr, err)
	}

	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i]), nil
		}
	}
	return "", fmt.Errorf("path too long or no null terminator (read %d bytes)", n)
}

const atFdCwd = -100

// ResolvePath resolves a potentially relative path using the process's
// working directory or an open directory fd.
func ResolvePath(pid uint32, dirfd int32, path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}

	if dirfd == atFdCwd {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return "", fmt.Errorf("readlink /proc/%d/cwd: %w", pid, err)
		}
		return filepath.Join(cwd, path), nil
	}

	dirPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	if err != nil {
		return "", fmt.Errorf("readlink /proc/%d/fd/%d: %w", pid, dirfd, err)
	}
	return filepath.Join(dirPath, path), nil
}

// TgidOfTid reads the TGID (process ID) for a given TID (thread ID)
// from /proc/<tid>/status.
func TgidOfTid(tid uint32) (uint32, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	for _, line := range strings.SplitN(string(buf[:n]), "\n", 10) {
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

// HashBinary computes the SHA-256 hash of the executable for the given PID.
// It reads /proc/PID/exe which is a kernel-resolved symlink that cannot be
// spoofed by the process.
func HashBinary(pid uint32) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", fmt.Errorf("open /proc/%d/exe: %w", pid, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing /proc/%d/exe: %w", pid, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ExePath returns the resolved executable path for the given PID.
func ExePath(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
