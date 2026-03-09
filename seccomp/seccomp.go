package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompSetModeFilter          = 1
	seccompFilterFlagNewListener  = 1 << 3
	seccompFilterFlagWaitKillable = 1 << 5

	seccompRetAllow     = 0x7fff0000
	seccompRetUserNotif = 0x7fc00000

	// seccomp_data field offset for syscall number
	seccompDataNROffset = 0

	// BPF instruction classes/modes
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfK   = 0x00
	bpfRET = 0x06

	// ioctl numbers for amd64
	ioctlNotifRecv    = 0xc0502100
	ioctlNotifSend    = 0xc0182101
	ioctlNotifIDValid = 0x40082102
	ioctlNotifAddFd   = 0x40182103

	seccompAddFdFlagSetfd        = 1 << 0
	seccompAddFdFlagSend         = 1 << 1
	seccompUserNotifFlagContinue = 1
)

// SeccompData matches struct seccomp_data (64 bytes).
type SeccompData struct {
	NR                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// SeccompNotif matches struct seccomp_notif (80 bytes).
type SeccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  SeccompData
}

// SeccompNotifResp matches struct seccomp_notif_resp (24 bytes).
type SeccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// SeccompNotifAddFd matches struct seccomp_notif_addfd (24 bytes).
type SeccompNotifAddFd struct {
	ID       uint64
	Flags    uint32
	SrcFd    uint32
	NewFd    uint32
	NewFlags uint32
}

// InstallFilter installs a seccomp BPF filter that intercepts openat/openat2
// with SECCOMP_RET_USER_NOTIF. Returns the notify fd.
func InstallFilter() (int, error) {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}

	filter := []unix.SockFilter{
		// Load syscall number
		{Code: bpfLD | bpfW | bpfABS, K: seccompDataNROffset},
		// if openat → skip 2 to NOTIFY
		{Code: bpfJMP | bpfJEQ | bpfK, Jt: 2, Jf: 0, K: unix.SYS_OPENAT},
		// if openat2 → skip 1 to NOTIFY
		{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: unix.SYS_OPENAT2},
		// ALLOW
		{Code: bpfRET | bpfK, K: seccompRetAllow},
		// USER_NOTIF
		{Code: bpfRET | bpfK, K: seccompRetUserNotif},
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)), // #nosec G115 -- fixed-size filter
		Filter: &filter[0],
	}

	fd, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		seccompSetModeFilter,
		seccompFilterFlagNewListener|seccompFilterFlagWaitKillable,
		uintptr(unsafe.Pointer(&prog)), // #nosec G103 -- required for seccomp syscall
	)
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
	}
	return int(fd), nil // #nosec G115 -- fd fits in int
}

// RecvNotif blocks until the child triggers an intercepted syscall.
func RecvNotif(notifyFd int) (*SeccompNotif, error) {
	var notif SeccompNotif
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifyFd), // #nosec G115 -- fd fits in uintptr
		ioctlNotifRecv,
		uintptr(unsafe.Pointer(&notif)), // #nosec G103 -- required for ioctl
	)
	if errno != 0 {
		return nil, errno
	}
	return &notif, nil
}

// NotifIDValid checks whether a notification is still pending (TOCTOU check).
func NotifIDValid(notifyFd int, id uint64) bool {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifyFd), // #nosec G115 -- fd fits in uintptr
		ioctlNotifIDValid,
		uintptr(unsafe.Pointer(&id)), // #nosec G103 -- required for ioctl
	)
	return errno == 0
}

// ContinueSyscall tells the kernel to execute the intercepted syscall normally.
func ContinueSyscall(notifyFd int, id uint64) error {
	resp := SeccompNotifResp{
		ID:    id,
		Val:   0,
		Error: 0,
		Flags: seccompUserNotifFlagContinue,
	}
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifyFd), // #nosec G115 -- fd fits in uintptr
		ioctlNotifSend,
		uintptr(unsafe.Pointer(&resp)), // #nosec G103 -- required for ioctl
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// InjectFd injects srcFd into the child's fd table as the return value of
// the intercepted openat/openat2 call.
func InjectFd(notifyFd int, id uint64, srcFd int) error {
	addfd := SeccompNotifAddFd{
		ID:       id,
		Flags:    seccompAddFdFlagSend,
		SrcFd:    uint32(srcFd), // #nosec G115 -- fd fits in uint32
		NewFd:    0,
		NewFlags: unix.O_CLOEXEC,
	}
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifyFd), // #nosec G115 -- fd fits in uintptr
		ioctlNotifAddFd,
		uintptr(unsafe.Pointer(&addfd)), // #nosec G103 -- required for ioctl
	)
	if errno != 0 {
		return fmt.Errorf("NOTIF_ADDFD: %w", errno)
	}
	return nil
}

// DenySyscall makes the child's syscall return an error.
func DenySyscall(notifyFd int, id uint64, errno int32) error {
	resp := SeccompNotifResp{
		ID:    id,
		Val:   -1,
		Error: -errno,
		Flags: 0,
	}
	_, _, e := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifyFd), // #nosec G115 -- fd fits in uintptr
		ioctlNotifSend,
		uintptr(unsafe.Pointer(&resp)), // #nosec G103 -- required for ioctl
	)
	if e != 0 {
		return e
	}
	return nil
}

// SendFd sends a file descriptor over a unix socket using SCM_RIGHTS.
func SendFd(conn int, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(conn, []byte{0}, rights, nil, 0)
}

// RecvFd receives a file descriptor from a unix socket using SCM_RIGHTS.
func RecvFd(conn int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(conn, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no fd received")
}
