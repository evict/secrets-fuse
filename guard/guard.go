package guard

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	secretguard "github.com/evict/secrets-guard/fuse"
	"github.com/evict/secrets-guard/seccomp"
	"github.com/evict/secrets-guard/secretmanager"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

const childEnvKey = "__SECRETS_GUARD_CHILD"

// SecretMapping maps an app-visible path to a 1Password reference.
type SecretMapping struct {
	Path           string   // path the app tries to open (absolute, ~ expanded)
	Reference      string   // op:// reference
	Filename       string   // FUSE filename (defaults to basename of Path)
	TrustedHashes  []string // "sha256:..." hashes of allowed binaries
	MaxReads       int32
	Writable       bool
}

// Guard orchestrates the seccomp-notify + FUSE secret serving.
type Guard struct {
	manager  secretmanager.SecretManager
	secrets  []SecretMapping
	pathMap  map[string]*SecretMapping // resolved path → mapping
	debug    bool
}

// New creates a Guard with the given secret mappings.
func New(manager secretmanager.SecretManager, secrets []SecretMapping, debug bool) *Guard {
	pathMap := make(map[string]*SecretMapping, len(secrets))
	for i := range secrets {
		s := &secrets[i]
		if s.Filename == "" {
			s.Filename = filepath.Base(s.Path)
		}
		pathMap[s.Path] = s
	}
	return &Guard{
		manager: manager,
		secrets: secrets,
		pathMap: pathMap,
		debug:   debug,
	}
}

// Run starts the FUSE mount, spawns the target binary under seccomp
// supervision, and handles secret injection until the child exits.
func (g *Guard) Run(target string, args []string) error {
	// Create private FUSE mount directory
	fusePath, err := os.MkdirTemp(
		fmt.Sprintf("/run/user/%d", os.Getuid()),
		".secrets-guard-",
	)
	if err != nil {
		// Fallback to /tmp if /run/user doesn't exist
		fusePath, err = os.MkdirTemp("", ".secrets-guard-")
		if err != nil {
			return fmt.Errorf("create fuse tmpdir: %w", err)
		}
	}
	defer os.RemoveAll(fusePath)
	_ = os.Chmod(fusePath, 0700) // #nosec G302 -- directory needs execute bit

	// Build FUSE secret configs
	guardPID := uint32(os.Getpid()) // #nosec G115 -- PID fits in uint32
	fuseSecrets := make([]secretguard.SecretConfig, len(g.secrets))
	for i, s := range g.secrets {
		fuseSecrets[i] = secretguard.SecretConfig{
			Reference: s.Reference,
			Filename:  s.Filename,
			MaxReads:  s.MaxReads,
			Writable:  s.Writable,
			GuardPID:  guardPID,
		}
	}

	root := secretguard.NewSecretRoot(g.manager, fuseSecrets, 0)
	zero := time.Duration(0)
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Name:        "secrets-guard",
			DirectMount: true,
			Debug:       g.debug,
		},
		AttrTimeout:     &zero,
		EntryTimeout:    &zero,
		NegativeTimeout: &zero,
	}

	server, err := fs.Mount(fusePath, root, opts)
	if err != nil {
		return fmt.Errorf("fuse mount: %w", err)
	}
	defer func() { _ = server.Unmount() }()

	log.Printf("FUSE mounted at %s (private)", fusePath)

	// Create socketpair for notify_fd passing
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	parentSock := fds[0]
	childSock := fds[1]

	// Spawn child (re-exec with child mode)
	childSockFile := os.NewFile(uintptr(childSock), "guard-sock") // #nosec G115 -- fd fits in uintptr
	cmd := exec.Command(os.Args[0])                              // #nosec G204 -- intentional re-exec of self
	cmd.Args = append([]string{os.Args[0]}, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{childSockFile}
	cmd.Env = append(filterEnv(os.Environ()), childEnvKey+"=1")

	if err := cmd.Start(); err != nil {
		_ = unix.Close(parentSock)
		_ = childSockFile.Close()
		return fmt.Errorf("start child: %w", err)
	}
	_ = childSockFile.Close()
	_ = unix.Close(childSock)

	log.Printf("child started: pid=%d target=%s", cmd.Process.Pid, target) // #nosec G706 -- target is from LookPath

	// Redirect log output away from the child's terminal.
	// TUI apps (like amp) use raw-mode on stderr; log output corrupts them.
	logFile, err := os.CreateTemp("", "secrets-guard-*.log")
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
		log.Printf("log redirected to %s", logFile.Name())
		fmt.Fprintf(os.Stderr, "secrets-guard: log → %s\n", logFile.Name())
	}

	// Receive seccomp notify_fd from child
	notifyFd, err := seccomp.RecvFd(parentSock)
	_ = unix.Close(parentSock)
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("recv notify_fd: %w", err)
	}
	defer unix.Close(notifyFd)

	log.Printf("received notify_fd=%d, starting interception", notifyFd)

	// Run notification loop in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.notifyLoop(ctx, notifyFd, fusePath)

	// Wait for child to exit
	err = cmd.Wait()
	cancel()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("child: %w", err)
	}
	return nil
}

func (g *Guard) notifyLoop(ctx context.Context, notifyFd int, fusePath string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		notif, err := seccomp.RecvNotif(notifyFd)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("recv_notif: %v (child likely exited)", err)
			return
		}

		go g.handleNotif(notifyFd, notif, fusePath)
	}
}

func (g *Guard) handleNotif(notifyFd int, notif *seccomp.SeccompNotif, fusePath string) {
	// Every notification MUST get a response. Use defer as safety net
	// in case any code path forgets to respond.
	responded := false
	defer func() {
		if !responded {
			log.Printf("BUG: notification %d (tid %d) had no response, sending CONTINUE", notif.ID, notif.PID)
			_ = seccomp.ContinueSyscall(notifyFd, notif.ID)
		}
	}()

	// Read the pathname from the child's memory
	path, err := seccomp.ReadPathFromPid(notif.PID, notif.Data.Args[1])
	if err != nil {
		if g.debug {
			log.Printf("read path from tid %d: %v", notif.PID, err)
		}
		responded = true
		if err := seccomp.ContinueSyscall(notifyFd, notif.ID); err != nil {
			log.Printf("continue syscall (read fail) tid %d: %v", notif.PID, err)
		}
		return
	}

	// Resolve to absolute path
	resolved, err := seccomp.ResolvePath(notif.PID, int32(notif.Data.Args[0]), path) // #nosec G115 -- dirfd fits in int32
	if err != nil {
		if g.debug {
			log.Printf("resolve path from tid %d: %v", notif.PID, err)
		}
		responded = true
		if err := seccomp.ContinueSyscall(notifyFd, notif.ID); err != nil {
			log.Printf("continue syscall (resolve fail) tid %d: %v", notif.PID, err)
		}
		return
	}

	if g.debug {
		log.Printf("openat tid=%d path=%s", notif.PID, resolved)
	}

	// Check if this is a configured secret path
	mapping, ok := g.pathMap[resolved]
	if !ok {
		responded = true
		if err := seccomp.ContinueSyscall(notifyFd, notif.ID); err != nil {
			log.Printf("continue syscall (no match) tid %d path=%s: %v", notif.PID, resolved, err)
		}
		return
	}

	log.Printf("intercepted secret open: tid=%d path=%s", notif.PID, resolved)

	// TOCTOU check: notification still valid?
	if !seccomp.NotifIDValid(notifyFd, notif.ID) {
		responded = true // kernel already handled it
		log.Printf("notif %d expired (TOCTOU)", notif.ID)
		return
	}

	// Verify the calling binary's hash
	hash, err := seccomp.HashBinary(notif.PID)
	if err != nil {
		log.Printf("hash binary tid %d: %v", notif.PID, err)
		responded = true
		_ = seccomp.DenySyscall(notifyFd, notif.ID, int32(syscall.EACCES))
		return
	}

	if !isTrusted(hash, mapping.TrustedHashes) {
		exePath, _ := seccomp.ExePath(notif.PID)
		log.Printf("DENIED: tid=%d exe=%s hash=%s path=%s", notif.PID, exePath, hash, resolved)
		responded = true
		_ = seccomp.DenySyscall(notifyFd, notif.ID, int32(syscall.EACCES))
		return
	}

	// TOCTOU check again before injecting
	if !seccomp.NotifIDValid(notifyFd, notif.ID) {
		responded = true // kernel already handled it
		log.Printf("notif %d expired (TOCTOU post-hash)", notif.ID)
		return
	}

	// Forward the child's open flags to the FUSE file so writes work.
	// openat(dirfd, pathname, flags, mode) → Args[2] = flags
	childFlags := int(notif.Data.Args[2]) // #nosec G115 -- open flags fit in int
	isWrite := childFlags&(syscall.O_WRONLY|syscall.O_RDWR) != 0

	if isWrite && !mapping.Writable {
		log.Printf("DENIED: tid=%d path=%s (write on non-writable secret)", notif.PID, resolved)
		responded = true
		_ = seccomp.DenySyscall(notifyFd, notif.ID, int32(syscall.EACCES))
		return
	}

	// Open the FUSE file with matching flags (the FUSE handler allows our PID).
	// Pass through read/write mode and O_TRUNC; strip flags that don't apply
	// to an already-existing FUSE file (O_CREAT, O_EXCL, O_NOFOLLOW, etc.).
	fuseFile := filepath.Join(fusePath, mapping.Filename)
	openFlags := childFlags & (syscall.O_RDONLY | syscall.O_WRONLY | syscall.O_RDWR | syscall.O_TRUNC | syscall.O_APPEND)
	f, err := os.OpenFile(fuseFile, openFlags, 0) // #nosec G304 -- path is constructed from controlled fusePath + mapping.Filename
	if err != nil {
		log.Printf("open fuse file %s (flags=0x%x): %v", fuseFile, openFlags, err)
		responded = true
		_ = seccomp.DenySyscall(notifyFd, notif.ID, int32(syscall.EIO))
		return
	}
	defer f.Close()

	// Inject the FUSE fd into the child's fd table
	if err := seccomp.InjectFd(notifyFd, notif.ID, int(f.Fd())); err != nil { // #nosec G115 -- fd fits in int
		log.Printf("inject fd: %v", err)
		responded = true
		_ = seccomp.DenySyscall(notifyFd, notif.ID, int32(syscall.EIO))
		return
	}
	responded = true

	exePath, _ := seccomp.ExePath(notif.PID)
	mode := "read"
	if isWrite {
		mode = "write"
	}
	log.Printf("GRANTED: tid=%d exe=%s path=%s → %s (%s)", notif.PID, exePath, resolved, mapping.Reference, mode)
}

func isTrusted(hash string, trusted []string) bool {
	if len(trusted) == 0 {
		return true // no trust list = allow all (for development)
	}
	for _, t := range trusted {
		if t == hash {
			return true
		}
	}
	return false
}

// RunChild is called in the re-exec'd child process. It installs the
// seccomp filter, sends the notify_fd to the parent, then execs the target.
func RunChild(target string, args []string) error {
	// fd 3 is the socket from ExtraFiles[0]
	const sockFd = 3

	// NOTE: PR_SET_DUMPABLE=0 was removed. It prevented the parent guard
	// from reading /proc/PID/mem (needed to extract openat path arguments).
	// NO_NEW_PRIVS (set in InstallFilter) provides the key security guarantee.

	notifyFd, err := seccomp.InstallFilter()
	if err != nil {
		return fmt.Errorf("install seccomp filter: %w", err)
	}

	if err := seccomp.SendFd(sockFd, notifyFd); err != nil {
		return fmt.Errorf("send notify_fd: %w", err)
	}

	_ = unix.Close(notifyFd)
	_ = unix.Close(sockFd)

	// Strip guard env vars before exec
	env := filterEnv(os.Environ())

	return syscall.Exec(target, args, env) // #nosec G204 -- intentional exec of target binary
}

// IsChild returns true if this process was re-exec'd as the child.
func IsChild() bool {
	return os.Getenv(childEnvKey) != ""
}

func filterEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, "__SECRETS_GUARD_") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
