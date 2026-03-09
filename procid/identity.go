package procid

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/v4/process"
)

// Identity describes the process shape that is allowed to access a guarded secret.
type Identity struct {
	Name    string
	Cmdline []string
}

type Guard struct {
	mu     sync.RWMutex
	pinned *Identity
}

func Current(pid uint32) (Identity, error) {
	tgid, err := tgidOfTid(pid)
	if err != nil {
		return Identity{}, err
	}

	proc, err := process.NewProcess(int32(tgid)) // #nosec G115 -- PID fits in int32
	if err != nil {
		return Identity{}, err
	}

	name, err := proc.Name()
	if err != nil {
		return Identity{}, err
	}

	cmdline, err := proc.CmdlineSlice()
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		Name:    name,
		Cmdline: cmdline,
	}, nil
}

func NewGuard() *Guard {
	return &Guard{}
}

func (i Identity) Matches(other Identity) bool {
	return i.Name == other.Name && slices.Equal(i.Cmdline, other.Cmdline)
}

func (i Identity) CmdlineString() string {
	return strings.Join(i.Cmdline, " ")
}

func (i Identity) String() string {
	return fmt.Sprintf("name=%q cmd=%q", i.Name, i.CmdlineString())
}

func (g *Guard) Expected() (Identity, bool) {
	if g == nil {
		return Identity{}, false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.pinned == nil {
		return Identity{}, false
	}

	return clone(*g.pinned), true
}

func (g *Guard) PinOrMatch(current Identity) (matched bool, expected Identity, pinned bool) {
	if g == nil {
		return false, Identity{}, false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.pinned == nil {
		pinnedIdentity := clone(current)
		g.pinned = &pinnedIdentity
		return true, pinnedIdentity, true
	}

	expected = clone(*g.pinned)
	return expected.Matches(current), expected, false
}

func clone(identity Identity) Identity {
	return Identity{
		Name:    identity.Name,
		Cmdline: slices.Clone(identity.Cmdline),
	}
}

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
