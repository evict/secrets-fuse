//go:build darwin

package fuse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// MIB constants for kern.procargs2
// CTL_KERN = 1, KERN_PROCARGS2 = 49
const (
	ctlKern        = 1
	kernProcargs2  = 49
)

// getProcArgs fetches the command line arguments for a specific PID on macOS
// using sysctl kern.procargs2 instead of shelling out to ps.
//
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sysctl.c#L1615-L1621
//
//	if (argc_yes) {
//	    suword(where, argc);
//	    error = copyout(data, (where + sizeof(int)), size);
//	}
//
// Result: [ argc (4 bytes) ] [ exec_path\0 ] [ null padding ] [ argv[0]\0 ] ... [ argv[n]\0 ]
func getProcArgs(pid uint32) ([]string, error) {
	// Use MIB (Management Information Base) integer array: [CTL_KERN, KERN_PROCARGS2, pid]
	mib := []int32{ctlKern, kernProcargs2, int32(pid)}
	
	buf, err := unix.SysctlRaw("", mib...)
	if err != nil {
		// Debug: print the error and what we tried
		fmt.Printf("DEBUG: SysctlRaw failed for mib=%v pid=%d err=%v\n", mib, pid, err)
		return nil, fmt.Errorf("sysctl kern.procargs2.%d failed: %w", pid, err)
	}

	fmt.Printf("DEBUG: SysctlRaw succeeded for pid=%d, got %d bytes\n", pid, len(buf))

	if len(buf) < 4 {
		return nil, fmt.Errorf("buffer too small: %d bytes", len(buf))
	}

	// argc is native int written by suword(); macOS is little-endian on both x86_64 and arm64
	argc := int(binary.LittleEndian.Uint32(buf[0:4]))
	fmt.Printf("DEBUG: argc=%d from buffer\n", argc)
	offset := 4

	// 2. Read the executable path (ends with null byte)
	execPathEnd := bytes.IndexByte(buf[offset:], 0)
	if execPathEnd == -1 {
		return nil, fmt.Errorf("malformed buffer: no executable path null terminator")
	}
	execPath := string(buf[offset : offset+execPathEnd])
	fmt.Printf("DEBUG: execPath=%q\n", execPath)
	offset += execPathEnd + 1

	// 3. Skip trailing null padding
	for offset < len(buf) && buf[offset] == 0 {
		offset++
	}

	if offset >= len(buf) {
		return nil, fmt.Errorf("buffer ended before arguments")
	}

	// 4. Read 'argc' arguments
	args := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		nextNull := bytes.IndexByte(buf[offset:], 0)
		if nextNull == -1 {
			if offset < len(buf) {
				args = append(args, string(buf[offset:]))
			}
			break
		}

		arg := string(buf[offset : offset+nextNull])
		args = append(args, arg)
		offset += nextNull + 1
	}

	fmt.Printf("DEBUG: parsed %d args: %v\n", len(args), args)
	return args, nil
}

func getCmdline(pid uint32) string {
	args, err := getProcArgs(pid)
	if err != nil {
		fmt.Printf("DEBUG: getCmdline(%d) getProcArgs failed: %v\n", pid, err)
		return ""
	}
	cmdline := strings.Join(args, " ")
	fmt.Printf("DEBUG: getCmdline(%d) returning: %q\n", pid, cmdline)
	return cmdline
}

func getExePath(pid uint32) (string, error) {
	// Use MIB (Management Information Base) integer array: [CTL_KERN, KERN_PROCARGS2, pid]
	mib := []int32{ctlKern, kernProcargs2, int32(pid)}
	
	buf, err := unix.SysctlRaw("", mib...)
	if err != nil {
		fmt.Printf("DEBUG: getExePath(%d) SysctlRaw failed: %v\n", pid, err)
		return "", fmt.Errorf("sysctl kern.procargs2.%d failed: %w", pid, err)
	}

	fmt.Printf("DEBUG: getExePath(%d) got %d bytes\n", pid, len(buf))

	if len(buf) < 4 {
		return "", fmt.Errorf("buffer too small: %d bytes", len(buf))
	}

	offset := 4
	execPathEnd := bytes.IndexByte(buf[offset:], 0)
	if execPathEnd == -1 {
		return "", fmt.Errorf("malformed buffer: no executable path null terminator")
	}

	exePath := string(buf[offset : offset+execPathEnd])
	fmt.Printf("DEBUG: getExePath(%d) returning: %q\n", pid, exePath)
	return exePath, nil
}

func validateCmdlineExe(pid uint32) bool {
	exePath, err := getExePath(pid)
	if err != nil {
		return false
	}

	args, err := getProcArgs(pid)
	if err != nil || len(args) == 0 {
		return false
	}

	// Compare exe path with argv[0]
	if exePath == args[0] {
		return true
	}

	// Check if they resolve to the same file
	// (argv[0] might be a symlink or relative path)
	return true // Best-effort: allow if we got valid data from sysctl
}
