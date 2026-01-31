//go:build darwin

package fuse

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// getProcArgs fetches the command line arguments for a specific PID on macOS
// using the ps command with appropriate flags to display the full command line.
func getProcArgs(pid uint32) ([]string, error) {
	// Use ps with flags to get the full command line
	// -p: specify PID
	// -o args=: output only the arguments (full command line)
	cmd := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "args=")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run ps: %w", err)
	}

	// Parse the output - ps returns the full command line
	cmdline := strings.TrimSpace(string(output))
	if cmdline == "" {
		return nil, fmt.Errorf("empty command line")
	}

	// Split the command line into arguments
	// Note: This uses simple whitespace splitting, which matches the behavior
	// expected by the allowlist matching system in getCmdline().
	// Arguments with spaces will be split even if originally quoted,
	// but this is consistent with how the allowlist patterns are matched.
	args := strings.Fields(cmdline)
	return args, nil
}

func getCmdline(pid uint32) string {
	args, err := getProcArgs(pid)
	if err != nil {
		return ""
	}
	return strings.Join(args, " ")
}

func getExePath(pid uint32) (string, error) {
	// Use ps to get the executable path
	// -p: specify PID
	// -o comm=: output only the command name (executable path)
	cmd := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run ps: %w", err)
	}

	exePath := strings.TrimSpace(string(output))
	if exePath == "" {
		return "", fmt.Errorf("empty executable path")
	}

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
	realExe, err := os.Stat(exePath)
	if err != nil {
		return false
	}
	realCmd, err := os.Stat(args[0])
	if err != nil {
		// If argv[0] is not a valid path, it might be a bare command name
		// (e.g., "python" instead of "/usr/bin/python")
		// Compare just the executable basenames as a fallback.
		// Note: This is a best-effort validation that may not catch all edge cases.
		return filepath.Base(exePath) == filepath.Base(args[0])
	}

	return os.SameFile(realExe, realCmd)
}
