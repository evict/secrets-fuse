//go:build darwin

package fuse

import (
	"fmt"
	"os/exec"
	"strings"
)

func getCmdline(pid uint32) string {
	// Use ps to get command line on macOS
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "args=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getExePath(pid uint32) (string, error) {
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func validateCmdlineExe(pid uint32) bool {
	// macOS doesn't have /proc, so we can't easily validate cmdline vs exe
	// Consider this a best-effort check
	return true
}
