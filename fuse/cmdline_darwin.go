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
