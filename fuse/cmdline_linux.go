//go:build linux

package fuse

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

func getCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}

	args := strings.Split(string(bytes.TrimRight(data, "\x00")), "\x00")
	return strings.Join(args, " ")
}
