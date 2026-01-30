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

func getExePath(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

func validateCmdlineExe(pid uint32) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}

	args := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	if len(args) == 0 || len(args[0]) == 0 {
		return false
	}

	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}

	cmdArg0 := string(args[0])

	if exePath == cmdArg0 {
		return true
	}

	realExe, err := os.Stat(exePath)
	if err != nil {
		return false
	}
	realCmd, err := os.Stat(cmdArg0)
	if err != nil {
		return false
	}

	return os.SameFile(realExe, realCmd)
}
