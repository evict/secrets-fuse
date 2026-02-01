package fuse

import (
	"os"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

func getCmdline(pid uint32) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return ""
	}

	cmdline, err := proc.CmdlineSlice()
	if err != nil {
		return ""
	}

	return strings.Join(cmdline, " ")
}

func validateCmdlineExe(pid uint32) bool {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return false
	}

	cmdlineSlice, err := proc.CmdlineSlice()
	if err != nil || len(cmdlineSlice) == 0 || cmdlineSlice[0] == "" {
		return false
	}

	exePath, err := getExePath(pid)
	if err != nil {
		return false
	}

	cmdArg0 := cmdlineSlice[0]

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
