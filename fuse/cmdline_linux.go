package fuse

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
)

func getExePath(pid uint32) (string, error) {
	proc, err := process.NewProcess(int32(pid)) // #nosec G115 -- PID fits in int32
	if err != nil {
		return "", err
	}

	return proc.ExeWithContext(context.Background())
}
